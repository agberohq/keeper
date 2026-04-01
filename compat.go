package keeper

import (
	"encoding/json"
	"fmt"
	"time"

	pkgaudit "github.com/agberohq/keeper/pkg/audit"
)

// Unlock derives a Master key from passphrase bytes and calls UnlockDatabase.
// Passphrase bytes are NOT zeroed by this method — the caller owns them.
func (s *Keeper) Unlock(passphrase []byte) error {
	master, err := s.DeriveMaster(passphrase)
	if err != nil {
		return err
	}
	return s.UnlockDatabase(master)
}

// RotateSalt generates a new KDF salt, re-derives the master key under it,
// re-encrypts all LevelPasswordOnly secrets, and updates the verification
// hash. The old salt is retained in the versioned salt store for audit
// purposes.
//
// Salt rotation is independent of passphrase rotation. Call this periodically
// or whenever you want to ensure that a compromised salt cannot be used to
// accelerate offline attacks against a future passphrase breach.
//
// passphrase must be the current passphrase — it is used to re-derive the
// master key under the new salt. It is NOT zeroed by this method.
func (s *Keeper) RotateSalt(passphrase []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.locked {
		return ErrStoreLocked
	}

	oldKey, err := s.master.Bytes()
	if err != nil {
		return fmt.Errorf("failed to read current master key: %w", err)
	}
	defer secureZero(oldKey)

	newSalt, _, err := s.rotateSalt()
	if err != nil {
		return fmt.Errorf("failed to rotate salt: %w", err)
	}

	newKey, err := s.config.KDF.DeriveKey(passphrase, newSalt, s.config.KeyLen)
	if err != nil {
		return fmt.Errorf("key derivation with new salt failed: %w", err)
	}
	defer secureZero(newKey)

	if err := s.reencryptAllWithKey(newKey, oldKey); err != nil {
		return fmt.Errorf("re-encryption failed: %w", err)
	}
	if err := s.storeVerificationHash(newKey); err != nil {
		return fmt.Errorf("failed to store verification hash: %w", err)
	}

	newMaster, err := NewMaster(newKey)
	if err != nil {
		return fmt.Errorf("failed to create new master: %w", err)
	}

	oldAuditKey, err := deriveAuditKey(oldKey)
	if err != nil {
		return fmt.Errorf("failed to derive old audit key: %w", err)
	}
	newAuditKey, err := deriveAuditKey(newKey)
	if err != nil {
		secureZero(oldAuditKey)
		return fmt.Errorf("failed to derive new audit key: %w", err)
	}

	s.appendRotationCheckpoints(oldAuditKey, newAuditKey)
	secureZero(oldAuditKey)

	s.master.Destroy()
	s.master = newMaster
	s.auditStore.setSigningKey(newAuditKey)
	secureZero(newAuditKey)

	newPolicyKey, err := derivePolicyKey(newKey)
	if err != nil {
		return fmt.Errorf("failed to derive new policy key: %w", err)
	}
	secureZero(s.policyKey)
	s.policyKey = newPolicyKey
	if err := s.upgradePolicyHMACs(); err != nil {
		s.logger.Fields("err", err).Warn("policy HMAC rewrite after salt rotation failed — continuing")
	}

	for _, policy := range s.schemeRegistry {
		if policy.Level == LevelPasswordOnly {
			if err := s.unlockBucketPasswordOnly(policy.Scheme, policy.Namespace); err != nil {
				s.audit("salt_rotate_reseed_failed", policy.Scheme, policy.Namespace, "", false, 0)
			}
		}
	}
	_ = s.unlockBucketPasswordOnly(s.defaultScheme, s.defaultNs)
	s.logger.Info("salt rotation completed")
	return nil
}

// Rotate re-derives the master key with a new passphrase and re-encrypts every
// LevelPasswordOnly secret. LevelAdminWrapped secrets use per-admin KEKs and
// are unaffected.
//
// After the master key changes:
//   - The audit signing key is re-derived from the new master.
//   - A key-rotation checkpoint event is appended to every active audit chain,
//     signed with the old key as the final event of the old epoch and
//     verifiable by the new key as the first event of the new epoch.
//
// Passphrase bytes are NOT zeroed by this method — the caller owns them.
func (s *Keeper) Rotate(newPassphrase []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.locked {
		return ErrStoreLocked
	}

	oldKey, err := s.master.Bytes()
	if err != nil {
		return fmt.Errorf("failed to read current master key: %w", err)
	}
	defer secureZero(oldKey)

	salt, err := s.getOrCreateSalt()
	if err != nil {
		return fmt.Errorf("failed to get salt: %w", err)
	}
	newKey, err := s.config.KDF.DeriveKey(newPassphrase, salt, s.config.KeyLen)
	if err != nil {
		return fmt.Errorf("key derivation failed: %w", err)
	}
	defer secureZero(newKey)

	if err := s.reencryptAllWithKey(newKey, oldKey); err != nil {
		return fmt.Errorf("re-encryption failed: %w", err)
	}
	if err := s.storeVerificationHash(newKey); err != nil {
		return fmt.Errorf("failed to store verification hash: %w", err)
	}

	newMaster, err := NewMaster(newKey)
	if err != nil {
		return fmt.Errorf("failed to create new master: %w", err)
	}

	// Derive the old and new audit keys before swapping the master, so we
	// can compute both fingerprints for the checkpoint event.
	oldAuditKey, err := deriveAuditKey(oldKey)
	if err != nil {
		return fmt.Errorf("failed to derive old audit key: %w", err)
	}
	newAuditKey, err := deriveAuditKey(newKey)
	if err != nil {
		secureZero(oldAuditKey)
		return fmt.Errorf("failed to derive new audit key: %w", err)
	}

	// Append a checkpoint event to every active chain, signed with the old key.
	// This is O(number of chains) — one small event per chain regardless of
	// how many events are in the chain.
	s.appendRotationCheckpoints(oldAuditKey, newAuditKey)
	secureZero(oldAuditKey)

	// Swap the master and activate the new audit signing key.
	s.master.Destroy()
	s.master = newMaster
	s.auditStore.setSigningKey(newAuditKey)
	secureZero(newAuditKey)

	// Re-derive the policy HMAC key from the new master and rewrite all
	// policy records with the new tag.
	newPolicyKey, err := derivePolicyKey(newKey)
	if err != nil {
		return fmt.Errorf("failed to derive new policy key: %w", err)
	}
	secureZero(s.policyKey)
	s.policyKey = newPolicyKey
	if err := s.upgradePolicyHMACs(); err != nil {
		s.logger.Fields("err", err).Warn("policy HMAC rewrite after rotation failed — continuing")
	}

	// Re-seed the Envelope for all LevelPasswordOnly buckets with the new key.
	for _, policy := range s.schemeRegistry {
		if policy.Level == LevelPasswordOnly {
			if err := s.unlockBucketPasswordOnly(policy.Scheme, policy.Namespace); err != nil {
				s.audit("rotate_reseed_failed", policy.Scheme, policy.Namespace, "", false, 0)
			}
		}
	}
	_ = s.unlockBucketPasswordOnly(s.defaultScheme, s.defaultNs)
	return nil
}

// appendRotationCheckpoints writes a key-rotation checkpoint event to every
// audit chain for which a policy exists. The event is signed with oldAuditKey
// (the last event of the old epoch). The store switches to newAuditKey
// immediately after this call.
//
// The checkpoint Details carry fingerprints of both keys so an auditor can
// verify the key transition without knowing the raw key bytes.
func (s *Keeper) appendRotationCheckpoints(oldAuditKey, newAuditKey []byte) {
	type checkpointDetails struct {
		OldKeyFp string `json:"old_key_fingerprint"`
		NewKeyFp string `json:"new_key_fingerprint"`
	}

	details := checkpointDetails{
		OldKeyFp: pkgaudit.KeyFingerprint(oldAuditKey),
		NewKeyFp: pkgaudit.KeyFingerprint(newAuditKey),
	}
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		return
	}

	// Temporarily activate the old signing key so the checkpoint is
	// authenticated by the epoch it closes.
	s.auditStore.setSigningKey(oldAuditKey)

	for registryKey, policy := range s.schemeRegistry {
		_ = registryKey
		prevCS := s.getLastChecksum(policy.Scheme, policy.Namespace)
		event := &BucketEvent{
			ID:           generateUUID(),
			BucketID:     policy.ID,
			Scheme:       policy.Scheme,
			Namespace:    policy.Namespace,
			EventType:    auditEventKeyRotation,
			Details:      detailsJSON,
			Timestamp:    time.Now(),
			PrevChecksum: prevCS,
		}
		event.Checksum = event.ComputeChecksum(prevCS)
		_ = s.auditStore.appendEvent(policy.Scheme, policy.Namespace, event)
	}
}

// Convenience wrappers — two-argument forms that apply the default scheme.

func (s *Keeper) SetNamespaced(namespace, key string, value []byte) error {
	return s.SetNamespacedFull(s.defaultScheme, namespace, key, value)
}

func (s *Keeper) GetNamespaced(namespace, key string) ([]byte, error) {
	return s.GetNamespacedFull(s.defaultScheme, namespace, key)
}

func (s *Keeper) GetStringNamespaced(namespace, key string) (string, error) {
	b, err := s.GetNamespaced(namespace, key)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (s *Keeper) SetStringNamespaced(namespace, key, value string) error {
	return s.SetNamespaced(namespace, key, []byte(value))
}

func (s *Keeper) GetBytesNamespaced(namespace, key string) ([]byte, error) {
	return s.GetNamespaced(namespace, key)
}

func (s *Keeper) DeleteNamespaced(namespace, key string) error {
	return s.DeleteNamespacedFull(s.defaultScheme, namespace, key)
}

func (s *Keeper) ListNamespace(namespace string) ([]string, error) {
	return s.ListNamespacedFull(s.defaultScheme, namespace)
}

func (s *Keeper) ListNamespaces() ([]string, error) {
	return s.ListNamespacesInSchemeFull(s.defaultScheme)
}

func (s *Keeper) ListPrefixNamespaced(namespace, prefix string) ([]string, error) {
	return s.ListPrefixNamespacedFull(s.defaultScheme, namespace, prefix)
}

func (s *Keeper) ListPrefix(prefix string) ([]string, error) {
	scheme, namespace, keyPrefix := parseKeyExtended(prefix)
	return s.ListPrefixNamespacedFull(scheme, namespace, keyPrefix)
}

func (s *Keeper) ExistsNamespaced(namespace, key string) (bool, error) {
	return s.ExistsNamespacedFull(s.defaultScheme, namespace, key)
}

func (s *Keeper) RenameNamespaced(namespace, oldKey, newKey string) error {
	return s.RenameNamespacedFull(s.defaultScheme, namespace, oldKey, newKey)
}

func (s *Keeper) CompareAndSwapNamespaced(namespace, key string, oldValue, newValue []byte) error {
	return s.CompareAndSwapNamespacedFull(s.defaultScheme, namespace, key, oldValue, newValue)
}

func (s *Keeper) CompareAndSwap(key, oldValue, newValue string) error {
	scheme, namespace, localKey := parseKeyExtended(key)
	return s.CompareAndSwapNamespacedFull(scheme, namespace, localKey, []byte(oldValue), []byte(newValue))
}

func (s *Keeper) DeleteNamespace(namespace string) error {
	return s.DeleteBucket(s.defaultScheme, namespace)
}

func (s *Keeper) Move(key, fromNS, toNS string) error {
	_, fErr := s.GetPolicy(s.defaultScheme, fromNS)
	_, tErr := s.GetPolicy(s.defaultScheme, toNS)
	if fErr != nil || tErr != nil {
		v, err := s.GetNamespaced(fromNS, key)
		if err != nil {
			return err
		}
		if err := s.SetNamespaced(toNS, key, v); err != nil {
			return err
		}
		return s.DeleteNamespaced(fromNS, key)
	}
	return s.MoveCrossBucket(key, s.defaultScheme, fromNS, s.defaultScheme, toNS, false)
}

func (s *Keeper) Copy(key, fromNS, toNS string) error {
	_, fErr := s.GetPolicy(s.defaultScheme, fromNS)
	_, tErr := s.GetPolicy(s.defaultScheme, toNS)
	if fErr != nil || tErr != nil {
		v, err := s.GetNamespaced(fromNS, key)
		if err != nil {
			return err
		}
		return s.SetNamespaced(toNS, key, v)
	}
	return s.CopyCrossBucket(key, s.defaultScheme, fromNS, s.defaultScheme, toNS, false)
}
