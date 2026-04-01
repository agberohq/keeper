package keeper

import (
	"encoding/json"
	"fmt"
	"time"

	pkgaudit "github.com/agberohq/keeper/pkg/audit"
	"github.com/olekukonko/zero"
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
// LevelAdminWrapped buckets are NOT re-keyed by this call because their DEKs
// use a per-bucket salt, not the master KDF salt. Call RotateAdminWrappedDEK
// separately after this method completes.
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
	defer zero.Bytes(oldKey)

	newSalt, _, err := s.rotateSalt()
	if err != nil {
		return fmt.Errorf("failed to rotate salt: %w", err)
	}

	newKey, err := s.config.KDF.DeriveKey(passphrase, newSalt, s.config.KeyLen)
	if err != nil {
		return fmt.Errorf("key derivation with new salt failed: %w", err)
	}
	defer zero.Bytes(newKey)

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
		zero.Bytes(oldAuditKey)
		return fmt.Errorf("failed to derive new audit key: %w", err)
	}

	s.appendRotationCheckpoints(oldAuditKey, newAuditKey)
	zero.Bytes(oldAuditKey)

	s.master.Destroy()
	s.master = newMaster
	s.auditStore.setSigningKey(newAuditKey)
	zero.Bytes(newAuditKey)

	newPolicyKey, err := derivePolicyKey(newKey)
	if err != nil {
		return fmt.Errorf("failed to derive new policy key: %w", err)
	}
	zero.Bytes(s.policyKey)
	s.policyKey = newPolicyKey
	if err := s.upgradePolicyHMACs(); err != nil {
		s.logger.Fields("err", err).Warn("policy HMAC rewrite after salt rotation failed — continuing")
	}

	for _, policy := range s.schemeRegistry {
		switch policy.Level {
		case LevelPasswordOnly:
			if err := s.unlockBucketPasswordOnly(policy.Scheme, policy.Namespace); err != nil {
				s.audit("salt_rotate_reseed_failed", policy.Scheme, policy.Namespace, "", false, 0)
			}
		case LevelAdminWrapped:
			s.logger.Fields(
				"scheme", policy.Scheme,
				"namespace", policy.Namespace,
				"policy_id", policy.ID,
			).Warn("LevelAdminWrapped bucket not re-keyed by RotateSalt — call RotateAdminWrappedDEK to update the per-bucket DEK salt")
		}
	}
	_ = s.unlockBucketPasswordOnly(s.defaultScheme, s.defaultNs)
	s.logger.Info("salt rotation completed")
	return nil
}

// NeedsAdminRekey reports whether a LevelAdminWrapped bucket's wrapped DEKs
// were last re-keyed before the current master salt was generated.
// Returns false with no error for LevelPasswordOnly, LevelHSM, and LevelRemote buckets.
func (s *Keeper) NeedsAdminRekey(scheme, namespace string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.locked {
		return false, ErrStoreLocked
	}
	policy, err := s.loadPolicy(scheme, namespace)
	if err != nil {
		return false, err
	}
	if policy.Level != LevelAdminWrapped {
		return false, nil
	}
	store, err := s.loadSaltStore()
	if err != nil || store == nil {
		return false, err
	}
	saltCreatedAt := store.currentSaltCreatedAt()
	if saltCreatedAt.IsZero() {
		return false, nil
	}
	// LastRekeyed zero means the bucket predates this feature and needs re-keying.
	return policy.LastRekeyed.IsZero() || policy.LastRekeyed.Before(saltCreatedAt), nil
}

// RotateAdminWrappedDEK re-wraps the bucket DEK under a fresh per-bucket salt
// for the given admin, then updates LastRekeyed on the policy.
// The admin must authenticate with their current password to prove they hold
// a valid copy of the DEK before it is re-wrapped. After this call, only
// admins whose credentials were supplied here will have up-to-date wrapped copies.
// Other admins must call this method with their own credentials to update their copy.
func (s *Keeper) RotateAdminWrappedDEK(scheme, namespace, adminID string, adminPassword []byte) error {
	defer zero.Bytes(adminPassword)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.locked {
		return ErrStoreLocked
	}
	policy, err := s.loadPolicy(scheme, namespace)
	if err != nil {
		return err
	}
	if policy.Level != LevelAdminWrapped {
		return fmt.Errorf("bucket %s:%s is not LevelAdminWrapped", scheme, namespace)
	}

	// Authenticate the admin by unwrapping the existing DEK with their current password.
	wrapped, ok := policy.WrappedDEKs[adminID]
	if !ok {
		return fmt.Errorf("%w: admin %q", ErrAdminNotFound, adminID)
	}
	masterBytes, err := s.master.Bytes()
	if err != nil {
		return fmt.Errorf("failed to read master key: %w", err)
	}
	defer zero.Bytes(masterBytes)

	existingKEK, err := DeriveKEK(masterBytes, adminPassword, policy.DEKSalt)
	if err != nil {
		return ErrAuthFailed
	}
	dekEnc, err := UnwrapDEK(wrapped, existingKEK) // existingKEK zeroed inside UnwrapDEK
	if err != nil {
		return ErrAuthFailed
	}
	dekBuf, err := dekEnc.Open()
	if err != nil {
		return fmt.Errorf("failed to open DEK enclave: %w", err)
	}
	dekBytes := make([]byte, dekBuf.Size())
	copy(dekBytes, dekBuf.Bytes())
	dekBuf.Destroy()
	defer zero.Bytes(dekBytes)

	// Generate a fresh per-bucket DEK salt.
	newSalt, err := GenerateDEKSalt()
	if err != nil {
		return fmt.Errorf("failed to generate new DEK salt: %w", err)
	}

	// Re-wrap the DEK for this admin under the new salt.
	newKEK, err := DeriveKEK(masterBytes, adminPassword, newSalt)
	if err != nil {
		return fmt.Errorf("failed to derive new KEK: %w", err)
	}
	newDEKEnc, err := NewMaster(dekBytes) // reuse memguard sealing pattern
	if err != nil {
		zero.Bytes(newKEK)
		return fmt.Errorf("failed to seal DEK for re-wrap: %w", err)
	}
	dekEncForWrap, oerr := newDEKEnc.Open()
	if oerr != nil {
		zero.Bytes(newKEK)
		return fmt.Errorf("failed to open sealed DEK: %w", oerr)
	}
	reWrapped, wErr := WrapDEK(dekEncForWrap.Seal(), newKEK) // newKEK zeroed inside WrapDEK
	if wErr != nil {
		return fmt.Errorf("failed to re-wrap DEK: %w", wErr)
	}

	policy.DEKSalt = newSalt
	policy.WrappedDEKs[adminID] = reWrapped
	policy.LastRekeyed = time.Now()

	if err := s.savePolicy(policy); err != nil {
		return fmt.Errorf("failed to save updated policy: %w", err)
	}
	s.schemeRegistry[fmt.Sprintf("%s:%s", scheme, namespace)] = policy
	_ = s.policyChain.AppendEvent(scheme, namespace, "dek_rekeyed",
		map[string]string{"admin": adminID})
	s.logger.Fields("scheme", scheme, "namespace", namespace, "admin", adminID).Info("DEK re-keyed successfully")
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
	defer zero.Bytes(oldKey)

	salt, err := s.getOrCreateSalt()
	if err != nil {
		return fmt.Errorf("failed to get salt: %w", err)
	}
	newKey, err := s.config.KDF.DeriveKey(newPassphrase, salt, s.config.KeyLen)
	if err != nil {
		return fmt.Errorf("key derivation failed: %w", err)
	}
	defer zero.Bytes(newKey)

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
		zero.Bytes(oldAuditKey)
		return fmt.Errorf("failed to derive new audit key: %w", err)
	}

	// Append a checkpoint event to every active chain, signed with the old key.
	// This is O(number of chains) — one small event per chain regardless of
	// how many events are in the chain.
	s.appendRotationCheckpoints(oldAuditKey, newAuditKey)
	zero.Bytes(oldAuditKey)

	// Swap the master and activate the new audit signing key.
	s.master.Destroy()
	s.master = newMaster
	s.auditStore.setSigningKey(newAuditKey)
	zero.Bytes(newAuditKey)

	// Re-derive the policy HMAC key from the new master and rewrite all
	// policy records with the new tag.
	newPolicyKey, err := derivePolicyKey(newKey)
	if err != nil {
		return fmt.Errorf("failed to derive new policy key: %w", err)
	}
	zero.Bytes(s.policyKey)
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
