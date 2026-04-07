package keeper

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	stdErrors "errors"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	pkgstore "github.com/agberohq/keeper/pkg/store"
	"github.com/awnumar/memguard"
	"github.com/olekukonko/errors"
	"github.com/olekukonko/zero"
	msgpack "github.com/vmihailenco/msgpack/v5"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// marshalSecret encodes a Secret using msgpack.
func marshalSecret(s *Secret) ([]byte, error) {
	return msgpack.Marshal(s)
}

// unmarshalSecret decodes a Secret using msgpack.
func unmarshalSecret(data []byte, s *Secret) error {
	return msgpack.Unmarshal(data, s)
}

// marshalEncryptedMetadata encodes EncryptedMetadata using msgpack.
func marshalEncryptedMetadata(m *EncryptedMetadata) ([]byte, error) {
	return msgpack.Marshal(m)
}

// unmarshalEncryptedMetadata decodes EncryptedMetadata using msgpack.
func unmarshalEncryptedMetadata(data []byte, m *EncryptedMetadata) error {
	return msgpack.Unmarshal(data, m)
}

// marshalPolicy encodes a BucketSecurityPolicy using msgpack and encrypts it
// with policyEncKey when the store is unlocked. When policyEncKey is nil
// (store locked or key not yet derived), returns plain msgpack — this path
// is only hit during CreateBucket before the first unlock, which is a setup
// operation that runs before any encryption keys exist.
func (s *Keeper) marshalPolicy(p *BucketSecurityPolicy) ([]byte, error) {
	plain, err := msgpack.Marshal(p)
	if err != nil {
		return nil, err
	}
	if len(s.policyEncKey) == 0 {
		return plain, nil
	}
	return s.encryptMetadata(plain, s.policyEncKey)
}

// errPolicyEncrypted is returned by unmarshalPolicy when the blob is ciphertext
// but policyEncKey is not yet available (store locked / pre-unlock load).
// loadPolicies treats this as a skip signal, not a hard failure.
var errPolicyEncrypted = stdErrors.New("policy is encrypted — key not available")

// unmarshalPolicy decodes a BucketSecurityPolicy.
//
// Format v2 (the only supported format) always stores policies encrypted.
// policyEncKey is required to read them — it is derived from the master key
// and available only after UnlockDatabase.
//
// When policyEncKey is nil (pre-unlock), all blobs are unconditionally
// skipped via errPolicyEncrypted. UnlockDatabase re-calls loadPolicies once
// the key is available. There is no plaintext fallback: keeper is pre-release
// and format v2 is the only on-disk format.
func (s *Keeper) unmarshalPolicy(data []byte, p *BucketSecurityPolicy) error {
	if len(data) == 0 {
		return fmt.Errorf("unmarshalPolicy: empty data")
	}
	if len(s.policyEncKey) == 0 {
		// No key yet — all policies are encrypted, nothing is readable.
		// UnlockDatabase will reload with the key.
		return errPolicyEncrypted
	}
	dec, err := s.decryptMetadata(data, s.policyEncKey)
	if err != nil {
		return fmt.Errorf("policy decryption failed: %w", err)
	}
	return msgpack.Unmarshal(dec, p)
}

// marshalWAL encodes a RotationWAL using msgpack and encrypts it.
func (s *Keeper) marshalWAL(w *RotationWAL) ([]byte, error) {
	plain, err := msgpack.Marshal(w)
	if err != nil {
		return nil, err
	}
	if len(s.policyEncKey) == 0 {
		return plain, nil
	}
	return s.encryptMetadata(plain, s.policyEncKey)
}

// unmarshalWAL decodes a RotationWAL, decrypting if policyEncKey is set.
func (s *Keeper) unmarshalWAL(data []byte, w *RotationWAL) error {
	payload := data
	if len(s.policyEncKey) > 0 {
		if dec, err := s.decryptMetadata(data, s.policyEncKey); err == nil {
			payload = dec
		}
	}
	if len(payload) > 0 && payload[0] == '{' {
		return json.Unmarshal(payload, w)
	}
	return msgpack.Unmarshal(payload, w)
}

// marshalSaltStore encodes a SaltStore using msgpack.
// The KDF salt is intentionally stored unencrypted: it must be readable before
// UnlockDatabase (to derive the master key), so encrypting it with policyEncKey
// — which is only available after unlock — would create a circular dependency.
// A KDF salt is not a secret; its purpose is uniqueness, not confidentiality.
func (s *Keeper) marshalSaltStore(st *SaltStore) ([]byte, error) {
	return msgpack.Marshal(st)
}

// unmarshalSaltStore decodes a SaltStore from msgpack or legacy JSON.
func (s *Keeper) unmarshalSaltStore(data []byte, st *SaltStore) error {
	if len(data) > 0 && data[0] == '{' {
		return json.Unmarshal(data, st)
	}
	return msgpack.Unmarshal(data, st)
}

// Metadata encryption key derivation

// deriveMetadataKeys derives policyEncKey and auditEncKey from masterKey using
// HKDF-SHA256. Key length is determined from the configured cipher's KeySize()
// method, defaulting to masterKeyLen (32) when NewCipher is nil.
func deriveMetadataKeys(masterKey []byte, cfg Config) (policyEncKey, auditEncKey []byte, err error) {
	keyLen := masterKeyLen
	if cfg.NewCipher != nil {
		if probe, perr := cfg.NewCipher(make([]byte, masterKeyLen)); perr == nil {
			keyLen = probe.KeySize()
		}
	}
	expand := func(info string) ([]byte, error) {
		r := hkdf.New(sha256.New, masterKey, nil, []byte(info))
		k := make([]byte, keyLen)
		if _, err := io.ReadFull(r, k); err != nil {
			return nil, fmt.Errorf("%s: HKDF expansion failed: %w", info, err)
		}
		return k, nil
	}
	policyEncKey, err = expand(hkdfInfoPolicyEnc)
	if err != nil {
		return nil, nil, err
	}
	auditEncKey, err = expand(hkdfInfoAuditEnc)
	if err != nil {
		zero.Bytes(policyEncKey)
		return nil, nil, err
	}
	return policyEncKey, auditEncKey, nil
}

// Policy bucket key helpers

// policyBaseKey returns the opaque on-disk key for a scheme:namespace pair.
// SHA-256("scheme:namespace")[:16] encoded as 32 hex chars = 128-bit key space.
func policyBaseKey(scheme, namespace string) string {
	h := sha256.Sum256([]byte(scheme + ":" + namespace))
	return hex.EncodeToString(h[:16])
}

func policyHashKey(base string) string { return base + policyHashSuffix }
func policyHMACKey(base string) string { return base + policyHMACSuffix }

// Generic metadata encrypt / decrypt

// encryptMetadata encrypts plaintext using the keeper's configured cipher.
// Wire format: nonce(cipher.NonceSize()) || AEAD-ciphertext.
func (s *Keeper) encryptMetadata(plaintext, key []byte) ([]byte, error) {
	c, err := s.config.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("encryptMetadata: cipher init: %w", err)
	}
	return c.Encrypt(plaintext)
}

// decryptMetadata decrypts a blob produced by encryptMetadata.
func (s *Keeper) decryptMetadata(blob, key []byte) ([]byte, error) {
	c, err := s.config.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("decryptMetadata: cipher init: %w", err)
	}
	return c.Decrypt(blob)
}

func (s *Keeper) initBuckets() error {
	return s.db.Update(func(tx pkgstore.Tx) error {
		for _, name := range []string{metaBucket, policyBucket, auditBucketRoot} {
			if _, err := tx.CreateBucketIfNotExists([]byte(name)); err != nil {
				return err
			}
		}
		sb, err := tx.CreateBucketIfNotExists([]byte(s.defaultScheme))
		if err != nil {
			return err
		}
		_, err = sb.CreateBucketIfNotExists([]byte(s.defaultNs))
		return err
	})
}

func (s *Keeper) getSchemeBucket(tx pkgstore.Tx, scheme string) pkgstore.Bucket {
	return tx.Bucket([]byte(scheme))
}

func (s *Keeper) getNamespaceBucket(tx pkgstore.Tx, scheme, namespace string) pkgstore.Bucket {
	sb := s.getSchemeBucket(tx, scheme)
	if sb == nil {
		return nil
	}
	return sb.Bucket([]byte(namespace))
}

func (s *Keeper) createNamespaceBucket(tx pkgstore.Tx, scheme, namespace string) (pkgstore.Bucket, error) {
	sb, err := tx.CreateBucketIfNotExists([]byte(scheme))
	if err != nil {
		return nil, err
	}
	return sb.CreateBucketIfNotExists([]byte(namespace))
}

// bucketKeyBytes retrieves the DEK for scheme/namespace from the Envelope,
// copies it to a plain slice, and destroys the LockedBuffer.
// The returned slice MUST be zeroed by the caller immediately after use.
func (s *Keeper) bucketKeyBytes(scheme, namespace string) ([]byte, error) {
	buf, err := s.envelope.Retrieve(scheme, namespace)
	if err != nil {
		return nil, err
	}
	defer buf.Destroy()
	key := make([]byte, buf.Size())
	copy(key, buf.Bytes())
	return key, nil
}

// isBucketUnlocked returns true when the Envelope holds a DEK for this bucket.
func (s *Keeper) isBucketUnlocked(scheme, namespace string) bool {
	if s.locked {
		return false
	}
	if s.envelope.IsHeld(scheme, namespace) {
		return true
	}
	policy, err := s.loadPolicy(scheme, namespace)
	if err != nil {
		return true // no policy — inherits store state
	}
	return policy.Level == LevelPasswordOnly
}

// deriveBucketDEK derives a per-bucket 32-byte DEK from the master key using
// HKDF-SHA256, domain-separated by scheme and namespace.
//
//	bucketDEK = HKDF-SHA256(ikm=masterKey, salt=nil, info="keeper-bucket-dek-v1:<scheme>:<namespace>")
//
// Each LevelPasswordOnly bucket gets an independent key. Leaking one bucket's
// DEK does not expose the master key or any other bucket's secrets.
// The info string is fixed — changing it is a breaking on-disk format change.
func deriveBucketDEK(masterKey []byte, scheme, namespace string) ([]byte, error) {
	info := hkdfInfoBucketDEK + ":" + scheme + ":" + namespace
	r := hkdf.New(sha256.New, masterKey, nil, []byte(info))
	key := make([]byte, masterKeyLen)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("deriveBucketDEK: HKDF failed for %s:%s: %w", scheme, namespace, err)
	}
	return key, nil
}

// unlockBucketPasswordOnly derives the per-bucket DEK and places it into the
// Envelope. When a migration is in progress both the new derived key and the
// old master-key-as-DEK are seeded so records can be decrypted regardless of
// which epoch they were written in.
func (s *Keeper) unlockBucketPasswordOnly(scheme, namespace string) error {
	if s.master == nil {
		return ErrStoreLocked
	}
	masterBytes, err := s.master.Bytes()
	if err != nil {
		return err
	}
	defer zero.Bytes(masterBytes)

	newDEK, err := deriveBucketDEK(masterBytes, scheme, namespace)
	if err != nil {
		return err
	}

	buf := memguard.NewBufferFromBytes(newDEK)
	zero.Bytes(newDEK)
	if buf.Size() == 0 {
		return fmt.Errorf("failed to allocate buffer for bucket DEK")
	}
	s.envelope.Hold(scheme, namespace, buf)

	// During migration the old key (master key used directly as DEK) must also
	// be available so unmigrated records can be decrypted. The fallback decrypt
	// path tries the new derived key first, then falls back to the old key.
	// XChaCha20-Poly1305 Open processes the full ciphertext before returning an
	// error, so both attempts take the same time — no timing side-channel.
	if atomic.LoadInt32(&s.migrationState) == int32(MigrationInProgress) {
		oldBuf := memguard.NewBufferFromBytes(masterBytes)
		if oldBuf.Size() > 0 {
			s.envelope.HoldOld(scheme, namespace, oldBuf)
		}
	}

	s.logger.Fields("scheme", scheme, "namespace", namespace).Debug("bucket seeded (password-only)")
	return nil
}

// unlockBucketAdminWrapped derives the KEK, unwraps the DEK, and places it
// in the Envelope. All authentication failures return ErrAuthFailed to prevent
// admin ID enumeration (CWE-204 / CVSS 5.3).
func (s *Keeper) unlockBucketAdminWrapped(scheme, namespace, adminID string, adminPassword []byte) error {
	policy, err := s.loadPolicy(scheme, namespace)
	if err != nil {
		return err
	}
	if policy.Level != LevelAdminWrapped {
		return fmt.Errorf("bucket %s:%s is not LevelAdminWrapped", scheme, namespace)
	}
	wrapped, ok := policy.WrappedDEKs[adminID]
	if !ok {
		s.logger.Fields("scheme", scheme, "namespace", namespace).Warn("unlock: admin not found")
		return ErrAuthFailed
	}

	masterBytes, err := s.master.Bytes()
	if err != nil {
		return err
	}

	// Deep copy before zeroing — slice assignment aliases the backing array.
	mbCopy := make([]byte, len(masterBytes))
	copy(mbCopy, masterBytes)
	zero.Bytes(masterBytes)
	defer zero.Bytes(mbCopy)

	kek, err := DeriveKEK(mbCopy, adminPassword, policy.DEKSalt)
	if err != nil {
		s.logger.Fields("scheme", scheme, "namespace", namespace, "err", err).Error("unlock: KEK derivation failed")
		return ErrAuthFailed
	}

	dekEnc, err := UnwrapDEK(wrapped, kek) // kek zeroed inside UnwrapDEK
	if err != nil {
		s.logger.Fields("scheme", scheme, "namespace", namespace).Warn("unlock: DEK unwrap failed")
		return ErrAuthFailed
	}
	dekBuf, err := dekEnc.Open()
	if err != nil {
		return fmt.Errorf("failed to open unwrapped DEK: %w", err)
	}
	s.envelope.Hold(scheme, namespace, dekBuf)

	if s.jackReaper != nil {
		s.jackReaper.Touch(scheme + ":" + namespace)
	}

	s.logger.Fields("scheme", scheme, "namespace", namespace, "admin", adminID).Info("bucket unlocked")
	_ = s.policyChain.AppendEvent(scheme, namespace, "unlocked",
		map[string]string{"admin": adminID})
	return nil
}

// unlockBucketHSM calls the HSMProvider to unwrap the DEK and places it in the Envelope.
// Both LevelHSM and LevelRemote buckets follow the same unwrap path through this function.
func (s *Keeper) unlockBucketHSM(scheme, namespace string) error {
	policy, err := s.loadPolicy(scheme, namespace)
	if err != nil {
		return err
	}
	if policy.Level != LevelHSM && policy.Level != LevelRemote {
		return fmt.Errorf("bucket %s:%s is not LevelHSM or LevelRemote", scheme, namespace)
	}
	if policy.HSMProvider == nil {
		return ErrHSMProviderNil
	}
	wrapped, ok := policy.WrappedDEKs[hsmWrappedDEKKey]
	if !ok {
		return fmt.Errorf("bucket %s:%s has no wrapped DEK", scheme, namespace)
	}
	dekBytes, err := policy.HSMProvider.UnwrapDEK(wrapped)
	if err != nil {
		return fmt.Errorf("HSM unwrap failed for %s:%s: %w", scheme, namespace, err)
	}
	// dekBytes is in plaintext for the minimum time required to seal it.
	s.envelope.HoldBytes(scheme, namespace, dekBytes)
	s.logger.Fields("scheme", scheme, "namespace", namespace, "level", string(policy.Level)).Info("bucket unlocked via HSM provider")
	_ = s.policyChain.AppendEvent(scheme, namespace, "unlocked_hsm", nil)
	return nil
}

// lockBucket removes the DEK from the Envelope for a single bucket.
func (s *Keeper) lockBucket(scheme, namespace string) {
	s.envelope.Drop(scheme, namespace)
	if s.jackReaper != nil {
		s.jackReaper.Remove(scheme + ":" + namespace)
	}
}

func (s *Keeper) encrypt(plaintext []byte, scheme, namespace string) ([]byte, error) {
	key, err := s.bucketKeyBytes(scheme, namespace)
	if err != nil {
		return nil, err
	}
	defer zero.Bytes(key)
	return s.encryptWithKey(plaintext, key)
}

func (s *Keeper) decrypt(ciphertext []byte, scheme, namespace string) ([]byte, error) {
	key, err := s.bucketKeyBytes(scheme, namespace)
	if err != nil {
		return nil, err
	}
	defer zero.Bytes(key)

	pt, err := s.decryptWithKey(ciphertext, key)
	if err == nil {
		return pt, nil
	}

	// Fallback: if the new derived key fails and a pre-migration old key is
	// available, try decrypting with it. This handles records written before
	// the per-bucket DEK derivation migration completed.
	//
	// XChaCha20-Poly1305 Open processes the full ciphertext before returning
	// an authentication error, so both attempts take the same time — no
	// timing side-channel leaks which key succeeded.
	oldBuf, oldErr := s.envelope.RetrieveOld(scheme, namespace)
	if oldErr != nil {
		return nil, err // original error — no fallback key available
	}
	oldKey := make([]byte, oldBuf.Size())
	copy(oldKey, oldBuf.Bytes())
	oldBuf.Destroy()
	defer zero.Bytes(oldKey)

	return s.decryptWithKey(ciphertext, oldKey)
}

func (s *Keeper) encryptWithKey(plaintext, key []byte) ([]byte, error) {
	c, err := s.config.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return c.Encrypt(plaintext)
}

func (s *Keeper) decryptWithKey(ciphertext, key []byte) ([]byte, error) {
	c, err := s.config.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return c.Decrypt(ciphertext)
}

func (s *Keeper) updateActivity() {
	atomic.StoreInt64(&s.lastActivity, time.Now().UnixNano())
}

// Crash-safe key rotation.
//
// reencryptAllWithKey writes a WAL before touching any record. The WAL stores
// a cursor (LastKey) and WrappedOldKey so interrupted rotations can resume
// after a crash without losing access to either the old or new ciphertext.
// LevelHSM and LevelRemote buckets are intentionally skipped — their DEKs
// are managed by the external provider and are unaffected by master key changes.
func (s *Keeper) reencryptAllWithKey(newKey, oldKey []byte) error {
	if len(oldKey) == 0 {
		return errors.New("old key is empty")
	}

	wrappedOldKey, err := s.encryptWithKey(oldKey, newKey)
	if err != nil {
		return fmt.Errorf("failed to wrap old key for WAL: %w", err)
	}

	oldHash := sha256.Sum256(oldKey)
	newHash := sha256.Sum256(newKey)
	wal := &RotationWAL{
		Status:        walStatusInProgress,
		OldKeyHash:    oldHash[:],
		NewKeyHash:    newHash[:],
		StartedAt:     time.Now(),
		WrappedOldKey: wrappedOldKey,
	}
	if err := s.writeRotationWAL(wal); err != nil {
		return fmt.Errorf("failed to write rotation WAL: %w", err)
	}
	s.logger.Info("key rotation started")

	if err := s.encryptAllRecords(newKey, oldKey, wal); err != nil {
		return fmt.Errorf("re-encryption failed: %w", err)
	}

	return s.clearRotationWAL()
}

// resumeRotation continues an interrupted rotation automatically.
// Called from UnlockDatabase when a WAL is present.
// masterKey is the new master key (already verified by UnlockDatabase).
//
// In addition to completing any unfinished secret re-encryption, this
// function re-encrypts all policy blobs from the old policyEncKey to the
// current s.policyEncKey. This is necessary because a crash between
// Rotate()'s reencryptAllWithKey and reencryptAllPolicies steps would
// leave policy blobs encrypted under the old key. s.policyEncKey is already
// set to the new-master-derived value by UnlockDatabase before we are called,
// so we derive the old policyEncKey from oldKey to decrypt the stale blobs.
func (s *Keeper) resumeRotation(masterKey []byte) error {
	wal, err := s.readRotationWAL()
	if err != nil {
		return fmt.Errorf("failed to read rotation WAL: %w", err)
	}

	// Verify this is the right key for this WAL.
	gotHash := sha256.Sum256(masterKey)
	if subtle.ConstantTimeCompare(gotHash[:], wal.NewKeyHash) != 1 {
		return fmt.Errorf("master key does not match rotation WAL — wrong passphrase or corrupt WAL")
	}

	// Unwrap the old key from the WAL.
	oldKey, err := s.decryptWithKey(wal.WrappedOldKey, masterKey)
	if err != nil {
		return fmt.Errorf("failed to unwrap old key from rotation WAL: %w", err)
	}
	defer zero.Bytes(oldKey)

	s.logger.Fields("cursor", wal.LastKey).Info("resuming interrupted key rotation")
	if err := s.encryptAllRecords(masterKey, oldKey, wal); err != nil {
		return fmt.Errorf("re-encryption resume failed: %w", err)
	}
	if err := s.clearRotationWAL(); err != nil {
		return err
	}

	// Re-encrypt any policy blobs that were not yet migrated to the new key.
	// Derive the old policyEncKey from the unwrapped old master key so we can
	// decrypt blobs that may still be encrypted under it.
	oldPolicyEncKey, _, err := deriveMetadataKeys(oldKey, s.config)
	if err != nil {
		return fmt.Errorf("resumeRotation: derive old policy enc key: %w", err)
	}
	defer zero.Bytes(oldPolicyEncKey)
	if err := s.reencryptAllPolicies(oldPolicyEncKey); err != nil {
		return fmt.Errorf("resumeRotation: policy re-encryption: %w", err)
	}
	if err := s.upgradePolicyHMACs(); err != nil {
		s.logger.Fields("err", err).Warn("resumeRotation: policy HMAC upgrade failed — continuing")
	}
	return nil
}

// isHSMOrRemotePolicy returns true when the registered policy for the given
// registry key is LevelHSM or LevelRemote and should be skipped during
// master-key re-encryption. Unregistered keys default to false.
func (s *Keeper) isHSMOrRemotePolicy(scheme, namespace string) bool {
	key := scheme + ":" + namespace
	s.registryMu.RLock()
	p, ok := s.schemeRegistry[key]
	s.registryMu.RUnlock()
	if ok {
		return p.Level == LevelHSM || p.Level == LevelRemote
	}
	return false
}

// encryptAllRecords iterates every secret bucket and re-encrypts each record
// individually, skipping LevelHSM and LevelRemote buckets whose DEKs are
// controlled by an external provider. Each record is committed in its own
// atomic bbolt.Update and the WAL cursor is advanced after each write.
func (s *Keeper) encryptAllRecords(newKey, oldKey []byte, wal *RotationWAL) error {
	var schemes []string
	if err := s.db.View(func(tx pkgstore.Tx) error {
		return tx.ForEach(func(name []byte, _ pkgstore.Bucket) error {
			n := string(name)
			if n != metaBucket && n != policyBucket && n != auditBucketRoot {
				schemes = append(schemes, n)
			}
			return nil
		})
	}); err != nil {
		return err
	}

	for _, schemeName := range schemes {
		var namespaces []string
		if err := s.db.View(func(tx pkgstore.Tx) error {
			sb := tx.Bucket([]byte(schemeName))
			if sb == nil {
				return nil
			}
			return sb.ForEach(func(nsName []byte, _ []byte) error {
				if string(nsName) != metadataKey {
					namespaces = append(namespaces, string(nsName))
				}
				return nil
			})
		}); err != nil {
			return err
		}

		for _, nsName := range namespaces {
			if s.isHSMOrRemotePolicy(schemeName, nsName) {
				s.logger.Fields("scheme", schemeName, "namespace", nsName).Info("skipping HSM/Remote bucket during key rotation")
				continue
			}

			// Derive the effective per-bucket DEKs for this namespace.
			// Records may be in either epoch:
			//   • pre-migration:  encrypted under the raw master key
			//   • post-migration: encrypted under deriveBucketDEK(masterKey, scheme, ns)
			// effectiveOld is tried first; rawOld is the fallback.
			// effectiveNew is always the derived DEK from the new master so that
			// unlockBucketPasswordOnly will find the right key after rotation.
			effectiveOld, errOld := deriveBucketDEK(oldKey, schemeName, nsName)
			if errOld != nil {
				return fmt.Errorf("derive old bucket DEK for %s:%s: %w", schemeName, nsName, errOld)
			}
			defer zero.Bytes(effectiveOld)
			effectiveNew, errNew := deriveBucketDEK(newKey, schemeName, nsName)
			if errNew != nil {
				return fmt.Errorf("derive new bucket DEK for %s:%s: %w", schemeName, nsName, errNew)
			}
			defer zero.Bytes(effectiveNew)

			var keys []string
			if err := s.db.View(func(tx pkgstore.Tx) error {
				nb := s.getNamespaceBucket(tx, schemeName, nsName)
				if nb == nil {
					return nil
				}
				return nb.ForEach(func(k, _ []byte) error {
					if string(k) != metadataKey {
						keys = append(keys, string(k))
					}
					return nil
				})
			}); err != nil {
				return err
			}

			for _, key := range keys {
				cursor := schemeName + ":" + nsName + ":" + key
				if wal.LastKey != "" && cursor <= wal.LastKey {
					continue // already completed before crash
				}
				if err := s.reencryptRecord(schemeName, nsName, key, effectiveNew, effectiveOld, oldKey); err != nil {
					return err
				}
				wal.LastKey = cursor
				if err := s.writeRotationWAL(wal); err != nil {
					return fmt.Errorf("failed to advance rotation WAL cursor: %w", err)
				}
			}
		}
	}
	return nil
}

// reencryptRecord re-encrypts a single secret in one atomic bbolt.Update
// during a master key rotation. For LevelPasswordOnly buckets the on-disk
// records may be encrypted under either the raw master key (pre-migration) or
// the per-bucket derived DEK (post-migration). This function accepts the two
// effective old keys in priority order: effectiveOld is tried first (the
// derived bucket DEK from the old master), then rawOld (the raw master key) as
// a fallback for records that have not yet been through DEK migration. The
// output is always written under effectiveNew (the derived bucket DEK from the
// new master), which matches what unlockBucketPasswordOnly will derive after
// the rotation completes.
//
// For non-LevelPasswordOnly buckets (LevelHSM, LevelRemote) this function is
// never called — they are skipped in encryptAllRecords. For callers that
// process buckets where both old keys are identical (e.g. the raw master key
// equals the derived key, which cannot happen in practice) the fallback is a
// no-op.
func (s *Keeper) reencryptRecord(scheme, namespace, key string, effectiveNew, effectiveOld, rawOld []byte) error {
	return s.db.Update(func(tx pkgstore.Tx) error {
		nb := s.getNamespaceBucket(tx, scheme, namespace)
		if nb == nil {
			return nil
		}
		v := nb.Get([]byte(key))
		if v == nil {
			return nil
		}
		var secret Secret
		if err := unmarshalSecret(v, &secret); err != nil {
			return fmt.Errorf("unmarshal %s: %w", key, err)
		}

		// Try the derived old DEK first (already-migrated record), then the
		// raw master key (not-yet-migrated record). Track which key succeeded
		// so we use the correct meta key for decrypting EncryptedMeta below.
		pt, err := s.decryptWithKey(secret.Ciphertext, effectiveOld)
		decryptedWithDerived := err == nil
		if !decryptedWithDerived {
			pt, err = s.decryptWithKey(secret.Ciphertext, rawOld)
			if err != nil {
				return fmt.Errorf("decrypt %s: %w", key, err)
			}
		}

		ct, err := s.encryptWithKey(pt, effectiveNew)
		zero.Bytes(pt)
		if err != nil {
			return fmt.Errorf("encrypt %s: %w", key, err)
		}
		secret.Ciphertext = ct

		if len(secret.EncryptedMeta) > 0 {
			// The meta key is derived from whichever DEK was used to encrypt
			// the record. Use the matching key so decryption succeeds.
			oldDecryptKey := rawOld
			if decryptedWithDerived {
				oldDecryptKey = effectiveOld
			}
			oldMetaKey, merr := s.deriveMetaKey(oldDecryptKey)
			if merr != nil {
				return fmt.Errorf("derive old meta key: %w", merr)
			}
			meta, merr := s.decryptMetaWithKey(secret.EncryptedMeta, oldMetaKey)
			zero.Bytes(oldMetaKey)
			if merr != nil {
				return fmt.Errorf("decrypt meta %s: %w", key, merr)
			}
			newMetaKey, merr := s.deriveMetaKey(effectiveNew)
			if merr != nil {
				return fmt.Errorf("derive new meta key: %w", merr)
			}
			newEM, merr := s.encryptMetaWithKey(meta, newMetaKey)
			zero.Bytes(newMetaKey)
			if merr != nil {
				return fmt.Errorf("encrypt meta %s: %w", key, merr)
			}
			secret.EncryptedMeta = newEM
		}

		data, err := marshalSecret(&secret)
		if err != nil {
			return err
		}
		return nb.Put([]byte(key), data)
	})
}

func (s *Keeper) writeRotationWAL(wal *RotationWAL) error {
	data, err := s.marshalWAL(wal)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx pkgstore.Tx) error {
		b := tx.Bucket([]byte(metaBucket))
		if b == nil {
			return stdErrors.New("metadata bucket not found")
		}
		return b.Put([]byte(rotationWALKey), data)
	})
}

func (s *Keeper) readRotationWAL() (*RotationWAL, error) {
	var wal RotationWAL
	err := s.db.View(func(tx pkgstore.Tx) error {
		b := tx.Bucket([]byte(metaBucket))
		if b == nil {
			return stdErrors.New("metadata bucket not found")
		}
		data := b.Get([]byte(rotationWALKey))
		if data == nil {
			return stdErrors.New("rotation WAL not found")
		}
		return s.unmarshalWAL(data, &wal)
	})
	return &wal, err
}

func (s *Keeper) clearRotationWAL() error {
	return s.db.Update(func(tx pkgstore.Tx) error {
		b := tx.Bucket([]byte(metaBucket))
		if b == nil {
			return nil
		}
		return b.Delete([]byte(rotationWALKey))
	})
}

func (s *Keeper) hasIncompleteRotation() bool {
	var found bool
	_ = s.db.View(func(tx pkgstore.Tx) error {
		b := tx.Bucket([]byte(metaBucket))
		if b == nil {
			return nil
		}
		found = b.Get([]byte(rotationWALKey)) != nil
		return nil
	})
	return found
}

// Versioned salt storage.
//
// The salt is stored as a JSON-encoded SaltStore under metaSaltKey.
// Each call to getOrCreateSalt returns the bytes of the current (highest
// version) salt entry. Callers never see the versioning structure; they
// receive and return raw salt bytes exactly as before.

func (s *Keeper) getOrCreateSalt() ([]byte, error) {
	store, err := s.loadSaltStore()
	if err != nil {
		return nil, err
	}
	if store != nil && len(store.Entries) > 0 {
		return store.currentSalt(), nil
	}
	// First run — generate salt and initialise the store.
	salt := make([]byte, masterKeyLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	newStore := &SaltStore{
		CurrentVersion: 1,
		Entries: []SaltEntry{
			{Version: 1, Salt: salt, CreatedAt: time.Now()},
		},
	}
	return salt, s.saveSaltStore(newStore)
}

// currentSalt returns the bytes of the active salt entry.
func (ss *SaltStore) currentSalt() []byte {
	for _, e := range ss.Entries {
		if e.Version == ss.CurrentVersion {
			return e.Salt
		}
	}
	// Fallback: highest version entry.
	if len(ss.Entries) > 0 {
		return ss.Entries[len(ss.Entries)-1].Salt
	}
	return nil
}

// currentSaltCreatedAt returns the CreatedAt time of the current salt entry.
// Used by NeedsAdminRekey to compare against policy.LastRekeyed.
func (ss *SaltStore) currentSaltCreatedAt() time.Time {
	for _, e := range ss.Entries {
		if e.Version == ss.CurrentVersion {
			return e.CreatedAt
		}
	}
	return time.Time{}
}

// saltVersion returns the current salt version number.
func (ss *SaltStore) saltVersion() int {
	return ss.CurrentVersion
}

// rotateSalt generates a new random salt and appends it to the store.
// The old salt is retained for crash-recovery purposes.
// Returns the new salt bytes and the new version number.
func (s *Keeper) rotateSalt() ([]byte, int, error) {
	store, err := s.loadSaltStore()
	if err != nil {
		return nil, 0, err
	}
	if store == nil {
		store = &SaltStore{}
	}
	newSalt := make([]byte, masterKeyLen)
	if _, err := rand.Read(newSalt); err != nil {
		return nil, 0, err
	}
	newVersion := store.CurrentVersion + 1
	store.Entries = append(store.Entries, SaltEntry{
		Version:   newVersion,
		Salt:      newSalt,
		CreatedAt: time.Now(),
	})
	store.CurrentVersion = newVersion
	return newSalt, newVersion, s.saveSaltStore(store)
}

func (s *Keeper) loadSaltStore() (*SaltStore, error) {
	var raw []byte
	if err := s.db.View(func(tx pkgstore.Tx) error {
		b := tx.Bucket([]byte(metaBucket))
		if b == nil {
			return nil
		}
		if data := b.Get([]byte(metaSaltKey)); data != nil {
			raw = append([]byte(nil), data...)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}
	// Three possible formats:
	// Legacy bare salt: exactly masterKeyLen random bytes (pre-versioned format).
	//      A versioned SaltStore — even the smallest possible — is always larger
	//      than masterKeyLen bytes, so length is the reliable discriminator.
	// JSON SaltStore (written before the msgpack migration): starts with '{'.
	// Msgpack SaltStore (current format): starts with a msgpack map header.
	//
	// We check length first so that random salt bytes that happen to start with
	// '{' or a msgpack header byte are never misidentified as structured records.
	if len(raw) == masterKeyLen {
		// Legacy bare salt — wrap it in a versioned store and rewrite.
		salt := append([]byte(nil), raw...)
		store := &SaltStore{
			CurrentVersion: 1,
			Entries: []SaltEntry{
				{Version: 1, Salt: salt, CreatedAt: time.Now()},
			},
		}
		if err := s.saveSaltStore(store); err != nil {
			return nil, fmt.Errorf("salt migration failed: %w", err)
		}
		return store, nil
	}
	var store SaltStore
	if err := s.unmarshalSaltStore(raw, &store); err != nil {
		return nil, fmt.Errorf("failed to decode salt store: %w", err)
	}
	return &store, nil
}

func (s *Keeper) saveSaltStore(store *SaltStore) error {
	data, err := s.marshalSaltStore(store)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx pkgstore.Tx) error {
		b := tx.Bucket([]byte(metaBucket))
		if b == nil {
			return stdErrors.New("metadata bucket not found")
		}
		return b.Put([]byte(metaSaltKey), data)
	})
}

// currentSaltVersion returns the current salt version for use in Stats.
func (s *Keeper) currentSaltVersion() int {
	store, err := s.loadSaltStore()
	if err != nil || store == nil {
		return 0
	}
	return store.CurrentVersion
}

func (s *Keeper) storeVerificationHash(key []byte) error {
	vt, vm, vp := s.verifyArgon2Params()
	h := argon2.IDKey(key, []byte(argon2VerificationSalt), vt, vm, vp, argon2OutLen)
	return s.db.Update(func(tx pkgstore.Tx) error {
		b := tx.Bucket([]byte(metaBucket))
		if b == nil {
			return stdErrors.New("metadata bucket not found")
		}
		return b.Put([]byte(metaVerifyKey), h)
	})
}

func (s *Keeper) verifyMasterKey(key []byte) error {
	var storedHash []byte
	if err := s.db.View(func(tx pkgstore.Tx) error {
		b := tx.Bucket([]byte(metaBucket))
		if b == nil {
			return nil
		}
		if data := b.Get([]byte(metaVerifyKey)); data != nil {
			storedHash = append([]byte(nil), data...)
		}
		return nil
	}); err != nil {
		return err
	}
	if storedHash == nil {
		return s.storeVerificationHash(key)
	}
	vt, vm, vp := s.verifyArgon2Params()
	computed := argon2.IDKey(key, []byte(argon2VerificationSalt), vt, vm, vp, argon2OutLen)
	if subtle.ConstantTimeCompare(computed, storedHash) != 1 {
		return ErrInvalidPassphrase
	}
	return nil
}

func (s *Keeper) verifyArgon2Params() (t, m uint32, p uint8) {
	t = s.config.VerifyArgon2Time
	if t == 0 {
		t = defaultVerifyArgon2Time
	}
	m = s.config.VerifyArgon2Memory
	if m == 0 {
		m = defaultArgon2Memory
	}
	p = s.config.VerifyArgon2Parallelism
	if p == 0 {
		p = defaultArgon2Threads
	}
	return
}

// Policy HMAC helpers.

// derivePolicyKey produces a 32-byte HMAC key for policy authentication.
func derivePolicyKey(masterBytes []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, masterBytes, nil, []byte(hkdfInfoPolicyHMAC))
	key := make([]byte, masterKeyLen)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("policy key: HKDF expansion failed: %w", err)
	}
	return key, nil
}

// computePolicyHMAC returns HMAC-SHA256(policyKey, policyJSON).
func computePolicyHMAC(policyKey, policyJSON []byte) string {
	h := hmac.New(sha256.New, policyKey)
	h.Write(policyJSON)
	return hex.EncodeToString(h.Sum(nil))
}

// policyHashIntegrity returns SHA-256(policyJSON) as hex.
// Used as an unauthenticated integrity check before the store is unlocked.
func policyHashIntegrity(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// savePolicy persists a policy with both a SHA-256 hash and, when the store
// is unlocked (policyKey set), an authenticated HMAC tag. All three entries
// are written in one atomic bbolt.Update — no partial state is possible.
// The on-disk key is policyBaseKey(scheme, namespace) — an opaque 32-hex-char
// hash that hides the bucket structure from offline readers.
func (s *Keeper) savePolicy(policy *BucketSecurityPolicy) error {
	return s.db.Update(func(tx pkgstore.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte(policyBucket))
		if err != nil {
			return err
		}
		base := policyBaseKey(policy.Scheme, policy.Namespace)
		data, err := s.marshalPolicy(policy)
		if err != nil {
			return err
		}
		if err := bucket.Put([]byte(base), data); err != nil {
			return err
		}
		if err := bucket.Put([]byte(policyHashKey(base)), []byte(policyHashIntegrity(data))); err != nil {
			return err
		}
		if len(s.policyKey) > 0 {
			tag := computePolicyHMAC(s.policyKey, data)
			if err := bucket.Put([]byte(policyHMACKey(base)), []byte(tag)); err != nil {
				return err
			}
		}
		return nil
	})
}

// loadPolicies populates schemeRegistry at startup before unlock.
// Iterates all keys in the policy bucket, skips hash/HMAC suffix keys,
// decrypts and decodes each policy value.
// When called before UnlockDatabase (policyEncKey nil), encrypted entries are
// silently skipped — UnlockDatabase re-calls loadPolicies once the key is set.
func (s *Keeper) loadPolicies() error {
	return s.db.View(func(tx pkgstore.Tx) error {
		policies := tx.Bucket([]byte(policyBucket))
		if policies == nil {
			return nil
		}
		return policies.ForEach(func(k, v []byte) error {
			key := string(k)
			if isPolicyHashKey(key) {
				return nil
			}
			var policy BucketSecurityPolicy
			if err := s.unmarshalPolicy(v, &policy); err != nil {
				if stdErrors.Is(err, errPolicyEncrypted) {
					// Key not available yet — skip; UnlockDatabase will reload.
					return nil
				}
				return err
			}
			// Registry key is always "scheme:namespace" in memory.
			registryKey := fmt.Sprintf("%s:%s", policy.Scheme, policy.Namespace)
			s.registryMu.Lock()
			s.schemeRegistry[registryKey] = &policy
			s.registryMu.Unlock()
			return nil
		})
	})
}

// loadPolicy returns the policy for scheme/namespace, verifying the HMAC when
// the store is unlocked. Falls back to SHA-256 when no HMAC tag exists yet.
func (s *Keeper) loadPolicy(scheme, namespace string) (*BucketSecurityPolicy, error) {
	registryKey := fmt.Sprintf("%s:%s", scheme, namespace)
	s.registryMu.RLock()
	p, ok := s.schemeRegistry[registryKey]
	s.registryMu.RUnlock()
	if ok {
		return p, nil
	}
	base := policyBaseKey(scheme, namespace)
	var policy BucketSecurityPolicy
	err := s.db.View(func(tx pkgstore.Tx) error {
		policies := tx.Bucket([]byte(policyBucket))
		if policies == nil {
			return ErrPolicyNotFound
		}
		data := policies.Get([]byte(base))
		if data == nil {
			return ErrPolicyNotFound
		}

		if len(s.policyKey) > 0 {
			if tag := policies.Get([]byte(policyHMACKey(base))); tag != nil {
				expected := computePolicyHMAC(s.policyKey, data)
				if !hmac.Equal([]byte(expected), tag) {
					return fmt.Errorf("%w: HMAC mismatch for policy %s:%s", ErrPolicySignature, scheme, namespace)
				}
			} else {
				if storedHash := policies.Get([]byte(policyHashKey(base))); storedHash != nil {
					if policyHashIntegrity(data) != string(storedHash) {
						return fmt.Errorf("policy integrity check failed for %s:%s", scheme, namespace)
					}
				}
			}
		} else {
			if storedHash := policies.Get([]byte(policyHashKey(base))); storedHash != nil {
				if policyHashIntegrity(data) != string(storedHash) {
					return fmt.Errorf("policy integrity check failed for %s:%s", scheme, namespace)
				}
			}
		}

		return s.unmarshalPolicy(data, &policy)
	})
	if err != nil {
		return nil, err
	}
	s.registryMu.Lock()
	s.schemeRegistry[registryKey] = &policy
	s.registryMu.Unlock()
	return &policy, nil
}

// upgradePolicyHMACs writes HMAC tags for any policy that only has a SHA-256
// hash. Called from UnlockDatabase and Rotate after policyKey is set.
// Uses hashed keys — compatible with the new savePolicy layout.
func (s *Keeper) upgradePolicyHMACs() error {
	if len(s.policyKey) == 0 {
		return nil
	}
	return s.db.Update(func(tx pkgstore.Tx) error {
		policies := tx.Bucket([]byte(policyBucket))
		if policies == nil {
			return nil
		}
		return policies.ForEach(func(k, v []byte) error {
			key := string(k)
			if isPolicyHashKey(key) {
				return nil
			}
			hmacKey := key + policyHMACSuffix
			if policies.Get([]byte(hmacKey)) != nil {
				return nil // already has HMAC tag
			}
			tag := computePolicyHMAC(s.policyKey, v)
			return policies.Put([]byte(hmacKey), []byte(tag))
		})
	})
}

func (s *Keeper) appendAuditEvent(event *BucketEvent) error {
	if s.auditStore == nil {
		return nil
	}
	if s.config.Jack.Pool != nil && event.EventType != "created" {
		ev := event
		s.config.Jack.Pool.Do(func() {
			if err := s.auditStore.appendEvent(ev.Scheme, ev.Namespace, ev); err != nil {
				s.logger.Fields(
					"scheme", ev.Scheme,
					"namespace", ev.Namespace,
					"event_type", ev.EventType,
					"err", err,
				).Error("async audit event failed")
			}
		})
		return nil
	}
	return s.auditStore.appendEvent(event.Scheme, event.Namespace, event)
}

// reencryptAllPolicies re-encrypts every on-disk policy from oldEncKey to
// the current s.policyEncKey. Call this immediately after swapping policyEncKey
// during Rotate/RotateSalt so the next Unlock can decrypt with the new key.
// Also called by resumeRotation to handle policies that were not yet migrated
// when a process died mid-rotation.
//
// All work is done atomically: a single View reads and re-encrypts every blob
// in memory, then a single Update writes all of them together. Either every
// policy is migrated or none are — there is no WAL to resume a partial policy
// re-encryption, so partial writes are treated as fatal errors.
func (s *Keeper) reencryptAllPolicies(oldEncKey []byte) error {
	type rewrite struct {
		base    string
		newData []byte
	}
	var rewrites []rewrite

	// Phase 1: read every policy blob under the old key and re-encrypt it
	// under the already-swapped s.policyEncKey (the new key). All work is
	// done inside a single View so the snapshot is consistent.
	if err := s.db.View(func(tx pkgstore.Tx) error {
		b := tx.Bucket([]byte(policyBucket))
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			key := string(k)
			if isPolicyHashKey(key) {
				return nil
			}
			if v == nil {
				// Nested bucket — should never appear in policyBucket, skip.
				return nil
			}
			// Decrypt with the OLD key explicitly — s.policyEncKey is the new key.
			plain, err := s.decryptMetadata(append([]byte(nil), v...), oldEncKey)
			if err != nil {
				return fmt.Errorf("reencryptAllPolicies: decrypt %q: %w", key, err)
			}
			var p BucketSecurityPolicy
			if err := msgpack.Unmarshal(plain, &p); err != nil {
				return fmt.Errorf("reencryptAllPolicies: unmarshal %q: %w", key, err)
			}
			// marshalPolicy encrypts with s.policyEncKey (the new key).
			newData, err := s.marshalPolicy(&p)
			if err != nil {
				return fmt.Errorf("reencryptAllPolicies: re-encrypt %q: %w", key, err)
			}
			rewrites = append(rewrites, rewrite{key, newData})
			return nil
		})
	}); err != nil {
		return err
	}

	if len(rewrites) == 0 {
		return nil
	}

	// Phase 2: write all re-encrypted blobs in a single atomic transaction.
	// Either every policy is updated together or none are — there is no WAL
	// to resume a partial policy re-encryption, so partial writes are fatal.
	return s.db.Update(func(tx pkgstore.Tx) error {
		b := tx.Bucket([]byte(policyBucket))
		if b == nil {
			return stdErrors.New("reencryptAllPolicies: policy bucket missing")
		}
		for _, rw := range rewrites {
			if err := b.Put([]byte(rw.base), rw.newData); err != nil {
				return fmt.Errorf("reencryptAllPolicies: write %q: %w", rw.base, err)
			}
			if err := b.Put([]byte(policyHashKey(rw.base)),
				[]byte(policyHashIntegrity(rw.newData))); err != nil {
				return fmt.Errorf("reencryptAllPolicies: write hash %q: %w", rw.base, err)
			}
			// Drop the stale HMAC tag — upgradePolicyHMACs (called after this
			// function) recomputes it with the new policyKey.
			_ = b.Delete([]byte(policyHMACKey(rw.base)))
		}
		return nil
	})
}

// seedAllBucketsFromDisk reads every policy directly from the _policies_ bbolt
// bucket and seeds or unlocks each bucket based on its security level.
//
// This is the authoritative seeding path used during UnlockDatabase. It does
// NOT rely on schemeRegistry being populated first — it reads the encrypted
// policy blobs from disk, decrypts them with the now-available policyEncKey,
// and acts on each one. schemeRegistry is updated as a side-effect so that
// subsequent lookups via loadPolicy benefit from the cache.
//
// LevelPasswordOnly: DEK derived and seeded into Envelope immediately.
// LevelHSM / LevelRemote: unlocked via the registered HSMProvider if present.
// LevelAdminWrapped: skipped — requires explicit UnlockBucket call per admin.
func (s *Keeper) seedAllBucketsFromDisk() error {
	var policies []*BucketSecurityPolicy

	if err := s.db.View(func(tx pkgstore.Tx) error {
		b := tx.Bucket([]byte(policyBucket))
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			if isPolicyHashKey(string(k)) {
				return nil
			}
			var p BucketSecurityPolicy
			if err := s.unmarshalPolicy(v, &p); err != nil {
				s.logger.Fields("key", string(k), "err", err).Warn("seedAllBucketsFromDisk: skipping unreadable policy")
				return nil // skip — do not abort; other buckets may be healthy
			}
			policies = append(policies, &p)
			return nil
		})
	}); err != nil {
		return fmt.Errorf("seedAllBucketsFromDisk: db read failed: %w", err)
	}

	for _, p := range policies {
		// Update schemeRegistry so loadPolicy cache is warm.
		registryKey := fmt.Sprintf("%s:%s", p.Scheme, p.Namespace)
		s.registryMu.Lock()
		s.schemeRegistry[registryKey] = p
		s.registryMu.Unlock()

		switch p.Level {
		case LevelPasswordOnly:
			if err := s.unlockBucketPasswordOnly(p.Scheme, p.Namespace); err != nil {
				s.logger.Fields("scheme", p.Scheme, "namespace", p.Namespace, "err", err).Warn("seedAllBucketsFromDisk: failed to seed PasswordOnly bucket")
				s.audit("unlock_bucket_failed", p.Scheme, p.Namespace, "", false, 0)
			}
		case LevelHSM, LevelRemote:
			if p.HSMProvider != nil {
				if err := s.unlockBucketHSM(p.Scheme, p.Namespace); err != nil {
					s.logger.Fields("scheme", p.Scheme, "namespace", p.Namespace, "err", err).Warn("seedAllBucketsFromDisk: HSM bucket unlock failed")
					s.audit("unlock_hsm_bucket_failed", p.Scheme, p.Namespace, "", false, 0)
				}
			}
			// LevelAdminWrapped: intentionally skipped — requires per-admin credential.
		}
	}
	return nil
}

func (s *Keeper) loadAuditChain(scheme, namespace string) ([]*BucketEvent, error) {
	if s.auditStore == nil {
		return nil, nil
	}
	return s.auditStore.loadChain(scheme, namespace)
}

func (s *Keeper) pruneAuditEvents(scheme, namespace string, olderThan time.Duration, keepLastN int) error {
	if s.auditStore == nil {
		return nil
	}
	return s.auditStore.pruneEvents(scheme, namespace, olderThan, keepLastN)
}

func (s *Keeper) getLastChecksum(scheme, namespace string) string {
	if s.auditStore == nil {
		return ""
	}
	return s.auditStore.getLastChecksum(scheme, namespace)
}

func (s *Keeper) incrementAccessCount(scheme, namespace, key string) {
	_ = s.db.Update(func(tx pkgstore.Tx) error {
		b := s.getNamespaceBucket(tx, scheme, namespace)
		if b == nil {
			return nil
		}
		data := b.Get([]byte(key))
		if data == nil {
			return nil
		}
		var secret Secret
		if err := unmarshalSecret(data, &secret); err != nil {
			return err
		}
		if len(secret.EncryptedMeta) > 0 {
			bucketDEK, err := s.bucketKeyBytes(scheme, namespace)
			if err != nil {
				return nil
			}
			defer zero.Bytes(bucketDEK)
			meta, err := s.decryptMeta(secret.EncryptedMeta, bucketDEK)
			if err != nil {
				return nil
			}
			meta.AccessCount++
			meta.LastAccess = time.Now()
			em, err := s.encryptMeta(meta, bucketDEK)
			if err != nil {
				return nil
			}
			secret.EncryptedMeta = em
		}
		newData, err := marshalSecret(&secret)
		if err != nil {
			return err
		}
		return b.Put([]byte(key), newData)
	})
}

func (s *Keeper) audit(action, scheme, namespace, key string, success bool, duration time.Duration) {
	if s.auditFn != nil && s.config.EnableAudit {
		s.auditFn(action, scheme, namespace, key, success, duration)
	}
	if s.hooks.OnAudit != nil {
		s.hooks.OnAudit(action, scheme, namespace, key, success, duration)
	}
}

// newDBHealthCheck returns a function suitable for use as a jack.Patient Check.
// It times a single BoltDB read on the metadata verification key and returns
// ErrCheckLatency when the latency exceeds the configured threshold.
func (s *Keeper) newDBHealthCheck(threshold time.Duration) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		start := time.Now()
		_ = s.db.View(func(tx pkgstore.Tx) error {
			b := tx.Bucket([]byte(metaBucket))
			if b != nil {
				_ = b.Get([]byte(metaVerifyKey))
			}
			return nil
		})
		if elapsed := time.Since(start); elapsed > threshold {
			return fmt.Errorf("%w: %s (threshold %s)", ErrCheckLatency, elapsed, threshold)
		}
		return nil
	}
}

// newEncHealthCheck returns a function suitable for use as a jack.Patient Check.
// It encrypts and decrypts a fixed synthetic test vector to confirm the active
// cipher and key are operational. The test vector never contains real secret data.
func (s *Keeper) newEncHealthCheck() func(ctx context.Context) error {
	return func(ctx context.Context) error {
		key, err := s.bucketKeyBytes(s.defaultScheme, s.defaultNs)
		if err != nil {
			return fmt.Errorf("enc health: cannot retrieve DEK: %w", err)
		}
		defer zero.Bytes(key)
		ct, err := s.encryptWithKey(encHealthTestVector, key)
		if err != nil {
			return fmt.Errorf("enc health: encryption failed: %w", err)
		}
		pt, err := s.decryptWithKey(ct, key)
		if err != nil {
			return fmt.Errorf("enc health: decryption failed: %w", err)
		}
		if string(pt) != string(encHealthTestVector) {
			return fmt.Errorf("enc health: round-trip mismatch")
		}
		return nil
	}
}

// Metadata encryption helpers.

func (s *Keeper) deriveMetaKey(bucketDEK []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, bucketDEK, nil, []byte(hkdfInfoMetaKey))
	key := make([]byte, masterKeyLen)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("meta: HKDF expansion failed: %w", err)
	}
	return key, nil
}

func (s *Keeper) encryptMeta(meta *EncryptedMetadata, bucketDEK []byte) ([]byte, error) {
	metaKey, err := s.deriveMetaKey(bucketDEK)
	if err != nil {
		return nil, err
	}
	defer zero.Bytes(metaKey)
	return s.encryptMetaWithKey(meta, metaKey)
}

func (s *Keeper) encryptMetaWithKey(meta *EncryptedMetadata, metaKey []byte) ([]byte, error) {
	plain, err := marshalEncryptedMetadata(meta)
	if err != nil {
		return nil, err
	}
	ct, err := s.encryptWithKey(plain, metaKey)
	zero.Bytes(plain)
	return ct, err
}

func (s *Keeper) decryptMeta(data, bucketDEK []byte) (*EncryptedMetadata, error) {
	metaKey, err := s.deriveMetaKey(bucketDEK)
	if err != nil {
		return nil, err
	}
	defer zero.Bytes(metaKey)
	return s.decryptMetaWithKey(data, metaKey)
}

func (s *Keeper) decryptMetaWithKey(data, metaKey []byte) (*EncryptedMetadata, error) {
	plain, err := s.decryptWithKey(data, metaKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMetadataDecrypt, err)
	}
	var meta EncryptedMetadata
	if err := unmarshalEncryptedMetadata(plain, &meta); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMetadataDecrypt, err)
	}
	return &meta, nil
}

// Per-bucket DEK derivation migration

// runMigrationBatch re-encrypts up to batchSize records across all
// LevelPasswordOnly buckets using the new per-bucket derived DEK.
//
// Crash safety: a per-bucket WAL cursor is written to the metadata bucket
// before each record is migrated. On restart the cursor lets the looper skip
// already-migrated records without re-doing work.
//
// Returns (true, nil) when every bucket is fully migrated and the completion
// marker has been written.
func (s *Keeper) runMigrationBatch(batchSize int) (complete bool, err error) {
	// Snapshot the registry under RLock so we don't race with CreateBucket /
	// loadPolicy which write s.schemeRegistry while holding s.mu.Lock/RLock.
	// Release the lock immediately after the snapshot — migrateBucket does
	// long-running bbolt operations that must not hold s.mu.
	type bucketRef = migrationBucket
	var buckets []bucketRef
	func() {
		s.registryMu.RLock()
		defer s.registryMu.RUnlock()
		buckets = append(buckets, bucketRef{s.defaultScheme, s.defaultNs})
		for _, policy := range s.schemeRegistry {
			if policy.Level == LevelPasswordOnly {
				key := policy.Scheme + ":" + policy.Namespace
				defaultKey := s.defaultScheme + ":" + s.defaultNs
				if key != defaultKey {
					buckets = append(buckets, bucketRef{policy.Scheme, policy.Namespace})
				}
			}
		}
	}()

	remaining := batchSize
	for _, b := range buckets {
		if remaining <= 0 {
			return false, nil
		}
		n, done, berr := s.migrateBucket(b.scheme, b.namespace, remaining)
		if berr != nil {
			return false, berr
		}
		remaining -= n
		if !done {
			return false, nil // still work to do in this bucket
		}
		// Bucket fully migrated — drop the old fallback key from memory.
		s.envelope.DropOld(b.scheme, b.namespace)
	}

	// All buckets complete — write the marker and clean up WAL cursors atomically.
	if err := s.writeMigrationDoneMarker(buckets); err != nil {
		return false, err
	}
	return true, nil
}

// migrateBucket re-encrypts up to limit records in scheme:namespace from the
// old master-key DEK to the new derived DEK. Returns (n, done, err) where n
// is the number of records processed and done is true when the bucket is fully
// migrated.
func (s *Keeper) migrateBucket(scheme, namespace string, limit int) (n int, done bool, err error) {
	// s.master is protected by s.mu. Hold RLock only for the memguard open+copy;
	// the expensive bbolt work below must not hold it.
	s.mu.RLock()
	masterBytes, err := s.master.Bytes()
	s.mu.RUnlock()
	if err != nil {
		return 0, false, err
	}
	oldKey := make([]byte, len(masterBytes))
	copy(oldKey, masterBytes)
	zero.Bytes(masterBytes)
	defer zero.Bytes(oldKey)

	newKey, err := deriveBucketDEK(oldKey, scheme, namespace)
	if err != nil {
		return 0, false, err
	}
	defer zero.Bytes(newKey)

	// Read the WAL cursor for this bucket.
	walKey := metaBucketDEKWALPrefix + scheme + ":" + namespace
	var cursorAfter string
	_ = s.db.View(func(tx pkgstore.Tx) error {
		b := tx.Bucket([]byte(metaBucket))
		if b != nil {
			if v := b.Get([]byte(walKey)); v != nil {
				cursorAfter = string(v)
			}
		}
		return nil
	})

	// Collect keys to migrate.
	var keys []string
	_ = s.db.View(func(tx pkgstore.Tx) error {
		nb := s.getNamespaceBucket(tx, scheme, namespace)
		if nb == nil {
			return nil
		}
		return nb.ForEach(func(k, _ []byte) error {
			ks := string(k)
			if ks == metadataKey {
				return nil
			}
			if cursorAfter == "" || ks > cursorAfter {
				keys = append(keys, ks)
			}
			return nil
		})
	})

	if len(keys) == 0 {
		return 0, true, nil // bucket fully migrated
	}

	processed := 0
	for _, key := range keys {
		if processed >= limit {
			return processed, false, nil
		}
		if err := s.migrateRecord(scheme, namespace, key, oldKey, newKey, walKey); err != nil {
			return processed, false, err
		}
		processed++
	}

	// If we processed all keys the bucket is done.
	done = processed == len(keys)
	if done {
		// Clear the WAL cursor for this bucket.
		_ = s.db.Update(func(tx pkgstore.Tx) error {
			b := tx.Bucket([]byte(metaBucket))
			if b != nil {
				_ = b.Delete([]byte(walKey))
			}
			return nil
		})
	}

	if s.config.BucketDEKMigrationProgress != nil {
		s.config.BucketDEKMigrationProgress(scheme, namespace, processed, len(keys))
	}

	return processed, done, nil
}

// migrateRecord re-encrypts a single secret record from oldKey to newKey in
// one atomic bbolt.Update and advances the WAL cursor.
func (s *Keeper) migrateRecord(scheme, namespace, key string, oldKey, newKey []byte, walKey string) error {
	return s.db.Update(func(tx pkgstore.Tx) error {
		nb := s.getNamespaceBucket(tx, scheme, namespace)
		if nb == nil {
			return nil
		}
		data := nb.Get([]byte(key))
		if data == nil {
			return nil
		}
		var secret Secret
		if err := unmarshalSecret(data, &secret); err != nil {
			return fmt.Errorf("migrate unmarshal %s: %w", key, err)
		}

		// Try decrypting with newKey first (already migrated records).
		// Fall back to oldKey for unmigrated records.
		pt, err := s.decryptWithKey(secret.Ciphertext, newKey)
		if err != nil {
			pt, err = s.decryptWithKey(secret.Ciphertext, oldKey)
			if err != nil {
				return fmt.Errorf("migrate decrypt %s: %w", key, err)
			}
		}

		ct, err := s.encryptWithKey(pt, newKey)
		zero.Bytes(pt)
		if err != nil {
			return fmt.Errorf("migrate encrypt %s: %w", key, err)
		}
		secret.Ciphertext = ct

		// Re-encrypt metadata if present.
		if len(secret.EncryptedMeta) > 0 {
			oldMetaKey, merr := s.deriveMetaKey(oldKey)
			if merr == nil {
				meta, merr2 := s.decryptMetaWithKey(secret.EncryptedMeta, oldMetaKey)
				zero.Bytes(oldMetaKey)
				if merr2 == nil {
					newMetaKey, merr3 := s.deriveMetaKey(newKey)
					if merr3 == nil {
						newEM, merr4 := s.encryptMetaWithKey(meta, newMetaKey)
						zero.Bytes(newMetaKey)
						if merr4 == nil {
							secret.EncryptedMeta = newEM
						}
					}
				}
			}
		}

		encoded, err := marshalSecret(&secret)
		if err != nil {
			return err
		}
		if err := nb.Put([]byte(key), encoded); err != nil {
			return err
		}

		// Advance WAL cursor.
		b := tx.Bucket([]byte(metaBucket))
		if b != nil {
			_ = b.Put([]byte(walKey), []byte(key))
		}
		return nil
	})
}

// writeMigrationDoneMarker writes the completion marker and deletes all WAL
// cursor entries in a single atomic transaction.
type migrationBucket struct{ scheme, namespace string }

func (s *Keeper) writeMigrationDoneMarker(buckets []migrationBucket) error {
	return s.db.Update(func(tx pkgstore.Tx) error {
		b := tx.Bucket([]byte(metaBucket))
		if b == nil {
			return nil
		}
		if err := b.Put([]byte(metaBucketDEKDoneKey), []byte("1")); err != nil {
			return err
		}
		for _, bk := range buckets {
			walKey := metaBucketDEKWALPrefix + bk.scheme + ":" + bk.namespace
			_ = b.Delete([]byte(walKey))
		}
		return nil
	})
}
