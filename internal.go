package keeper

import (
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

// unlockBucketPasswordOnly places the master key (as DEK) into the Envelope.
func (s *Keeper) unlockBucketPasswordOnly(scheme, namespace string) error {
	if s.master == nil {
		return ErrStoreLocked
	}
	masterBytes, err := s.master.Bytes()
	if err != nil {
		return err
	}
	buf := memguard.NewBufferFromBytes(masterBytes)
	if buf.Size() == 0 {
		return fmt.Errorf("failed to allocate buffer for master key")
	}
	s.envelope.Hold(scheme, namespace, buf)
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
	secureZero(masterBytes)
	defer secureZero(mbCopy)

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
	defer secureZero(key)
	return s.encryptWithKey(plaintext, key)
}

func (s *Keeper) decrypt(ciphertext []byte, scheme, namespace string) ([]byte, error) {
	key, err := s.bucketKeyBytes(scheme, namespace)
	if err != nil {
		return nil, err
	}
	defer secureZero(key)
	return s.decryptWithKey(ciphertext, key)
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

// reencryptAllWithKey re-encrypts every LevelPasswordOnly secret and its
// metadata from oldKey to newKey.
//
// Crash safety: the WAL records status and a cursor (scheme:namespace:key of
// the last successfully written record). Each record is committed in its own
// bbolt.Update, which is atomic. On crash, New() reads the WAL and calls
// resumeRotation to complete from the cursor.
func (s *Keeper) reencryptAllWithKey(newKey, oldKey []byte) error {
	if len(oldKey) == 0 {
		return errors.New("old key is empty")
	}

	// Write WAL before touching any record.
	oldHash := sha256.Sum256(oldKey)
	newHash := sha256.Sum256(newKey)
	wal := &RotationWAL{
		Status:     walStatusInProgress,
		OldKeyHash: oldHash[:],
		NewKeyHash: newHash[:],
		StartedAt:  time.Now(),
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

// encryptAllRecords iterates every secret bucket and re-encrypts each record
// individually. The WAL cursor is updated after each successful record write.
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
				// Skip records already processed before a crash.
				if wal.LastKey != "" && cursor <= wal.LastKey {
					continue
				}
				if err := s.reencryptRecord(schemeName, nsName, key, newKey, oldKey); err != nil {
					return err
				}
				wal.LastKey = cursor
				if err := s.writeRotationWAL(wal); err != nil {
					return fmt.Errorf("failed to update rotation WAL cursor: %w", err)
				}
			}
		}
	}
	return nil
}

// reencryptRecord re-encrypts a single secret record in one atomic Update.
func (s *Keeper) reencryptRecord(scheme, namespace, key string, newKey, oldKey []byte) error {
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
		pt, err := s.decryptWithKey(secret.Ciphertext, oldKey)
		if err != nil {
			return fmt.Errorf("decrypt %s: %w", key, err)
		}
		ct, err := s.encryptWithKey(pt, newKey)
		secureZero(pt)
		if err != nil {
			return fmt.Errorf("encrypt %s: %w", key, err)
		}
		secret.Ciphertext = ct

		if len(secret.EncryptedMeta) > 0 {
			oldMetaKey, merr := s.deriveMetaKey(oldKey)
			if merr != nil {
				return fmt.Errorf("derive old meta key: %w", merr)
			}
			meta, merr := s.decryptMetaWithKey(secret.EncryptedMeta, oldMetaKey)
			secureZero(oldMetaKey)
			if merr != nil {
				return fmt.Errorf("decrypt meta %s: %w", key, merr)
			}
			newMetaKey, merr := s.deriveMetaKey(newKey)
			if merr != nil {
				return fmt.Errorf("derive new meta key: %w", merr)
			}
			newEM, merr := s.encryptMetaWithKey(meta, newMetaKey)
			secureZero(newMetaKey)
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

// resumeRotation continues a rotation that was interrupted by a crash.
// Called from New() when hasIncompleteRotation() returns true.
func (s *Keeper) resumeRotation(newKey, oldKey []byte) error {
	wal, err := s.readRotationWAL()
	if err != nil {
		return fmt.Errorf("failed to read rotation WAL: %w", err)
	}
	s.logger.Fields("cursor", wal.LastKey).Info("resuming interrupted key rotation")
	if err := s.encryptAllRecords(newKey, oldKey, wal); err != nil {
		return fmt.Errorf("re-encryption resume failed: %w", err)
	}
	return s.clearRotationWAL()
}

func (s *Keeper) writeRotationWAL(wal *RotationWAL) error {
	data, err := json.Marshal(wal)
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
		return json.Unmarshal(data, &wal)
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

func (s *Keeper) getOrCreateSalt() ([]byte, error) {
	var salt []byte
	if err := s.db.View(func(tx pkgstore.Tx) error {
		b := tx.Bucket([]byte(metaBucket))
		if b == nil {
			return nil
		}
		if data := b.Get([]byte(metaSaltKey)); data != nil {
			salt = append([]byte(nil), data...)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if salt != nil {
		return salt, nil
	}
	salt = make([]byte, masterKeyLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, s.storeSalt(salt)
}

func (s *Keeper) storeSalt(salt []byte) error {
	return s.db.Update(func(tx pkgstore.Tx) error {
		b := tx.Bucket([]byte(metaBucket))
		if b == nil {
			return stdErrors.New("metadata bucket not found")
		}
		return b.Put([]byte(metaSaltKey), salt)
	})
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

// Policy HMAC key helpers.

// derivePolicyKey produces a 32-byte HMAC key for policy authentication.
// Distinct info string from the audit key — each key has one purpose.
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

// policyHashIntegrity returns SHA-256(policyJSON) as hex — used before unlock.
func policyHashIntegrity(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// savePolicy persists a policy with both the unauthenticated SHA-256 hash and,
// when the store is unlocked (policyKey available), an authenticated HMAC tag.
func (s *Keeper) savePolicy(policy *BucketSecurityPolicy) error {
	return s.db.Update(func(tx pkgstore.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte(policyBucket))
		if err != nil {
			return err
		}
		key := fmt.Sprintf("%s:%s", policy.Scheme, policy.Namespace)
		data, err := json.Marshal(policy)
		if err != nil {
			return err
		}
		if err := bucket.Put([]byte(key), data); err != nil {
			return err
		}
		// Always write the unauthenticated hash for pre-unlock integrity checks.
		if err := bucket.Put([]byte(key+policyHashSuffix), []byte(policyHashIntegrity(data))); err != nil {
			return err
		}
		// Write the authenticated HMAC when the policy key is available.
		if len(s.policyKey) > 0 {
			tag := computePolicyHMAC(s.policyKey, data)
			if err := bucket.Put([]byte(key+policyHMACSuffix), []byte(tag)); err != nil {
				return err
			}
		}
		return nil
	})
}

// loadPolicies populates schemeRegistry at startup (before unlock).
// Only SHA-256 hash verification is available at this stage.
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
			if err := json.Unmarshal(v, &policy); err != nil {
				return err
			}
			s.schemeRegistry[key] = &policy
			return nil
		})
	})
}

// loadPolicy returns the policy for scheme/namespace, verifying the HMAC when
// the store is unlocked. Falls back to SHA-256 integrity check when no HMAC
// tag is stored (e.g. policies created before this version).
func (s *Keeper) loadPolicy(scheme, namespace string) (*BucketSecurityPolicy, error) {
	key := fmt.Sprintf("%s:%s", scheme, namespace)
	if p, ok := s.schemeRegistry[key]; ok {
		return p, nil
	}
	var policy BucketSecurityPolicy
	err := s.db.View(func(tx pkgstore.Tx) error {
		policies := tx.Bucket([]byte(policyBucket))
		if policies == nil {
			return ErrPolicyNotFound
		}
		data := policies.Get([]byte(key))
		if data == nil {
			return ErrPolicyNotFound
		}

		// Prefer HMAC verification when the store is unlocked and a tag exists.
		if len(s.policyKey) > 0 {
			if tag := policies.Get([]byte(key + policyHMACSuffix)); tag != nil {
				expected := computePolicyHMAC(s.policyKey, data)
				if !hmac.Equal([]byte(expected), tag) {
					return fmt.Errorf("%w: HMAC mismatch for policy %s", ErrPolicySignature, key)
				}
			} else {
				// No HMAC tag yet — fall back to SHA-256 and upgrade on next save.
				if storedHash := policies.Get([]byte(key + policyHashSuffix)); storedHash != nil {
					if policyHashIntegrity(data) != string(storedHash) {
						return fmt.Errorf("policy integrity check failed for %s", key)
					}
				}
			}
		} else {
			// Pre-unlock: SHA-256 only.
			if storedHash := policies.Get([]byte(key + policyHashSuffix)); storedHash != nil {
				if policyHashIntegrity(data) != string(storedHash) {
					return fmt.Errorf("policy integrity check failed for %s", key)
				}
			}
		}

		return json.Unmarshal(data, &policy)
	})
	if err != nil {
		return nil, err
	}
	s.schemeRegistry[key] = &policy
	return &policy, nil
}

// upgradePolicyHMACs rewrites all policy records with an authenticated HMAC tag.
// Called from UnlockDatabase after policyKey is set. Policies created before
// this version only have a SHA-256 hash; this upgrades them in one pass.
func (s *Keeper) upgradePolicyHMACs() error {
	if len(s.policyKey) == 0 {
		return nil
	}
	return s.db.Update(func(tx pkgstore.Tx) error {
		policies := tx.Bucket([]byte(policyBucket))
		if policies == nil {
			return nil
		}
		var toUpgrade []struct{ key, data []byte }
		_ = policies.ForEach(func(k, v []byte) error {
			key := string(k)
			if isPolicyHashKey(key) {
				return nil
			}
			// Only upgrade if no HMAC tag yet.
			if policies.Get([]byte(key+policyHMACSuffix)) == nil {
				kCopy := make([]byte, len(k))
				copy(kCopy, k)
				vCopy := make([]byte, len(v))
				copy(vCopy, v)
				toUpgrade = append(toUpgrade, struct{ key, data []byte }{kCopy, vCopy})
			}
			return nil
		})
		for _, item := range toUpgrade {
			tag := computePolicyHMAC(s.policyKey, item.data)
			if err := policies.Put(append(item.key, []byte(policyHMACSuffix)...), []byte(tag)); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Keeper) appendAuditEvent(event *BucketEvent) error {
	if s.auditStore == nil {
		return nil
	}
	if s.config.Jack.Pool != nil && event.EventType != "created" {
		ev := event
		s.config.Jack.Pool.Do(func() {
			_ = s.auditStore.appendEvent(ev.Scheme, ev.Namespace, ev)
		})
		return nil
	}
	return s.auditStore.appendEvent(event.Scheme, event.Namespace, event)
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
			defer secureZero(bucketDEK)
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
	defer secureZero(metaKey)
	return s.encryptMetaWithKey(meta, metaKey)
}

func (s *Keeper) encryptMetaWithKey(meta *EncryptedMetadata, metaKey []byte) ([]byte, error) {
	plain, err := marshalEncryptedMetadata(meta)
	if err != nil {
		return nil, err
	}
	ct, err := s.encryptWithKey(plain, metaKey)
	secureZero(plain)
	return ct, err
}

func (s *Keeper) decryptMeta(data, bucketDEK []byte) (*EncryptedMetadata, error) {
	metaKey, err := s.deriveMetaKey(bucketDEK)
	if err != nil {
		return nil, err
	}
	defer secureZero(metaKey)
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
