package keeper

import (
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
	jack "github.com/olekukonko/jack"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

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
// copies it to a plain slice for immediate use, and destroys the LockedBuffer.
// The returned slice MUST be zeroed by the caller as soon as it is no longer needed.
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
		// No policy — treat as password-only, inherits store state.
		return true
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
	return nil
}

// unlockBucketAdminWrapped derives the KEK, unwraps the DEK, and holds it
// in the Envelope. DeriveKEK (Argon2id) runs inside jack.Async so the
// calling goroutine is not blocked during the CPU-intensive derivation.
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
		return fmt.Errorf("%w: admin %q", ErrAdminNotFound, adminID)
	}

	masterBytes, err := s.master.Bytes()
	if err != nil {
		return err
	}

	// Capture values for the goroutine; masterBytes is zeroed after Await.
	salt := policy.DEKSalt
	mb := masterBytes
	ap := adminPassword
	future := jack.Async(func() ([]byte, error) {
		return DeriveKEK(mb, ap, salt)
	})

	kek, err := future.Await()
	if err != nil {
		return err
	}

	// wait for future to finish
	secureZero(masterBytes)

	dekEnc, err := UnwrapDEK(wrapped, kek) // kek is zeroed inside UnwrapDEK
	if err != nil {
		return err
	}
	dekBuf, err := dekEnc.Open()
	if err != nil {
		return fmt.Errorf("failed to open unwrapped DEK: %w", err)
	}
	s.envelope.Hold(scheme, namespace, dekBuf)

	if s.jackReaper != nil {
		s.jackReaper.Touch(scheme + ":" + namespace)
	}

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

// reencryptAllWithKey re-encrypts every secret from oldKey to newKey.
// For V1 records it also re-encrypts EncryptedMeta.
// Uses rotationWALKey as a crash-detection marker.
func (s *Keeper) reencryptAllWithKey(newKey, oldKey []byte) error {
	if len(oldKey) == 0 {
		return errors.New("old key is empty")
	}

	if err := s.db.Update(func(tx pkgstore.Tx) error {
		b := tx.Bucket([]byte(metaBucket))
		if b == nil {
			return stdErrors.New("metadata bucket not found")
		}
		return b.Put([]byte(rotationWALKey), []byte(walStatusInProgress))
	}); err != nil {
		return fmt.Errorf("failed to write rotation WAL: %w", err)
	}

	if err := s.db.Update(func(tx pkgstore.Tx) error {
		return tx.ForEach(func(name []byte, sb pkgstore.Bucket) error {
			schemeName := string(name)
			if schemeName == metaBucket || schemeName == policyBucket || schemeName == auditBucketRoot {
				return nil
			}
			return sb.ForEach(func(nsName []byte, _ []byte) error {
				if string(nsName) == metadataKey {
					return nil
				}
				nb := sb.Bucket(nsName)
				if nb == nil {
					return nil
				}
				return nb.ForEach(func(k, v []byte) error {
					if string(k) == metadataKey {
						return nil
					}
					var secret Secret
					if err := json.Unmarshal(v, &secret); err != nil {
						return err
					}

					pt, err := s.decryptWithKey(secret.Ciphertext, oldKey)
					if err != nil {
						return fmt.Errorf("decrypt %s: %w", k, err)
					}
					ct, err := s.encryptWithKey(pt, newKey)
					secureZero(pt)
					if err != nil {
						return fmt.Errorf("encrypt %s: %w", k, err)
					}
					secret.Ciphertext = ct

					if secret.SchemaVersion == secretSchemaV1 && len(secret.EncryptedMeta) > 0 {
						oldMetaKey, merr := s.deriveMetaKey(oldKey)
						if merr != nil {
							return fmt.Errorf("derive old meta key: %w", merr)
						}
						meta, merr := s.decryptMetaWithKey(secret.EncryptedMeta, oldMetaKey)
						secureZero(oldMetaKey)
						if merr != nil {
							return fmt.Errorf("decrypt meta %s: %w", k, merr)
						}
						newMetaKey, merr := s.deriveMetaKey(newKey)
						if merr != nil {
							return fmt.Errorf("derive new meta key: %w", merr)
						}
						newEM, merr := s.encryptMetaWithKey(meta, newMetaKey)
						secureZero(newMetaKey)
						if merr != nil {
							return fmt.Errorf("encrypt meta %s: %w", k, merr)
						}
						secret.EncryptedMeta = newEM
					} else if secret.SchemaVersion == secretSchemaV0 {
						secret.Version++
					}

					data, err := json.Marshal(secret)
					if err != nil {
						return err
					}
					return nb.Put(k, data)
				})
			})
		})
	}); err != nil {
		return fmt.Errorf("re-encryption failed: %w", err)
	}

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

// verifyArgon2Params returns the Argon2 parameters for verification hash
// derivation, applying defaults where the config has zero values.
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

func policyHash(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func (s *Keeper) savePolicy(policy *BucketSecurityPolicy) error {
	return s.db.Update(func(tx pkgstore.Tx) error {
		policies, err := tx.CreateBucketIfNotExists([]byte(policyBucket))
		if err != nil {
			return err
		}
		key := fmt.Sprintf("%s:%s", policy.Scheme, policy.Namespace)
		data, err := json.Marshal(policy)
		if err != nil {
			return err
		}
		if err := policies.Put([]byte(key), data); err != nil {
			return err
		}
		return policies.Put([]byte(key+policyHashSuffix), []byte(policyHash(data)))
	})
}

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
		if storedHash := policies.Get([]byte(key + policyHashSuffix)); storedHash != nil {
			if policyHash(data) != string(storedHash) {
				return fmt.Errorf("policy tamper detected for %s", key)
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

func (s *Keeper) appendAuditEvent(event *BucketEvent) error {
	if s.auditStore == nil {
		return nil
	}
	// Policy creation events are synchronous: CreateBucket must not return
	// before the audit record is committed.
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
		if err := json.Unmarshal(data, &secret); err != nil {
			return err
		}

		if secret.SchemaVersion == secretSchemaV1 && len(secret.EncryptedMeta) > 0 {
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
		} else {
			secret.AccessCount++
			secret.LastAccess = time.Now()
		}

		newData, err := json.Marshal(secret)
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

// deriveMetaKey produces a 32-byte encryption key for EncryptedMetadata
// from a bucket DEK using HKDF-SHA256. The metadata key is bucket-scoped:
// inaccessible without both the master passphrase and (for LevelAdminWrapped)
// the admin password.
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
	plain, err := json.Marshal(meta)
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
	if err := json.Unmarshal(plain, &meta); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMetadataDecrypt, err)
	}
	return &meta, nil
}

// Background metadata migration.

// runMigrations creates and starts a jack.Looper that migrates V0 records to
// V1 in small batches, yielding between each batch to avoid blocking the data
// plane. The Looper stops itself after signalling migrationDone.
func (s *Keeper) runMigrations() *jack.Looper {
	looper := jack.NewLooper(
		jack.Func(func() error {
			done, err := s.migrateBatch()
			if err != nil {
				s.audit("migration_batch_error", "", "", "", false, 0)
			}
			if done {
				select {
				case s.migrationDone <- struct{}{}:
				default:
				}
			}
			return err
		}),
		jack.WithLooperInterval(migrationYieldMs),
		jack.WithLooperImmediate(true),
	)
	looper.Start()
	return looper
}

// migrateBatch migrates up to migrationBatchSize V0 records to V1.
// Returns (true, nil) when all records have been migrated.
func (s *Keeper) migrateBatch() (bool, error) {
	if s.isMigrationComplete() {
		return true, nil
	}

	cursor, err := s.migrationCursor()
	if err != nil {
		return false, err
	}

	count := 0
	batchFull := false

	err = s.db.Update(func(tx pkgstore.Tx) error {
		return tx.ForEach(func(name []byte, sb pkgstore.Bucket) error {
			schemeName := string(name)
			if schemeName == metaBucket || schemeName == policyBucket || schemeName == auditBucketRoot {
				return nil
			}
			return sb.ForEach(func(nsName []byte, _ []byte) error {
				if string(nsName) == metadataKey {
					return nil
				}
				nb := sb.Bucket(nsName)
				if nb == nil {
					return nil
				}
				return nb.ForEach(func(k, v []byte) error {
					if batchFull {
						return nil
					}
					if string(k) == metadataKey {
						return nil
					}
					curKey := schemeName + ":" + string(nsName) + ":" + string(k)
					if cursor != "" && curKey <= cursor {
						return nil
					}
					var secret Secret
					if err := json.Unmarshal(v, &secret); err != nil {
						return nil
					}
					if secret.SchemaVersion != secretSchemaV0 {
						return nil
					}
					bucketDEK, err := s.bucketKeyBytes(schemeName, string(nsName))
					if err != nil {
						return nil // bucket locked; skip silently
					}
					defer secureZero(bucketDEK)

					meta := &EncryptedMetadata{
						CreatedAt:   secret.CreatedAt,
						UpdatedAt:   secret.UpdatedAt,
						AccessCount: secret.AccessCount,
						LastAccess:  secret.LastAccess,
						Version:     secret.Version,
					}
					em, err := s.encryptMeta(meta, bucketDEK)
					if err != nil {
						return nil
					}
					newSecret := Secret{
						Ciphertext:    secret.Ciphertext,
						EncryptedMeta: em,
						SchemaVersion: secretSchemaV1,
					}
					data, err := json.Marshal(newSecret)
					if err != nil {
						return nil
					}
					if err := nb.Put(k, data); err != nil {
						return err
					}
					count++
					if count >= migrationBatchSize {
						batchFull = true
						_ = s.storeMigrationCursorTx(tx, curKey)
					}
					return nil
				})
			})
		})
	})
	if err != nil {
		return false, err
	}

	if batchFull {
		return false, nil
	}
	return true, s.markMigrationDone()
}

func (s *Keeper) isMigrationComplete() bool {
	var done bool
	_ = s.db.View(func(tx pkgstore.Tx) error {
		b := tx.Bucket([]byte(metaBucket))
		if b == nil {
			return nil
		}
		done = b.Get([]byte(migrationDoneKey)) != nil
		return nil
	})
	return done
}

func (s *Keeper) migrationCursor() (string, error) {
	var cursor string
	err := s.db.View(func(tx pkgstore.Tx) error {
		b := tx.Bucket([]byte(metaBucket))
		if b == nil {
			return nil
		}
		if v := b.Get([]byte(migrationWALKey)); v != nil {
			cursor = string(v)
		}
		return nil
	})
	return cursor, err
}

// storeMigrationCursorTx writes the migration cursor inside an existing transaction.
func (s *Keeper) storeMigrationCursorTx(tx pkgstore.Tx, cursor string) error {
	b := tx.Bucket([]byte(metaBucket))
	if b == nil {
		return nil
	}
	return b.Put([]byte(migrationWALKey), []byte(cursor))
}

func (s *Keeper) markMigrationDone() error {
	return s.db.Update(func(tx pkgstore.Tx) error {
		b := tx.Bucket([]byte(metaBucket))
		if b == nil {
			return nil
		}
		if err := b.Put([]byte(migrationDoneKey), []byte("1")); err != nil {
			return err
		}
		return b.Delete([]byte(migrationWALKey))
	})
}
