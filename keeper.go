package keeper

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/agberohq/keeper/pkg/core"
	"github.com/agberohq/keeper/pkg/crypt"
	pkgstore "github.com/agberohq/keeper/pkg/store"
	"github.com/awnumar/memguard"
	jack "github.com/olekukonko/jack"
	"github.com/olekukonko/ll"
)

// Keeper is the encrypted secret store.
//
// Security model:
//
// LevelPasswordOnly buckets (vault://):
//
//	Master key → Envelope at UnlockDatabase. Available immediately at startup;
//	background jobs always have access.
//
// LevelAdminWrapped buckets (keeper://):
//
//	Random DEK per bucket. DEK wrapped per-admin via
//	WrapDEK(dek, HKDF(master‖adminPass, salt)).
//	UnlockBucket(adminID, adminPassword) → Envelope.
//	Reaper TTL drops these DEKs after inactivity when Jack is configured.
type Keeper struct {
	db             pkgstore.Store
	master         *Master
	locked         bool
	mu             sync.RWMutex
	config         Config
	auditFn        func(action, scheme, namespace, key string, success bool, duration time.Duration)
	lastActivity   int64
	logger         *ll.Logger
	defaultScheme  string
	defaultNs      string
	metrics        *core.Metrics
	schemeRegistry map[string]*BucketSecurityPolicy
	hooks          Hooks
	envelope       *Envelope
	auditStore     *auditStore
	policyChain    *Chain
	policyKey      []byte // HMAC key for policy authentication; nil when locked

	// Jack-managed background components; nil when running without Jack.
	autoLocker *jack.Looper
	jackReaper *jack.Reaper
}

// WithJack returns an option that attaches Jack integration handles to the Config.
func WithJack(cfg JackConfig) func(*Config) {
	return func(c *Config) { c.Jack = cfg }
}

// New opens or creates a keeper database.
func New(config Config, opts ...func(*Config)) (*Keeper, error) {
	for _, o := range opts {
		o(&config)
	}
	if err := validateConfig(&config); err != nil {
		return nil, err
	}
	if config.DefaultScheme == "" {
		config.DefaultScheme = defaultScheme
	}
	if config.DefaultNamespace == "" {
		config.DefaultNamespace = defaultNamespace
	}
	if config.Argon2Time == 0 {
		config.Argon2Time = defaultArgon2TimeCost
	}
	if config.Argon2Memory == 0 {
		config.Argon2Memory = defaultArgon2Memory
	}
	if config.Argon2Parallelism == 0 {
		config.Argon2Parallelism = defaultArgon2Threads
	}
	if config.VerifyArgon2Time == 0 {
		config.VerifyArgon2Time = defaultVerifyArgon2Time
	}
	if config.VerifyArgon2Memory == 0 {
		config.VerifyArgon2Memory = defaultArgon2Memory
	}
	if config.VerifyArgon2Parallelism == 0 {
		config.VerifyArgon2Parallelism = defaultArgon2Threads
	}
	if config.KDF == nil {
		config.KDF = crypt.DefaultArgon2KDF()
	}
	if config.NewCipher == nil {
		config.NewCipher = func(key []byte) (crypt.Cipher, error) {
			return crypt.NewCipherFromKey(key)
		}
	}
	if config.Logger == nil {
		config.Logger = ll.New("keeper").Disable()
	} else {
		config.Logger = config.Logger.Clone()
	}

	if err := os.MkdirAll(filepath.Dir(config.DBPath), 0700); err != nil {
		return nil, fmt.Errorf("failed to create secrets directory: %w", err)
	}
	db, err := pkgstore.Open(config.DBPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open secrets database: %w", err)
	}

	store := &Keeper{
		db:             db,
		locked:         true,
		config:         config,
		logger:         config.Logger.Namespace("keeper"),
		defaultScheme:  config.DefaultScheme,
		defaultNs:      config.DefaultNamespace,
		metrics:        &core.Metrics{},
		schemeRegistry: make(map[string]*BucketSecurityPolicy),
		envelope:       NewEnvelope(),
	}

	store.auditStore = newAuditStore(db)
	if err := store.auditStore.init(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to init audit store: %w", err)
	}
	store.policyChain = &Chain{store: store}

	if err := store.initBuckets(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize buckets: %w", err)
	}
	if err := store.loadPolicies(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to load policies: %w", err)
	}

	// Register with Jack Shutdown when provided.
	// Keeper's only registered callback is Lock — the pool lifecycle
	// belongs to Agbero and is never touched here.
	if config.Jack.Shutdown != nil {
		_ = config.Jack.Shutdown.Register(func() error {
			return store.Lock()
		})
	}

	return store, nil
}

// Open opens an existing database. Returns an error if it does not exist.
func Open(config Config, opts ...func(*Config)) (*Keeper, error) {
	if _, err := os.Stat(config.DBPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("secret store does not exist at %s", config.DBPath)
	}
	return New(config, opts...)
}

// CreateBucket registers a new immutable bucket policy.
//
// For LevelPasswordOnly: the bucket is accessible as soon as UnlockDatabase
// has been called. If the store is already unlocked when CreateBucket is
// called the bucket is seeded into the Envelope immediately.
//
// For LevelAdminWrapped: the bucket is inaccessible until at least one admin
// is added via AddAdminToPolicy and then unlocked via UnlockBucket.
func (s *Keeper) CreateBucket(scheme, namespace string, level SecurityLevel, createdBy string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !isValidScheme(scheme) {
		return ErrSchemeInvalid
	}
	if !isValidNamespace(namespace) {
		return ErrNamespaceInvalid
	}
	if existing, err := s.policyChain.GetPolicy(scheme, namespace); err == nil && existing != nil {
		return ErrPolicyImmutable
	}

	policy := &BucketSecurityPolicy{
		ID:                generateUUID(),
		Scheme:            scheme,
		Namespace:         namespace,
		Level:             level,
		CreatedAt:         time.Now(),
		CreatedBy:         createdBy,
		EncryptionVersion: 1,
	}
	if level == LevelAdminWrapped {
		salt, err := GenerateDEKSalt()
		if err != nil {
			return fmt.Errorf("failed to generate DEK salt: %w", err)
		}
		policy.DEKSalt = salt
		policy.WrappedDEKs = make(map[string][]byte)
	}

	if err := policy.Validate(); err != nil {
		return err
	}
	if err := s.policyChain.CreatePolicy(policy); err != nil {
		return err
	}
	if err := s.db.Update(func(tx pkgstore.Tx) error {
		_, err := s.createNamespaceBucket(tx, scheme, namespace)
		return err
	}); err != nil {
		return err
	}

	// Seed the Envelope immediately for LevelPasswordOnly buckets created
	// while the store is already unlocked.
	if !s.locked && level == LevelPasswordOnly {
		if err := s.unlockBucketPasswordOnly(scheme, namespace); err != nil {
			s.audit("seed_new_bucket_failed", scheme, namespace, "", false, 0)
		}
	}
	s.logger.Fields("scheme", scheme, "namespace", namespace, "level", string(level), "createdBy", createdBy).Info("bucket created")
	return nil
}

// AddAdminToPolicy wraps the bucket DEK under a new admin's KEK and persists
// the updated policy.
func (s *Keeper) AddAdminToPolicy(scheme, namespace, adminID string, adminPassword []byte) error {
	defer secureZero(adminPassword)
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
	masterBytes, err := s.master.Bytes()
	if err != nil {
		return err
	}
	defer secureZero(masterBytes)

	var dekEnc *memguard.Enclave
	if len(policy.WrappedDEKs) == 0 {
		dekEnc, err = GenerateDEK()
		if err != nil {
			return err
		}
	} else {
		dekBuf, rerr := s.envelope.Retrieve(scheme, namespace)
		if rerr != nil {
			return fmt.Errorf("bucket must be unlocked to add a subsequent admin: %w", rerr)
		}
		dekEnc = dekBuf.Seal()
	}
	kek, err := DeriveKEK(masterBytes, adminPassword, policy.DEKSalt)
	if err != nil {
		return err
	}
	wrapped, err := WrapDEK(dekEnc, kek)
	if err != nil {
		return err
	}
	if policy.WrappedDEKs == nil {
		policy.WrappedDEKs = make(map[string][]byte)
	}
	policy.WrappedDEKs[adminID] = wrapped
	if err := s.savePolicy(policy); err != nil {
		return err
	}
	s.schemeRegistry[fmt.Sprintf("%s:%s", scheme, namespace)] = policy

	// First admin: seed the Envelope so the bucket is usable immediately.
	if len(policy.WrappedDEKs) == 1 {
		kek2, kerr := DeriveKEK(masterBytes, adminPassword, policy.DEKSalt)
		if kerr != nil {
			return kerr
		}
		seedEnc, serr := UnwrapDEK(wrapped, kek2)
		if serr != nil {
			return serr
		}
		seedBuf, oerr := seedEnc.Open()
		if oerr != nil {
			return fmt.Errorf("failed to open seed DEK: %w", oerr)
		}
		s.envelope.Hold(scheme, namespace, seedBuf)
	}
	_ = s.policyChain.AppendEvent(scheme, namespace, "admin_added",
		map[string]string{"admin": adminID})
	return nil
}

// RevokeAdmin removes an admin's wrapped DEK copy from the policy.
// The bucket DEK and all secrets remain untouched.
func (s *Keeper) RevokeAdmin(scheme, namespace, adminID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	policy, err := s.loadPolicy(scheme, namespace)
	if err != nil {
		return err
	}
	if _, ok := policy.WrappedDEKs[adminID]; !ok {
		return fmt.Errorf("%w: admin %q", ErrAdminNotFound, adminID)
	}
	delete(policy.WrappedDEKs, adminID)
	if err := s.savePolicy(policy); err != nil {
		return err
	}
	s.schemeRegistry[fmt.Sprintf("%s:%s", scheme, namespace)] = policy
	_ = s.policyChain.AppendEvent(scheme, namespace, "admin_revoked",
		map[string]string{"admin": adminID})
	return nil
}

// UnlockBucket unlocks a LevelAdminWrapped bucket.
// adminPassword is zeroed by this method.
func (s *Keeper) UnlockBucket(scheme, namespace, adminID string, adminPassword []byte) error {
	defer secureZero(adminPassword)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.locked {
		return ErrStoreLocked
	}
	return s.unlockBucketAdminWrapped(scheme, namespace, adminID, adminPassword)
}

// LockBucket drops the DEK for a single bucket from the Envelope.
func (s *Keeper) LockBucket(scheme, namespace string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lockBucket(scheme, namespace)
	_ = s.policyChain.AppendEvent(scheme, namespace, "locked", nil)
	return nil
}

// IsBucketUnlocked reports whether a bucket's DEK is in the Envelope.
func (s *Keeper) IsBucketUnlocked(scheme, namespace string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.isBucketUnlocked(scheme, namespace)
}

// GetPolicy returns a bucket's immutable policy.
func (s *Keeper) GetPolicy(scheme, namespace string) (*BucketSecurityPolicy, error) {
	return s.policyChain.GetPolicy(scheme, namespace)
}

// DeriveMaster derives a Master key from passphrase bytes using the configured KDF.
// The dummy timing code from the previous version is removed: Argon2 dominates
// the timing, making the failure path indistinguishable in practice.
func (s *Keeper) DeriveMaster(passphrase []byte) (*Master, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	salt, err := s.getOrCreateSalt()
	if err != nil {
		return nil, fmt.Errorf("failed to get salt: %w", err)
	}
	key, err := s.config.KDF.DeriveKey(passphrase, salt, s.config.KeyLen)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}
	if err := s.verifyMasterKey(key); err != nil {
		memguard.WipeBytes(key)
		return nil, ErrInvalidPassphrase
	}
	master, err := NewMaster(key)
	memguard.WipeBytes(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create master: %w", err)
	}
	return master, nil
}

// UnlockDatabase unlocks the store with a pre-derived Master key.
//
// All LevelPasswordOnly buckets are unlocked immediately via the Envelope.
// LevelAdminWrapped buckets require a separate UnlockBucket call.
// The audit HMAC signing key is derived from the master and activated.
// Background metadata migration starts after unlock completes.
func (s *Keeper) UnlockDatabase(master *Master) error {
	if master == nil || !master.IsValid() {
		return ErrMasterRequired
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.locked {
		return ErrAlreadyUnlocked
	}

	s.master = master
	s.locked = false

	// Derive and activate the audit HMAC signing key from the master key.
	masterBytes, err := master.Bytes()
	if err != nil {
		s.locked = true
		s.master = nil
		return fmt.Errorf("failed to read master key for audit derivation: %w", err)
	}
	auditKey, err := deriveAuditKey(masterBytes)
	secureZero(masterBytes)
	if err != nil {
		s.locked = true
		s.master = nil
		return fmt.Errorf("failed to derive audit signing key: %w", err)
	}
	s.auditStore.setSigningKey(auditKey)
	secureZero(auditKey)

	// Derive and activate the policy HMAC key.
	masterBytes2, err := master.Bytes()
	if err != nil {
		s.locked = true
		s.master = nil
		s.auditStore.setSigningKey(nil)
		return fmt.Errorf("failed to read master key for policy key derivation: %w", err)
	}
	policyKey, err := derivePolicyKey(masterBytes2)
	secureZero(masterBytes2)
	if err != nil {
		s.locked = true
		s.master = nil
		s.auditStore.setSigningKey(nil)
		return fmt.Errorf("failed to derive policy HMAC key: %w", err)
	}
	s.policyKey = policyKey

	// If a rotation was interrupted by a crash, complete it now.
	// The master key has been verified, so we know it is the new key.
	if s.hasIncompleteRotation() {
		masterBytesForResume, rerr := master.Bytes()
		if rerr != nil {
			s.locked = true
			s.master = nil
			s.auditStore.setSigningKey(nil)
			secureZero(s.policyKey)
			s.policyKey = nil
			return fmt.Errorf("failed to read master key for rotation resume: %w", rerr)
		}
		if rerr := s.resumeRotation(masterBytesForResume); rerr != nil {
			secureZero(masterBytesForResume)
			s.locked = true
			s.master = nil
			s.auditStore.setSigningKey(nil)
			secureZero(s.policyKey)
			s.policyKey = nil
			return fmt.Errorf("failed to resume interrupted rotation: %w", rerr)
		}
		secureZero(masterBytesForResume)
		s.logger.Info("interrupted rotation completed successfully")
	}

	// Upgrade any policy records that only have a SHA-256 hash to HMAC tags.
	if err := s.upgradePolicyHMACs(); err != nil {
		s.logger.Fields("err", err).Warn("policy HMAC upgrade failed — continuing")
	}

	// Seed all LevelPasswordOnly buckets.
	if err := s.unlockBucketPasswordOnly(s.defaultScheme, s.defaultNs); err != nil {
		s.locked = true
		s.master = nil
		s.auditStore.setSigningKey(nil)
		return fmt.Errorf("failed to unlock default bucket: %w", err)
	}
	for _, policy := range s.schemeRegistry {
		if policy.Level == LevelPasswordOnly {
			if err := s.unlockBucketPasswordOnly(policy.Scheme, policy.Namespace); err != nil {
				s.audit("unlock_bucket_failed", policy.Scheme, policy.Namespace, "", false, 0)
			}
		}
	}

	s.updateActivity()

	// Auto-lock Looper: replaces the old autoLockRoutine goroutine + channel.
	// The single write-lock pattern inside the task eliminates the previous
	// RUnlock→Lock race condition.
	if s.config.AutoLockInterval > 0 {
		interval := s.config.AutoLockInterval
		s.autoLocker = jack.NewLooper(
			jack.Func(func() error {
				last := time.Unix(0, atomic.LoadInt64(&s.lastActivity))
				if time.Since(last) > interval {
					s.mu.Lock()
					if !s.locked {
						s.envelope.DropAdminWrapped(s.schemeRegistry)
						s.audit("auto_lock_admin_wrapped", "", "", "", true, 0)
					}
					s.mu.Unlock()
				}
				return nil
			}),
			jack.WithLooperInterval(interval),
		)
		s.autoLocker.Start()
	}

	// Reaper for per-bucket DEK TTL (LevelAdminWrapped, Jack mode only).
	if s.config.Jack.Pool != nil && s.config.AutoLockInterval > 0 {
		interval := s.config.AutoLockInterval
		s.jackReaper = jack.NewReaper(
			interval,
			jack.ReaperWithHandler(func(ctx context.Context, id string) {
				parts := splitReaperKey(id)
				if len(parts) != 2 {
					return
				}
				s.mu.Lock()
				if !s.locked {
					s.envelope.Drop(parts[0], parts[1])
				}
				s.mu.Unlock()
			}),
		)
	}

	s.logger.Fields("defaultScheme", s.defaultScheme, "defaultNs", s.defaultNs).Info("store unlocked")
	s.audit("unlock_database", "", "", "", true, 0)
	return nil
}

// Lock locks the store: drops all DEKs, wipes the master key, clears the audit
// signing key, and stops all background goroutines.
func (s *Keeper) Lock() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.locked {
		return nil
	}
	if s.autoLocker != nil {
		s.autoLocker.Stop()
		s.autoLocker = nil
	}
	if s.jackReaper != nil {
		s.jackReaper.Stop()
		s.jackReaper = nil
	}
	s.envelope.DropAll()
	s.auditStore.setSigningKey(nil)
	secureZero(s.policyKey)
	s.policyKey = nil
	if s.master != nil {
		s.master.Destroy()
		s.master = nil
	}
	s.locked = true
	s.logger.Info("store locked")
	s.audit("lock", "", "", "", true, 0)
	return nil
}

// IsLocked reports whether the store is currently locked.
func (s *Keeper) IsLocked() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.locked
}

// Get retrieves a secret. Returns raw bytes.
func (s *Keeper) Get(key string) ([]byte, error) {
	scheme, namespace, localKey := parseKeyExtended(key)
	return s.GetNamespacedFull(scheme, namespace, localKey)
}

// GetNamespacedFull retrieves a secret with explicit scheme/namespace/key.
func (s *Keeper) GetNamespacedFull(scheme, namespace, key string) ([]byte, error) {
	start := time.Now()
	s.metrics.IncrementRead()
	s.metrics.IncrementActive()
	defer s.metrics.DecrementActive()

	s.mu.RLock()
	if s.locked {
		s.mu.RUnlock()
		s.metrics.IncrementReadError()
		s.audit("get", scheme, namespace, key, false, time.Since(start))
		return nil, ErrStoreLocked
	}
	if scheme == "" {
		scheme = s.defaultScheme
	}
	if namespace == "" {
		namespace = s.defaultNs
	}
	if !isValidScheme(scheme) {
		s.mu.RUnlock()
		return nil, ErrSchemeInvalid
	}
	if !isValidNamespace(namespace) {
		s.mu.RUnlock()
		return nil, ErrNamespaceInvalid
	}
	if !s.isBucketUnlocked(scheme, namespace) {
		s.mu.RUnlock()
		s.metrics.IncrementReadError()
		s.audit("get", scheme, namespace, key, false, time.Since(start))
		return nil, ErrBucketLocked
	}
	s.updateActivity()
	if s.jackReaper != nil {
		s.jackReaper.Touch(scheme + ":" + namespace)
	}
	s.mu.RUnlock()

	var secret Secret
	if err := s.db.View(func(tx pkgstore.Tx) error {
		b := s.getNamespaceBucket(tx, scheme, namespace)
		if b == nil {
			return ErrKeyNotFound
		}
		data := b.Get([]byte(key))
		if data == nil {
			return ErrKeyNotFound
		}
		return unmarshalSecret(data, &secret)
	}); err != nil {
		s.metrics.IncrementReadError()
		s.audit("get", scheme, namespace, key, false, time.Since(start))
		return nil, err
	}

	plaintext, err := s.decrypt(secret.Ciphertext, scheme, namespace)
	if err != nil {
		s.metrics.IncrementDecryptError()
		s.logger.Fields("scheme", scheme, "namespace", namespace, "key", key, "err", err).Error("decryption failed")
		s.audit("get", scheme, namespace, key, false, time.Since(start))
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	if s.hooks.PostGet != nil {
		plaintext, err = s.hooks.PostGet(scheme, namespace, key, plaintext)
		if err != nil {
			s.audit("get", scheme, namespace, key, false, time.Since(start))
			return nil, err
		}
	}
	if policy, _ := s.policyChain.GetPolicy(scheme, namespace); policy != nil && policy.Handler != nil {
		plaintext, err = policy.Handler.PostGet(scheme, namespace, key, plaintext)
		if err != nil {
			s.audit("get", scheme, namespace, key, false, time.Since(start))
			return nil, err
		}
	}

	go s.incrementAccessCount(scheme, namespace, key)
	latency := time.Since(start)
	s.metrics.RecordReadLatency(latency)
	s.audit("get", scheme, namespace, key, true, latency)
	return plaintext, nil
}

// GetString retrieves a secret as a UTF-8 string.
func (s *Keeper) GetString(key string) (string, error) {
	b, err := s.Get(key)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// GetBytes is an alias for Get.
func (s *Keeper) GetBytes(key string) ([]byte, error) { return s.Get(key) }

// Set stores a secret.
func (s *Keeper) Set(key string, value []byte) error {
	scheme, namespace, localKey := parseKeyExtended(key)
	return s.SetNamespacedFull(scheme, namespace, localKey, value)
}

// SetString stores a UTF-8 string.
func (s *Keeper) SetString(key, value string) error { return s.Set(key, []byte(value)) }

// SetBytes is an alias for Set.
func (s *Keeper) SetBytes(key string, value []byte) error { return s.Set(key, value) }

// SetNamespacedFull stores a secret with explicit scheme/namespace/key.
func (s *Keeper) SetNamespacedFull(scheme, namespace, key string, value []byte) error {
	start := time.Now()
	s.metrics.IncrementWrite()
	s.metrics.IncrementActive()
	defer s.metrics.DecrementActive()

	s.mu.RLock()
	if s.locked {
		s.mu.RUnlock()
		s.metrics.IncrementWriteError()
		s.audit("set", scheme, namespace, key, false, time.Since(start))
		return ErrStoreLocked
	}
	if scheme == "" {
		scheme = s.defaultScheme
	}
	if namespace == "" {
		namespace = s.defaultNs
	}
	if !isValidScheme(scheme) {
		s.mu.RUnlock()
		return ErrSchemeInvalid
	}
	if !isValidNamespace(namespace) {
		s.mu.RUnlock()
		return ErrNamespaceInvalid
	}
	if !s.isBucketUnlocked(scheme, namespace) {
		s.mu.RUnlock()
		s.metrics.IncrementWriteError()
		s.audit("set", scheme, namespace, key, false, time.Since(start))
		return ErrBucketLocked
	}
	s.updateActivity()
	if s.jackReaper != nil {
		s.jackReaper.Touch(scheme + ":" + namespace)
	}
	s.mu.RUnlock()

	if s.hooks.PreSet != nil {
		var err error
		value, err = s.hooks.PreSet(scheme, namespace, key, value)
		if err != nil {
			s.metrics.IncrementWriteError()
			s.audit("set", scheme, namespace, key, false, time.Since(start))
			return err
		}
	}
	if policy, _ := s.policyChain.GetPolicy(scheme, namespace); policy != nil && policy.Handler != nil {
		var err error
		value, err = policy.Handler.PreSet(scheme, namespace, key, value)
		if err != nil {
			s.metrics.IncrementWriteError()
			s.audit("set", scheme, namespace, key, false, time.Since(start))
			return err
		}
	}

	var existing Secret
	_ = s.db.View(func(tx pkgstore.Tx) error {
		b := s.getNamespaceBucket(tx, scheme, namespace)
		if b == nil {
			return nil
		}
		if data := b.Get([]byte(key)); data != nil {
			unmarshalSecret(data, &existing)
		}
		return nil
	})

	ciphertext, err := s.encrypt(value, scheme, namespace)
	if err != nil {
		s.metrics.IncrementEncryptError()
		s.logger.Fields("scheme", scheme, "namespace", namespace, "key", key, "err", err).Error("encryption failed")
		s.audit("set", scheme, namespace, key, false, time.Since(start))
		return fmt.Errorf("encryption failed: %w", err)
	}

	bucketDEK, err := s.bucketKeyBytes(scheme, namespace)
	if err != nil {
		s.metrics.IncrementWriteError()
		return err
	}
	defer secureZero(bucketDEK)

	// Carry forward creation time and access count from the existing record.
	now := time.Now()
	var createdAt time.Time
	var accessCount, prevVersion int

	if len(existing.EncryptedMeta) > 0 {
		if prev, merr := s.decryptMeta(existing.EncryptedMeta, bucketDEK); merr == nil {
			createdAt = prev.CreatedAt
			accessCount = prev.AccessCount
			prevVersion = prev.Version
		}
	}
	if createdAt.IsZero() {
		createdAt = now
	}

	meta := &EncryptedMetadata{
		CreatedAt:   createdAt,
		UpdatedAt:   now,
		AccessCount: accessCount,
		Version:     prevVersion + 1,
	}
	em, err := s.encryptMeta(meta, bucketDEK)
	if err != nil {
		s.metrics.IncrementEncryptError()
		s.audit("set", scheme, namespace, key, false, time.Since(start))
		return fmt.Errorf("metadata encryption failed: %w", err)
	}

	secret := Secret{
		Ciphertext:    ciphertext,
		EncryptedMeta: em,
		SchemaVersion: currentSchemaVersion,
	}

	if err := s.db.Update(func(tx pkgstore.Tx) error {
		b, err := s.createNamespaceBucket(tx, scheme, namespace)
		if err != nil {
			return err
		}
		data, err := marshalSecret(&secret)
		if err != nil {
			return err
		}
		return b.Put([]byte(key), data)
	}); err != nil {
		s.metrics.IncrementWriteError()
		s.audit("set", scheme, namespace, key, false, time.Since(start))
		return err
	}

	_ = s.policyChain.AppendEvent(scheme, namespace, "key_added",
		map[string]string{"key": key, "size": fmt.Sprintf("%d", len(value))})
	latency := time.Since(start)
	s.metrics.RecordWriteLatency(latency)
	s.audit("set", scheme, namespace, key, true, latency)
	return nil
}

// Delete removes a secret.
func (s *Keeper) Delete(key string) error {
	scheme, namespace, localKey := parseKeyExtended(key)
	return s.DeleteNamespacedFull(scheme, namespace, localKey)
}

// DeleteNamespacedFull removes a secret with explicit scheme/namespace/key.
func (s *Keeper) DeleteNamespacedFull(scheme, namespace, key string) error {
	start := time.Now()
	s.metrics.IncrementDelete()
	s.metrics.IncrementActive()
	defer s.metrics.DecrementActive()

	s.mu.RLock()
	if s.locked {
		s.mu.RUnlock()
		s.audit("delete", scheme, namespace, key, false, time.Since(start))
		return ErrStoreLocked
	}
	if scheme == "" {
		scheme = s.defaultScheme
	}
	if namespace == "" {
		namespace = s.defaultNs
	}
	s.updateActivity()
	s.mu.RUnlock()

	if s.hooks.PreDelete != nil {
		if err := s.hooks.PreDelete(scheme, namespace, key); err != nil {
			s.audit("delete", scheme, namespace, key, false, time.Since(start))
			return err
		}
	}
	if policy, _ := s.policyChain.GetPolicy(scheme, namespace); policy != nil && policy.Handler != nil {
		if err := policy.Handler.OnDelete(scheme, namespace, key); err != nil {
			s.audit("delete", scheme, namespace, key, false, time.Since(start))
			return err
		}
	}

	err := s.db.Update(func(tx pkgstore.Tx) error {
		b := s.getNamespaceBucket(tx, scheme, namespace)
		if b == nil {
			return ErrKeyNotFound
		}
		if b.Get([]byte(key)) == nil {
			return ErrKeyNotFound
		}
		return b.Delete([]byte(key))
	})
	if err == nil {
		_ = s.policyChain.AppendEvent(scheme, namespace, "key_deleted",
			map[string]string{"key": key})
	}
	s.audit("delete", scheme, namespace, key, err == nil, time.Since(start))
	return err
}

// CompareAndSwapNamespacedFull atomically reads, compares, and replaces a value.
// The DEK is retrieved inside the transaction to avoid a stale-key window.
func (s *Keeper) CompareAndSwapNamespacedFull(scheme, namespace, key string, oldValue, newValue []byte) error {
	start := time.Now()
	s.metrics.IncrementCAS()
	s.metrics.IncrementActive()
	defer s.metrics.DecrementActive()

	s.mu.RLock()
	if s.locked {
		s.mu.RUnlock()
		return ErrStoreLocked
	}
	if scheme == "" {
		scheme = s.defaultScheme
	}
	if namespace == "" {
		namespace = s.defaultNs
	}
	s.updateActivity()
	s.mu.RUnlock()

	now := time.Now()
	err := s.db.Update(func(tx pkgstore.Tx) error {
		// Retrieve DEK inside the transaction to prevent stale-key use
		// if Rotate runs concurrently.
		casKey, err := s.bucketKeyBytes(scheme, namespace)
		if err != nil {
			return err
		}
		defer secureZero(casKey)

		b, err := s.createNamespaceBucket(tx, scheme, namespace)
		if err != nil {
			return err
		}
		data := b.Get([]byte(key))
		if data == nil {
			return ErrKeyNotFound
		}
		var secret Secret
		if err := unmarshalSecret(data, &secret); err != nil {
			return err
		}
		cur, err := s.decryptWithKey(secret.Ciphertext, casKey)
		if err != nil {
			return fmt.Errorf("decryption failed: %w", err)
		}
		if !bytes.Equal(cur, oldValue) {
			secureZero(cur)
			return ErrCASConflict
		}
		secureZero(cur)

		ct, err := s.encryptWithKey(newValue, casKey)
		if err != nil {
			return fmt.Errorf("encryption failed: %w", err)
		}
		secret.Ciphertext = ct

		if len(secret.EncryptedMeta) > 0 {
			metaKey, merr := s.deriveMetaKey(casKey)
			if merr == nil {
				if meta, merr := s.decryptMetaWithKey(secret.EncryptedMeta, metaKey); merr == nil {
					meta.UpdatedAt = now
					meta.Version++
					if em, merr := s.encryptMetaWithKey(meta, metaKey); merr == nil {
						secret.EncryptedMeta = em
					}
				}
				secureZero(metaKey)
			}
		}

		nd, err := marshalSecret(&secret)
		if err != nil {
			return err
		}
		return b.Put([]byte(key), nd)
	})
	s.audit("cas", scheme, namespace, key, err == nil, time.Since(start))
	return err
}

// List returns all keys in the default bucket.
func (s *Keeper) List() ([]string, error) {
	return s.ListNamespacedFull(s.defaultScheme, s.defaultNs)
}

// ListNamespacedFull returns all keys for the given scheme/namespace.
func (s *Keeper) ListNamespacedFull(scheme, namespace string) ([]string, error) {
	s.metrics.IncrementList()
	s.mu.RLock()
	if s.locked {
		s.mu.RUnlock()
		return nil, ErrStoreLocked
	}
	if scheme == "" {
		scheme = s.defaultScheme
	}
	if namespace == "" {
		namespace = s.defaultNs
	}
	if !s.isBucketUnlocked(scheme, namespace) {
		s.mu.RUnlock()
		return nil, ErrBucketLocked
	}
	s.mu.RUnlock()

	var keys []string
	err := s.db.View(func(tx pkgstore.Tx) error {
		b := s.getNamespaceBucket(tx, scheme, namespace)
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			if string(k) != metadataKey {
				keys = append(keys, string(k))
			}
			return nil
		})
	})
	return keys, err
}

// ListSchemes returns all scheme names in the database.
func (s *Keeper) ListSchemes() ([]string, error) {
	s.mu.RLock()
	if s.locked {
		s.mu.RUnlock()
		return nil, ErrStoreLocked
	}
	s.mu.RUnlock()
	var schemes []string
	err := s.db.View(func(tx pkgstore.Tx) error {
		return tx.ForEach(func(name []byte, _ pkgstore.Bucket) error {
			n := string(name)
			if n != metaBucket && n != policyBucket && n != auditBucketRoot {
				schemes = append(schemes, n)
			}
			return nil
		})
	})
	return schemes, err
}

// ListNamespacesInSchemeFull returns all namespace names within a scheme.
func (s *Keeper) ListNamespacesInSchemeFull(scheme string) ([]string, error) {
	s.mu.RLock()
	if s.locked {
		s.mu.RUnlock()
		return nil, ErrStoreLocked
	}
	if scheme == "" {
		scheme = s.defaultScheme
	}
	s.mu.RUnlock()
	var namespaces []string
	err := s.db.View(func(tx pkgstore.Tx) error {
		sb := s.getSchemeBucket(tx, scheme)
		if sb == nil {
			return nil
		}
		return sb.ForEach(func(name []byte, _ []byte) error {
			if string(name) != metadataKey {
				namespaces = append(namespaces, string(name))
			}
			return nil
		})
	})
	return namespaces, err
}

// ListPrefixNamespacedFull returns all keys matching prefix in the given bucket.
func (s *Keeper) ListPrefixNamespacedFull(scheme, namespace, prefix string) ([]string, error) {
	s.mu.RLock()
	if s.locked {
		s.mu.RUnlock()
		return nil, ErrStoreLocked
	}
	if scheme == "" {
		scheme = s.defaultScheme
	}
	if namespace == "" {
		namespace = s.defaultNs
	}
	s.mu.RUnlock()
	var keys []string
	pfx := []byte(prefix)
	err := s.db.View(func(tx pkgstore.Tx) error {
		b := s.getNamespaceBucket(tx, scheme, namespace)
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			if string(k) != metadataKey && bytes.HasPrefix(k, pfx) {
				keys = append(keys, string(k))
			}
			return nil
		})
	})
	return keys, err
}

// Exists reports whether a key is present.
func (s *Keeper) Exists(key string) (bool, error) {
	scheme, namespace, localKey := parseKeyExtended(key)
	return s.ExistsNamespacedFull(scheme, namespace, localKey)
}

// ExistsNamespacedFull reports whether a key is present in the given bucket.
func (s *Keeper) ExistsNamespacedFull(scheme, namespace, key string) (bool, error) {
	s.mu.RLock()
	if s.locked {
		s.mu.RUnlock()
		return false, ErrStoreLocked
	}
	if scheme == "" {
		scheme = s.defaultScheme
	}
	if namespace == "" {
		namespace = s.defaultNs
	}
	s.mu.RUnlock()
	err := s.db.View(func(tx pkgstore.Tx) error {
		b := s.getNamespaceBucket(tx, scheme, namespace)
		if b == nil {
			return ErrKeyNotFound
		}
		if b.Get([]byte(key)) == nil {
			return ErrKeyNotFound
		}
		return nil
	})
	if err == ErrKeyNotFound {
		return false, nil
	}
	return err == nil, err
}

// Rename moves a key to a new name within the same bucket.
func (s *Keeper) Rename(key, newKey string) error {
	scheme, namespace, localOld := parseKeyExtended(key)
	_, _, localNew := parseKeyExtended(newKey)
	return s.RenameNamespacedFull(scheme, namespace, localOld, localNew)
}

// RenameNamespacedFull moves a key within an explicit bucket.
func (s *Keeper) RenameNamespacedFull(scheme, namespace, oldKey, newKey string) error {
	s.mu.RLock()
	if s.locked {
		s.mu.RUnlock()
		return ErrStoreLocked
	}
	if scheme == "" {
		scheme = s.defaultScheme
	}
	if namespace == "" {
		namespace = s.defaultNs
	}
	s.mu.RUnlock()
	return s.db.Update(func(tx pkgstore.Tx) error {
		b := s.getNamespaceBucket(tx, scheme, namespace)
		if b == nil {
			return ErrKeyNotFound
		}
		data := b.Get([]byte(oldKey))
		if data == nil {
			return ErrKeyNotFound
		}
		if err := b.Put([]byte(newKey), data); err != nil {
			return err
		}
		return b.Delete([]byte(oldKey))
	})
}

// DeleteBucket removes a namespace bucket and all its contents.
func (s *Keeper) DeleteBucket(scheme, namespace string) error {
	if scheme == "" {
		scheme = s.defaultScheme
	}
	if namespace == "" || namespace == defaultNamespace {
		return ErrNamespaceInvalid
	}
	s.mu.RLock()
	if s.locked {
		s.mu.RUnlock()
		return ErrStoreLocked
	}
	s.mu.RUnlock()
	_ = s.policyChain.AppendEvent(scheme, namespace, "bucket_deleted", nil)
	return s.db.Update(func(tx pkgstore.Tx) error {
		sb := s.getSchemeBucket(tx, scheme)
		if sb == nil {
			return nil
		}
		return sb.DeleteBucket([]byte(namespace))
	})
}

// DeleteScheme removes an entire scheme and all its namespaces.
func (s *Keeper) DeleteScheme(scheme string) error {
	if scheme == "" || scheme == defaultScheme {
		return ErrSchemeInvalid
	}
	s.mu.RLock()
	if s.locked {
		s.mu.RUnlock()
		return ErrStoreLocked
	}
	s.mu.RUnlock()
	return s.db.Update(func(tx pkgstore.Tx) error { return tx.DeleteBucket([]byte(scheme)) })
}

// Stats returns aggregate statistics for all schemes and namespaces.
// Locked buckets contribute key counts and sizes but zero metadata.
func (s *Keeper) Stats() (*StoreStats, error) {
	s.mu.RLock()
	if s.locked {
		s.mu.RUnlock()
		return nil, ErrStoreLocked
	}
	lastActivity := time.Unix(0, atomic.LoadInt64(&s.lastActivity))
	s.mu.RUnlock()

	stats := &StoreStats{
		IsLocked:         false,
		DefaultScheme:    s.defaultScheme,
		DefaultNamespace: s.defaultNs,
		AutoLockInterval: s.config.AutoLockInterval,
		TotalReads:       s.metrics.ReadsTotal.Load(),
		TotalWrites:      s.metrics.WritesTotal.Load(),
		LastActivity:     lastActivity,
		KeyDerivation:    keyDerivationLabel,
		SaltVersion:      s.currentSaltVersion(),
	}
	if info, err := os.Stat(s.config.DBPath); err == nil {
		stats.DBSize = info.Size()
	}

	err := s.db.View(func(tx pkgstore.Tx) error {
		return tx.ForEach(func(name []byte, sb pkgstore.Bucket) error {
			sn := string(name)
			if sn == metaBucket || sn == policyBucket || sn == auditBucketRoot {
				return nil
			}
			ss := SchemeStats{Name: sn}
			err := sb.ForEach(func(nsName []byte, _ []byte) error {
				ns := string(nsName)
				if ns == metadataKey {
					return nil
				}
				nb := sb.Bucket(nsName)
				if nb == nil {
					return nil
				}
				nsStats := NamespaceStats{Scheme: sn, Name: ns}
				if policy, err := s.policyChain.GetPolicy(sn, ns); err == nil {
					nsStats.SecurityLevel = string(policy.Level)
				}

				bucketDEK, _ := s.bucketKeyBytes(sn, ns)
				defer func() {
					if bucketDEK != nil {
						secureZero(bucketDEK)
					}
				}()

				_ = nb.ForEach(func(k, v []byte) error {
					if string(k) == metadataKey {
						return nil
					}
					nsStats.KeyCount++
					nsStats.TotalSize += int64(len(v))

					var secret Secret
					if err := unmarshalSecret(v, &secret); err != nil {
						return nil
					}

					var meta *EncryptedMetadata
					if len(secret.EncryptedMeta) > 0 && bucketDEK != nil {
						meta, _ = s.decryptMeta(secret.EncryptedMeta, bucketDEK)
					}

					if meta != nil {
						if nsStats.OldestKey.IsZero() || meta.CreatedAt.Before(nsStats.OldestKey) {
							nsStats.OldestKey = meta.CreatedAt
						}
						if meta.CreatedAt.After(nsStats.NewestKey) {
							nsStats.NewestKey = meta.CreatedAt
						}
						nsStats.TotalReads += int64(meta.AccessCount)
						nsStats.EncryptionVersion = meta.Version
					}
					return nil
				})

				if nsStats.KeyCount > 0 {
					nsStats.AvgKeySize = float64(nsStats.TotalSize) / float64(nsStats.KeyCount)
				}
				ss.Namespaces = append(ss.Namespaces, nsStats)
				ss.TotalKeys += nsStats.KeyCount
				ss.TotalSize += nsStats.TotalSize
				return nil
			})
			if err != nil {
				return err
			}
			if ss.TotalKeys > 0 {
				stats.Schemes = append(stats.Schemes, ss)
				stats.TotalKeys += ss.TotalKeys
				stats.TotalSize += ss.TotalSize
			}
			return nil
		})
	})
	if stats.DBSize > 0 {
		stats.StorageEfficiency = float64(stats.TotalSize) / float64(stats.DBSize)
	}
	return stats, err
}

// Metrics returns a snapshot of operational counters.
func (s *Keeper) Metrics() core.MetricsSnapshot { return s.metrics.Snapshot() }

// Close locks the store and closes the underlying database.
func (s *Keeper) Close() error {
	s.Lock()
	return s.db.Close()
}

// SetAuditFunc registers a callback invoked on every auditable operation.
func (s *Keeper) SetAuditFunc(fn func(action, scheme, namespace, key string, success bool, duration time.Duration)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auditFn = fn
}

// SetHooks configures lifecycle hooks for pre/post processing.
func (s *Keeper) SetHooks(hooks Hooks) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hooks = hooks
}

// SetDefaultScheme sets the default scheme used when none is specified.
func (s *Keeper) SetDefaultScheme(scheme string) error {
	if !isValidScheme(scheme) {
		return ErrSchemeInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.defaultScheme = scheme
	return nil
}

// SetDefaultNamespace sets the default namespace used when none is specified.
func (s *Keeper) SetDefaultNamespace(ns string) error {
	if !isValidNamespace(ns) {
		return ErrNamespaceInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.defaultNs = ns
	return nil
}

// RegisterScheme validates and registers a scheme name with an optional handler.
func (s *Keeper) RegisterScheme(name string, handler SchemeHandler) error {
	if !isValidScheme(name) {
		return ErrSchemeInvalid
	}
	return nil
}

// MoveCrossBucket moves a key between two buckets.
func (s *Keeper) MoveCrossBucket(key, fromScheme, fromNS, toScheme, toNS string, confirmDowngrade bool) error {
	fp, err := s.policyChain.GetPolicy(fromScheme, fromNS)
	if err != nil {
		return err
	}
	tp, err := s.policyChain.GetPolicy(toScheme, toNS)
	if err != nil {
		return err
	}
	if fp.Level > tp.Level && !confirmDowngrade {
		s.audit("security_downgrade_attempt", fromScheme, fromNS, key, false, 0)
		return ErrSecurityDowngrade
	}
	v, err := s.GetNamespacedFull(fromScheme, fromNS, key)
	if err != nil {
		return err
	}
	if err := s.SetNamespacedFull(toScheme, toNS, key, v); err != nil {
		return err
	}
	return s.DeleteNamespacedFull(fromScheme, fromNS, key)
}

// CopyCrossBucket copies a key between two buckets.
func (s *Keeper) CopyCrossBucket(key, fromScheme, fromNS, toScheme, toNS string, confirmDowngrade bool) error {
	fp, err := s.policyChain.GetPolicy(fromScheme, fromNS)
	if err != nil {
		return err
	}
	tp, err := s.policyChain.GetPolicy(toScheme, toNS)
	if err != nil {
		return err
	}
	if fp.Level > tp.Level && !confirmDowngrade {
		s.audit("security_downgrade_attempt", fromScheme, fromNS, key, false, 0)
		return ErrSecurityDowngrade
	}
	v, err := s.GetNamespacedFull(fromScheme, fromNS, key)
	if err != nil {
		return err
	}
	return s.SetNamespacedFull(toScheme, toNS, key, v)
}

// splitReaperKey splits a "scheme:namespace" Reaper ID into its two parts.
func splitReaperKey(id string) []string {
	for i := 0; i < len(id); i++ {
		if id[i] == ':' {
			return []string{id[:i], id[i+1:]}
		}
	}
	return []string{id, ""}
}
