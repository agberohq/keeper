package keeper

import (
	"context"
	"time"

	"github.com/agberohq/keeper/pkg/crypt"
	"github.com/olekukonko/errors"
	"github.com/olekukonko/ll"
)

// Sentinel errors.
var (
	ErrStoreLocked        = errors.New("secret store is locked")
	ErrInvalidPassphrase  = errors.New("invalid passphrase or admin credential")
	ErrKeyNotFound        = errors.New("secret key not found")
	ErrNamespaceNotFound  = errors.New("namespace not found")
	ErrNamespaceEmpty     = errors.New("namespace cannot be empty")
	ErrNamespaceInvalid   = errors.New("invalid namespace name")
	ErrSchemeInvalid      = errors.New("invalid scheme name")
	ErrAlreadyUnlocked    = errors.New("store already unlocked")
	ErrInvalidConfig      = errors.New("invalid store configuration")
	ErrCASConflict        = errors.New("compare-and-swap conflict: value changed")
	ErrMigrationFailed    = errors.New("database migration failed")
	ErrMasterRequired     = errors.New("master key required")
	ErrPolicyImmutable    = errors.New("bucket policy is immutable after creation")
	ErrChainBroken        = errors.New("audit chain integrity check failed")
	ErrPolicyNotFound     = errors.New("bucket policy not found")
	ErrBucketLocked       = errors.New("bucket is locked — call UnlockBucket first")
	ErrSecurityDowngrade  = errors.New("security downgrade requires explicit confirmation")
	ErrRotationIncomplete = errors.New("incomplete key rotation detected: call Rotate again with the new passphrase")
	ErrAdminNotFound      = errors.New("admin ID not found in bucket policy")
	ErrPolicySignature    = errors.New("policy signature verification failed")
	ErrMetadataDecrypt    = errors.New("metadata decryption failed")
	ErrMigrationActive    = errors.New("background migration in progress")
	// ErrAuthFailed is the single error returned for any authentication failure
	// in public-facing methods (UnlockBucket, UnlockDatabase). It deliberately
	// does not distinguish between "wrong password" and "unknown admin ID" to
	// prevent admin ID enumeration attacks (CVSS 5.3 / CWE-204).
	ErrAuthFailed = errors.New("authentication failed")
)

// SecurityLevel defines the key-management model for a bucket.
type SecurityLevel string

// SchemeHandler allows custom pre/post processing per scheme.
type SchemeHandler interface {
	PreSet(scheme, namespace, key string, value []byte) ([]byte, error)
	PostGet(scheme, namespace, key string, value []byte) ([]byte, error)
	OnDelete(scheme, namespace, key string) error
}

// Hooks injects custom logic at key lifecycle points.
type Hooks struct {
	PreSet    func(scheme, namespace, key string, value []byte) ([]byte, error)
	PostGet   func(scheme, namespace, key string, value []byte) ([]byte, error)
	PreDelete func(scheme, namespace, key string) error
	OnAudit   func(action, scheme, namespace, key string, success bool, duration time.Duration)
}

// JackPool is the subset of jack.Pool that keeper uses.
// Agbero passes a *jack.Pool which satisfies this interface.
// Keeper never calls Shutdown — the pool lifecycle is owned by Agbero.
type JackPool interface {
	Do(fn func())
	DoCtx(ctx context.Context, fn func(context.Context))
	IsClosed() bool
}

// JackShutdown is the subset of jack.Shutdown that keeper uses.
type JackShutdown interface {
	Register(fn any) error
	Done() <-chan struct{}
}

// JackConfig carries optional Jack integration handles.
// Pass via WithJack when constructing a Keeper from an Agbero process.
// Both fields are optional; nil means keeper manages its own equivalent.
type JackConfig struct {
	Pool     JackPool
	Shutdown JackShutdown
}

// Config holds all configuration for a Keeper instance.
type Config struct {
	DBPath           string
	KeyLen           int
	AutoLockInterval time.Duration
	EnableAudit      bool
	DefaultScheme    string
	DefaultNamespace string
	Logger           *ll.Logger
	Jack             JackConfig

	KDF       crypt.KDF
	NewCipher func(key []byte) (crypt.Cipher, error)

	Argon2Time              uint32
	Argon2Memory            uint32
	Argon2Parallelism       uint8
	VerifyArgon2Time        uint32
	VerifyArgon2Memory      uint32
	VerifyArgon2Parallelism uint8
}

// Secret is the on-disk record for a single key.
//
// SchemaVersion distinguishes legacy records (V0, plaintext metadata fields)
// from current records (V1, metadata encrypted in EncryptedMeta).
// The dual-format read path in Get is removed once all records are migrated.
type Secret struct {
	Ciphertext    []byte `json:"ct"`
	EncryptedMeta []byte `json:"em,omitempty"`
	SchemaVersion int    `json:"sv"`

	// V0 plaintext fields — present only in legacy records (SchemaVersion == 0).
	// Do not write these on new records; use EncryptedMeta instead.
	CreatedAt   time.Time `json:"created_at,omitempty"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"`
	AccessCount int       `json:"access_count,omitempty"`
	LastAccess  time.Time `json:"last_access,omitempty"`
	Version     int       `json:"version,omitempty"`
}

// EncryptedMetadata holds per-secret metadata encrypted alongside the ciphertext.
// Encrypted with a key derived from the bucket's DEK so it is inaccessible
// without both the master passphrase and (for LevelAdminWrapped) the admin password.
type EncryptedMetadata struct {
	CreatedAt   time.Time `json:"ca"`
	UpdatedAt   time.Time `json:"ua"`
	AccessCount int       `json:"ac"`
	LastAccess  time.Time `json:"la,omitempty"`
	Version     int       `json:"v"`
}

// SaltEntry holds a versioned KDF salt. Defined now for the salt-rotation
// milestone; not yet written to the database.
type SaltEntry struct {
	Version   int       `json:"v"`
	Salt      []byte    `json:"s"`
	CreatedAt time.Time `json:"ca"`
	KeyLen    int       `json:"kl"`
}

// RotationWAL tracks the state of an in-progress key rotation.
// Defined now for the crash-recovery milestone; not yet used in rotation.
type RotationWAL struct {
	Status      string    `json:"status"`
	OldKeyHash  []byte    `json:"old_hash"`
	NewKeyHash  []byte    `json:"new_hash"`
	StartedAt   time.Time `json:"started"`
	ShadowKeys  []string  `json:"shadows"`
	SaltVersion int       `json:"salt_ver"`
}

// NamespaceStats holds aggregate statistics for one namespace.
type NamespaceStats struct {
	Scheme            string    `json:"scheme"`
	Name              string    `json:"name"`
	KeyCount          int64     `json:"key_count"`
	TotalSize         int64     `json:"total_size"`
	AvgKeySize        float64   `json:"avg_key_size"`
	OldestKey         time.Time `json:"oldest_key"`
	NewestKey         time.Time `json:"newest_key"`
	TotalReads        int64     `json:"total_reads"`
	TotalWrites       int64     `json:"total_writes"`
	EncryptionVersion int       `json:"encryption_version"`
	SecurityLevel     string    `json:"security_level"`
}

// SchemeStats holds aggregate statistics for one scheme.
type SchemeStats struct {
	Name       string           `json:"name"`
	Namespaces []NamespaceStats `json:"namespaces"`
	TotalKeys  int64            `json:"total_keys"`
	TotalSize  int64            `json:"total_size"`
}

// StoreStats is returned by Keeper.Stats.
type StoreStats struct {
	Schemes           []SchemeStats `json:"schemes"`
	TotalKeys         int64         `json:"total_keys"`
	TotalSize         int64         `json:"total_size"`
	IsLocked          bool          `json:"is_locked"`
	DefaultScheme     string        `json:"default_scheme"`
	DefaultNamespace  string        `json:"default_namespace"`
	AutoLockInterval  time.Duration `json:"auto_lock_interval"`
	TotalReads        int64         `json:"total_reads"`
	TotalWrites       int64         `json:"total_writes"`
	LastActivity      time.Time     `json:"last_activity"`
	DBSize            int64         `json:"db_size_bytes"`
	StorageEfficiency float64       `json:"storage_efficiency"`
	KeyDerivation     string        `json:"key_derivation"`
}
