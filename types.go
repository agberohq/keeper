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

	// ErrAuthFailed is returned for any authentication failure in UnlockBucket.
	// It deliberately does not distinguish between an unknown admin ID and a
	// wrong password to prevent admin ID enumeration (CWE-204 / CVSS 5.3).
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
// Keeper never calls Shutdown — the pool lifecycle is owned by the caller.
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

// Secret is the on-disk record for a single key, encoded with msgpack.
// SchemaVersion is always currentSchemaVersion.
type Secret struct {
	Ciphertext    []byte `msgpack:"ct"`
	EncryptedMeta []byte `msgpack:"em,omitempty"`
	SchemaVersion int    `msgpack:"sv"`
}

// EncryptedMetadata holds per-secret metadata encrypted with a key derived
// from the bucket DEK. Inaccessible without the bucket key.
type EncryptedMetadata struct {
	CreatedAt   time.Time `msgpack:"ca"`
	UpdatedAt   time.Time `msgpack:"ua"`
	AccessCount int       `msgpack:"ac"`
	LastAccess  time.Time `msgpack:"la,omitempty"`
	Version     int       `msgpack:"v"`
}

// SaltEntry records one generation of the KDF salt.
type SaltEntry struct {
	Version   int       `json:"v"`
	Salt      []byte    `json:"s"`
	CreatedAt time.Time `json:"ca"`
}

// SaltStore is the versioned salt container stored under metaSaltKey.
// CurrentVersion indexes into Entries. Old entries are retained as an
// audit trail and for crash-recovery during salt rotation.
type SaltStore struct {
	CurrentVersion int         `json:"current"`
	Entries        []SaltEntry `json:"entries"`
}

// RotationWAL tracks the state of an in-progress key rotation.
// Written atomically before the first record is re-encrypted.
// On crash, UnlockDatabase reads this record and resumes automatically.
//
// WrappedOldKey is the pre-rotation master key encrypted with the new master
// key using XChaCha20-Poly1305. It is the only safe way to carry the old
// key across a crash boundary without storing it in plaintext.
type RotationWAL struct {
	Status        string    `json:"status"`
	OldKeyHash    []byte    `json:"old_hash"`
	NewKeyHash    []byte    `json:"new_hash"`
	StartedAt     time.Time `json:"started"`
	LastKey       string    `json:"last_key"`
	SaltVersion   int       `json:"salt_ver"`
	WrappedOldKey []byte    `json:"wrapped_old_key"`
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
	SaltVersion       int           `json:"salt_version"`
}

// currentSchemaVersion is the schema version written by all new records.
const currentSchemaVersion = 1
