package keeper

import (
	"time"

	"github.com/agberohq/keeper/pkg/crypt"
	"github.com/olekukonko/errors"
	"github.com/olekukonko/ll"
)

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
)

const (
	defaultScheme      = "default"
	defaultNamespace   = "__default__"
	metaBucket         = "metadata"
	policyBucket       = "__policies__"
	namespaceSeparator = "/"
	schemeSeparator    = "://"
	auditBucketRoot    = "__audit__"
	auditSnapshotEvery = 1000

	currentSaltVersion = 1
	minArgon2Memory    = 64 * 1024
	argon2TimeCost     = 3
	argon2Parallelism  = 4
)

type SecurityLevel string

const (
	LevelPasswordOnly SecurityLevel = "password_only"
	LevelAdminWrapped SecurityLevel = "admin_wrapped"
	LevelHSM          SecurityLevel = "hsm"
)

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

// Config holds all configuration for a Keeper instance.
type Config struct {
	DBPath                  string
	KeyLen                  int
	AutoLockInterval        time.Duration
	EnableAudit             bool
	DefaultScheme           string
	DefaultNamespace        string
	Logger                  *ll.Logger
	KDF                     crypt.KDF
	NewCipher               func(key []byte) (crypt.Cipher, error)
	Argon2Time              uint32
	Argon2Memory            uint32
	Argon2Parallelism       uint8
	VerifyArgon2Time        uint32
	VerifyArgon2Memory      uint32
	VerifyArgon2Parallelism uint8
}

// Secret is the encrypted record stored for each key.
type Secret struct {
	Ciphertext    []byte    `json:"ct"`
	EncryptedMeta []byte    `json:"em,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	AccessCount   int       `json:"access_count"`
	LastAccess    time.Time `json:"last_access,omitempty"`
	Version       int       `json:"version"`
}

type EncryptedMetadata struct {
	CreatedAt   time.Time `json:"ca"`
	UpdatedAt   time.Time `json:"ua"`
	AccessCount int       `json:"ac"`
	LastAccess  time.Time `json:"la,omitempty"`
}

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

type SchemeStats struct {
	Name       string           `json:"name"`
	Namespaces []NamespaceStats `json:"namespaces"`
	TotalKeys  int64            `json:"total_keys"`
	TotalSize  int64            `json:"total_size"`
}

// SaltEntry represents a versioned salt for passphrase derivation.
type SaltEntry struct {
	Version   int       `json:"v"`
	Salt      []byte    `json:"s"`
	CreatedAt time.Time `json:"ca"`
	KeyLen    int       `json:"kl"`
}

// RotationWAL tracks the state of key rotation for crash recovery.
type RotationWAL struct {
	Status      string    `json:"status"`
	OldKeyHash  []byte    `json:"old_hash"`
	NewKeyHash  []byte    `json:"new_hash"`
	StartedAt   time.Time `json:"started"`
	ShadowKeys  []string  `json:"shadows"`
	SaltVersion int       `json:"salt_ver"`
}

// EncryptedMetadata contains encrypted secret metadata.
type SignedPolicy struct {
	Policy    []byte `json:"policy"`
	Signature []byte `json:"sig"`
}
