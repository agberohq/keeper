package keeper

import "time"

// DB bucket names.
const (
	defaultScheme    = "default"
	defaultNamespace = "__default__"
	metaBucket       = "metadata"
	policyBucket     = "__policies__"
	auditBucketRoot  = "__audit__"
)

// Separators used when parsing and constructing key paths.
const (
	namespaceSeparator = "/"
	schemeSeparator    = "://"
)

// metadataKey is the reserved sentinel key inside namespace buckets.
// ForEach iterations skip this key.
const metadataKey = "__metadata__"

// Keys stored inside the metadata bucket.
const (
	metaSaltKey         = "salt" // JSON-encoded SaltStore
	metaVerifyKey       = "verify"
	rotationWALKey      = "__rotation_wal__"
	walStatusInProgress = "in_progress"
	walStatusComplete   = "complete"
)

// policyHashSuffix stores the unauthenticated SHA-256 integrity hash written
// before the store is unlocked (no HMAC key is available yet).
const policyHashSuffix = ":hash"

// policyHMACSuffix stores the authenticated HMAC-SHA256 tag written after
// the store is unlocked. loadPolicy verifies this tag when present.
const policyHMACSuffix = ":hmac"

// HKDF info strings used as domain-separation labels.
// Changing any of these values is a breaking change to the on-disk format.
const (
	hkdfInfoKEK        = "keeper-kek-v1"
	hkdfInfoAuditKey   = "keeper-audit-hmac-v1"
	hkdfInfoMetaKey    = "keeper-metadata-v1"
	hkdfInfoPolicyHMAC = "keeper-policy-hmac-v1"
	hkdfInfoBucketDEK  = "keeper-bucket-dek-v1"
	hkdfInfoPolicyEnc  = "keeper-policy-enc-v1"
	hkdfInfoAuditEnc   = "keeper-audit-enc-v1"
)

// Bucket DEK migration keys stored in the metadata bucket.
const (
	metaBucketDEKDoneKey   = "meta:bucket_dek_v1_done"
	metaBucketDEKWALPrefix = "meta:bucket_dek_v1_wal:"
)

// Default migration tuning values.
const (
	defaultMigrationBatchSize = 500
	defaultMigrationInterval  = 100 * time.Millisecond
)

// argon2VerificationSalt is the fixed domain-separation salt passed to
// argon2.IDKey when producing or verifying the master-key confirmation hash.
const argon2VerificationSalt = "verification"

// Argon2id default parameters for master-key derivation.
const (
	defaultArgon2TimeCost   uint32 = 3
	defaultArgon2Memory     uint32 = 64 * 1024 // 64 MiB — meets OWASP minimum
	defaultArgon2Threads    uint8  = 4
	defaultVerifyArgon2Time uint32 = 1
)

// Cryptographic key and output lengths in bytes.
const (
	masterKeyLen = 32
	dekSaltLen   = 32
	argon2OutLen = 32
)

// Audit chain constants.
const (
	auditSnapshotEvery    = 1000
	auditEventKeyRotation = "key_rotation_checkpoint"
)

// SecurityLevel values for BucketSecurityPolicy.
const (
	LevelPasswordOnly SecurityLevel = "password_only"
	LevelAdminWrapped SecurityLevel = "admin_wrapped"
	LevelHSM          SecurityLevel = "hsm"
	LevelRemote       SecurityLevel = "remote"
)

// hsmWrappedDEKKey is the map key used to store the HSM/Remote wrapped DEK
// inside BucketSecurityPolicy.WrappedDEKs.
const hsmWrappedDEKKey = "hsm"

// keyDerivationLabel is the human-readable algorithm identifier stored in StoreStats.
const keyDerivationLabel = "argon2id+xchacha20poly1305"

// Audit prune defaults. Stored as seconds so they can be declared as untyped
// integer constants and converted to time.Duration at the call site.
const (
	defaultAuditPruneInterval  = 24 * 60 * 60 // seconds — 24 h
	defaultAuditPruneKeepLastN = 10_000
	defaultAuditPruneOlderThan = 90 * 24 * 60 * 60 // seconds — 90 days
)

// defaultDBLatencyThreshold is the maximum acceptable single-key read latency
// before the DB health patient reports degradation (200 ms in nanoseconds).
const defaultDBLatencyThreshold = 200 * time.Millisecond

// healthPatientIDDB and healthPatientIDEnc are the patient IDs registered
// with jack.Doctor for the two keeper health checks.
const (
	healthPatientIDDB  = "keeper:health:db"
	healthPatientIDEnc = "keeper:health:enc"
)

// encHealthTestVector is the fixed 32-byte plaintext used by the encryption
// health check. It must never be derived from real secret material.
var encHealthTestVector = []byte("keeper-enc-health-check-v1-00000")
