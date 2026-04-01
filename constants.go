package keeper

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
)

// keyDerivationLabel is the human-readable algorithm identifier stored in StoreStats.
const keyDerivationLabel = "argon2id+xchacha20poly1305"
