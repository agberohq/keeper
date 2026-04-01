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
// ForEach iterations skip this key; it holds EncryptedMetadata once
// a record has been migrated to secretSchemaV1.
const metadataKey = "__metadata__"

// Keys stored inside the metadata bucket.
const (
	rotationWALKey      = "__rotation_wal__"
	migrationWALKey     = "__migration_wal__"
	migrationDoneKey    = "__migration_done__"
	metaSaltKey         = "salt"
	metaVerifyKey       = "verify"
	walStatusInProgress = "in_progress"
)

// policyHashSuffix is appended to a policy key when storing its integrity hash.
const policyHashSuffix = ":hash"

// HKDF info strings used as domain-separation labels.
// Changing any of these values is a breaking change to the on-disk format.
const (
	hkdfInfoKEK      = "keeper-kek-v1"
	hkdfInfoAuditKey = "keeper-audit-hmac-v1"
	hkdfInfoMetaKey  = "keeper-metadata-v1"
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

// Secret schema versions.
// V0: JSON encoding, plaintext metadata fields (legacy, read-only decode path).
// V1: JSON encoding, metadata encrypted in EncryptedMeta.
// V2: msgpack encoding, metadata encrypted in EncryptedMeta (current write format).
const (
	secretSchemaV0 = 0
	secretSchemaV1 = 1
	secretSchemaV2 = 2
)

// Background metadata migration settings.
const (
	migrationBatchSize = 100
	migrationYieldMs   = 10 * time.Millisecond
)

// Audit chain constants.
const (
	auditSnapshotEvery    = 1000
	auditEventKeyRotation = "key_rotation_checkpoint"
)

// SecurityLevel values for BucketSecurityPolicy.
// Declared here so the type stays in types.go while the values live alongside
// all other constants.
const (
	LevelPasswordOnly SecurityLevel = "password_only"
	LevelAdminWrapped SecurityLevel = "admin_wrapped"
	LevelHSM          SecurityLevel = "hsm"
)

// keyDerivationLabel is the human-readable algorithm identifier stored in StoreStats.
const keyDerivationLabel = "argon2id+xchacha20poly1305"
