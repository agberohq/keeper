# keeper

Keeper is a cryptographic secret store for Go. It encrypts arbitrary byte
payloads at rest using Argon2id key derivation and XChaCha20-Poly1305
authenticated encryption, and stores them in an embedded bbolt database. It
is designed to be the foundational secret management layer for the Agbero
load balancer but is fully self-contained and has no dependency on Agbero.

---

## Contents

- [Security model](#security-model)
- [Cryptographic design](#cryptographic-design)
- [Key hierarchy](#key-hierarchy)
- [Storage schema](#storage-schema)
- [Audit chain](#audit-chain)
- [Jack integration](#jack-integration)
- [API reference](#api-reference)
- [Error catalogue](#error-catalogue)
- [Security decisions](#security-decisions)

---

## Security model

Keeper partitions secrets into buckets. Every bucket has an immutable
`BucketSecurityPolicy` that governs how its Data Encryption Key (DEK) is
protected. Four levels are available.

The URI scheme (`vault://`, `certs://`, `space://`, or any name you register)
is independent of the security level. A scheme is just a namespace prefix that
groups related buckets. The security level is a property of the
`BucketSecurityPolicy` set at `CreateBucket` time and cannot be changed
afterwards. You can mix security levels freely within the same scheme.

### LevelPasswordOnly

The bucket DEK is the master key itself. All `LevelPasswordOnly` buckets are
unlocked automatically when `UnlockDatabase` is called with the correct master
passphrase. No per-bucket credential is required at runtime. This level is
appropriate for secrets the process needs at startup without human interaction.

### LevelAdminWrapped

The bucket has a randomly generated 32-byte DEK unique to that bucket. The DEK
is never stored in plaintext. For each authorised admin a Key Encryption Key
(KEK) is derived from `HKDF(masterKey‖adminCred, dekSalt)` and used to wrap
the DEK via XChaCha20-Poly1305. The bucket is inaccessible until an admin calls
`UnlockBucket` with their credential. The master passphrase alone cannot
decrypt the bucket. Revoking one admin does not affect any other admin's wrapped
copy.

### LevelHSM

The bucket DEK is generated at `CreateBucket` time and immediately wrapped by
a caller-supplied `HSMProvider`. The provider performs the wrap and unwrap
operations — keeper never handles the raw DEK after handing it to the provider.
`UnlockDatabase` automatically calls the provider to unwrap and seed the
Envelope for all registered HSM buckets. Master key rotation does not
re-encrypt these buckets; the DEK is provider-controlled.

A built-in `SoftHSM` implementation backed by a memguard-protected wrapping
key is available in `pkg/hsm` for testing and CI environments. Do not use it
in production.

### LevelRemote

Identical to `LevelHSM` in key management behaviour, but the `HSMProvider` is
implemented by `pkg/remote.Provider` — a configurable HTTPS adapter that
delegates wrap and unwrap to any remote KMS service over TLS. Pre-built
configurations for HashiCorp Vault Transit, AWS KMS, and GCP Cloud KMS are
provided in `pkg/remote`. For production use, configure `TLSClientCert` and
`TLSClientKey` to enable mutual TLS authentication.

---

## Cryptographic design

### Master key derivation

```
salt ← random 32 bytes, generated once, stored as a versioned SaltStore
masterKey ← Argon2id(passphrase, salt, t=3, m=64 MiB, p=4) → 32 bytes
```

A verification hash is stored on first derivation:

```
verifyHash ← Argon2id(masterKey, "verification", t=1, m=64 MiB, p=4) → 32 bytes
```

Subsequent `DeriveMaster` calls recompute this hash and compare it with
`crypto/subtle.ConstantTimeCompare`. A mismatch returns `ErrInvalidPassphrase`.

### Secret encryption

Each plaintext value is encrypted with XChaCha20-Poly1305 using the bucket DEK:

```
nonce ← random 24 bytes
ciphertext ← XChaCha20-Poly1305.Seal(nonce, DEK, plaintext)
```

The stored record is a msgpack-encoded `Secret` struct containing the
ciphertext, encrypted metadata, and schema version. Authentication is implicit:
a ciphertext decrypted with the wrong key produces an AEAD authentication
failure before any plaintext is returned.

### KEK derivation — LevelAdminWrapped

```
salt ← random 32 bytes, generated at bucket creation, stored in policy
ikm ← masterKey ‖ adminCredential
KEK ← HKDF-SHA256(ikm, salt, info="keeper-kek-v1") → 32 bytes
wrappedDEK ← XChaCha20-Poly1305.Seal(nonce, KEK, DEK)
```

The KEK is derived using HKDF rather than a second Argon2 pass. The master key
was already produced by a high-cost KDF; a second Argon2 invocation would add
hundreds of milliseconds of latency to every `UnlockBucket` call with no
security benefit. HKDF-SHA256 operates in approximately one microsecond.

The neither-alone property holds: an attacker who compromises only the database
obtains the wrapped DEK and the HKDF salt but cannot derive the KEK without the
master key. An attacker who compromises only the master key cannot unwrap any
`LevelAdminWrapped` DEK without also knowing the admin credential.

### Metadata encryption

Secret metadata (creation time, update time, access count, version) is
encrypted separately from the ciphertext:

```
metaKey ← HKDF-SHA256(bucketDEK, nil, info="keeper-metadata-v1") → 32 bytes
encryptedMeta ← XChaCha20-Poly1305.Seal(nonce, metaKey, msgpack(metadata))
```

For `LevelAdminWrapped`, `LevelHSM`, and `LevelRemote` buckets this means
metadata is inaccessible without the bucket credential, preventing an attacker
with read access to the database file from learning access patterns or
timestamps.

### Policy authentication

Each policy record carries two integrity tags written atomically in one bbolt
transaction:

```
hash ← SHA-256(policyJSON)                         — unauthenticated, verified before unlock
policyKey ← HKDF-SHA256(masterKey, nil, info="keeper-policy-hmac-v1") → 32 bytes
hmac ← HMAC-SHA256(policyKey, policyJSON)          — authenticated, verified after unlock
```

Before `UnlockDatabase`, only the SHA-256 hash is available. After unlock,
`loadPolicy` verifies the HMAC tag. `UnlockDatabase` calls `upgradePolicyHMACs`
to backfill HMAC tags on policies created before this feature existed.

### Audit HMAC signing

```
auditKey ← HKDF-SHA256(masterKey, nil, info="keeper-audit-hmac-v1") → 32 bytes
HMAC ← HMAC-SHA256(auditKey, event fields including Seq)
```

The signing key is activated at `UnlockDatabase` and cleared at `Lock`. When
the master key is rotated, `Rotate` appends a key-rotation checkpoint event to
every active audit chain, signed with the old audit key as the final event of
the old epoch. History is never rewritten; the checkpoint is the trust bridge
between epochs.

---

## Key hierarchy

```
passphrase
    │
    └─ Argon2id(salt) ──→ masterKey (32 bytes, memguard Enclave)
                              │
                              ├─ HKDF("keeper-audit-hmac-v1")  ──→ auditKey
                              ├─ HKDF("keeper-policy-hmac-v1") ──→ policyKey
                              │
                              ├─ [LevelPasswordOnly]
                              │       └─ DEK = masterKey
                              │               └─ HKDF("keeper-metadata-v1") ──→ metaKey
                              │
                              ├─ [LevelAdminWrapped]
                              │       ├─ random 32 bytes ──→ DEK
                              │       │       └─ HKDF("keeper-metadata-v1") ──→ metaKey
                              │       │
                              │       └─ HKDF("keeper-kek-v1", masterKey‖adminCred, dekSalt)
                              │                 └─ KEK
                              │                       └─ XChaCha20-Poly1305(KEK, DEK) ──→ wrappedDEK
                              │
                              └─ [LevelHSM / LevelRemote]
                                      ├─ random 32 bytes ──→ DEK
                                      │       └─ HKDF("keeper-metadata-v1") ──→ metaKey
                                      │
                                      └─ HSMProvider.WrapDEK(DEK) ──→ wrappedDEK
                                         (stored; provider controls the wrapping key)
```

All intermediate keys are zeroed immediately after use. The master key is
never written to disk in any form.

---

## Storage schema

The underlying database is bbolt. All buckets and their contents:

| bbolt bucket | Key format | Value format |
|---|---|---|
| `metadata` | string | raw bytes / JSON (salt store, verification hash, rotation WAL) |
| `__policies__` | `scheme:namespace` | JSON — BucketSecurityPolicy |
| `__policies__` | `scheme:namespace:hash` | hex SHA-256 of policy JSON |
| `__policies__` | `scheme:namespace:hmac` | hex HMAC-SHA256(policyKey, policy JSON) |
| `__audit__/scheme/namespace` | event UUID | JSON — audit Event |
| `scheme/namespace/key` | key string | msgpack — Secret struct |

### Secret struct (msgpack)

```go
type Secret struct {
    Ciphertext    []byte `msgpack:"ct"`
    EncryptedMeta []byte `msgpack:"em,omitempty"`
    SchemaVersion int    `msgpack:"sv"`  // always 1
}
```

`EncryptedMeta` holds msgpack-encoded `EncryptedMetadata` encrypted with the
`keeper-metadata-v1` key derived from the bucket DEK.

### Versioned salt store

The KDF salt is stored as a JSON-encoded `SaltStore` under the `salt` metadata
key. Each salt rotation appends a new `SaltEntry` and advances
`CurrentVersion`. Old entries are retained as an audit trail.

```json
{
  "current": 2,
  "entries": [
    {"v": 1, "s": "<base64>", "ca": "2025-01-01T00:00:00Z"},
    {"v": 2, "s": "<base64>", "ca": "2025-06-01T00:00:00Z"}
  ]
}
```

### Crash-safe rotation WAL

```json
{
  "status": "in_progress",
  "old_hash": "<sha256 of old master key>",
  "new_hash": "<sha256 of new master key>",
  "started":  "2025-06-01T12:00:00Z",
  "last_key": "vault:system:jwt_secret",
  "wrapped_old_key": "<XChaCha20-Poly1305(newKey, oldKey)>"
}
```

`last_key` is the cursor: scheme:namespace:key of the last successfully written
record. On resume, records at or before the cursor are skipped. `wrapped_old_key`
allows the old master key to be recovered at resume time without storing it in
plaintext — it is decrypted with the new master key which `UnlockDatabase` has
already verified.

---

## Audit chain

Every significant operation appends a tamper-evident event to the bucket's
audit chain. Chain integrity depends on two mechanisms.

**Checksum.** SHA-256 over prevChecksum, ID, BucketID, Scheme, Namespace,
Details, EventType, and Timestamp. Covering ID, BucketID, Scheme, and Namespace
prevents an event from one chain being transplanted to another without
detection.

**HMAC.** HMAC-SHA256 over all fields including Seq. An attacker who can write
to the database but does not know the audit key cannot produce a valid HMAC.
`VerifyIntegrity` checks both layers for every event.

**Key rotation epoch boundary.** At `Rotate`, a checkpoint event is appended
to every active chain carrying fingerprints of both the outgoing and incoming
audit keys. The checkpoint is signed with the outgoing key. `VerifyIntegrity`
segments verification at checkpoint events without rewriting any history.

**Automatic pruning.** When `AuditPruneInterval` is set in `Config`, a
`jack.Scheduler` runs periodically and calls `PruneEvents` on every registered
bucket. `LevelHSM` and `LevelRemote` buckets are never pruned regardless of
this setting. Events are sorted by Seq before trimming; the `chainIndex` is
rewritten after every deletion.

---

## Jack integration

Jack is an optional process supervision library. When a `JackConfig` is
provided via `WithJack`, keeper activates background components automatically.

**Auto-lock Looper.** A `jack.Looper` fires at `AutoLockInterval`, checks
`lastActivity`, and drops all `LevelAdminWrapped` and `LevelHSM`/`LevelRemote`
DEKs from the Envelope when the idle threshold is exceeded.

**Reaper.** A `jack.Reaper` manages per-bucket DEK TTL for `LevelAdminWrapped`
buckets independently of the global idle check. `UnlockBucket` and every
subsequent `Get`/`Set` touch the reaper entry.

**Health monitoring.** A `jack.Doctor` registers two `jack.Patient` instances:
one measuring bbolt read latency against a configurable threshold
(`DBLatencyThreshold`, default 200 ms), and one performing an encrypt/decrypt
round-trip on a fixed synthetic test vector to confirm the active cipher and key
are operational. Both patients use a 30-second check interval and switch to a
5-second accelerated interval on degradation.

To share a Doctor across multiple Keeper instances, supply one via
`JackConfig.Doctor`. Otherwise Keeper creates and owns its own.

**Audit prune scheduler.** A `jack.Scheduler` runs `PruneEvents` on all
registered buckets at `AuditPruneInterval` (disabled when zero).

**Pool.** Non-critical audit events are submitted to `jack.Pool` for
asynchronous execution. Policy creation events remain synchronous.

**Shutdown.** `New` registers `store.Lock` with `jack.Shutdown` when a
`JackShutdown` handle is provided.

Keeper never calls `pool.Shutdown`. The pool lifecycle belongs to the caller.

---

## API reference

### Construction and unlock

```go
store, err := keeper.New(keeper.Config{
    DBPath:              "/var/lib/agbero/keeper.db",
    AutoLockInterval:    30 * time.Minute,
    EnableAudit:         true,
    AuditPruneInterval:  24 * time.Hour,
    AuditPruneKeepLastN: 10_000,
    AuditPruneOlderThan: 90 * 24 * time.Hour,
    DBLatencyThreshold:  200 * time.Millisecond,
    Logger:              logger,
}, keeper.WithJack(keeper.JackConfig{
    Pool:     jackPool,
    Shutdown: jackShutdown,
}))
if err != nil {
    log.Fatal(err)
}
defer store.Close()

master, err := store.DeriveMaster([]byte(os.Getenv("KEEPER_PASSPHRASE")))
if err != nil {
    log.Fatal(err) // ErrInvalidPassphrase on wrong passphrase
}
if err := store.UnlockDatabase(master); err != nil {
    log.Fatal(err)
}
```

If the process crashed mid-rotation on a previous run, `UnlockDatabase`
detects the WAL, recovers the old key from `WrappedOldKey`, and completes the
remaining records automatically before proceeding.

### LevelPasswordOnly bucket — full lifecycle

`LevelPasswordOnly` buckets are unlocked automatically at `UnlockDatabase`. No
per-bucket credential is needed.

```go
// Create the bucket once (immutable policy).
err := store.CreateBucket("vault", "system", keeper.LevelPasswordOnly, "init")

// Write and read immediately — no UnlockBucket call needed.
store.SetNamespacedFull("vault", "system", "jwt_secret", []byte("supersecret"))
val, err := store.GetNamespacedFull("vault", "system", "jwt_secret")

// Convenience wrappers use the default scheme.
store.SetNamespaced("admin", "jwt_secret", secretBytes)
val, err = store.GetNamespaced("admin", "jwt_secret")

// Or with the full key path.
store.Set("vault://system/jwt_secret", secretBytes)
val, err = store.Get("vault://system/jwt_secret")
```

### LevelAdminWrapped bucket — full lifecycle

`LevelAdminWrapped` buckets have a unique random DEK. The master passphrase
alone cannot decrypt them. Each admin holds an independent wrapped copy of the
DEK — revoking one admin does not affect others.

```go
// Create the bucket (policy is immutable after this call).
err := store.CreateBucket("finance", "payroll", keeper.LevelAdminWrapped, "ops-team")

// Add the first admin. This generates the random DEK, wraps it under
// alice's KEK, and immediately seeds the Envelope so the bucket is usable.
err = store.AddAdminToPolicy("finance", "payroll", "alice", []byte("alicepass"))

// Write secrets while the bucket is unlocked.
store.SetNamespacedFull("finance", "payroll", "salary_key", []byte("AES256..."))

// Add a second admin (bucket must be unlocked).
err = store.AddAdminToPolicy("finance", "payroll", "bob", []byte("bobpass"))

// Lock the bucket (drops the DEK from the Envelope).
store.LockBucket("finance", "payroll")

// Unlock as bob.
err = store.UnlockBucket("finance", "payroll", "bob", []byte("bobpass"))
if err != nil {
    // keeper.ErrAuthFailed — wrong password OR unknown admin ID.
    // The error deliberately does not distinguish between the two
    // to prevent admin ID enumeration (CWE-204).
}

// Read is now available.
val, err := store.GetNamespacedFull("finance", "payroll", "salary_key")

// Revoke alice. Her wrapped DEK copy is deleted from the policy.
// The underlying DEK and all secrets are unchanged.
err = store.RevokeAdmin("finance", "payroll", "alice")

// Re-key this admin's wrapped DEK under a fresh per-bucket salt.
// Must be called after RotateSalt to keep the wrapped DEK current.
err = store.RotateAdminWrappedDEK("finance", "payroll", "bob", []byte("bobpass"))

// Check whether a re-key is needed since the last salt rotation.
needs, err := store.NeedsAdminRekey("finance", "payroll")
```

### LevelHSM bucket — full lifecycle

```go
import "github.com/agberohq/keeper/pkg/hsm"

// Create a SoftHSM provider (testing only — use a real HSM in production).
provider, err := hsm.NewSoftHSM()
if err != nil {
    log.Fatal(err)
}

// Open the store and register the provider before UnlockDatabase.
store, _ := keeper.New(keeper.Config{DBPath: "keeper.db"})
store.RegisterHSMProvider("secure", "keys", provider)

// Create the bucket. The DEK is generated and wrapped by the provider here.
err = store.CreateBucket("secure", "keys", keeper.LevelHSM, "ops")
// On subsequent opens, RegisterHSMProvider must be called before UnlockDatabase.
// UnlockDatabase will call provider.UnwrapDEK automatically.

store.UnlockDatabase(master)
store.SetNamespacedFull("secure", "keys", "api_key", []byte("secret"))
```

### LevelRemote bucket — full lifecycle

```go
import "github.com/agberohq/keeper/pkg/remote"

// Use a pre-built adapter for HashiCorp Vault Transit.
cfg := remote.VaultTransit("https://vault.corp:8200", vaultToken, "my-key")
// For mTLS:
cfg.TLSClientCert = "/etc/keeper/client.crt"
cfg.TLSClientKey  = "/etc/keeper/client.key"

provider, err := remote.New(cfg)
if err != nil {
    log.Fatal(err)
}

store.RegisterHSMProvider("tenant", "secrets", provider)
err = store.CreateBucket("tenant", "secrets", keeper.LevelRemote, "ops")
```

AWS KMS and GCP Cloud KMS adapters are available as `remote.AWSKMS` and
`remote.GCPKMS`. For any other service, populate `remote.Config` directly
using `WrapRequestTemplate` and `WrapResponseJSONPath` to match the service's
request and response format.

### Key rotation

```go
// Rotate the master passphrase. Re-encrypts all LevelPasswordOnly secrets.
// LevelAdminWrapped, LevelHSM, and LevelRemote secrets are unaffected.
// The WAL ensures this is crash-safe and resumes automatically on next unlock.
if err := store.Rotate([]byte("new-passphrase")); err != nil {
    log.Fatal(err)
}

// Rotate the KDF salt independently of the passphrase.
// Generates a new random salt, re-derives the master key, and re-encrypts
// all LevelPasswordOnly secrets. LevelAdminWrapped buckets are logged as
// needing a follow-up RotateAdminWrappedDEK call.
if err := store.RotateSalt([]byte("current-passphrase")); err != nil {
    log.Fatal(err)
}
```

### Compare-and-swap

```go
err := store.CompareAndSwapNamespacedFull("vault", "system", "counter",
    []byte("old"), []byte("new"))
// Returns ErrCASConflict if the current value does not match old.
```

### Backup

```go
f, _ := os.Create("keeper.db.bak")
info, err := store.Backup(f)
// info.Bytes, info.Timestamp, info.DBPath
```

---

## Error catalogue

| Error | Meaning |
|---|---|
| `ErrStoreLocked` | Operation attempted while the store is locked |
| `ErrInvalidPassphrase` | Wrong master passphrase in `DeriveMaster` or `Unlock` |
| `ErrAuthFailed` | Any authentication failure in `UnlockBucket` — does not distinguish wrong password from unknown admin ID |
| `ErrKeyNotFound` | Secret key does not exist |
| `ErrBucketLocked` | Bucket has not been unlocked |
| `ErrPolicyImmutable` | Attempt to create a second policy for an existing bucket |
| `ErrPolicyNotFound` | No policy exists for the given scheme/namespace |
| `ErrAdminNotFound` | Admin ID not in policy — returned by `RevokeAdmin` only, not by `UnlockBucket` |
| `ErrHSMProviderNil` | `LevelHSM` or `LevelRemote` bucket created without a registered `HSMProvider` |
| `ErrCheckLatency` | Database read latency exceeded `DBLatencyThreshold` in the health patient |
| `ErrCASConflict` | Current value does not match expected value in `CompareAndSwap` |
| `ErrSecurityDowngrade` | Cross-bucket move/copy from higher to lower security level without `confirmDowngrade=true` |
| `ErrAlreadyUnlocked` | `UnlockDatabase` called on an already-unlocked store |
| `ErrMasterRequired` | `UnlockDatabase` called with a nil or destroyed `Master` |
| `ErrChainBroken` | Audit chain integrity verification failed |
| `ErrMetadataDecrypt` | Encrypted metadata could not be decrypted |
| `ErrPolicySignature` | Policy HMAC verification failed — record was tampered |

---

## Security decisions

### ErrAuthFailed unifies all UnlockBucket failures (CWE-204 / CVSS 5.3)

`UnlockBucket` returns `ErrAuthFailed` for both an unknown admin ID and a wrong
password. This prevents an attacker from enumerating valid admin IDs by
observing which error is returned. `RevokeAdmin` retains `ErrAdminNotFound`
because it is an administrative operation on an already-unlocked store where
the caller legitimately needs to know whether the ID exists.

### Argon2id dominates timing — no dummy code in DeriveMaster

Argon2id takes 200–500 ms on typical hardware. Any difference in the
post-derivation comparison is four or more orders of magnitude smaller and is
not measurable remotely. No artificial timing equalisation is applied.

### DEK retrieved inside the CAS transaction boundary

`CompareAndSwapNamespacedFull` retrieves the bucket DEK inside the bbolt write
transaction closure. This eliminates the window where a concurrent `Rotate`
could change the DEK between retrieval and use.

### LevelHSM and LevelRemote buckets skipped during master key rotation

`reencryptAllWithKey` and `RotateSalt` explicitly skip `LevelHSM` and
`LevelRemote` buckets and log a structured info message for each. The DEK is
provider-controlled; master salt rotation does not affect it.

### LevelAdminWrapped salt rotation gap and RotateAdminWrappedDEK

`RotateSalt` re-derives the master key under a new KDF salt but does not
re-key `LevelAdminWrapped` WrappedDEKs. Those DEKs are encrypted with a KEK
derived from `HKDF(masterKey‖adminCred, dekSalt)` where `dekSalt` is a
per-bucket salt independent of the master KDF salt. After `RotateSalt`, a
structured Warn is logged for each `LevelAdminWrapped` bucket. Admins should
call `RotateAdminWrappedDEK` to generate a fresh `dekSalt` and re-wrap their
copy. `NeedsAdminRekey` reports whether a bucket's `LastRekeyed` timestamp
predates the current master salt generation.

### Slice copy before secureZero

`mbCopy := make([]byte, len(masterBytes)); copy(mbCopy, masterBytes)` is used
before `zero.Bytes(masterBytes)` throughout. A plain assignment aliases the
backing array; zeroing it would corrupt a concurrent reader. The copy gives
each caller exclusive ownership of its byte slice.

### msgpack on the Secret hot path

All `Secret` and `EncryptedMetadata` records use
`github.com/vmihailenco/msgpack/v5`. Policy records remain JSON — they are
written infrequently and must be human-readable for forensic purposes.

### Policy authenticated with HMAC after unlock

The unauthenticated SHA-256 hash detects accidental corruption and simple
tampering before unlock. The HMAC-SHA256 tag detects deliberate tampering by an
adversary who has write access to the database file and can update both the
record and its SHA-256 hash. Both tags are written atomically with the policy
record in one bbolt.Update.

### Crash-safe rotation with WrappedOldKey

`Rotate` writes a WAL before touching any record. The WAL carries
`WrappedOldKey`: the pre-rotation master key encrypted with the new master key.
After a crash the old passphrase is gone; `WrappedOldKey` is the only correct
way to carry the old key across the boundary. At `UnlockDatabase`, when a WAL
is present, the new master key decrypts `WrappedOldKey` and rotation resumes
from the WAL cursor. Both keys exist in plaintext simultaneously only for the
duration of each individual `reencryptRecord` call.

### Versioned salt store with legacy migration

The KDF salt is stored as a `SaltStore` with versioned `SaltEntry` records.
`loadSaltStore` detects the legacy format (a bare 32-byte value, first byte
not `{`) and migrates it in-place on first read, wrapping it in a versioned
store at version 1.

### Audit chain covers ID, BucketID, Scheme, and Namespace

The checksum hashes ID, BucketID, Scheme, Namespace, Details, EventType, and
Timestamp. This prevents an event from one chain being transplanted to another
chain without detection.