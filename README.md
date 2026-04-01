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
- [Deferred work](#deferred-work)

---

## Security model

Keeper partitions secrets into buckets. Every bucket has an immutable
`BucketSecurityPolicy` that governs how its Data Encryption Key (DEK) is
protected. Two levels are implemented.

The URI scheme (`vault://`, `certs://`, `space://`, or any name you register)
is independent of the security level. A scheme is just a namespace prefix that
groups related buckets. The security level is a property of the
`BucketSecurityPolicy` set at `CreateBucket` time and cannot be changed
afterwards. You can have `LevelPasswordOnly` and `LevelAdminWrapped` buckets
under the same scheme.

### LevelPasswordOnly

The bucket DEK is the master key itself. All `LevelPasswordOnly` buckets are
unlocked automatically when `UnlockDatabase` is called with the correct master
passphrase. No per-bucket credential is required at runtime. This level is
appropriate for secrets the process needs at startup without human interaction.

Agbero uses `vault://` as the scheme for system-level `LevelPasswordOnly`
buckets: `vault://system/auth/jwt_secret`, `vault://admin/users/<username>`,
`vault://system/cluster/secret`, and so on. It uses `certs://` for TLS
certificate storage and `space://` for non-admin tenant secrets. All of these
are just naming conventions. Any scheme can hold any security level.

### LevelAdminWrapped

The bucket has a randomly generated 32-byte DEK that is unique to that bucket.
The DEK is never stored in plaintext. Instead, for each authorised admin a Key
Encryption Key (KEK) is derived and used to wrap the DEK via
XChaCha20-Poly1305. The bucket is inaccessible until an admin calls
`UnlockBucket` with their credential. The master passphrase alone cannot
decrypt the bucket. This level provides multi-tenancy: a system administrator
who knows the master passphrase cannot read a tenant's secrets without also
knowing the tenant's bucket password.

### LevelHSM

Reserved. Not yet implemented. Intended for hardware-backed key protection.

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

Each plaintext value is encrypted with XChaCha20-Poly1305 using the bucket's
DEK:

```
nonce ← random 24 bytes
ciphertext ← XChaCha20-Poly1305.Seal(nonce, DEK, plaintext)
```

The stored record is a msgpack-encoded `Secret` struct containing the
ciphertext, encrypted metadata, and schema version. Authentication is
implicit: a ciphertext decrypted with the wrong key produces an AEAD
authentication failure before any plaintext is returned.

### KEK derivation — LevelAdminWrapped

```
salt ← random 32 bytes, generated at bucket creation, stored in policy
ikm ← masterKey ‖ adminCredential
KEK ← HKDF-SHA256(ikm, salt, info="keeper-kek-v1") → 32 bytes
wrappedDEK ← XChaCha20-Poly1305.Seal(nonce, KEK, DEK)
```

The KEK is derived using HKDF rather than a second Argon2 pass. This is
intentional: the master key was already produced by a high-cost KDF; a second
Argon2 invocation would provide no additional security while adding hundreds of
milliseconds of latency to every `UnlockBucket` call. HKDF-SHA256 operates in
approximately one microsecond.

The neither-alone property holds because HKDF requires both `masterKey` and
`adminCredential` as input key material. An attacker who compromises only the
database (and therefore obtains the wrapped DEK and the HKDF salt) cannot
derive the KEK without also knowing the master key. An attacker who compromises
only the master key cannot unwrap any `LevelAdminWrapped` DEK without also
knowing the admin credential.

### Metadata encryption

Secret metadata (creation time, update time, access count, version) is
encrypted separately from the ciphertext using a key derived from the bucket
DEK:

```
metaKey ← HKDF-SHA256(bucketDEK, nil, info="keeper-metadata-v1") → 32 bytes
encryptedMeta ← XChaCha20-Poly1305.Seal(nonce, metaKey, msgpack(metadata))
```

For `LevelAdminWrapped` buckets this means metadata is inaccessible without
the admin credential, which prevents an attacker with read access to the
database file from learning access patterns or timestamps.

### Policy authentication

Each policy record carries two integrity tags written atomically in the same
bbolt transaction:

```
hash ← SHA-256(policyJSON)                         — unauthenticated, verified before unlock
policyKey ← HKDF-SHA256(masterKey, nil, info="keeper-policy-hmac-v1") → 32 bytes
hmac ← HMAC-SHA256(policyKey, policyJSON)          — authenticated, verified after unlock
```

Before `UnlockDatabase`, only the SHA-256 hash is available for integrity
checking. After unlock, `loadPolicy` verifies the HMAC tag and rejects any
policy whose tag does not match. `UnlockDatabase` calls `upgradePolicyHMACs`
to write HMAC tags for any policy that was created before this feature existed.

### Audit HMAC signing

Each audit event is signed with a key derived from the master key:

```
auditKey ← HKDF-SHA256(masterKey, nil, info="keeper-audit-hmac-v1") → 32 bytes
HMAC ← HMAC-SHA256(auditKey, event fields including Seq)
```

The signing key is activated in `UnlockDatabase` and cleared in `Lock`. When
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
                              └─ [LevelAdminWrapped]
                                      ├─ random 32 bytes ──→ DEK
                                      │       └─ HKDF("keeper-metadata-v1") ──→ metaKey
                                      │
                                      └─ HKDF("keeper-kek-v1", masterKey‖adminCred, dekSalt)
                                                └─ KEK
                                                      └─ XChaCha20-Poly1305(KEK, DEK) ──→ wrappedDEK
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

`last_key` is the cursor: scheme:namespace:key of the last successfully
written record. On resume, records at or before the cursor are skipped.
`wrapped_old_key` allows the old master key to be recovered at resume time
without storing it in plaintext — it is decrypted with the new master key
which `UnlockDatabase` has already verified.

---

## Audit chain

Every significant operation appends a tamper-evident event to the bucket's
audit chain. Chain integrity depends on two mechanisms.

**Checksum.** SHA-256 over prevChecksum, ID, BucketID, Scheme, Namespace,
Details, EventType, and Timestamp. Covering ID, BucketID, Scheme, and
Namespace prevents an event from one chain being transplanted to another
without detection.

**HMAC.** HMAC-SHA256 over all fields including Seq. An attacker who can
write to the database but does not know the audit key cannot produce a valid
HMAC. `VerifyIntegrity` checks both layers for every event.

**Key rotation epoch boundary.** At `Rotate`, a checkpoint event is appended
to every active chain carrying fingerprints of both the outgoing and incoming
audit keys (`HKDF(key, "epoch-boundary") → 16 bytes → hex`). The checkpoint
is signed with the outgoing key. `VerifyIntegrity` segments verification at
checkpoint events without rewriting any history.

**Prune.** Events are sorted by Seq before trimming. The `chainIndex` (holding
`LastID`, `LastChecksum`, `EventCount`) is rewritten after every deletion.

---

## Jack integration

Jack is an optional process supervision library. When a `JackConfig` is
provided via `WithJack`, keeper activates three background components.

**Auto-lock Looper.** A `jack.Looper` fires at `AutoLockInterval`, checks
`lastActivity`, and drops all `LevelAdminWrapped` DEKs from the Envelope when
the idle threshold is exceeded. A single write lock covers both the check and
the drop, eliminating the TOCTOU race present in the previous goroutine-based
implementation.

**Reaper.** A `jack.Reaper` manages per-bucket DEK TTL for `LevelAdminWrapped`
buckets independently of the global idle check. `UnlockBucket` and every
subsequent `Get`/`Set` call `jackReaper.Touch(scheme+":"+namespace)`.

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
    DBPath:           "/var/lib/agbero/keeper.db",
    AutoLockInterval: 30 * time.Minute,
    EnableAudit:      true,
    Logger:           logger,
}, keeper.WithJack(keeper.JackConfig{
    Pool:     jackPool,
    Shutdown: jackShutdown,
}))
if err != nil {
    log.Fatal(err)
}
defer store.Close()

master, err := store.DeriveMaster([]byte(os.Getenv("AGBERO_PASSPHRASE")))
if err != nil {
    log.Fatal(err) // ErrInvalidPassphrase on wrong passphrase
}
if err := store.UnlockDatabase(master); err != nil {
    log.Fatal(err)
}
```

If the process crashed mid-rotation on a previous run, `UnlockDatabase`
detects the WAL, recovers the old key from `WrappedOldKey`, and completes
the remaining records automatically before proceeding.

### LevelPasswordOnly bucket — full lifecycle

`LevelPasswordOnly` buckets are unlocked automatically at `UnlockDatabase`.
No per-bucket credential is needed.

```go
// Create the bucket once (immutable policy).
err := store.CreateBucket("vault", "system", keeper.LevelPasswordOnly, "agbero-init")

// Write and read immediately — no UnlockBucket call needed.
store.SetNamespacedFull("vault", "system", "jwt_secret", []byte("supersecret"))
val, err := store.GetNamespacedFull("vault", "system", "jwt_secret")

// Convenience wrappers use the default scheme.
store.SetNamespaced("admin", "jwt_secret", secretBytes)
val, err := store.GetNamespaced("admin", "jwt_secret")

// Or with the full key path.
store.Set("vault://system/jwt_secret", secretBytes)
val, err := store.Get("vault://system/jwt_secret")
```

### LevelAdminWrapped bucket — full lifecycle

`LevelAdminWrapped` buckets have a unique random DEK. The master passphrase
alone cannot decrypt them. Each admin holds an independent wrapped copy of
the DEK — revoking one admin does not affect others.

```go
// 1. Create the bucket (policy is immutable after this call).
err := store.CreateBucket("finance", "payroll", keeper.LevelAdminWrapped, "ops-team")
// Bucket exists but is locked. No DEK exists yet.

// 2. Add the first admin. This generates the random DEK, wraps it under
//    alice's KEK, and immediately seeds the Envelope so the bucket is usable.
err = store.AddAdminToPolicy("finance", "payroll", "alice", []byte("alicepass"))

// 3. Write secrets while the bucket is unlocked.
store.SetNamespacedFull("finance", "payroll", "salary_key", []byte("AES256..."))

// 4. Add a second admin (bucket must be unlocked; alice's session is active).
err = store.AddAdminToPolicy("finance", "payroll", "bob", []byte("bobpass"))

// 5. Lock the bucket (drops the DEK from the Envelope).
store.LockBucket("finance", "payroll")

// 6. Unlock as bob.
err = store.UnlockBucket("finance", "payroll", "bob", []byte("bobpass"))
if err != nil {
    // keeper.ErrAuthFailed — wrong password OR unknown admin ID.
    // The error deliberately does not distinguish between the two
    // to prevent admin ID enumeration (CWE-204).
}

// 7. Read is now available.
val, err := store.GetNamespacedFull("finance", "payroll", "salary_key")

// 8. Revoke alice. Her wrapped DEK copy is deleted from the policy.
//    The underlying DEK and all secrets are unchanged.
//    bob can still unlock; alice cannot.
err = store.RevokeAdmin("finance", "payroll", "alice")
// To immediately drop alice's active session if she was unlocked:
// store.LockBucket("finance", "payroll")

// 9. Check lock state.
unlocked := store.IsBucketUnlocked("finance", "payroll")

// 10. Read the immutable policy.
policy, err := store.GetPolicy("finance", "payroll")
fmt.Println(policy.Level, len(policy.WrappedDEKs))
```

### Key rotation

```go
// Rotate the master passphrase. Re-encrypts all LevelPasswordOnly secrets.
// LevelAdminWrapped secrets are unaffected (they use per-admin KEKs).
// The WAL ensures this is crash-safe and resumes automatically on next unlock.
if err := store.Rotate([]byte("new-passphrase")); err != nil {
    log.Fatal(err)
}

// Rotate the KDF salt independently of the passphrase.
// Generates a new random salt, re-derives the master key under it,
// and re-encrypts all LevelPasswordOnly secrets.
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
| `ErrBucketLocked` | `LevelAdminWrapped` bucket has not been unlocked via `UnlockBucket` |
| `ErrPolicyImmutable` | Attempt to create a second policy for an existing bucket |
| `ErrPolicyNotFound` | No policy exists for the given scheme/namespace |
| `ErrAdminNotFound` | Admin ID not in policy — returned by `RevokeAdmin` only, not by `UnlockBucket` |
| `ErrCASConflict` | Current value does not match expected value in `CompareAndSwap` |
| `ErrSecurityDowngrade` | Cross-bucket move/copy from higher to lower security level without `confirmDowngrade=true` |
| `ErrRotationIncomplete` | No longer returned by `New`. Kept for external callers that may check for it |
| `ErrAlreadyUnlocked` | `UnlockDatabase` called on an already-unlocked store |
| `ErrMasterRequired` | `UnlockDatabase` called with a nil or destroyed `Master` |
| `ErrChainBroken` | Audit chain integrity verification failed |
| `ErrMetadataDecrypt` | Encrypted metadata could not be decrypted (wrong key or corruption) |
| `ErrPolicySignature` | Policy HMAC verification failed — record was tampered |

---

## Security decisions

### ErrAuthFailed unifies all UnlockBucket failures (CWE-204 / CVSS 5.3)

`unlockBucketAdminWrapped` previously returned `ErrAdminNotFound` when the
admin ID was not in the policy and `ErrInvalidPassphrase` when the DEK unwrap
failed. This observable distinction allowed an attacker to enumerate valid
admin IDs. All authentication failures in `UnlockBucket` now return
`ErrAuthFailed`. `RevokeAdmin` retains `ErrAdminNotFound` — it is an
administrative operation on an already-unlocked store where the caller
legitimately needs to know whether the ID exists.

### No dummy timing code in DeriveMaster

A previous version added a `crypto/rand.Read` + `subtle.ConstantTimeCompare`
block after a failed passphrase verification to equalise timing. This was
removed. Argon2id takes 200–500 ms; any difference in the post-derivation
comparison is four or more orders of magnitude smaller and is not measurable
remotely.

### DEK retrieved inside the CAS transaction boundary

`CompareAndSwapNamespacedFull` previously retrieved the bucket DEK before
entering the bbolt write transaction, creating a window where a concurrent
`Rotate` could change the DEK between retrieval and use. The DEK is now
retrieved inside the write transaction closure.

### CreateBucket seeds the Envelope immediately

When `CreateBucket` is called on a `LevelPasswordOnly` bucket while the store
is already unlocked, the bucket is seeded into the Envelope immediately rather
than requiring a subsequent `UnlockDatabase` call.

### Slice copy before secureZero

`mb := masterBytes` aliases the same backing array. `secureZero(masterBytes)`
would zero the array while a goroutine reads `mb`. The fix is
`mbCopy := make([]byte, len(masterBytes)); copy(mbCopy, masterBytes)` before
zeroing. `mbCopy` is owned by its user and zeroed via `defer secureZero`.

### msgpack on the Secret hot path

All `Secret` and `EncryptedMetadata` records use
`github.com/vmihailenco/msgpack/v5`. Policy records remain JSON — they are
written infrequently and must be human-readable for forensic purposes.

### Policy authenticated with HMAC after unlock

The unauthenticated SHA-256 hash detects accidental corruption and simple
tampering before unlock. The HMAC-SHA256 tag (written after unlock using a
key derived from the master) detects deliberate tampering by an adversary who
has write access to the database file and can update both the record and its
SHA-256 hash. Both tags are written atomically with the policy record in one
bbolt.Update. `upgradePolicyHMACs` runs at every unlock to backfill HMAC
tags on policies that predate this feature, and is idempotent.

### Crash-safe rotation with WrappedOldKey

`Rotate` writes a WAL before touching any record. The WAL carries
`WrappedOldKey`: the pre-rotation master key encrypted with the new master
key. This is the only correct way to carry the old key across a crash
boundary — after a crash the old passphrase is gone. At `UnlockDatabase`,
when a WAL is present, the new master key (already verified by Argon2id
against the stored verification hash) decrypts `WrappedOldKey`, and rotation
resumes from the WAL cursor. The old key is zeroed immediately after use.
Both keys exist in plaintext simultaneously only for the duration of each
individual `reencryptRecord` call.

### Versioned salt store

The KDF salt is stored as a `SaltStore` with versioned `SaltEntry` records.
`RotateSalt` generates a new random salt, re-derives the master key, and
re-encrypts all secrets. Old salt entries are retained as an audit trail.
`loadSaltStore` detects the legacy format (a bare 32-byte value, first byte
not `{`) and migrates it in-place on first read.

### Audit chain covers ID, BucketID, Scheme, and Namespace

An earlier checksum hashed only Details, EventType, and Timestamp. Covering
ID, BucketID, Scheme, and Namespace prevents an event from one chain being
transplanted to another without detection.

