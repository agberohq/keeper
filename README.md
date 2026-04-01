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
salt ← random 32 bytes, generated once, stored in the metadata bucket
masterKey ← Argon2id(passphrase, salt, t=3, m=64 MiB, p=4) → 32 bytes
```

A verification hash is stored on first derivation:

```
verifyHash ← Argon2id(masterKey, "verification", t=1, m=64 MiB, p=4) → 32 bytes
```

Subsequent `DeriveMaster` calls recompute this hash and compare it with
`crypto/subtle.ConstantTimeCompare`. A mismatch returns `ErrInvalidPassphrase`.
The dummy-timing block that previously followed this comparison (a stray
`crypto/rand.Read` + `ConstantTimeCompare` intended to equalise timing but
actually providing no benefit after Argon2) was removed. Argon2 dominates the
timing profile on both success and failure paths; any remaining discrepancy is
below measurable threshold.

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

This means metadata is inaccessible without the bucket DEK. For
`LevelAdminWrapped` buckets it is therefore inaccessible without the admin
credential, which prevents an attacker who has read access to the database from
learning access patterns or timestamps even if they cannot decrypt the payload.

### Audit HMAC signing

Each audit event is signed with a key derived from the master key:

```
auditKey ← HKDF-SHA256(masterKey, nil, info="keeper-audit-hmac-v1") → 32 bytes
HMAC ← HMAC-SHA256(auditKey, event fields including Seq)
```

The signing key is activated in `UnlockDatabase` and cleared in `Lock`. When
the master key is rotated, `Rotate` appends a key-rotation checkpoint event to
every active audit chain, signed with the old audit key as the final event of
the old epoch. The store then switches to a new audit key derived from the new
master. History is never rewritten; the checkpoint is the trust bridge between
epochs.

---

## Key hierarchy

```
passphrase
    │
    └─ Argon2id ──→ masterKey (32 bytes, held in memguard Enclave)
                        │
                        ├─ HKDF("keeper-audit-hmac-v1") ──→ auditKey
                        │
                        ├─ [LevelPasswordOnly] ─────────────→ DEK = masterKey
                        │                                         │
                        │                                         └─ HKDF("keeper-metadata-v1") ──→ metaKey
                        │
                        └─ [LevelAdminWrapped]
                                │
                                ├─ random ──→ DEK (32 bytes)
                                │                │
                                │                └─ HKDF("keeper-metadata-v1") ──→ metaKey
                                │
                                └─ HKDF("keeper-kek-v1", masterKey ‖ adminCred, salt) ──→ KEK
                                        │
                                        └─ XChaCha20-Poly1305.Seal(KEK, DEK) ──→ wrappedDEK (stored in policy)
```

All intermediate keys are held in `memguard`-protected memory where possible.
Raw byte slices derived from protected buffers are zeroed with `secureZero`
immediately after use. The master key is never written to disk in any form.

---

## Storage schema

The underlying database is bbolt. All buckets and their contents:

| bbolt bucket | Contents |
|---|---|
| `metadata` | KDF salt, master key verification hash, rotation WAL marker, migration cursor |
| `__policies__` | JSON-encoded `BucketSecurityPolicy` per namespace, plus a SHA-256 integrity hash per entry |
| `__audit__/<scheme>/<namespace>` | Append-only audit event chain |
| `<scheme>/<namespace>/<key>` | msgpack-encoded `Secret` struct |

### Secret encoding — schema versions

| Version | Encoding | Metadata |
|---|---|---|
| V0 (legacy) | JSON | Plaintext fields in Secret struct |
| V1 (transitional) | JSON | Encrypted in `EncryptedMeta` field |
| V2 (current) | msgpack | Encrypted in `EncryptedMeta` field |

All new writes produce V2. `reencryptAllWithKey` (called by `Rotate`) and
`migrateBatch` (background migration) read with format auto-detection: the
first byte `{` (0x7B) selects JSON; anything else selects msgpack. All other
read paths use pure msgpack. Once the background migration completes
(`migrationDoneKey` is set in the metadata bucket), all records in the database
are V2 and the JSON path is no longer exercised.

Policy records always use JSON regardless of the Secret schema version. Policies
are written infrequently, are not on the encryption hot path, and must be
human-readable for forensic purposes.

---

## Audit chain

Every significant operation appends a tamper-evident event to the bucket's audit
chain. Chain integrity depends on two mechanisms.

### Checksum

Each event stores a SHA-256 hash over its predecessor's checksum, its own
`ID`, `BucketID`, `Scheme`, `Namespace`, `Details`, `EventType`, and
`Timestamp`. The `Seq` field is excluded from the checksum because it is
assigned by the write transaction after the caller computes the hash. Including
it would require a second pass. The `ID`, `BucketID`, `Scheme`, and `Namespace`
fields are covered to prevent an event from one chain being transplanted to
another.

### HMAC

When the store is unlocked, each event also carries an HMAC-SHA256 tag computed
over all fields including `Seq`. An attacker who can write to the database but
does not know the audit key cannot produce a valid HMAC. `VerifyIntegrity`
checks both the checksum chain and the HMAC for every event.

### Key rotation epoch boundary

At `Rotate`, a checkpoint event is appended to every active chain. It carries
fingerprints of both the outgoing and incoming audit keys (derived via
`HKDF(key, nil, "epoch-boundary") → 16 bytes → hex`). The checkpoint is signed
with the outgoing key. `VerifyIntegrity` segments verification at checkpoint
events: events before the checkpoint are verified with the signing key the store
was constructed with; the checkpoint itself proves the transition.

### Pruning

`Prune` sorts all events by `Seq` before trimming and rewrites the `chainIndex`
(which holds `LastID`, `LastChecksum`, and `EventCount`) after deletion. An
earlier version sorted events by timestamp, which could delete events
out-of-sequence when clocks were adjusted, and did not update the index,
leaving `LastChecksum` pointing at a deleted event.

---

## Jack integration

Jack is an optional process supervision library. When a `JackConfig` is provided
via `WithJack`, keeper activates three background components.

### Auto-lock Looper

Replaces the previous `autoLockRoutine` goroutine and `autoLockStop` channel.
A `jack.Looper` fires at `AutoLockInterval`. Its task checks `lastActivity`
and, if the idle threshold has been exceeded, acquires a single write lock and
drops all `LevelAdminWrapped` DEKs from the Envelope. The previous
implementation had a TOCTOU race: it acquired an RLock to read `lastActivity`,
released it, then acquired a write lock to drop the DEKs. Between the two lock
acquisitions another goroutine could modify state. The Looper eliminates this
window by performing both the check and the drop inside one write lock
acquisition.

### Reaper

A `jack.Reaper` manages per-bucket DEK TTL for `LevelAdminWrapped` buckets
independently of the global idle check. `UnlockBucket` and every subsequent
`Get`/`Set` call `jackReaper.Touch(scheme+":"+namespace)`, resetting that
bucket's individual timer. When the timer expires the Reaper callback drops the
DEK for that bucket only, without affecting other unlocked buckets.

### Pool

Non-critical audit events are submitted to `jack.Pool` for asynchronous
execution, keeping `Set` and `Delete` off the audit write path. Policy
creation events remain synchronous: `CreateBucket` must not return before the
audit record is committed. Keeper never calls `pool.Shutdown`; the pool
lifecycle belongs to the calling process (Agbero).

### Shutdown

`New` registers `store.Lock` with `jack.Shutdown` when a `JackShutdown` handle
is provided. This ensures the master key and all DEKs are wiped and all
background goroutines are stopped as part of the process shutdown sequence,
before the database file is closed.

---

## API reference

### Construction

```go
// Open or create a database.
store, err := keeper.New(keeper.Config{
DBPath:           "/var/lib/agbero/keeper.db",
AutoLockInterval: 30 * time.Minute,
EnableAudit:      true,
})

// Open an existing database (returns error if path does not exist).
store, err := keeper.Open(keeper.Config{DBPath: "/var/lib/agbero/keeper.db"})

// Attach Jack integration.
store, err := keeper.New(config, keeper.WithJack(keeper.JackConfig{
Pool:     jackPool,
Shutdown: jackShutdown,
}))
```

### Unlock sequence

```go
master, err := store.DeriveMaster([]byte(os.Getenv("AGBERO_PASSPHRASE")))
if err != nil {
log.Fatal(err) // ErrInvalidPassphrase on wrong passphrase
}
if err := store.UnlockDatabase(master); err != nil {
log.Fatal(err)
}
defer store.Close()
```

### Default bucket operations

```go
store.Set("jwt_secret", secretBytes)
val, err := store.Get("jwt_secret")
store.Delete("jwt_secret")
exists, _ := store.Exists("jwt_secret")
```

### Namespaced operations

```go
// Explicit scheme, namespace, key.
store.SetNamespacedFull("vault", "system", "jwt_secret", secretBytes)
val, err := store.GetNamespacedFull("vault", "system", "jwt_secret")

// Default scheme, explicit namespace.
store.SetNamespaced("system", "jwt_secret", secretBytes)
val, err := store.GetNamespaced("system", "jwt_secret")
```

### Bucket management

```go
// Create a password-only bucket (unlocked at UnlockDatabase).
store.CreateBucket("vault", "admin", keeper.LevelPasswordOnly, "agbero-init")

// Create an admin-wrapped bucket.
store.CreateBucket("finance", "payroll", keeper.LevelAdminWrapped, "ops-team")

// Add an admin (generates or re-wraps the DEK).
store.AddAdminToPolicy("finance", "payroll", "alice", []byte("alicepass"))

// Unlock an admin-wrapped bucket.
store.UnlockBucket("finance", "payroll", "alice", []byte("alicepass"))

// Revoke an admin (does not drop the DEK from the Envelope).
store.RevokeAdmin("finance", "payroll", "alice")
// To immediately drop access: store.LockBucket("finance", "payroll")
```

### Key rotation

```go
// Re-encrypts all LevelPasswordOnly secrets with the new master key.
// LevelAdminWrapped secrets are unaffected.
if err := store.Rotate([]byte("new-passphrase")); err != nil {
log.Fatal(err)
}
```

`Rotate` is crash-safe: it writes a WAL marker before starting and clears it
on completion. `New` refuses to open a database with an incomplete rotation
(`ErrRotationIncomplete`).

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
| `ErrAuthFailed` | Authentication failure in `UnlockBucket` — deliberately does not distinguish wrong password from unknown admin ID |
| `ErrKeyNotFound` | Secret key does not exist |
| `ErrBucketLocked` | `LevelAdminWrapped` bucket has not been unlocked |
| `ErrPolicyImmutable` | Attempt to create a second policy for an existing bucket |
| `ErrPolicyNotFound` | No policy exists for the given scheme/namespace |
| `ErrAdminNotFound` | Admin ID not in policy — returned by `RevokeAdmin` only |
| `ErrCASConflict` | Current value does not match expected value in `CompareAndSwap` |
| `ErrSecurityDowngrade` | Cross-bucket move/copy from higher to lower security level without `confirmDowngrade=true` |
| `ErrRotationIncomplete` | Database has a partial key rotation; call `Rotate` again with the new passphrase |
| `ErrAlreadyUnlocked` | `UnlockDatabase` called on an already-unlocked store |
| `ErrMasterRequired` | `UnlockDatabase` called with a nil or destroyed `Master` |
| `ErrChainBroken` | Audit chain integrity verification failed |
| `ErrMetadataDecrypt` | Encrypted metadata could not be decrypted (wrong key or corruption) |
