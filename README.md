# keeper

Keeper is a cryptographic secret store for Go. It encrypts arbitrary byte
payloads at rest using Argon2id key derivation and XChaCha20-Poly1305 (default)
authenticated encryption, and stores them in an embedded bbolt database.

It ships as three things you can use independently:

- **A Go library** — embed a hardened secret store directly in your process,
  with four security levels, per-bucket DEK isolation, and a tamper-evident
  audit chain.
- **An HTTP handler** (`x/keephandler`) — mount keeper endpoints on any
  `net/http` mux in one call, with pluggable hooks, guards, and response
  encoders for access control and audit logging.
- **A CLI** (`cmd/keeper`) — a terminal interface with a persistent REPL
  session, no-echo secret entry, and zero shell-history exposure.

Keeper was designed as the foundational secret management layer for the [Agbero](https://github.com/agberohq/agbero)
load balancer but has no dependency on Agbero and works in any Go project.

---

## Contents

- [Security model](#security-model)
- [Cryptographic design](#cryptographic-design)
- [Key hierarchy](#key-hierarchy)
- [Storage schema](#storage-schema)
- [Audit chain](#audit-chain)
- [Jack integration](#jack-integration)
- [x/keepcmd — reusable CLI operations](#xkeepcmd)
- [x/keephandler — HTTP handler](#xkeephandler)
- [API reference](#api-reference)
- [Error catalogue](#error-catalogue)
- [Security decisions](#security-decisions)
- [Dependencies](#dependencies)

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

### Versioned salt store

The KDF salt is stored as a JSON-encoded `SaltStore` under the `salt` metadata
key. Each salt rotation appends a new `SaltEntry` and advances
`CurrentVersion`. Old entries are retained as an audit trail.

### Crash-safe rotation WAL

`Rotate` writes a WAL before touching any record. The WAL carries
`WrappedOldKey`: the pre-rotation master key encrypted with the new master key.
After a crash the old passphrase is gone; `WrappedOldKey` is the only correct
way to carry the old key across the boundary. At `UnlockDatabase`, when a WAL
is present, the new master key decrypts `WrappedOldKey` and rotation resumes
from the WAL cursor.

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
audit keys. The checkpoint is signed with the outgoing key.

**Automatic pruning.** When `AuditPruneInterval` is set in `Config`, a
`jack.Scheduler` runs periodically and calls `PruneEvents` on every registered
bucket. `LevelHSM` and `LevelRemote` buckets are never pruned regardless of
this setting.

---

## Jack integration

Jack is an optional process supervision library. When a `JackConfig` is
provided via `WithJack`, keeper activates background components automatically:
auto-lock Looper, per-bucket DEK Reaper, health monitoring patients (bbolt
read latency + encrypt/decrypt round-trip), audit prune scheduler, and async
event Pool. Keeper never calls `pool.Shutdown` — the pool lifecycle belongs to
the caller.

---

## x/keepcmd

`x/keepcmd` provides reusable keeper operations decoupled from any CLI
framework. Embed it in your own application to get typed, testable secret
management without pulling in the CLI binary.

```go
import "github.com/agberohq/keeper/x/keepcmd"

cmds := &keepcmd.Commands{
    Store: func() (*keeper.Keeper, error) {
        return security.KeeperOpen(cfg)  // your own config
    },
    Out:     keepcmd.PlainOutput{},
    NoClose: false, // true in REPL / session contexts
}

cmds.List()
cmds.Get("vault://system/jwt_secret")
cmds.Set("vault://system/jwt_secret", "newsecret", keepcmd.SetOptions{})
cmds.Rotate(newPassphraseBytes)    // caller resolved the passphrase — no prompter dependency
cmds.RotateSalt(currentPassBytes)  // same
```

`keepcmd` never calls `prompter` or reads from stdin. Passphrase resolution
is entirely the caller's responsibility — this keeps the package safe in
headless server contexts.

`NoClose: true` prevents `Commands` from calling `store.Close()` after each
operation. Use this in REPL / session contexts where one store is shared
across many calls.

---

## x/keephandler

`x/keephandler` mounts keeper HTTP endpoints on any `net/http` mux. No
external router dependency — it uses Go 1.22+ method+pattern routing with
stdlib `http.ServeMux`.

```go
import "github.com/agberohq/keeper/x/keephandler"

keephandler.Mount(mux, store,
    keephandler.WithPrefix("/api/keeper"),
    keephandler.WithGuard(func(w http.ResponseWriter, r *http.Request, route string) bool {
        // principal-level access control per route
        if !acl.Allow(r.Header.Get("X-Principal"), route) {
            http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
            return false
        }
        return true
    }),
    keephandler.WithHooks(
        keephandler.Hook{
            Route:       keephandler.RouteGet,
            CaptureBody: false,
            After: func(r *http.Request, status int, _ []byte) {
                audit.Log(r.Context(), route, status)
            },
        },
    ),
    keephandler.WithEncoder(func(w http.ResponseWriter, route string, status int, data any) {
        // custom envelope — add tenant ID, trace ID, etc.
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(status)
        json.NewEncoder(w).Encode(map[string]any{
            "ok":    status < 400,
            "route": route,
            "data":  data,
        })
    }),
    keephandler.WithRoutes(func(m *http.ServeMux) {
        // application-specific extensions
        m.HandleFunc("POST /api/keeper/totp/{user}", myTOTPHandler)
    }),
)
```

### Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `{prefix}/unlock` | Unlock the store with a passphrase |
| `POST` | `{prefix}/lock` | Lock the store |
| `GET` | `{prefix}/status` | Lock state — safe to poll without auth |
| `GET` | `{prefix}/keys` | List all secret keys |
| `GET` | `{prefix}/keys/{key}` | Retrieve a secret value |
| `POST` | `{prefix}/keys` | Store a secret (JSON or multipart) |
| `DELETE` | `{prefix}/keys/{key}` | Delete a secret |
| `POST` | `{prefix}/rotate` | Rotate the master passphrase |
| `POST` | `{prefix}/rotate/salt` | Rotate the KDF salt |
| `GET` | `{prefix}/backup` | Stream a database snapshot |

### Hook contract

`BeforeFunc` returns `(allow bool, err error)`.

- `(true, nil)` — let the request proceed.
- `(false, nil)` — abort; the hook has already written a complete response.
- `(false, err)` — abort; the framework writes a `500` using `err.Error()`.
  The hook must **not** have written anything to `w`.

`Hook.CaptureBody bool` controls whether `AfterFunc` receives the response
body. `false` (default) costs one lightweight `statusWriter` wrapper;
`true` buffers the full body into a `bytes.Buffer` for the `AfterFunc` — one
allocation per request.

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
defer store.Close()

// Shorthand (wraps DeriveMaster + UnlockDatabase):
if err := store.Unlock([]byte(os.Getenv("KEEPER_PASSPHRASE"))); err != nil {
    log.Fatal(err) // ErrInvalidPassphrase on wrong passphrase
}
```

If the process crashed mid-rotation on a previous run, `UnlockDatabase`
detects the WAL, recovers the old key from `WrappedOldKey`, and completes the
remaining records automatically before proceeding.

### LevelPasswordOnly bucket — full lifecycle

```go
err := store.CreateBucket("vault", "system", keeper.LevelPasswordOnly, "init")

store.Set("vault://system/jwt_secret", []byte("supersecret"))
val, err := store.Get("vault://system/jwt_secret")

// Namespaced convenience wrappers
store.SetNamespaced("admin", "jwt_secret", secretBytes)
val, err = store.GetNamespaced("admin", "jwt_secret")
```

### LevelAdminWrapped bucket — full lifecycle

```go
err := store.CreateBucket("finance", "payroll", keeper.LevelAdminWrapped, "ops-team")
err = store.AddAdminToPolicy("finance", "payroll", "alice", []byte("alicepass"))

store.SetNamespacedFull("finance", "payroll", "salary_key", []byte("AES256..."))

store.LockBucket("finance", "payroll")
err = store.UnlockBucket("finance", "payroll", "bob", []byte("bobpass"))
// ErrAuthFailed — does not distinguish wrong password from unknown admin (CWE-204)

err = store.RevokeAdmin("finance", "payroll", "alice")
err = store.RotateAdminWrappedDEK("finance", "payroll", "bob", []byte("bobpass"))

needs, err := store.NeedsAdminRekey("finance", "payroll")
```

### LevelHSM / LevelRemote buckets

```go
import (
    "github.com/agberohq/keeper/pkg/hsm"
    "github.com/agberohq/keeper/pkg/remote"
)

// SoftHSM — testing only
provider, _ := hsm.NewSoftHSM()
store.RegisterHSMProvider("secure", "keys", provider)
store.CreateBucket("secure", "keys", keeper.LevelHSM, "ops")

// Vault Transit
cfg := remote.VaultTransit("https://vault.corp:8200", vaultToken, "my-key")
cfg.TLSClientCert = "/etc/keeper/client.crt"
cfg.TLSClientKey  = "/etc/keeper/client.key"
provider, _ = remote.New(cfg)
store.RegisterHSMProvider("tenant", "secrets", provider)
store.CreateBucket("tenant", "secrets", keeper.LevelRemote, "ops")
```

### Key rotation

```go
// Rotate passphrase — crash-safe WAL, resumes on next Unlock if interrupted
store.Rotate([]byte("new-passphrase"))

// Rotate KDF salt — re-derives master key, re-encrypts LevelPasswordOnly
store.RotateSalt([]byte("current-passphrase"))
```

### Compare-and-swap

```go
err := store.CompareAndSwapNamespacedFull("vault", "system", "counter",
    []byte("old"), []byte("new"))
// ErrCASConflict if current value does not match old
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
| `ErrInvalidPassphrase` | Wrong master passphrase |
| `ErrAuthFailed` | Any `UnlockBucket` failure — does not distinguish wrong password from unknown admin ID (CWE-204) |
| `ErrKeyNotFound` | Secret key does not exist |
| `ErrBucketLocked` | Bucket has not been unlocked |
| `ErrPolicyImmutable` | Second policy for an existing bucket |
| `ErrPolicyNotFound` | No policy for the given scheme/namespace |
| `ErrAdminNotFound` | Admin ID not in policy — `RevokeAdmin` only |
| `ErrHSMProviderNil` | HSM/Remote bucket created without a registered provider |
| `ErrCheckLatency` | DB read latency exceeded `DBLatencyThreshold` |
| `ErrCASConflict` | Current value does not match expected in `CompareAndSwap` |
| `ErrSecurityDowngrade` | Cross-bucket move from higher to lower security level |
| `ErrAlreadyUnlocked` | `UnlockDatabase` called on an already-unlocked store |
| `ErrMasterRequired` | `UnlockDatabase` called with nil or destroyed `Master` |
| `ErrChainBroken` | Audit chain integrity verification failed |
| `ErrMetadataDecrypt` | Encrypted metadata could not be decrypted |
| `ErrPolicySignature` | Policy HMAC verification failed — record was tampered |

---

## Security decisions

**ErrAuthFailed unifies all UnlockBucket failures (CWE-204 / CVSS 5.3).** Both
an unknown admin ID and a wrong password return `ErrAuthFailed`. This prevents
admin ID enumeration by timing or error-string comparison. `RevokeAdmin` retains
`ErrAdminNotFound` because it is an administrative operation on an
already-unlocked store.

**Argon2id dominates timing.** Argon2id takes 200–500 ms on typical hardware.
Post-derivation comparison differences are four or more orders of magnitude
smaller and are not measurable remotely. No artificial equalisation is applied.

**DEK retrieved inside the CAS transaction boundary.** `CompareAndSwapNamespacedFull`
retrieves the bucket DEK inside the bbolt write transaction, eliminating the
window where a concurrent `Rotate` could change the DEK between retrieval and
use.

**Passphrase never stored as a Go string in the HTTP handler.** All three
passphrase fields (`passphrase`, `new_passphrase`) are decoded from JSON
directly into `[]byte` via raw-map extraction, keeping the string backing array
off the long-lived heap. The `[]byte` copy is zeroed with `wipeBytes` after use.

**No `--passphrase` flag in the CLI.** Flags appear in `ps` output and shell
history. The CLI accepts the passphrase only from `KEEPER_PASSPHRASE` env or
an interactive no-echo prompt.

**REPL secret values are never visible.** `set <key>` in the REPL uses
`term.ReadPassword` for the value — it does not appear in terminal scrollback,
shell history, or `ps`.

**LevelHSM and LevelRemote buckets skipped during master key rotation.**
`reencryptAllWithKey` and `RotateSalt` explicitly skip these buckets. The DEK
is provider-controlled; master salt rotation does not affect it.

**Crash-safe rotation with WrappedOldKey.** `Rotate` writes a WAL before
touching any record. The WAL carries `WrappedOldKey`: the pre-rotation master
key encrypted with the new master key. After a crash, `UnlockDatabase` decrypts
`WrappedOldKey` using the verified new key and resumes rotation from the cursor.
