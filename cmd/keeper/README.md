# keeper CLI

A terminal interface to a keeper encrypted secret store. Secrets are encrypted
at rest and stored in a local bbolt database. The passphrase never appears as a
command-line argument and is never written to disk.

---

## Installation

```sh
go install github.com/agberohq/keeper/cmd/keeper@latest
```

Or build from source:

```sh
git clone https://github.com/agberohq/keeper
cd keeper
go build ./cmd/keeper        # binary in ./keeper
go install ./cmd/keeper      # binary in $GOBIN
```

> **Do not** run `go run main.go` — the package spans multiple files.
> Use `go run ./cmd/keeper` or build first.

---

## Key format

Keeper uses a `scheme://namespace/key` addressing model. Every secret lives in
a named bucket identified by its scheme and namespace:

```
ss://tmp/name          scheme=ss, namespace=tmp, key=name
vault://system/jwt     scheme=vault, namespace=system, key=jwt
certs://web/tls.crt    scheme=certs, namespace=web, key=tls.crt
```

You can also use bare keys (no `://`), in which case keeper routes them to the
default bucket. All `ls`, `get`, `set`, and `delete` commands accept both forms.

---

## Database location

The CLI resolves the database path in this order:

1. `--db <path>` flag
2. `KEEPER_DB` environment variable
3. A single `*.db` file found in the current directory (auto-selected)
4. Multiple `*.db` files — a numbered menu lets you pick one
5. No `*.db` files — `keeper.db` in the current directory is offered for
   creation (requires confirmation)

When a new database is created the CLI prompts for a passphrase with
confirmation before writing anything to disk.

---

## Passphrase

The passphrase is resolved in this order:

1. `KEEPER_PASSPHRASE` environment variable (for scripted / non-interactive use)
2. Secure terminal prompt — no echo, not recorded in shell history

A passphrase is **never** accepted as a command-line flag. Flags appear in
`ps` output and shell history; passphrases must not.

---

## Non-interactive (subcommand) mode

```
keeper [--db <path>] <command> [args]
```

| Command | Alias | Description |
|---|---|---|
| `list` | `ls` | List all secret keys |
| `get <key>` | `cat <key>` | Print the value for key |
| `set <key> [value]` | `put <key> [value]` | Store a secret. Omit value to read from `--file` |
| `delete <key>` | `rm <key>` | Remove a key (prompts for confirmation unless `--force`) |
| `rotate` | | Change the master passphrase |
| `rotate-salt` | | Rotate the KDF salt (re-encrypts all secrets) |
| `backup` | | Stream a database snapshot to a file |
| `status` | | Print whether the store is locked or unlocked |

### Examples

```sh
# Store a secret (value on command line)
keeper set ss://tmp/name john

# Store a secret (value prompted with no echo)
keeper set vault://system/jwt_secret

# Read it back
keeper get vault://system/jwt_secret

# Store from a file (e.g. a TLS certificate)
keeper set certs://web/tls.crt --file ./tls.crt

# Store a base64-encoded value
keeper set vault://system/aes_key --base64 "$(base64 < /dev/urandom | head -c 44)"

# List all keys (output: scheme://namespace/key)
keeper ls

# List keys in a specific scheme
keeper ls vault

# List keys in a specific bucket
keeper ls vault system

# Delete a key
keeper delete ss://tmp/name

# Delete without confirmation prompt
keeper delete --force ss://tmp/name

# Backup
keeper backup --out /var/backup/keeper-$(date +%Y%m%d).db

# Scripted unlock via environment
KEEPER_PASSPHRASE=mysecret keeper ls
```

---

## Interactive (REPL) session

Run `keeper` with no subcommand on a terminal to enter the session REPL. The
store is unlocked **once** at session start; you never re-enter your passphrase
between commands.

```
$ keeper
keeper — ./keeper.db  (help for commands, quit to exit)

keeper> set ss://tmp/name john
✓ stored "ss://tmp/name" (4 bytes)

keeper> set vault://system/jwt_secret
Value for vault://system/jwt_secret (hidden):
✓ stored "vault://system/jwt_secret" (32 bytes)

keeper> ls
Key
──────────────────────────────────────
ss://tmp/name
vault://system/jwt_secret

keeper> get ss://tmp/name
ss://tmp/name: john

keeper> get "vault://system/jwt_secret"
vault://system/jwt_secret: supersecret

keeper> ls ss
Key
──────────────────────────
ss://tmp/name

keeper> ls vault system
Key
──────────────────────────────────────
jwt_secret

keeper> status
  store is unlocked

keeper> lock
  store locked — use 'unlock' to resume

keeper> unlock
Passphrase:
keeper> status
  store is unlocked

keeper> rotate
New passphrase:
Confirm new passphrase:
✓ passphrase rotated

keeper> quit
bye
```

### Session commands

| Command | Aliases | Description |
|---|---|---|
| `ls [scheme] [ns]` | `list` | List keys — all, by scheme, or by bucket |
| `get <key>` | `cat <key>` | Print a secret value |
| `set <key> [value]` | `put <key> [value]` | Store a secret. Omit value to prompt with no echo |
| `delete <key>` | `rm`, `del` | Remove a key (asks for confirmation) |
| `status` | | Show live lock state |
| `lock` | | Drop keys from memory (store stays open) |
| `unlock` | | Re-unlock after a `lock` (prompts for passphrase) |
| `backup [dest]` | | Write a database snapshot (auto-names if dest omitted) |
| `rotate` | | Change the master passphrase (prompts interactively) |
| `rotate-salt` | | Rotate the KDF salt |
| `clear` | | Clear the terminal screen |
| `help`, `?` | | Show command list |
| `quit` | `exit`, `q` | End the session |

### Notes on secret values in the REPL

`set <key>` without an inline value prompts for it with **no echo** using
`term.ReadPassword`. The value is never written to terminal scrollback, shell
history, or `ps` output.

`set <key> <value>` accepts an inline value directly — useful for non-sensitive
data or when piping from scripts. Multiple words are joined with a space, so
`set key hello world` stores `"hello world"`.

Surrounding quotes are stripped from arguments, so `get "vault://system/key"`
and `get vault://system/key` are identical.

### Muscle-memory convenience

If you type `keeper ls` inside the REPL the leading `keeper` token is silently
stripped and `ls` runs normally.

---

## Encryption model

Keeper uses a layered encryption model:

| Layer | What is encrypted | Key |
|---|---|---|
| Secret values | Every secret value | Per-bucket DEK derived from master key |
| Bucket policies | Scheme, namespace, security level, wrapped DEKs | `policyEncKey` (HKDF from master) |
| Audit events | Scheme, namespace, details fields | `auditEncKey` (HKDF from master) |
| Audit HMAC | Tamper-evidence tag on every event | Audit signing key (HKDF from master) |

The master key is derived from your passphrase using Argon2id with a random
salt stored in the database. All encryption uses XChaCha20-Poly1305 by default
(AES-256-GCM in FIPS mode). Nonces are random and never reused.

### Security levels

| Level | Description |
|---|---|
| `LevelPasswordOnly` | DEK derived from master key — unlocks automatically at `Unlock` |
| `LevelAdminWrapped` | DEK wrapped per-admin with Argon2id KEK — requires `UnlockBucket` |
| `LevelHSM` / `LevelRemote` | DEK managed by an external HSM or remote provider |

---

## Security notes

**Never store the passphrase in shell history.** Use `KEEPER_PASSPHRASE` for
scripted access, or rely on the interactive prompt. The flag interface
deliberately has no `--passphrase` option.

**Rotate the passphrase periodically.** `rotate` re-encrypts all
`LevelPasswordOnly` secrets under the new key using a crash-safe write-ahead
log. If the process dies mid-rotation, the next `Unlock` resumes automatically.

**Rotate the KDF salt after a database file compromise.** `rotate-salt`
generates a new Argon2id salt, re-derives the master key, and re-encrypts all
`LevelPasswordOnly` secrets. `LevelAdminWrapped` buckets need a follow-up
`RotateAdminWrappedDEK` call per admin.

**Backup before rotation.** `backup` streams a consistent bbolt snapshot.
Always take a backup before `rotate` or `rotate-salt` in production.

**Audit chain integrity.** Every operation is appended to an immutable
per-bucket audit chain. The chain can be verified without decryption by anyone
with access to the database file. Holders of the audit key can also verify
HMAC signatures and decrypt event details.