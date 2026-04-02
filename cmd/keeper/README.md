# keeper CLI

A terminal interface to a keeper encrypted secret store. Secrets are encrypted
at rest and stored in a local database. The passphrase never appears as a command-line argument and is never
written to disk.

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

## Database location

The CLI resolves the database path in this order:

1. `--db <path>` flag
2. `KEEPER_DB` environment variable
3. A single `*.db` file found in the current directory (auto-selected)
4. Multiple `*.db` files found — a numbered menu lets you pick one
5. No `*.db` files found — `keeper.db` in the current directory is offered
   for creation (requires confirmation)

When a new database is created the CLI prompts for a passphrase with
confirmation before writing anything to disk. The first `Unlock` call sets the
verification hash — whatever you type becomes the permanent passphrase.

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
# Store a secret
keeper set vault://system/jwt_secret "supersecret"

# Read it back
keeper get vault://system/jwt_secret

# Store from a file (e.g. a TLS certificate)
keeper set certs://web/tls.crt --file ./tls.crt

# Store a base64-encoded value
keeper set vault://system/aes_key --base64 "$(base64 < /dev/urandom | head -c 44)"

# List all keys
keeper ls

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

keeper> ls
  store is empty

keeper> set jwt_secret
Value for jwt_secret (hidden):
✓ stored "jwt_secret" (32 bytes)

keeper> ls
Key
──────────────────────────────
jwt_secret

keeper> get jwt_secret
jwt_secret: supersecret

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
| `ls` | `list` | List all keys |
| `get <key>` | `cat <key>` | Print a secret value |
| `set <key>` | `put <key>` | Store a secret (value prompted with no echo) |
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

`set <key>` prompts for the value with **no echo** using `term.ReadPassword`.
The value is never written to:

- terminal scrollback
- shell history (`~/.bash_history`, `~/.zsh_history`)
- process argument list (`ps aux`)

This is why `set` takes only the key on the command line. The value is always
read interactively.

### Muscle-memory convenience

If you type `keeper ls` inside the REPL (forgetting you are already in a
session) the leading `keeper` token is silently stripped and `ls` runs
normally.

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