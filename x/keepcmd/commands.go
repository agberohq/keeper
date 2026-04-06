package keepcmd

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/agberohq/keeper"
)

// StoreFactory opens and returns a keeper.Keeper.
// For most operations the store must be unlocked; for Status it may be locked.
// When NoClose is false (the default), Commands calls store.Close() after each
// operation — the store returned by StoreFactory is treated as ephemeral.
// When NoClose is true, Commands never calls Close; the caller owns the
// lifecycle. Use NoClose in REPL / session contexts where one store is shared
// across many operations.
type StoreFactory func() (*keeper.Keeper, error)

// Commands holds all keeper CLI operations. Construct one with a StoreFactory
// and an Output. Neither field may be nil.
type Commands struct {
	// Store is called once per operation to obtain the store.
	Store StoreFactory

	// Out handles all display output.
	Out Output

	// NoClose prevents Commands from calling store.Close() after each
	// operation. Set this to true when the caller owns the store lifecycle
	// (e.g. a REPL session that opens the store once and reuses it).
	NoClose bool

	// Bucket selects the named bucket for Get/Set/Delete/List operations.
	// Empty string means the default bucket (keeper's DefaultScheme /
	// DefaultNamespace). Set this to route operations to a specific bucket
	// without changing the key strings themselves.
	//
	// For path-based keys ("vault://system/jwt_secret") the CLI layer should
	// parse the scheme and namespace out of the key string and set this field
	// before calling the operation.
	Bucket string
}

// open calls the StoreFactory and returns the store.
// If NoClose is false it also returns a cleanup function that closes the store;
// if NoClose is true the cleanup is a no-op.
func (c *Commands) open() (*keeper.Keeper, func(), error) {
	store, err := c.Store()
	if err != nil {
		return nil, nil, err
	}
	if c.NoClose {
		return store, func() {}, nil
	}
	return store, func() { store.Close() }, nil
}

// List prints secret keys.
//
//	List()          — all keys across every scheme and namespace
//	List(scheme)    — all keys in every namespace of that scheme
//	List(scheme,ns) — all keys in the specific bucket
func (c *Commands) List(filter ...string) error {
	store, cleanup, err := c.open()
	if err != nil {
		return err
	}
	defer cleanup()

	var rows [][]string

	switch len(filter) {
	case 0:
		// All schemes → all namespaces → all keys.
		schemes, err := store.ListSchemes()
		if err != nil {
			return fmt.Errorf("list schemes: %w", err)
		}
		for _, scheme := range schemes {
			namespaces, err := store.ListNamespacesInSchemeFull(scheme)
			if err != nil {
				return fmt.Errorf("list namespaces in %s: %w", scheme, err)
			}
			for _, ns := range namespaces {
				keys, err := store.ListNamespacedFull(scheme, ns)
				if err != nil {
					return fmt.Errorf("list %s/%s: %w", scheme, ns, err)
				}
				for _, k := range keys {
					rows = append(rows, []string{scheme + "/" + ns + "/" + k})
				}
			}
		}
	case 1:
		// One scheme → all its namespaces → all keys.
		scheme := filter[0]
		namespaces, err := store.ListNamespacesInSchemeFull(scheme)
		if err != nil {
			return fmt.Errorf("list namespaces in %s: %w", scheme, err)
		}
		for _, ns := range namespaces {
			keys, err := store.ListNamespacedFull(scheme, ns)
			if err != nil {
				return fmt.Errorf("list %s/%s: %w", scheme, ns, err)
			}
			for _, k := range keys {
				rows = append(rows, []string{ns + "/" + k})
			}
		}
	default:
		// Explicit scheme + namespace.
		scheme, ns := filter[0], filter[1]
		keys, err := store.ListNamespacedFull(scheme, ns)
		if err != nil {
			return fmt.Errorf("list %s/%s: %w", scheme, ns, err)
		}
		for _, k := range keys {
			rows = append(rows, []string{k})
		}
	}

	if len(rows) == 0 {
		c.Out.Info("store is empty")
		return nil
	}
	c.Out.Table([]string{"Key"}, rows)
	return nil
}

// Get retrieves and displays the value for key.
func (c *Commands) Get(key string) error {
	if key == "" {
		return fmt.Errorf("key is required")
	}
	store, cleanup, err := c.open()
	if err != nil {
		return err
	}
	defer cleanup()

	val, err := store.Get(key)
	if err != nil {
		return fmt.Errorf("get %q: %w", key, err)
	}
	c.Out.KeyValue(key, string(val))
	return nil
}

// Set stores a value for key according to opts.
func (c *Commands) Set(key, value string, opts SetOptions) error {
	if key == "" {
		return fmt.Errorf("key is required")
	}

	var data []byte
	switch {
	case opts.FromFile != "":
		var err error
		data, err = os.ReadFile(opts.FromFile)
		if err != nil {
			return fmt.Errorf("read file: %w", err)
		}
	case opts.Base64:
		var err error
		data, err = base64.StdEncoding.DecodeString(value)
		if err != nil {
			data, err = base64.URLEncoding.DecodeString(value)
			if err != nil {
				return fmt.Errorf("invalid base64: %w", err)
			}
		}
	default:
		data = []byte(value)
	}

	store, cleanup, err := c.open()
	if err != nil {
		return err
	}
	defer cleanup()

	// Ensure the target bucket exists before writing. EnsureBucket is
	// idempotent — it creates the bucket if absent and ignores
	// ErrPolicyImmutable when it already exists. This lets the CLI write
	// to any scheme/namespace (ss://, vault://, etc.) without requiring
	// an explicit CreateBucket call first.
	if bErr := store.EnsureBucket(key); bErr != nil {
		return fmt.Errorf("ensure bucket for %q: %w", key, bErr)
	}

	if err := store.Set(key, data); err != nil {
		return fmt.Errorf("set %q: %w", key, err)
	}
	c.Out.Success(fmt.Sprintf("stored %q (%d bytes)", key, len(data)))
	return nil
}

// Delete removes key from the store.
// The caller is responsible for obtaining confirmation before calling Delete.
func (c *Commands) Delete(key string) error {
	if key == "" {
		return fmt.Errorf("key is required")
	}
	store, cleanup, err := c.open()
	if err != nil {
		return err
	}
	defer cleanup()

	if err := store.Delete(key); err != nil {
		return fmt.Errorf("delete %q: %w", key, err)
	}
	c.Out.Success(fmt.Sprintf("deleted %q", key))
	return nil
}

// Rotate re-encrypts all LevelPasswordOnly secrets under newPassphrase.
// The store must already be unlocked. newPassphrase is NOT zeroed by this
// method — the caller owns it and must zero it when done.
func (c *Commands) Rotate(newPassphrase []byte) error {
	if len(newPassphrase) == 0 {
		return fmt.Errorf("new passphrase is required")
	}
	store, cleanup, err := c.open()
	if err != nil {
		return err
	}
	defer cleanup()

	if err := store.Rotate(newPassphrase); err != nil {
		return fmt.Errorf("rotate: %w", err)
	}
	c.Out.Success("passphrase rotated")
	return nil
}

// RotateSalt re-derives the master key under a new random KDF salt and
// re-encrypts all LevelPasswordOnly secrets. currentPassphrase is NOT zeroed
// by this method — the caller owns it and must zero it when done.
func (c *Commands) RotateSalt(currentPassphrase []byte) error {
	if len(currentPassphrase) == 0 {
		return fmt.Errorf("current passphrase is required")
	}
	store, cleanup, err := c.open()
	if err != nil {
		return err
	}
	defer cleanup()

	if err := store.RotateSalt(currentPassphrase); err != nil {
		return fmt.Errorf("rotate-salt: %w", err)
	}
	c.Out.Success("KDF salt rotated — LevelAdminWrapped buckets may need RotateAdminWrappedDEK")
	return nil
}

// Backup streams a consistent snapshot of the database to opts.Dest.
// If opts.Dest is empty a timestamped filename is used.
func (c *Commands) Backup(opts BackupOptions) error {
	store, cleanup, err := c.open()
	if err != nil {
		return err
	}
	defer cleanup()

	dest := opts.Dest
	if dest == "" {
		dest = generatedBackupName()
	}

	f, err := os.Create(dest)
	if err != nil {
		return fmt.Errorf("create backup file: %w", err)
	}
	defer f.Close()

	info, err := store.Backup(f)
	if err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	c.Out.Success(fmt.Sprintf("backup written to %s (%d bytes)", dest, info.Bytes))
	return nil
}

// Status prints whether the store is locked or unlocked.
func (c *Commands) Status() error {
	store, cleanup, err := c.open()
	if err != nil {
		return err
	}
	defer cleanup()

	if store.IsLocked() {
		c.Out.Info("store is locked")
	} else {
		c.Out.Info("store is unlocked")
	}
	return nil
}
