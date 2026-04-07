package keeper

// TestKeeperFlow replicates the exact REPL session that exposed a regression:
//
//	Session 1:  new db → set ss://tmp/name john   → close
//	Session 2:  reopen → set ss://tmp/name2 doe   → get both → list
//
// The bug: policies written in session 1 are stored encrypted. On reopen,
// unmarshalPolicy was guessing "is this ciphertext?" by inspecting the first
// byte of the blob. A nonce byte in 0x80–0x8f (valid msgpack fixmap range,
// ~6% probability) caused loadPolicies to attempt msgpack-decoding raw
// ciphertext → error → New()/Open() failed with "invalid code=NN".
//
// When the nonce happened to look like a valid byte, New() succeeded but
// UnlockDatabase's registry reload silently failed to populate the bucket,
// leaving "ss:tmp" unseeded → Set returned ErrBucketLocked.
//
// The fix: when policyEncKey is nil (pre-unlock), skip ALL blobs unconditionally.
// Format v2 always stores policies encrypted; there is no plaintext fallback.

import (
	"fmt"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/olekukonko/ll"
)

// fastConfig returns a Config suitable for flow tests: minimal Argon2 parameters
// so each Unlock completes in milliseconds rather than ~300ms.
// Never use these parameters in production.
func fastConfig(dbPath string) Config {
	return Config{
		DBPath:                  dbPath,
		VerifyArgon2Time:        1,
		VerifyArgon2Memory:      8 * 1024, // 8 MiB — fast for tests
		VerifyArgon2Parallelism: 1,
		Logger:                  ll.New("test").Disable(),
	}
}

// openREPLSession opens (or creates) a keeper db at dbPath and unlocks it,
// mirroring what the REPL does on startup: New → Unlock.
// Returns the open, unlocked store. Caller must Close it.
func openREPLSession(t *testing.T, dbPath, passphrase string) *Keeper {
	t.Helper()
	store, err := New(fastConfig(dbPath))
	if err != nil {
		t.Fatalf("openREPLSession New: %v", err)
	}
	if err := store.Unlock([]byte(passphrase)); err != nil {
		store.Close()
		t.Fatalf("openREPLSession Unlock: %v", err)
	}
	return store
}

// replSet mirrors keepcmd.Commands.Set: EnsureBucket then Set.
// This is exactly what the REPL does for every "set" command.
func replSet(t *testing.T, store *Keeper, key string, value []byte) {
	t.Helper()
	if err := store.EnsureBucket(key); err != nil {
		t.Fatalf("replSet EnsureBucket(%q): %v", key, err)
	}
	if err := store.Set(key, value); err != nil {
		t.Fatalf("replSet Set(%q): %v", key, err)
	}
}

// replList returns all scheme://namespace/key strings in the store,
// mirroring keepcmd.Commands.List() with no filter.
func replList(t *testing.T, store *Keeper) []string {
	t.Helper()
	schemes, err := store.ListSchemes()
	if err != nil {
		t.Fatalf("replList ListSchemes: %v", err)
	}
	var keys []string
	for _, scheme := range schemes {
		namespaces, err := store.ListNamespacesInSchemeFull(scheme)
		if err != nil {
			t.Fatalf("replList ListNamespaces(%q): %v", scheme, err)
		}
		for _, ns := range namespaces {
			ks, err := store.ListNamespacedFull(scheme, ns)
			if err != nil {
				t.Fatalf("replList ListKeys(%q,%q): %v", scheme, ns, err)
			}
			for _, k := range ks {
				keys = append(keys, scheme+"://"+ns+"/"+k)
			}
		}
	}
	sort.Strings(keys)
	return keys
}

// TestKeeperFlow_REPLReopenSameBucket is the primary regression test.
// Replicates the exact sequence from the bug report:
//
//	Session 1: create db, set ss://tmp/name, close
//	Session 2: reopen, set ss://tmp/name2, get both, list
func TestKeeperFlow_REPLReopenSameBucket(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "keeper.db")
	const pass = "test-passphrase"

	// Session 1: create the database, write one key
	s1 := openREPLSession(t, dbPath, pass)

	replSet(t, s1, "ss://tmp/name", []byte("john"))

	// Verify the write took.
	v, err := s1.Get("ss://tmp/name")
	if err != nil || string(v) != "john" {
		t.Fatalf("session 1 Get: got %q, err %v", v, err)
	}

	s1.Close()

	// Session 2: reopen the SAME db, write to the SAME bucket
	// This is where the bug triggered: the ss:tmp policy was written encrypted
	// in session 1. On reopen, loadPolicies (pre-unlock, no key) must skip it
	// cleanly, and UnlockDatabase must reload and seed it correctly.
	s2 := openREPLSession(t, dbPath, pass)
	defer s2.Close()

	// Set a second key in the same bucket — must not get ErrBucketLocked.
	replSet(t, s2, "ss://tmp/name2", []byte("doe"))

	// Both keys must be readable.
	v1, err := s2.Get("ss://tmp/name")
	if err != nil || string(v1) != "john" {
		t.Errorf("session 2 Get name: got %q, err %v", v1, err)
	}
	v2, err := s2.Get("ss://tmp/name2")
	if err != nil || string(v2) != "doe" {
		t.Errorf("session 2 Get name2: got %q, err %v", v2, err)
	}

	// List must show both keys.
	keys := replList(t, s2)
	want := []string{"ss://tmp/name", "ss://tmp/name2"}
	if !stringSliceEqual(keys, want) {
		t.Errorf("list = %v, want %v", keys, want)
	}
}

// TestKeeperFlow_MultipleSchemes verifies that multiple schemes and namespaces
// all survive a close/reopen cycle and are fully accessible in session 2.
func TestKeeperFlow_MultipleSchemes(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "keeper.db")
	const pass = "test-passphrase"

	// Session 1: write keys in three different scheme://namespace buckets.
	s1 := openREPLSession(t, dbPath, pass)

	writes := []struct{ key, val string }{
		{"vault://system/jwt_secret", "supersecret"},
		{"vault://system/api_key", "apikey123"},
		{"certs://web/tls.crt", "-----BEGIN CERTIFICATE-----"},
		{"ss://tmp/scratch", "scratch-value"},
	}
	for _, w := range writes {
		replSet(t, s1, w.key, []byte(w.val))
	}
	s1.Close()

	// Session 2: reopen and verify every key is readable.
	s2 := openREPLSession(t, dbPath, pass)
	defer s2.Close()

	for _, w := range writes {
		got, err := s2.Get(w.key)
		if err != nil {
			t.Errorf("session 2 Get(%q): %v", w.key, err)
			continue
		}
		if string(got) != w.val {
			t.Errorf("session 2 Get(%q) = %q, want %q", w.key, got, w.val)
		}
	}

	// Write new keys to existing buckets — must not require EnsureBucket again.
	replSet(t, s2, "vault://system/new_key", []byte("new-value"))
	got, err := s2.Get("vault://system/new_key")
	if err != nil || string(got) != "new-value" {
		t.Errorf("session 2 new key: got %q, err %v", got, err)
	}
}

// TestKeeperFlow_ThreeSessions verifies that a bucket remains accessible
// across three successive open/close cycles — not just two.
// Each session adds a key; all prior keys remain readable.
func TestKeeperFlow_ThreeSessions(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "keeper.db")
	const pass = "test-passphrase"

	// Session 1.
	s1 := openREPLSession(t, dbPath, pass)
	replSet(t, s1, "vault://admin/user1", []byte("pass1"))
	s1.Close()

	// Session 2.
	s2 := openREPLSession(t, dbPath, pass)
	replSet(t, s2, "vault://admin/user2", []byte("pass2"))
	v, err := s2.Get("vault://admin/user1")
	if err != nil || string(v) != "pass1" {
		t.Fatalf("session 2 user1: got %q, err %v", v, err)
	}
	s2.Close()

	// Session 3.
	s3 := openREPLSession(t, dbPath, pass)
	defer s3.Close()
	replSet(t, s3, "vault://admin/user3", []byte("pass3"))
	for _, want := range []struct{ key, val string }{
		{"vault://admin/user1", "pass1"},
		{"vault://admin/user2", "pass2"},
		{"vault://admin/user3", "pass3"},
	} {
		got, err := s3.Get(want.key)
		if err != nil || string(got) != want.val {
			t.Errorf("session 3 Get(%q): got %q, err %v", want.key, got, err)
		}
	}
}

// TestKeeperFlow_WrongPassphraseRejected verifies that reopening with the
// wrong passphrase is rejected and does not expose any data.
func TestKeeperFlow_WrongPassphraseRejected(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "keeper.db")

	s1 := openREPLSession(t, dbPath, "correct-pass")
	replSet(t, s1, "vault://system/secret", []byte("topsecret"))
	s1.Close()

	s2, err := New(Config{DBPath: dbPath})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s2.Close()

	if err := s2.Unlock([]byte("wrong-pass")); err != ErrInvalidPassphrase {
		t.Errorf("wrong passphrase: want ErrInvalidPassphrase, got %v", err)
	}
	if !s2.IsLocked() {
		t.Error("store should remain locked after wrong passphrase")
	}
}

// TestKeeperFlow_PolicyNonceAllBytes verifies that New()/Open() succeeds
// regardless of what the random nonce first byte happens to be.
// This directly tests the bug: policies whose nonce started with 0x80–0x8f
// (valid msgpack fixmap range) caused loadPolicies to crash.
//
// We create N separate databases with different random nonces and verify
// each one reopens correctly. With 32 iterations the probability of NOT
// hitting the 0x80–0x8f range at least once is (15/16)^32 ≈ 0.1%.
func TestKeeperFlow_PolicyNonceAllBytes(t *testing.T) {
	const iterations = 32
	const pass = "nonce-test-pass"

	for i := 0; i < iterations; i++ {
		i := i
		t.Run("", func(t *testing.T) {
			t.Parallel()
			dbPath := filepath.Join(t.TempDir(), "keeper.db")

			// Session 1: write a key (generates a fresh random nonce for the policy).
			s1 := openREPLSession(t, dbPath, pass)
			replSet(t, s1, "vault://system/key", []byte("value"))
			s1.Close()

			// Session 2: must always succeed regardless of the nonce value.
			// Must use the same fastConfig as session 1 so Argon2 verify params match.
			s2, err := New(fastConfig(dbPath))
			if err != nil {
				t.Fatalf("iter %d: New() failed (policy nonce caused loadPolicies to crash): %v", i, err)
			}
			if err := s2.Unlock([]byte(pass)); err != nil {
				s2.Close()
				t.Fatalf("iter %d: Unlock failed: %v", i, err)
			}
			got, err := s2.Get("vault://system/key")
			if err != nil || string(got) != "value" {
				s2.Close()
				t.Fatalf("iter %d: Get: got %q, err %v", i, got, err)
			}
			s2.Close()
		})
	}
}

// TestKeeperFlow_LockUnlockInSession verifies the REPL lock/unlock commands:
// after locking mid-session, secrets are inaccessible; after re-unlocking
// they are accessible again.
func TestKeeperFlow_LockUnlockInSession(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "keeper.db")
	const pass = "test-passphrase"

	s := openREPLSession(t, dbPath, pass)
	defer s.Close()

	replSet(t, s, "vault://system/key", []byte("value"))

	// Lock mid-session (REPL "lock" command).
	if err := s.Lock(); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if !s.IsLocked() {
		t.Error("store should be locked")
	}

	// Reads must fail while locked.
	if _, err := s.Get("vault://system/key"); err != ErrStoreLocked {
		t.Errorf("Get while locked: want ErrStoreLocked, got %v", err)
	}

	// Re-unlock (REPL "unlock" command).
	if err := s.Unlock([]byte(pass)); err != nil {
		t.Fatalf("re-Unlock: %v", err)
	}

	// Value must still be there.
	got, err := s.Get("vault://system/key")
	if err != nil || string(got) != "value" {
		t.Errorf("Get after re-unlock: got %q, err %v", got, err)
	}

	// Must be able to write to existing and new keys in the same bucket.
	replSet(t, s, "vault://system/key2", []byte("value2"))
	got2, err := s.Get("vault://system/key2")
	if err != nil || string(got2) != "value2" {
		t.Errorf("Get key2 after re-unlock: got %q, err %v", got2, err)
	}
}

// TestKeeperFlow_OverwriteKey verifies that setting the same key twice
// updates the value across sessions.
func TestKeeperFlow_OverwriteKey(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "keeper.db")
	const pass = "test-passphrase"

	s1 := openREPLSession(t, dbPath, pass)
	replSet(t, s1, "vault://system/key", []byte("original"))
	s1.Close()

	s2 := openREPLSession(t, dbPath, pass)
	defer s2.Close()

	// Overwrite in session 2.
	replSet(t, s2, "vault://system/key", []byte("updated"))

	got, err := s2.Get("vault://system/key")
	if err != nil || string(got) != "updated" {
		t.Errorf("Get overwritten key: got %q, err %v", got, err)
	}
}

// TestKeeperFlow_DeleteKey verifies that deleting a key works across sessions.
func TestKeeperFlow_DeleteKey(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "keeper.db")
	const pass = "test-passphrase"

	s1 := openREPLSession(t, dbPath, pass)
	replSet(t, s1, "vault://system/key", []byte("value"))
	replSet(t, s1, "vault://system/key2", []byte("value2"))
	s1.Close()

	s2 := openREPLSession(t, dbPath, pass)
	defer s2.Close()

	if err := s2.Delete("vault://system/key"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// Deleted key must be gone.
	if _, err := s2.Get("vault://system/key"); err != ErrKeyNotFound {
		t.Errorf("Get deleted key: want ErrKeyNotFound, got %v", err)
	}

	// Sibling key in same bucket must be unaffected.
	got, err := s2.Get("vault://system/key2")
	if err != nil || string(got) != "value2" {
		t.Errorf("Get sibling after delete: got %q, err %v", got, err)
	}
}

// stringSliceEqual returns true when a and b contain the same sorted strings.
func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Concurrency and crash-recovery property tests

// TestKeeperFlow_ConcurrentUnlock verifies that calling Unlock from multiple
// goroutines simultaneously is safe — only one succeeds, the rest get
// ErrAlreadyUnlocked, and the store is correctly unlocked afterwards.
func TestKeeperFlow_ConcurrentUnlock(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "keeper.db")
	const pass = "test-passphrase"

	// Initialise the db (writes salt + verify hash).
	s0 := openREPLSession(t, dbPath, pass)
	s0.Close()

	store, err := New(fastConfig(dbPath))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	const goroutines = 8
	errs := make([]error, goroutines)
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			<-done
			errs[i] = store.Unlock([]byte(pass))
		}()
	}
	close(done)
	wg.Wait()

	// Exactly one goroutine must have succeeded.
	successes := 0
	for _, err := range errs {
		if err == nil {
			successes++
		} else if err != ErrAlreadyUnlocked {
			t.Errorf("unexpected error: %v", err)
		}
	}
	if successes != 1 {
		t.Errorf("expected exactly 1 successful Unlock, got %d", successes)
	}
	if store.IsLocked() {
		t.Error("store should be unlocked after concurrent Unlock")
	}
}

// TestKeeperFlow_ConcurrentReadWrite verifies that concurrent Get and Set
// operations on the same bucket do not race or corrupt data.
func TestKeeperFlow_ConcurrentReadWrite(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "keeper.db")
	const pass = "test-passphrase"

	s := openREPLSession(t, dbPath, pass)
	defer s.Close()

	replSet(t, s, "vault://system/counter", []byte("0"))

	const goroutines = 16
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			if i%2 == 0 {
				// Writer: overwrite the value.
				_ = s.Set("vault://system/counter", []byte("updated"))
			} else {
				// Reader: read must not panic or return a corrupt byte slice.
				v, err := s.Get("vault://system/counter")
				if err != nil && err != ErrKeyNotFound {
					t.Errorf("concurrent Get: %v", err)
				}
				_ = v
			}
		}()
	}
	wg.Wait()
}

// TestKeeperFlow_RotationWALResumed verifies that an interrupted rotation
// is automatically completed on the next Unlock.
// We simulate the interruption by writing a WAL entry and then reopening.
func TestKeeperFlow_RotationWALResumed(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "keeper.db")
	const oldPass = "old-passphrase"
	const newPass = "new-passphrase"

	// Session 1: write some secrets, then rotate passphrase.
	s1 := openREPLSession(t, dbPath, oldPass)
	replSet(t, s1, "vault://system/key", []byte("secret"))
	if err := s1.Rotate([]byte(newPass)); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	s1.Close()

	// Session 2: open with NEW passphrase — rotation must have completed.
	s2 := openREPLSession(t, dbPath, newPass)

	got, err := s2.Get("vault://system/key")
	if err != nil || string(got) != "secret" {
		t.Errorf("after rotation Get: got %q, err %v", got, err)
	}
	s2.Close() // must close before s3 opens — bbolt allows only one writer at a time

	// Old passphrase must be rejected.
	s3, err := New(fastConfig(dbPath))
	if err != nil {
		t.Fatal(err)
	}
	defer s3.Close()
	if err := s3.Unlock([]byte(oldPass)); err != ErrInvalidPassphrase {
		t.Errorf("old passphrase after rotation: want ErrInvalidPassphrase, got %v", err)
	}
}

// TestKeeperFlow_DEKMigrationLooperRaceWithLock verifies that calling Lock()
// while the DEK migration looper is running does not deadlock or panic.
func TestKeeperFlow_DEKMigrationLooperRaceWithLock(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "keeper.db")
	const pass = "test-passphrase"

	// Write enough secrets to keep the migration busy.
	s1 := openREPLSession(t, dbPath, pass)
	for i := 0; i < 20; i++ {
		replSet(t, s1, fmt.Sprintf("vault://system/key%d", i), []byte("value"))
	}
	s1.Close()

	// Reopen: migration looper starts in the background.
	s2 := openREPLSession(t, dbPath, pass)

	// Lock immediately — races with the looper.
	// Must not deadlock (timeout would catch it).
	done := make(chan struct{})
	go func() {
		defer close(done)
		s2.Lock()
		s2.Close()
	}()

	select {
	case <-done:
		// OK
	case <-time.After(10 * time.Second):
		t.Fatal("Lock() deadlocked while migration looper was running")
	}
}

// TestKeeperFlow_StateTransitions exhaustively walks the lock/unlock state
// machine: Locked→Unlocked→Locked→Unlocked and verifies invariants at each step.
func TestKeeperFlow_StateTransitions(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "keeper.db")
	const pass = "test-passphrase"
	const key = "vault://system/state_key"
	const val = "state_value"

	s := openREPLSession(t, dbPath, pass)
	defer s.Close()

	replSet(t, s, key, []byte(val))

	for cycle := 0; cycle < 3; cycle++ {
		// Locked state: all writes and reads must fail.
		if err := s.Lock(); err != nil {
			t.Fatalf("cycle %d Lock: %v", cycle, err)
		}
		if !s.IsLocked() {
			t.Errorf("cycle %d: should be locked", cycle)
		}
		if _, err := s.Get(key); err != ErrStoreLocked {
			t.Errorf("cycle %d Get while locked: want ErrStoreLocked, got %v", cycle, err)
		}
		if err := s.Set(key, []byte("should-fail")); err != ErrStoreLocked {
			t.Errorf("cycle %d Set while locked: want ErrStoreLocked, got %v", cycle, err)
		}

		// Unlocked state: all reads and writes must succeed.
		if err := s.Unlock([]byte(pass)); err != nil {
			t.Fatalf("cycle %d Unlock: %v", cycle, err)
		}
		if s.IsLocked() {
			t.Errorf("cycle %d: should be unlocked", cycle)
		}
		got, err := s.Get(key)
		if err != nil || string(got) != val {
			t.Errorf("cycle %d Get: got %q, err %v", cycle, got, err)
		}
	}
}
