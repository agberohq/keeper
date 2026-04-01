package keeper

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/agberohq/keeper/pkg/crypt"
)

func newTestStore(t testing.TB) *Keeper {
	t.Helper()
	s, err := New(Config{DBPath: filepath.Join(t.TempDir(), "secrets.db")})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func newUnlockedStore(t testing.TB) *Keeper {
	t.Helper()
	s := newTestStore(t)
	if err := s.Unlock([]byte("passphrase")); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	return s
}

func TestNamespacedOperations(t *testing.T) {
	store := newUnlockedStore(t)
	store.CreateBucket("default", "prod", LevelPasswordOnly, "t")
	store.CreateBucket("default", "staging", LevelPasswordOnly, "t")
	store.SetNamespaced("prod", "db/password", []byte("prod-secret"))
	store.SetNamespaced("staging", "db/password", []byte("staging-secret"))
	pv, _ := store.GetNamespaced("prod", "db/password")
	if string(pv) != "prod-secret" {
		t.Errorf("prod = %q", pv)
	}
	sv, _ := store.GetNamespaced("staging", "db/password")
	if string(sv) != "staging-secret" {
		t.Errorf("staging = %q", sv)
	}
}

func TestListPrefixNamespaced(t *testing.T) {
	store := newUnlockedStore(t)
	store.CreateBucket("default", "prod", LevelPasswordOnly, "t")
	store.SetNamespaced("prod", "db/host", []byte("h1"))
	store.SetNamespaced("prod", "db/port", []byte("h2"))
	store.SetNamespaced("prod", "api/key", []byte("k1"))
	dbKeys, _ := store.ListPrefixNamespaced("prod", "db/")
	if len(dbKeys) != 2 {
		t.Errorf("db/ prefix: want 2, got %d", len(dbKeys))
	}
}

func TestDeleteNamespace(t *testing.T) {
	store := newUnlockedStore(t)
	store.CreateBucket("default", "tmp", LevelPasswordOnly, "t")
	store.SetNamespaced("tmp", "k1", []byte("v1"))
	if err := store.DeleteNamespace("tmp"); err != nil {
		t.Fatalf("DeleteNamespace: %v", err)
	}
	if _, err := store.GetNamespaced("tmp", "k1"); err != ErrKeyNotFound {
		t.Errorf("after delete: want ErrKeyNotFound, got %v", err)
	}
}

func TestMoveAndCopy(t *testing.T) {
	store := newUnlockedStore(t)
	store.CreateBucket("default", "src", LevelPasswordOnly, "t")
	store.CreateBucket("default", "dst", LevelPasswordOnly, "t")
	store.CreateBucket("default", "moved", LevelPasswordOnly, "t")
	store.SetNamespaced("src", "k", []byte("v"))
	store.Copy("k", "src", "dst")
	src, _ := store.GetNamespaced("src", "k")
	dst, _ := store.GetNamespaced("dst", "k")
	if string(src) != "v" || string(dst) != "v" {
		t.Error("Copy failed")
	}
	store.Move("k", "src", "moved")
	if _, err := store.GetNamespaced("src", "k"); err != ErrKeyNotFound {
		t.Error("source should be gone after Move")
	}
	mv, _ := store.GetNamespaced("moved", "k")
	if string(mv) != "v" {
		t.Errorf("Move: %q", mv)
	}
}

func TestStats(t *testing.T) {
	store := newUnlockedStore(t)
	store.CreateBucket("default", "prod", LevelPasswordOnly, "t")
	store.CreateBucket("default", "staging", LevelPasswordOnly, "t")
	store.SetNamespaced("prod", "k1", []byte("v1"))
	store.SetNamespaced("prod", "k2", []byte("v2"))
	store.SetNamespaced("staging", "k1", []byte("v1"))
	stats, err := store.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats.TotalKeys < 3 {
		t.Errorf("expected >= 3 keys, got %d", stats.TotalKeys)
	}
}

func TestAutoLock_OnlyDropsAdminWrapped(t *testing.T) {
	store, err := New(Config{
		DBPath:           filepath.Join(t.TempDir(), "s.db"),
		AutoLockInterval: 80 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	store.Unlock([]byte("pass"))
	store.CreateBucket("vault", "sys", LevelPasswordOnly, "test")
	store.CreateBucket("user", "prod", LevelAdminWrapped, "test")
	store.AddAdminToPolicy("user", "prod", "admin1", []byte("adminpass"))
	time.Sleep(200 * time.Millisecond)
	if !store.envelope.IsHeld("vault", "sys") {
		t.Error("vault:sys (LevelPasswordOnly) should remain in envelope after auto-lock")
	}
	if store.envelope.IsHeld("user", "prod") {
		t.Error("user:prod (LevelAdminWrapped) should be dropped after auto-lock")
	}
}

func TestNew(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "secrets.db")
	store, err := New(Config{DBPath: dbPath})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer store.Close()
	if !store.IsLocked() {
		t.Error("new store should be locked")
	}
	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("db file missing: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("permissions: got %o, want 0600", info.Mode().Perm())
	}
}

func TestOpenExisting(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "secrets.db")
	s1, _ := New(Config{DBPath: dbPath})
	s1.Close()
	s2, err := Open(Config{DBPath: dbPath})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s2.Close()
	if !s2.IsLocked() {
		t.Error("opened store should be locked")
	}
}

func TestOpen_NonExistent(t *testing.T) {
	if _, err := Open(Config{DBPath: "/tmp/keeper_does_not_exist.db"}); err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestUnlock(t *testing.T) {
	store := newTestStore(t)
	if err := store.Unlock([]byte("test-passphrase")); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if store.IsLocked() {
		t.Error("should be unlocked")
	}
	if err := store.Unlock([]byte("test-passphrase")); err != ErrAlreadyUnlocked {
		t.Errorf("expected ErrAlreadyUnlocked, got %v", err)
	}
	store.Lock()
	if err := store.Unlock([]byte("wrong")); err != ErrInvalidPassphrase {
		t.Errorf("expected ErrInvalidPassphrase, got %v", err)
	}
	if err := store.Unlock([]byte("test-passphrase")); err != nil {
		t.Fatalf("re-unlock: %v", err)
	}
}

func TestRotate(t *testing.T) {
	store := newTestStore(t)
	store.Unlock([]byte("old"))
	store.Set("k", []byte("v"))

	if err := store.Rotate([]byte("new")); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	// Still readable with new key in memory.
	if v, err := store.Get("k"); err != nil || string(v) != "v" {
		t.Errorf("Get after rotate: %v %v", v, err)
	}
	store.Lock()
	if err := store.Unlock([]byte("new")); err != nil {
		t.Fatalf("Unlock with new pass: %v", err)
	}
	store.Lock()
	if err := store.Unlock([]byte("old")); err != ErrInvalidPassphrase {
		t.Errorf("old pass should fail: %v", err)
	}
}

func TestSetGet(t *testing.T) {
	store := newTestStore(t)
	if err := store.Set("k", []byte("v")); err != ErrStoreLocked {
		t.Errorf("Set when locked: want ErrStoreLocked, got %v", err)
	}
	if _, err := store.Get("k"); err != ErrStoreLocked {
		t.Errorf("Get when locked: want ErrStoreLocked, got %v", err)
	}
	store.Unlock([]byte("pass"))
	if err := store.Set("mykey", []byte("mysecret")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	v, err := store.Get("mykey")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(v) != "mysecret" {
		t.Errorf("Get = %q, want mysecret", v)
	}
	if _, err := store.Get("nonexistent"); err != ErrKeyNotFound {
		t.Errorf("Get missing: want ErrKeyNotFound, got %v", err)
	}
}

func TestSetGet_BinaryValue(t *testing.T) {
	store := newUnlockedStore(t)
	bin := []byte{0x00, 0x01, 0xFF, 0xFE, 0x80}
	store.Set("bin", bin)
	got, err := store.Get("bin")
	if err != nil || !bytes.Equal(got, bin) {
		t.Errorf("binary roundtrip failed: %v %v", got, err)
	}
}

func TestSetGet_LargeValue(t *testing.T) {
	store := newUnlockedStore(t)
	large := make([]byte, 1<<20) // 1 MB
	for i := range large {
		large[i] = byte(i)
	}
	store.Set("large", large)
	got, _ := store.Get("large")
	if !bytes.Equal(got, large) {
		t.Error("large value roundtrip failed")
	}
}

func TestAdminWrapped_FullLifecycle(t *testing.T) {
	store := newUnlockedStore(t)

	if err := store.CreateBucket("finance", "secrets", LevelAdminWrapped, "test"); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	// Bucket locked until first admin added.
	if store.IsBucketUnlocked("finance", "secrets") {
		t.Error("bucket should be locked before any admin added")
	}

	// Add first admin — this generates the DEK and immediately seeds the Envelope.
	if err := store.AddAdminToPolicy("finance", "secrets", "alice", []byte("alicepass")); err != nil {
		t.Fatalf("AddAdminToPolicy(alice): %v", err)
	}
	if !store.IsBucketUnlocked("finance", "secrets") {
		t.Error("bucket should be unlocked after first admin added")
	}

	// Write a secret.
	if err := store.SetNamespacedFull("finance", "secrets", "api_key", []byte("supersecret")); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Add second admin (requires bucket to be unlocked).
	if err := store.AddAdminToPolicy("finance", "secrets", "bob", []byte("bobpass")); err != nil {
		t.Fatalf("AddAdminToPolicy(bob): %v", err)
	}

	// Lock and re-unlock as bob.
	store.LockBucket("finance", "secrets")
	if store.IsBucketUnlocked("finance", "secrets") {
		t.Error("should be locked after LockBucket")
	}
	if err := store.UnlockBucket("finance", "secrets", "bob", []byte("bobpass")); err != nil {
		t.Fatalf("UnlockBucket(bob): %v", err)
	}

	// Secret is accessible.
	v, err := store.GetNamespacedFull("finance", "secrets", "api_key")
	if err != nil || string(v) != "supersecret" {
		t.Errorf("Get after unlock as bob: %v %v", v, err)
	}

	// Wrong admin password fails.
	store.LockBucket("finance", "secrets")
	if err := store.UnlockBucket("finance", "secrets", "alice", []byte("wrongpass")); err != ErrInvalidPassphrase {
		t.Errorf("wrong pass: want ErrInvalidPassphrase, got %v", err)
	}

	// Unknown adminID fails.
	if err := store.UnlockBucket("finance", "secrets", "charlie", []byte("pass")); !errors.Is(err, ErrAdminNotFound) {
		t.Errorf("unknown admin: want ErrAdminNotFound, got %v", err)
	}
}

func TestAdminWrapped_RevokeAdmin(t *testing.T) {
	store := newUnlockedStore(t)
	store.CreateBucket("a", "b", LevelAdminWrapped, "t")
	store.AddAdminToPolicy("a", "b", "alice", []byte("alicepass"))
	store.AddAdminToPolicy("a", "b", "bob", []byte("bobpass"))

	if err := store.RevokeAdmin("a", "b", "alice"); err != nil {
		t.Fatalf("RevokeAdmin: %v", err)
	}

	// Alice can no longer unlock.
	store.LockBucket("a", "b")
	if err := store.UnlockBucket("a", "b", "alice", []byte("alicepass")); !errors.Is(err, ErrAdminNotFound) {
		t.Errorf("revoked admin: want ErrAdminNotFound, got %v", err)
	}

	// Bob still can.
	if err := store.UnlockBucket("a", "b", "bob", []byte("bobpass")); err != nil {
		t.Fatalf("bob still works: %v", err)
	}
}

func TestAdminWrapped_PolicySurvivesReopen(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "s.db")
	s1, _ := New(Config{DBPath: dbPath})
	s1.Unlock([]byte("masterpass"))
	s1.CreateBucket("fin", "ns", LevelAdminWrapped, "test")
	s1.AddAdminToPolicy("fin", "ns", "admin1", []byte("adminpass"))
	s1.SetNamespacedFull("fin", "ns", "secret", []byte("value"))
	s1.Close()

	s2, err := Open(Config{DBPath: dbPath})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s2.Close()
	s2.Unlock([]byte("masterpass"))

	// Bucket is locked on reopen — must explicitly unlock.
	if s2.IsBucketUnlocked("fin", "ns") {
		t.Error("bucket should start locked after reopen")
	}
	if err := s2.UnlockBucket("fin", "ns", "admin1", []byte("adminpass")); err != nil {
		t.Fatalf("UnlockBucket after reopen: %v", err)
	}
	v, err := s2.GetNamespacedFull("fin", "ns", "secret")
	if err != nil || string(v) != "value" {
		t.Errorf("Get after reopen: %v %v", v, err)
	}
}

func TestDelete(t *testing.T) {
	store := newUnlockedStore(t)
	store.Set("k", []byte("v"))
	if err := store.Delete("k"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := store.Get("k"); err != ErrKeyNotFound {
		t.Errorf("after delete: want ErrKeyNotFound, got %v", err)
	}
	if err := store.Delete("nonexistent"); err != ErrKeyNotFound {
		t.Errorf("delete missing: want ErrKeyNotFound, got %v", err)
	}
}

func TestList(t *testing.T) {
	store := newUnlockedStore(t)
	keys, _ := store.List()
	if len(keys) != 0 {
		t.Errorf("empty store: got %d keys", len(keys))
	}
	store.Set("key1", []byte("v1"))
	store.Set("key2", []byte("v2"))
	store.Set("key3", []byte("v3"))
	keys, _ = store.List()
	sort.Strings(keys)
	if len(keys) != 3 {
		t.Fatalf("expected 3 keys, got %d", len(keys))
	}
	for i, want := range []string{"key1", "key2", "key3"} {
		if keys[i] != want {
			t.Errorf("keys[%d] = %q, want %q", i, keys[i], want)
		}
	}
}

func TestExists(t *testing.T) {
	store := newUnlockedStore(t)
	store.Set("k", []byte("v"))
	ok, err := store.Exists("k")
	if err != nil || !ok {
		t.Errorf("Exists(k): %v %v", ok, err)
	}
	ok, err = store.Exists("nope")
	if err != nil || ok {
		t.Errorf("Exists(nope): %v %v", ok, err)
	}
}

func TestRename(t *testing.T) {
	store := newUnlockedStore(t)
	store.Set("old", []byte("v"))
	store.Rename("old", "new")
	if _, err := store.Get("old"); err != ErrKeyNotFound {
		t.Error("old key should be gone")
	}
	v, _ := store.Get("new")
	if string(v) != "v" {
		t.Errorf("renamed: %q", v)
	}
}

func TestCompareAndSwap(t *testing.T) {
	store := newUnlockedStore(t)
	store.Set("k", []byte("initial"))
	if err := store.CompareAndSwap("k", "initial", "updated"); err != nil {
		t.Fatalf("CAS: %v", err)
	}
	v, _ := store.Get("k")
	if string(v) != "updated" {
		t.Errorf("after CAS: %q", v)
	}
	if err := store.CompareAndSwap("k", "wrong", "x"); err != ErrCASConflict {
		t.Errorf("bad old val: want ErrCASConflict, got %v", err)
	}
}

func TestConcurrentAccess(t *testing.T) {
	store := newUnlockedStore(t)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			store.Set(fmt.Sprintf("key%d", n), []byte(fmt.Sprintf("value%d", n)))
		}(i)
	}
	wg.Wait()
	for i := 0; i < 10; i++ {
		v, err := store.Get(fmt.Sprintf("key%d", i))
		if err != nil || string(v) != fmt.Sprintf("value%d", i) {
			t.Errorf("key%d: %v %v", i, v, err)
		}
	}
}

func TestAuditLogging(t *testing.T) {
	store, err := New(Config{
		DBPath:      filepath.Join(t.TempDir(), "s.db"),
		EnableAudit: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	var mu sync.Mutex
	var actions []string
	store.SetAuditFunc(func(action, scheme, namespace, key string, success bool, d time.Duration) {
		mu.Lock()
		actions = append(actions, action)
		mu.Unlock()
	})

	store.Unlock([]byte("pass"))
	store.Set("k", []byte("v"))
	store.Get("k")
	store.Lock()

	mu.Lock()
	defer mu.Unlock()
	found := false
	for _, a := range actions {
		if a == "unlock_database" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("missing unlock_database event; got: %v", actions)
	}
}

func TestMetrics(t *testing.T) {
	store := newUnlockedStore(t)
	store.Set("k", []byte("v"))
	store.Get("k")
	store.Get("missing")
	m := store.Metrics()
	if m.ReadsTotal < 2 {
		t.Errorf("reads: want >= 2, got %d", m.ReadsTotal)
	}
	if m.WritesTotal < 1 {
		t.Errorf("writes: want >= 1, got %d", m.WritesTotal)
	}
}

func TestCustomKDF(t *testing.T) {
	var called bool
	store, err := New(Config{
		DBPath: filepath.Join(t.TempDir(), "s.db"),
		KDF: &mockKDF{fn: func(password, salt []byte, keyLen int) ([]byte, error) {
			called = true
			k := make([]byte, keyLen)
			copy(k, password)
			return k, nil
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	store.Unlock([]byte("pass"))
	if !called {
		t.Error("custom KDF not called")
	}
}

func TestCustomCipher(t *testing.T) {
	var enc, dec int
	store, err := New(Config{
		DBPath: filepath.Join(t.TempDir(), "s.db"),
		NewCipher: func(key []byte) (crypt.Cipher, error) {
			return &countingCipher{key: key, enc: &enc, dec: &dec}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	store.Unlock([]byte("pass"))
	store.Set("k", []byte("v"))
	store.Get("k")
	if enc == 0 {
		t.Error("custom cipher Encrypt not called")
	}
	if dec == 0 {
		t.Error("custom cipher Decrypt not called")
	}
}

func TestGlobalStore(t *testing.T) {
	store := newUnlockedStore(t)
	GlobalStore(store)
	defer GlobalStore(nil)
	store.Set("k", []byte("v"))
	v, err := GlobalGetKey("k")
	if err != nil || string(v) != "v" {
		t.Errorf("GlobalGetKey: %v %v", v, err)
	}
	GlobalStore(nil)
	if _, err := GlobalGetKey("k"); err == nil {
		t.Error("nil store should fail")
	}
}

func TestBackup(t *testing.T) {
	store := newUnlockedStore(t)
	store.Set("k", []byte("v"))

	var buf bytes.Buffer
	info, err := store.Backup(&buf)
	if err != nil {
		t.Fatalf("Backup: %v", err)
	}
	if info.Bytes == 0 {
		t.Error("backup should be non-empty")
	}
	if buf.Len() == 0 {
		t.Error("buffer should be non-empty")
	}
	// Backup does NOT require unlock.
	store.Lock()
	var buf2 bytes.Buffer
	_, err = store.Backup(&buf2)
	if err != nil {
		t.Fatalf("Backup (locked): %v", err)
	}
}

func TestDeriveKEK_Deterministic(t *testing.T) {
	master := make([]byte, 32)
	admin := []byte("adminpass")
	salt := make([]byte, 32)
	salt[0] = 0x01

	k1, err := DeriveKEK(master, admin, salt)
	if err != nil {
		t.Fatalf("DeriveKEK: %v", err)
	}
	k2, err := DeriveKEK(master, admin, salt)
	if err != nil {
		t.Fatalf("DeriveKEK: %v", err)
	}
	if !bytes.Equal(k1, k2) {
		t.Error("DeriveKEK not deterministic")
	}
}

func TestDeriveKEK_DifferentInputs(t *testing.T) {
	master := make([]byte, 32)
	salt := make([]byte, 32)
	k1, _ := DeriveKEK(master, []byte("pass1"), salt)
	k2, _ := DeriveKEK(master, []byte("pass2"), salt)
	if bytes.Equal(k1, k2) {
		t.Error("different passwords must yield different KEKs")
	}
}

func TestWrapUnwrapDEK(t *testing.T) {
	dek, err := GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}

	kek := make([]byte, 32)
	kek[0] = 0xAB

	kek2 := make([]byte, 32)
	kek2[0] = 0xAB
	wrapped, err := WrapDEK(dek, kek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}

	unwrappedEnc, err := UnwrapDEK(wrapped, kek2)
	if err != nil {
		t.Fatalf("UnwrapDEK: %v", err)
	}

	// Open both enclaves to compare contents.
	origBuf, err := dek.Open()
	if err != nil {
		t.Fatalf("open original DEK: %v", err)
	}
	defer origBuf.Destroy()

	unwrappedBuf, err := unwrappedEnc.Open()
	if err != nil {
		t.Fatalf("open unwrapped DEK: %v", err)
	}
	defer unwrappedBuf.Destroy()

	if !bytes.Equal(origBuf.Bytes(), unwrappedBuf.Bytes()) {
		t.Error("unwrapped DEK does not match original")
	}
}

func TestUnwrapDEK_WrongKEK(t *testing.T) {
	dek, _ := GenerateDEK()
	kek1 := make([]byte, 32)
	kek1[0] = 0xAA
	kek2 := make([]byte, 32)
	kek2[0] = 0xBB
	wrapped, _ := WrapDEK(dek, kek1)
	if _, err := UnwrapDEK(wrapped, kek2); err != ErrInvalidPassphrase {
		t.Errorf("wrong KEK: want ErrInvalidPassphrase, got %v", err)
	}
}

func TestEnvelope_HoldRetrieve(t *testing.T) {
	env := NewEnvelope()
	dek, err := GenerateDEK()
	if err != nil {
		t.Fatal(err)
	}

	env.HoldEnclave("s", "ns", dek)
	if !env.IsHeld("s", "ns") {
		t.Error("should be held")
	}

	buf, err := env.Retrieve("s", "ns")
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	defer buf.Destroy()
	if len(buf.Bytes()) != 32 {
		t.Errorf("DEK size: got %d, want 32", len(buf.Bytes()))
	}
}

func TestEnvelope_Drop(t *testing.T) {
	env := NewEnvelope()
	dek, _ := GenerateDEK()
	env.HoldEnclave("s", "ns", dek)
	env.Drop("s", "ns")
	if env.IsHeld("s", "ns") {
		t.Error("should not be held after Drop")
	}
	if _, err := env.Retrieve("s", "ns"); err != ErrBucketLocked {
		t.Errorf("Retrieve after Drop: want ErrBucketLocked, got %v", err)
	}
}

func TestEnvelope_DropAdminWrapped(t *testing.T) {
	env := NewEnvelope()
	dek1, _ := GenerateDEK()
	dek2, _ := GenerateDEK()
	env.HoldEnclave("vault", "sys", dek1)
	env.HoldEnclave("user", "prod", dek2)

	registry := map[string]*BucketSecurityPolicy{
		"vault:sys": {Level: LevelPasswordOnly},
		"user:prod": {Level: LevelAdminWrapped},
	}
	env.DropAdminWrapped(registry)

	if !env.IsHeld("vault", "sys") {
		t.Error("vault:sys (PasswordOnly) should survive DropAdminWrapped")
	}
	if env.IsHeld("user", "prod") {
		t.Error("user:prod (AdminWrapped) should be dropped")
	}
}

func TestEnvelope_DropAll(t *testing.T) {
	env := NewEnvelope()
	for i := 0; i < 3; i++ {
		dek, _ := GenerateDEK()
		env.HoldEnclave(fmt.Sprintf("s%d", i), "ns", dek)
	}
	env.DropAll()
	if len(env.HeldKeys()) != 0 {
		t.Errorf("DropAll: %d keys remain", len(env.HeldKeys()))
	}
}

type mockKDF struct {
	fn func([]byte, []byte, int) ([]byte, error)
}

func (m *mockKDF) DeriveKey(p, s []byte, n int) ([]byte, error) { return m.fn(p, s, n) }

type countingCipher struct {
	key      []byte
	enc, dec *int
}

func (c *countingCipher) Encrypt(pt []byte) ([]byte, error) {
	*c.enc++
	out := make([]byte, len(pt)+1)
	out[0] = 0xAB
	for i, b := range pt {
		out[i+1] = b ^ c.key[i%len(c.key)]
	}
	return out, nil
}
func (c *countingCipher) Decrypt(ct []byte) ([]byte, error) {
	*c.dec++
	if len(ct) < 1 {
		return nil, fmt.Errorf("too short")
	}
	out := make([]byte, len(ct)-1)
	for i, b := range ct[1:] {
		out[i] = b ^ c.key[i%len(c.key)]
	}
	return out, nil
}

// ── Benchmarks ───────────────────────────────────────────────────────────

func BenchmarkSet(b *testing.B) {
	store, _ := New(Config{DBPath: filepath.Join(b.TempDir(), "s.db")})
	defer store.Close()
	store.Unlock([]byte("pass"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store.Set(fmt.Sprintf("key%d", i), []byte("benchmark-value"))
	}
}

func BenchmarkGet(b *testing.B) {
	store, _ := New(Config{DBPath: filepath.Join(b.TempDir(), "s.db")})
	defer store.Close()
	store.Unlock([]byte("pass"))
	store.Set("bench-key", []byte("bench-value"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store.Get("bench-key")
	}
}
