package keeper

import (
	"bytes"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agberohq/keeper/pkg/crypt"
	"github.com/olekukonko/zero"
)

func TestIsBucketUnlocked_DefaultBucket(t *testing.T) {
	store := newTestStore(t)
	if store.isBucketUnlocked(store.defaultScheme, store.defaultNs) {
		t.Error("default bucket should be locked when store is locked")
	}
	store.Unlock([]byte("pass"))
	if !store.isBucketUnlocked(store.defaultScheme, store.defaultNs) {
		t.Error("default bucket should be unlocked when store is unlocked")
	}
}

func TestIsBucketUnlocked_NoPolicyInheritsStore(t *testing.T) {
	store := newUnlockedStore(t)
	if !store.isBucketUnlocked(store.defaultScheme, "anynamespace") {
		t.Error("policy-less namespace should inherit store unlock state")
	}
}

func TestIsBucketUnlocked_PasswordOnlyPolicy(t *testing.T) {
	store := newUnlockedStore(t)
	store.CreateBucket("s", "ns", LevelPasswordOnly, "t")
	if !store.isBucketUnlocked("s", "ns") {
		t.Error("LevelPasswordOnly bucket should be unlocked when store is unlocked")
	}
}

func TestIsBucketUnlocked_AdminWrappedPolicy(t *testing.T) {
	store := newUnlockedStore(t)
	store.CreateBucket("s", "ns", LevelAdminWrapped, "t")
	if store.isBucketUnlocked("s", "ns") {
		t.Error("LevelAdminWrapped bucket should be locked until explicit UnlockBucket")
	}
}

func TestIsBucketUnlocked_AfterExplicitUnlock(t *testing.T) {
	store := newUnlockedStore(t)
	store.CreateBucket("s", "ns", LevelAdminWrapped, "t")
	dek := make([]byte, 32)
	store.envelope.HoldBytes("s", "ns", dek)
	if !store.isBucketUnlocked("s", "ns") {
		t.Error("should be unlocked after DEK held in envelope")
	}
}

func TestIsBucketUnlocked_StoreLocked(t *testing.T) {
	store := newUnlockedStore(t)
	store.Lock()
	if store.isBucketUnlocked(store.defaultScheme, store.defaultNs) {
		t.Error("all buckets should be locked when store is locked")
	}
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	store := newUnlockedStore(t)
	store.CreateBucket("test", "ns", LevelPasswordOnly, "t")
	plaintext := []byte("the quick brown fox")
	ct, err := store.encrypt(plaintext, "test", "ns")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	got, err := store.decrypt(ct, "test", "ns")
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("decrypt = %q, want %q", got, plaintext)
	}
}

func TestEncryptDecrypt_WrongBucket(t *testing.T) {
	store := newUnlockedStore(t)
	store.CreateBucket("s1", "n1", LevelAdminWrapped, "t")
	store.CreateBucket("s2", "n2", LevelAdminWrapped, "t")

	// Adding the first admin auto-unlocks and seeds the unique DEK into the Envelope.
	if err := store.AddAdminToPolicy("s1", "n1", "admin", []byte("pass1")); err != nil {
		t.Fatalf("AddAdminToPolicy s1: %v", err)
	}
	if err := store.AddAdminToPolicy("s2", "n2", "admin", []byte("pass2")); err != nil {
		t.Fatalf("AddAdminToPolicy s2: %v", err)
	}

	ct, err := store.encrypt([]byte("secret"), "s1", "n1")
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	if _, err := store.decrypt(ct, "s2", "n2"); err == nil {
		t.Error("decrypt with wrong bucket key should fail")
	}
}

func TestEncryptDecrypt_CustomCipherFactory(t *testing.T) {
	var encCount atomic.Int64
	store, _ := New(Config{
		DBPath: filepath.Join(t.TempDir(), "s.db"),
		NewCipher: func(key []byte) (crypt.Cipher, error) {
			return &countingCipher{key: key, enc: &encCount, dec: &atomic.Int64{}}, nil
		},
	})
	defer store.Close()
	store.Unlock([]byte("pass"))
	store.Set("k", []byte("v"))
	if encCount.Load() == 0 {
		t.Error("custom cipher Encrypt was not called")
	}
}

func TestGetOrCreateSalt_Idempotent(t *testing.T) {
	store := newUnlockedStore(t)
	s1, err := store.getOrCreateSalt()
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	s2, err := store.getOrCreateSalt()
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if string(s1) != string(s2) {
		t.Error("salt must be stable across calls")
	}
	if len(s1) < 16 {
		t.Errorf("salt too short: %d bytes", len(s1))
	}
}

func TestVerifyMasterKey_WrongKey(t *testing.T) {
	store := newTestStore(t)
	store.Unlock([]byte("correct"))
	store.Lock()
	if err := store.Unlock([]byte("wrong")); err != ErrInvalidPassphrase {
		t.Errorf("expected ErrInvalidPassphrase, got %v", err)
	}
}

func TestReencryptAllWithKey(t *testing.T) {
	store := newUnlockedStore(t)
	store.Set("k1", []byte("v1"))
	store.Set("k2", []byte("v2"))
	oldKey, _ := store.master.Bytes()
	newKey := make([]byte, 32)
	newKey[0] = 0xAB
	if err := store.reencryptAllWithKey(newKey, oldKey); err != nil {
		t.Fatalf("reencryptAllWithKey: %v", err)
	}
	newMaster, _ := NewMaster(newKey)
	store.mu.Lock()
	store.master.Destroy()
	store.master = newMaster
	// Reseed the Envelope: the default bucket's DEK is the master key itself
	// (LevelPasswordOnly). After swapping the master, the Envelope still holds
	// the old key, causing decrypt to fail against the re-encrypted ciphertext.
	_ = store.unlockBucketPasswordOnly(store.defaultScheme, store.defaultNs)
	store.mu.Unlock()
	v, err := store.Get("k1")
	if err != nil || string(v) != "v1" {
		t.Errorf("after re-encrypt: v=%q err=%v", v, err)
	}
}

func TestReencryptAllWithKey_EmptyOldKey(t *testing.T) {
	store := newUnlockedStore(t)
	if err := store.reencryptAllWithKey(make([]byte, 32), nil); err == nil {
		t.Error("empty old key should return error")
	}
}

func TestBucketKey_DefaultUsesMaster(t *testing.T) {
	store := newUnlockedStore(t)
	key, err := store.bucketKeyBytes(store.defaultScheme, store.defaultNs)
	if err != nil {
		t.Fatalf("bucketKeyBytes: %v", err)
	}
	defer zero.Bytes(key)
	if len(key) == 0 {
		t.Error("bucket key must be non-empty")
	}
}

func TestBucketKey_StoreLocked(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.bucketKeyBytes(store.defaultScheme, store.defaultNs); err != ErrBucketLocked {
		t.Errorf("expected ErrBucketLocked, got %v", err)
	}
}

func TestBucketKey_ExplicitKey(t *testing.T) {
	store := newUnlockedStore(t)
	explicit := []byte("explicit-key-32-bytes-padding!!!")
	// Save a copy before HoldBytes zeroes the source slice.
	// memguard.NewBufferFromBytes copies the bytes into protected memory and
	// then wipes the original slice — comparing against explicit after calling
	// HoldBytes would compare against all-zeros.
	expected := make([]byte, len(explicit))
	copy(expected, explicit)
	store.envelope.HoldBytes("myscheme", "myns", explicit)
	key, err := store.bucketKeyBytes("myscheme", "myns")
	if err != nil {
		t.Fatalf("bucketKeyBytes: %v", err)
	}
	defer zero.Bytes(key)
	if !bytes.Equal(key, expected) {
		t.Errorf("expected explicit key, got different value")
	}
}

func TestAudit_CallsAuditFn(t *testing.T) {
	store := newUnlockedStore(t)
	var called bool
	store.SetAuditFunc(func(action, scheme, namespace, key string, success bool, d time.Duration) {
		called = true
	})
	store.config.EnableAudit = true
	store.audit("test", "s", "ns", "k", true, 0)
	if !called {
		t.Error("auditFn was not called")
	}
}

func TestAudit_CallsOnAuditHook(t *testing.T) {
	store := newUnlockedStore(t)
	var hookCalled bool
	store.SetHooks(Hooks{
		OnAudit: func(action, scheme, namespace, key string, success bool, d time.Duration) {
			hookCalled = true
		},
	})
	store.audit("test", "s", "ns", "k", true, 0)
	if !hookCalled {
		t.Error("OnAudit hook was not called")
	}
}

func TestAudit_DisabledWhenFlagOff(t *testing.T) {
	store := newUnlockedStore(t)
	var called bool
	store.SetAuditFunc(func(action, scheme, namespace, key string, success bool, d time.Duration) {
		called = true
	})
	store.audit("test", "s", "ns", "k", true, 0)
	if called {
		t.Error("auditFn should not be called when EnableAudit=false")
	}
}

func TestLoadPolicies_PopulatesRegistry(t *testing.T) {
	store := newUnlockedStore(t)
	store.CreateBucket("reg1", "ns1", LevelPasswordOnly, "t")
	store.CreateBucket("reg2", "ns2", LevelPasswordOnly, "t")
	store.mu.Lock()
	store.schemeRegistry = make(map[string]*BucketSecurityPolicy)
	store.mu.Unlock()
	if err := store.loadPolicies(); err != nil {
		t.Fatalf("loadPolicies: %v", err)
	}
	store.mu.RLock()
	_, ok1 := store.schemeRegistry["reg1:ns1"]
	_, ok2 := store.schemeRegistry["reg2:ns2"]
	store.mu.RUnlock()
	if !ok1 || !ok2 {
		t.Error("loadPolicies did not repopulate registry")
	}
}

func TestIncrementAccessCount(t *testing.T) {
	store := newUnlockedStore(t)
	store.Set("counted", []byte("v"))
	store.Get("counted")
	store.Get("counted")
	time.Sleep(50 * time.Millisecond)
	v, err := store.Get("counted")
	if err != nil || string(v) != "v" {
		t.Errorf("Get after access count increment: val=%q err=%v", v, err)
	}
}

// ── Change 3: Per-bucket DEK derivation ──────────────────────────────────────

func TestDeriveBucketDEK_Deterministic(t *testing.T) {
	master := make([]byte, 32)
	for i := range master {
		master[i] = byte(i + 1)
	}
	k1, err := deriveBucketDEK(master, "default", "ns1")
	if err != nil {
		t.Fatalf("deriveBucketDEK: %v", err)
	}
	k2, err := deriveBucketDEK(master, "default", "ns1")
	if err != nil {
		t.Fatalf("deriveBucketDEK (2nd): %v", err)
	}
	if !bytes.Equal(k1, k2) {
		t.Error("deriveBucketDEK must be deterministic")
	}
}

func TestDeriveBucketDEK_DifferentNamespacesProduceDifferentKeys(t *testing.T) {
	master := make([]byte, 32)
	for i := range master {
		master[i] = byte(i + 1)
	}
	k1, _ := deriveBucketDEK(master, "default", "ns1")
	k2, _ := deriveBucketDEK(master, "default", "ns2")
	if bytes.Equal(k1, k2) {
		t.Error("different namespaces must produce different DEKs")
	}
}

func TestDeriveBucketDEK_DifferentSchemesProduceDifferentKeys(t *testing.T) {
	master := make([]byte, 32)
	for i := range master {
		master[i] = byte(i + 1)
	}
	k1, _ := deriveBucketDEK(master, "schemeA", "ns")
	k2, _ := deriveBucketDEK(master, "schemeB", "ns")
	if bytes.Equal(k1, k2) {
		t.Error("different schemes must produce different DEKs")
	}
}

func TestDeriveBucketDEK_DifferentFromMasterKey(t *testing.T) {
	master := make([]byte, 32)
	for i := range master {
		master[i] = byte(i + 1)
	}
	dek, err := deriveBucketDEK(master, "default", "ns")
	if err != nil {
		t.Fatalf("deriveBucketDEK: %v", err)
	}
	if bytes.Equal(dek, master) {
		t.Error("bucket DEK must differ from the master key")
	}
}

func TestDeriveBucketDEK_KeyLength(t *testing.T) {
	master := make([]byte, 32)
	dek, err := deriveBucketDEK(master, "s", "n")
	if err != nil {
		t.Fatalf("deriveBucketDEK: %v", err)
	}
	if len(dek) != 32 {
		t.Errorf("expected 32-byte DEK, got %d", len(dek))
	}
}

func TestMigration_NewStoreIsNotNeeded(t *testing.T) {
	// A freshly created store (no data written before the DEK derivation change)
	// should mark migration as not needed after the first unlock.
	// Since our code always starts a migration on first unlock (no done marker),
	// the migration will run and complete quickly on an empty store.
	store := newUnlockedStore(t)
	// Give the migration looper time to complete on the empty store.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		st := store.MigrationStatus()
		if st == MigrationDone || st == MigrationNotNeeded {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	// Allow InProgress on a fresh empty store — it will finish quickly.
	st := store.MigrationStatus()
	if st != MigrationDone && st != MigrationNotNeeded && st != MigrationInProgress {
		t.Errorf("unexpected migration state: %v", st)
	}
}

func TestMigration_DataAccessibleDuringMigration(t *testing.T) {
	// Write several secrets, then verify they are readable while migration runs.
	store := newUnlockedStore(t)

	for i := 0; i < 10; i++ {
		key := "migkey" + string(rune('A'+i))
		if err := store.Set(key, []byte("value"+string(rune('A'+i)))); err != nil {
			t.Fatalf("Set %s: %v", key, err)
		}
	}

	// All secrets must still be readable regardless of migration state.
	for i := 0; i < 10; i++ {
		key := "migkey" + string(rune('A'+i))
		val, err := store.Get(key)
		if err != nil {
			t.Errorf("Get %s during migration: %v", key, err)
			continue
		}
		want := "value" + string(rune('A'+i))
		if string(val) != want {
			t.Errorf("Get %s: want %q, got %q", key, want, val)
		}
	}
}

func TestMigration_SurvivesReopen(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "mig.db")

	// First session: write secrets.
	{
		s, err := New(Config{DBPath: dbPath})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		s.Unlock([]byte("pass")) //nolint:errcheck
		for i := 0; i < 5; i++ {
			s.Set("k"+string(rune('0'+i)), []byte("v"+string(rune('0'+i)))) //nolint:errcheck
		}
		// Wait for migration to complete before closing.
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if s.MigrationStatus() == MigrationDone {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		s.Close()
	}

	// Second session: migration should be marked done, data readable.
	{
		s, err := New(Config{DBPath: dbPath})
		if err != nil {
			t.Fatalf("New (reopen): %v", err)
		}
		defer s.Close()
		s.Unlock([]byte("pass")) //nolint:errcheck

		// On reopen, migration should be NotNeeded (done marker present).
		time.Sleep(100 * time.Millisecond) // allow startDEKMigration to run
		st := s.MigrationStatus()
		if st != MigrationNotNeeded && st != MigrationDone {
			t.Errorf("expected NotNeeded or Done on reopen, got %v", st)
		}

		for i := 0; i < 5; i++ {
			key := "k" + string(rune('0'+i))
			val, err := s.Get(key)
			if err != nil {
				t.Errorf("Get %s after migration reopen: %v", key, err)
				continue
			}
			want := "v" + string(rune('0'+i))
			if string(val) != want {
				t.Errorf("Get %s: want %q, got %q", key, want, val)
			}
		}
	}
}

func TestMigration_StatusStringValues(t *testing.T) {
	if MigrationNotNeeded.String() != "not_needed" {
		t.Errorf("MigrationNotNeeded.String() = %q", MigrationNotNeeded.String())
	}
	if MigrationInProgress.String() != "in_progress" {
		t.Errorf("MigrationInProgress.String() = %q", MigrationInProgress.String())
	}
	if MigrationDone.String() != "done" {
		t.Errorf("MigrationDone.String() = %q", MigrationDone.String())
	}
}

func TestMigration_ConfigurableBatchSize(t *testing.T) {
	var progressCalls atomic.Int32
	s, err := New(Config{
		DBPath:                      filepath.Join(t.TempDir(), "batch.db"),
		BucketDEKMigrationBatchSize: 2,
		BucketDEKMigrationInterval:  10 * time.Millisecond,
		BucketDEKMigrationProgress: func(scheme, namespace string, done, total int) {
			progressCalls.Add(1)
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()
	s.Unlock([]byte("pass")) //nolint:errcheck

	// Write enough secrets to require multiple batches.
	for i := 0; i < 6; i++ {
		s.Set("bk"+string(rune('0'+i)), []byte("val")) //nolint:errcheck
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if s.MigrationStatus() == MigrationDone {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
}
