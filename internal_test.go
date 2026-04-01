package keeper

import (
	"bytes"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agberohq/keeper/pkg/crypt"
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
	defer secureZero(key)
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
	defer secureZero(key)
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
