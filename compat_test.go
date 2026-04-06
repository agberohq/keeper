package keeper

import (
	"errors"
	"path/filepath"
	"testing"
)

// TestRotateAdminWrappedDEK_DoesNotInvalidateOtherAdmins is the primary
// regression test for the lockout bug. Before the fix, rotating admin Alice's
// DEK would write a new DEKSalt to the policy. Bob's wrapped DEK was produced
// under the old salt, so his next UnlockBucket would derive the wrong KEK and
// fail authentication — permanently locking him out.
func TestRotateAdminWrappedDEK_DoesNotInvalidateOtherAdmins(t *testing.T) {
	store := newUnlockedStore(t)

	if err := store.CreateBucket("sc", "ns", LevelAdminWrapped, "test"); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	if err := store.AddAdminToPolicy("sc", "ns", "alice", []byte("alicepass")); err != nil {
		t.Fatalf("AddAdminToPolicy alice: %v", err)
	}
	if err := store.AddAdminToPolicy("sc", "ns", "bob", []byte("bobpass")); err != nil {
		t.Fatalf("AddAdminToPolicy bob: %v", err)
	}

	// Record the DEKSalt before Alice rotates.
	policyBefore, err := store.loadPolicy("sc", "ns")
	if err != nil {
		t.Fatalf("loadPolicy before: %v", err)
	}
	saltBefore := string(policyBefore.DEKSalt)

	// Alice rotates her wrapped DEK (e.g. changing her password).
	if err := store.RotateAdminWrappedDEK("sc", "ns", "alice", []byte("alicepass")); err != nil {
		t.Fatalf("RotateAdminWrappedDEK: %v", err)
	}

	// The DEKSalt must be identical after the rotation — it is shared by all
	// admins and must never change during a per-admin re-key.
	policyAfter, err := store.loadPolicy("sc", "ns")
	if err != nil {
		t.Fatalf("loadPolicy after: %v", err)
	}
	if string(policyAfter.DEKSalt) != saltBefore {
		t.Errorf("DEKSalt changed after RotateAdminWrappedDEK: before=%x after=%x — other admins are now locked out",
			policyBefore.DEKSalt, policyAfter.DEKSalt)
	}

	// Bob must still be able to unlock the bucket with his original password.
	store.LockBucket("sc", "ns")
	if err := store.UnlockBucket("sc", "ns", "bob", []byte("bobpass")); err != nil {
		t.Errorf("Bob locked out after Alice's re-key (DEKSalt bug): %v", err)
	}
}

// TestRotateAdminWrappedDEK_CallerCanStillUnlock verifies the calling admin
// (Alice) can still unlock the bucket with the same password after re-keying.
// (The re-wrap uses a fresh nonce so the ciphertext differs, but the password
// and salt are unchanged.)
func TestRotateAdminWrappedDEK_CallerCanStillUnlock(t *testing.T) {
	store := newUnlockedStore(t)
	store.CreateBucket("sc", "ns", LevelAdminWrapped, "test")
	store.AddAdminToPolicy("sc", "ns", "alice", []byte("alicepass"))

	if err := store.RotateAdminWrappedDEK("sc", "ns", "alice", []byte("alicepass")); err != nil {
		t.Fatalf("RotateAdminWrappedDEK: %v", err)
	}

	store.LockBucket("sc", "ns")
	if err := store.UnlockBucket("sc", "ns", "alice", []byte("alicepass")); err != nil {
		t.Errorf("Alice locked out after her own re-key: %v", err)
	}
}

// TestRotateAdminWrappedDEK_WrongPasswordFails verifies authentication is
// enforced — you cannot re-key with the wrong current password.
func TestRotateAdminWrappedDEK_WrongPasswordFails(t *testing.T) {
	store := newUnlockedStore(t)
	store.CreateBucket("sc", "ns", LevelAdminWrapped, "test")
	store.AddAdminToPolicy("sc", "ns", "alice", []byte("alicepass"))

	err := store.RotateAdminWrappedDEK("sc", "ns", "alice", []byte("wrongpass"))
	if !errors.Is(err, ErrAuthFailed) {
		t.Errorf("wrong password: want ErrAuthFailed, got %v", err)
	}
}

// TestRotateAdminWrappedDEK_UnknownAdminFails verifies that an unknown adminID
// returns an appropriate error without touching the policy.
func TestRotateAdminWrappedDEK_UnknownAdminFails(t *testing.T) {
	store := newUnlockedStore(t)
	store.CreateBucket("sc", "ns", LevelAdminWrapped, "test")
	store.AddAdminToPolicy("sc", "ns", "alice", []byte("alicepass"))

	err := store.RotateAdminWrappedDEK("sc", "ns", "charlie", []byte("pass"))
	if err == nil {
		t.Error("expected error for unknown admin, got nil")
	}
}

// TestRotateAdminWrappedDEK_DataAccessibleAfterRekey ensures secrets written
// before a re-key are still readable after — the DEK itself must not change.
func TestRotateAdminWrappedDEK_DataAccessibleAfterRekey(t *testing.T) {
	store := newUnlockedStore(t)
	store.CreateBucket("sc", "ns", LevelAdminWrapped, "test")
	store.AddAdminToPolicy("sc", "ns", "alice", []byte("alicepass"))

	if err := store.SetNamespacedFull("sc", "ns", "secret", []byte("value123")); err != nil {
		t.Fatalf("Set: %v", err)
	}

	if err := store.RotateAdminWrappedDEK("sc", "ns", "alice", []byte("alicepass")); err != nil {
		t.Fatalf("RotateAdminWrappedDEK: %v", err)
	}

	// Re-lock and re-unlock to force the envelope to be re-seeded from the
	// policy (exercises the full unwrap path with the re-wrapped DEK).
	store.LockBucket("sc", "ns")
	if err := store.UnlockBucket("sc", "ns", "alice", []byte("alicepass")); err != nil {
		t.Fatalf("UnlockBucket after rekey: %v", err)
	}

	val, err := store.GetNamespacedFull("sc", "ns", "secret")
	if err != nil {
		t.Fatalf("Get after rekey: %v", err)
	}
	if string(val) != "value123" {
		t.Errorf("data corrupted after rekey: got %q", val)
	}
}

// TestRotateAdminWrappedDEK_MultipleAdminsAllAccessibleAfterRekey is the
// full multi-admin regression: Alice re-keys, then both Alice and Bob must
// still be able to unlock and read data.
func TestRotateAdminWrappedDEK_MultipleAdminsAllAccessibleAfterRekey(t *testing.T) {
	store := newUnlockedStore(t)
	store.CreateBucket("fin", "secrets", LevelAdminWrapped, "test")
	store.AddAdminToPolicy("fin", "secrets", "alice", []byte("alicepass"))
	store.AddAdminToPolicy("fin", "secrets", "bob", []byte("bobpass"))
	store.AddAdminToPolicy("fin", "secrets", "carol", []byte("carolpass"))

	store.SetNamespacedFull("fin", "secrets", "key", []byte("topSecret"))

	// Alice re-keys.
	if err := store.RotateAdminWrappedDEK("fin", "secrets", "alice", []byte("alicepass")); err != nil {
		t.Fatalf("RotateAdminWrappedDEK alice: %v", err)
	}

	for _, tc := range []struct{ id, pass string }{
		{"alice", "alicepass"},
		{"bob", "bobpass"},
		{"carol", "carolpass"},
	} {
		store.LockBucket("fin", "secrets")
		if err := store.UnlockBucket("fin", "secrets", tc.id, []byte(tc.pass)); err != nil {
			t.Errorf("admin %q locked out after Alice's re-key: %v", tc.id, err)
			continue
		}
		val, err := store.GetNamespacedFull("fin", "secrets", "key")
		if err != nil || string(val) != "topSecret" {
			t.Errorf("admin %q: data inaccessible after rekey: %v %q", tc.id, err, val)
		}
	}
}

// TestRotateAdminWrappedDEK_SurvivesReopen verifies the fix is durable: the
// corrected policy (with unchanged DEKSalt) must round-trip through bbolt so
// that Bob can still unlock after the store is closed and reopened.
func TestRotateAdminWrappedDEK_SurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "rekey.db")

	// First session: create bucket, add admins, rotate Alice.
	{
		s, err := New(Config{DBPath: dbPath})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		s.Unlock([]byte("masterpass"))
		s.CreateBucket("sc", "ns", LevelAdminWrapped, "test")
		s.AddAdminToPolicy("sc", "ns", "alice", []byte("alicepass"))
		s.AddAdminToPolicy("sc", "ns", "bob", []byte("bobpass"))
		if err := s.RotateAdminWrappedDEK("sc", "ns", "alice", []byte("alicepass")); err != nil {
			t.Fatalf("RotateAdminWrappedDEK: %v", err)
		}
		s.Close()
	}

	// Second session: Bob must still be able to unlock.
	{
		s, err := New(Config{DBPath: dbPath})
		if err != nil {
			t.Fatalf("New (reopen): %v", err)
		}
		defer s.Close()
		s.Unlock([]byte("masterpass"))
		if err := s.UnlockBucket("sc", "ns", "bob", []byte("bobpass")); err != nil {
			t.Errorf("Bob locked out after reopen: %v", err)
		}
	}
}

// Move / Copy security downgrade bypass
//
// The old code short-circuited on policy lookup failure and did a raw get+set
// with no security level comparison, bypassing ErrSecurityDowngrade.
// The fix removes the shortcut: Move and Copy unconditionally delegate to
// MoveCrossBucket/CopyCrossBucket which always enforce the downgrade check.
//
// MoveCrossBucket/CopyCrossBucket require both namespaces to have registered
// policies. Tests always call CreateBucket for both sides — this is the
// correct production pattern.

// TestMove_DowngradeIsBlocked is the core security regression test.
// Moving from a higher-security bucket to a lower-security one without
// confirmDowngrade=true must return ErrSecurityDowngrade.
// The old shortcut silently bypassed this check when GetPolicy failed.
func TestMove_DowngradeIsBlocked(t *testing.T) {
	store := newUnlockedStore(t)
	store.CreateBucket(store.defaultScheme, "high", LevelAdminWrapped, "test")
	store.CreateBucket(store.defaultScheme, "low", LevelPasswordOnly, "test")

	// Unlock the admin-wrapped bucket so we can write to it.
	if err := store.AddAdminToPolicy(store.defaultScheme, "high", "alice", []byte("alicepass")); err != nil {
		t.Fatalf("AddAdminToPolicy: %v", err)
	}
	if err := store.SetNamespacedFull(store.defaultScheme, "high", "k", []byte("secret")); err != nil {
		t.Fatalf("Set: %v", err)
	}

	err := store.MoveCrossBucket("k", store.defaultScheme, "high", store.defaultScheme, "low", false)
	if !errors.Is(err, ErrSecurityDowngrade) {
		t.Errorf("move high→low: want ErrSecurityDowngrade, got %v", err)
	}

	// Key must still be in source after the blocked move.
	val, err2 := store.GetNamespacedFull(store.defaultScheme, "high", "k")
	if err2 != nil || string(val) != "secret" {
		t.Errorf("source data should be intact after blocked move: %v %q", err2, val)
	}
}

// TestCopy_DowngradeIsBlocked mirrors TestMove_DowngradeIsBlocked for Copy.
func TestCopy_DowngradeIsBlocked(t *testing.T) {
	store := newUnlockedStore(t)
	store.CreateBucket(store.defaultScheme, "high", LevelAdminWrapped, "test")
	store.CreateBucket(store.defaultScheme, "low", LevelPasswordOnly, "test")

	store.AddAdminToPolicy(store.defaultScheme, "high", "alice", []byte("alicepass"))
	store.SetNamespacedFull(store.defaultScheme, "high", "k", []byte("secret"))

	err := store.CopyCrossBucket("k", store.defaultScheme, "high", store.defaultScheme, "low", false)
	if !errors.Is(err, ErrSecurityDowngrade) {
		t.Errorf("copy high→low: want ErrSecurityDowngrade, got %v", err)
	}
}

// TestMove_SameLevelAllowed verifies Move between equal-security buckets works.
func TestMove_SameLevelAllowed(t *testing.T) {
	store := newUnlockedStore(t)
	store.CreateBucket(store.defaultScheme, "src", LevelPasswordOnly, "test")
	store.CreateBucket(store.defaultScheme, "dst", LevelPasswordOnly, "test")

	store.SetNamespaced("src", "k", []byte("data"))

	if err := store.Move("k", "src", "dst"); err != nil {
		t.Fatalf("Move same-level: %v", err)
	}
	if _, err := store.GetNamespaced("src", "k"); !errors.Is(err, ErrKeyNotFound) {
		t.Error("source should be gone after Move")
	}
	val, _ := store.GetNamespaced("dst", "k")
	if string(val) != "data" {
		t.Errorf("dst wrong: %q", val)
	}
}

// TestCopy_SameLevelAllowed mirrors TestMove_SameLevelAllowed for Copy.
func TestCopy_SameLevelAllowed(t *testing.T) {
	store := newUnlockedStore(t)
	store.CreateBucket(store.defaultScheme, "src", LevelPasswordOnly, "test")
	store.CreateBucket(store.defaultScheme, "dst", LevelPasswordOnly, "test")

	store.SetNamespaced("src", "k", []byte("data"))

	if err := store.Copy("k", "src", "dst"); err != nil {
		t.Fatalf("Copy same-level: %v", err)
	}
	src, _ := store.GetNamespaced("src", "k")
	dst, _ := store.GetNamespaced("dst", "k")
	if string(src) != "data" || string(dst) != "data" {
		t.Errorf("Copy wrong: src=%q dst=%q", src, dst)
	}
}

// TestMove_WithPolicies confirms Move with both policies works after refactor.
func TestMove_WithPolicies(t *testing.T) {
	store := newUnlockedStore(t)
	store.CreateBucket(store.defaultScheme, "src", LevelPasswordOnly, "test")
	store.CreateBucket(store.defaultScheme, "dst", LevelPasswordOnly, "test")

	store.SetNamespaced("src", "k", []byte("data"))

	if err := store.Move("k", "src", "dst"); err != nil {
		t.Fatalf("Move (with policies): %v", err)
	}
	if _, err := store.GetNamespaced("src", "k"); !errors.Is(err, ErrKeyNotFound) {
		t.Error("source should be gone")
	}
	val, _ := store.GetNamespaced("dst", "k")
	if string(val) != "data" {
		t.Errorf("dst wrong: %q", val)
	}
}

// TestCopy_WithPolicies mirrors TestMove_WithPolicies for Copy.
func TestCopy_WithPolicies(t *testing.T) {
	store := newUnlockedStore(t)
	store.CreateBucket(store.defaultScheme, "src", LevelPasswordOnly, "test")
	store.CreateBucket(store.defaultScheme, "dst", LevelPasswordOnly, "test")

	store.SetNamespaced("src", "k", []byte("data"))

	if err := store.Copy("k", "src", "dst"); err != nil {
		t.Fatalf("Copy (with policies): %v", err)
	}
	src, _ := store.GetNamespaced("src", "k")
	dst, _ := store.GetNamespaced("dst", "k")
	if string(src) != "data" || string(dst) != "data" {
		t.Errorf("Copy wrong: src=%q dst=%q", src, dst)
	}
}
