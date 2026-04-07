package keeper

import (
	"strings"
	"testing"
)

// TestGenerateUUID_Format verifies that generateUUID returns a string that
// looks like a UUID (five hex groups separated by dashes) under normal
// conditions where crypto/rand is available.
func TestGenerateUUID_Format(t *testing.T) {
	id := generateUUID()
	parts := strings.Split(id, "-")
	if len(parts) != 5 {
		t.Errorf("expected 5 dash-separated groups, got %d: %q", len(parts), id)
	}
	lengths := []int{8, 4, 4, 4, 12}
	for i, p := range parts {
		if len(p) != lengths[i] {
			t.Errorf("part %d: want len %d, got %d (%q)", i, lengths[i], len(p), p)
		}
		for _, c := range p {
			if !strings.ContainsRune("0123456789abcdef", c) {
				t.Errorf("part %d contains non-hex character %q", i, c)
				break
			}
		}
	}
}

// TestGenerateUUID_Unique verifies that two sequential calls produce different
// UUIDs — all-zero UUIDs from a silently-failing rand.Read would be equal.
func TestGenerateUUID_Unique(t *testing.T) {
	seen := make(map[string]struct{}, 100)
	for i := 0; i < 100; i++ {
		id := generateUUID()
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate UUID on iteration %d: %q", i, id)
		}
		seen[id] = struct{}{}
	}
}

// TestGenerateUUID_NotAllZeros confirms the UUID is never the all-zero sentinel
// that would result from a silently-ignored crypto/rand error in the old code.
func TestGenerateUUID_NotAllZeros(t *testing.T) {
	id := generateUUID()
	allZero := "00000000-0000-0000-0000-000000000000"
	if id == allZero {
		t.Errorf("generateUUID returned all-zero UUID — crypto/rand may be broken")
	}
}

// GlobalClear

// TestGlobalClear_NilsReference verifies that GlobalClear sets the global
// store to nil so subsequent GlobalGetKey calls return an error instead of
// operating on a closed store.
func TestGlobalClear_NilsReference(t *testing.T) {
	store := newUnlockedStore(t)
	GlobalStore(store)

	store.Set("k", []byte("v")) //nolint:errcheck

	// Confirm it's reachable before clear.
	if _, err := GlobalGetKey("k"); err != nil {
		t.Fatalf("GlobalGetKey before clear: %v", err)
	}

	GlobalClear()

	// After clear, GlobalGet must return nil.
	if GlobalGet() != nil {
		t.Error("GlobalGet() should return nil after GlobalClear()")
	}

	// GlobalGetKey must fail cleanly.
	if _, err := GlobalGetKey("k"); err == nil {
		t.Error("GlobalGetKey should error after GlobalClear()")
	}
}

// TestGlobalClear_IdempotentOnNil verifies that calling GlobalClear when the
// global store is already nil does not panic.
func TestGlobalClear_IdempotentOnNil(t *testing.T) {
	GlobalClear() // ensure nil
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("GlobalClear on nil panicked: %v", r)
		}
	}()
	GlobalClear() // second call must not panic
}

// TestGlobalClear_AfterClose simulates the primary lifecycle gap: set global,
// close the store, then clear. Without GlobalClear, a post-Close GlobalGetKey
// would use a closed store. With GlobalClear the call errors cleanly.
func TestGlobalClear_AfterClose(t *testing.T) {
	// Create store without the t.Cleanup auto-close so we control timing.
	s, err := New(testConfig(t.TempDir() + "/gc.db"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s.Unlock([]byte("pass")) //nolint:errcheck
	GlobalStore(s)

	s.Close()
	GlobalClear()

	if GlobalGet() != nil {
		t.Error("global reference should be nil after Close + GlobalClear")
	}
	if _, err := GlobalGetKey("anything"); err == nil {
		t.Error("GlobalGetKey on cleared store should error")
	}
}

// TestGlobalStore_ReplaceStore verifies that GlobalStore replaces a previous
// registration and GlobalClear subsequently clears the new one.
func TestGlobalStore_ReplaceStore(t *testing.T) {
	s1 := newUnlockedStore(t)
	s2 := newUnlockedStore(t)

	GlobalStore(s1)
	s1.Set("key1", []byte("v1")) //nolint:errcheck

	GlobalStore(s2)              // replace
	s2.Set("key2", []byte("v2")) //nolint:errcheck

	// key1 is in s1, not accessible through global (which is now s2).
	if _, err := GlobalGetKey("key1"); err == nil {
		t.Error("key1 should not be in s2 (the current global store)")
	}
	if v, err := GlobalGetKey("key2"); err != nil || string(v) != "v2" {
		t.Errorf("key2 via global: %v %q", err, v)
	}

	GlobalClear()
	if GlobalGet() != nil {
		t.Error("should be nil after GlobalClear")
	}
}
