package keeper

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// helpers

// hookStore returns an unlocked store with a single LevelPasswordOnly bucket
// "ss:test" ready for hook tests.
func hookStore(t *testing.T) *Keeper {
	t.Helper()
	s := newUnlockedStore(t)
	if err := s.CreateBucket("ss", "test", LevelPasswordOnly, "hook-test"); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	return s
}

// mustSet writes a value and fatals on error.
func mustSet(t *testing.T, s *Keeper, key string, val []byte) {
	t.Helper()
	if err := s.Set(key, val); err != nil {
		t.Fatalf("Set(%q): %v", key, val)
	}
}

// mustGet reads a value and fatals on error.
func mustGet(t *testing.T, s *Keeper, key string) []byte {
	t.Helper()
	v, err := s.Get(key)
	if err != nil {
		t.Fatalf("Get(%q): %v", key, err)
	}
	return v
}

// errBoom is a sentinel error returned by Pre* hooks to abort operations.
var errBoom = errors.New("hook abort")

// Global Hooks — PreGet

func TestHook_PreGet_Called(t *testing.T) {
	s := hookStore(t)
	mustSet(t, s, "ss://test/k", []byte("v"))

	var called atomic.Bool
	s.SetHooks(Hooks{
		PreGet: func(scheme, namespace, key string) error {
			called.Store(true)
			if scheme != "ss" || namespace != "test" || key != "k" {
				t.Errorf("PreGet args: got (%q,%q,%q)", scheme, namespace, key)
			}
			return nil
		},
	})
	mustGet(t, s, "ss://test/k")
	if !called.Load() {
		t.Error("PreGet was not called")
	}
}

func TestHook_PreGet_Aborts(t *testing.T) {
	s := hookStore(t)
	mustSet(t, s, "ss://test/k", []byte("v"))

	s.SetHooks(Hooks{
		PreGet: func(_, _, _ string) error { return errBoom },
	})
	_, err := s.Get("ss://test/k")
	if !errors.Is(err, errBoom) {
		t.Errorf("expected errBoom, got %v", err)
	}
	// Value must be unchanged.
	s.SetHooks(Hooks{})
	if got := string(mustGet(t, s, "ss://test/k")); got != "v" {
		t.Errorf("value corrupted: got %q", got)
	}
}

// Global Hooks — PostGet

func TestHook_PostGet_TransformsValue(t *testing.T) {
	s := hookStore(t)
	mustSet(t, s, "ss://test/k", []byte("original"))

	s.SetHooks(Hooks{
		PostGet: func(_, _, _ string, v []byte) ([]byte, error) {
			return append(v, []byte("-transformed")...), nil
		},
	})
	got := mustGet(t, s, "ss://test/k")
	if string(got) != "original-transformed" {
		t.Errorf("PostGet transform: got %q", got)
	}
}

func TestHook_PostGet_CalledAfterSuccessfulRead(t *testing.T) {
	s := hookStore(t)
	mustSet(t, s, "ss://test/k", []byte("v"))

	var called atomic.Bool
	s.SetHooks(Hooks{
		PostGet: func(scheme, namespace, key string, v []byte) ([]byte, error) {
			called.Store(true)
			if scheme != "ss" || namespace != "test" || key != "k" {
				t.Errorf("PostGet args: got (%q,%q,%q)", scheme, namespace, key)
			}
			return v, nil
		},
	})
	mustGet(t, s, "ss://test/k")
	if !called.Load() {
		t.Error("PostGet was not called")
	}
}

func TestHook_PostGet_NotCalledOnMissingKey(t *testing.T) {
	s := hookStore(t)

	var called atomic.Bool
	s.SetHooks(Hooks{
		PostGet: func(_, _, _ string, v []byte) ([]byte, error) {
			called.Store(true)
			return v, nil
		},
	})
	_, err := s.Get("ss://test/missing")
	if err == nil {
		t.Fatal("expected error for missing key")
	}
	if called.Load() {
		t.Error("PostGet should not be called when key is missing")
	}
}

// Global Hooks — PreSet

func TestHook_PreSet_Called(t *testing.T) {
	s := hookStore(t)

	var called atomic.Bool
	s.SetHooks(Hooks{
		PreSet: func(scheme, namespace, key string, value []byte) ([]byte, error) {
			called.Store(true)
			if scheme != "ss" || namespace != "test" || key != "k" {
				t.Errorf("PreSet args: got (%q,%q,%q)", scheme, namespace, key)
			}
			return value, nil
		},
	})
	mustSet(t, s, "ss://test/k", []byte("v"))
	if !called.Load() {
		t.Error("PreSet was not called")
	}
}

func TestHook_PreSet_TransformsValue(t *testing.T) {
	s := hookStore(t)

	s.SetHooks(Hooks{
		PreSet: func(_, _, _ string, v []byte) ([]byte, error) {
			return append(v, []byte("-hook")...), nil
		},
	})
	mustSet(t, s, "ss://test/k", []byte("raw"))

	// Read without hook to see stored value.
	s.SetHooks(Hooks{})
	if got := string(mustGet(t, s, "ss://test/k")); got != "raw-hook" {
		t.Errorf("PreSet transform: stored %q, want %q", got, "raw-hook")
	}
}

func TestHook_PreSet_Aborts(t *testing.T) {
	s := hookStore(t)

	s.SetHooks(Hooks{
		PreSet: func(_, _, _ string, _ []byte) ([]byte, error) { return nil, errBoom },
	})
	err := s.Set("ss://test/k", []byte("v"))
	if !errors.Is(err, errBoom) {
		t.Errorf("expected errBoom, got %v", err)
	}
	// Key must not exist.
	s.SetHooks(Hooks{})
	_, err = s.Get("ss://test/k")
	if !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("key should not exist after aborted Set, got %v", err)
	}
}

// Global Hooks — PostSet

func TestHook_PostSet_CalledAfterCommit(t *testing.T) {
	s := hookStore(t)

	var called atomic.Bool
	s.SetHooks(Hooks{
		PostSet: func(scheme, namespace, key string, value []byte) {
			called.Store(true)
			if scheme != "ss" || namespace != "test" || key != "k" {
				t.Errorf("PostSet args: got (%q,%q,%q)", scheme, namespace, key)
			}
			if string(value) != "v" {
				t.Errorf("PostSet value: got %q, want %q", value, "v")
			}
		},
	})
	mustSet(t, s, "ss://test/k", []byte("v"))
	if !called.Load() {
		t.Error("PostSet was not called")
	}
}

func TestHook_PostSet_NotCalledOnAbort(t *testing.T) {
	s := hookStore(t)

	var postCalled atomic.Bool
	s.SetHooks(Hooks{
		PreSet:  func(_, _, _ string, _ []byte) ([]byte, error) { return nil, errBoom },
		PostSet: func(_, _, _ string, _ []byte) { postCalled.Store(true) },
	})
	s.Set("ss://test/k", []byte("v")) //nolint:errcheck
	if postCalled.Load() {
		t.Error("PostSet must not be called when PreSet aborts")
	}
}

// Global Hooks — PreDelete

func TestHook_PreDelete_Called(t *testing.T) {
	s := hookStore(t)
	mustSet(t, s, "ss://test/k", []byte("v"))

	var called atomic.Bool
	s.SetHooks(Hooks{
		PreDelete: func(scheme, namespace, key string) error {
			called.Store(true)
			if scheme != "ss" || namespace != "test" || key != "k" {
				t.Errorf("PreDelete args: got (%q,%q,%q)", scheme, namespace, key)
			}
			return nil
		},
	})
	if err := s.Delete("ss://test/k"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if !called.Load() {
		t.Error("PreDelete was not called")
	}
}

func TestHook_PreDelete_Aborts(t *testing.T) {
	s := hookStore(t)
	mustSet(t, s, "ss://test/k", []byte("v"))

	s.SetHooks(Hooks{
		PreDelete: func(_, _, _ string) error { return errBoom },
	})
	err := s.Delete("ss://test/k")
	if !errors.Is(err, errBoom) {
		t.Errorf("expected errBoom, got %v", err)
	}
	// Value must still exist.
	s.SetHooks(Hooks{})
	if got := string(mustGet(t, s, "ss://test/k")); got != "v" {
		t.Errorf("value should survive aborted delete, got %q", got)
	}
}

// Global Hooks — PostDelete

func TestHook_PostDelete_CalledAfterCommit(t *testing.T) {
	s := hookStore(t)
	mustSet(t, s, "ss://test/k", []byte("v"))

	var called atomic.Bool
	s.SetHooks(Hooks{
		PostDelete: func(scheme, namespace, key string) {
			called.Store(true)
			if scheme != "ss" || namespace != "test" || key != "k" {
				t.Errorf("PostDelete args: got (%q,%q,%q)", scheme, namespace, key)
			}
		},
	})
	if err := s.Delete("ss://test/k"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if !called.Load() {
		t.Error("PostDelete was not called")
	}
}

func TestHook_PostDelete_NotCalledOnAbort(t *testing.T) {
	s := hookStore(t)
	mustSet(t, s, "ss://test/k", []byte("v"))

	var postCalled atomic.Bool
	s.SetHooks(Hooks{
		PreDelete:  func(_, _, _ string) error { return errBoom },
		PostDelete: func(_, _, _ string) { postCalled.Store(true) },
	})
	s.Delete("ss://test/k") //nolint:errcheck
	if postCalled.Load() {
		t.Error("PostDelete must not be called when PreDelete aborts")
	}
}

// Global Hooks — PreCAS

func TestHook_PreCAS_Called(t *testing.T) {
	s := hookStore(t)
	mustSet(t, s, "ss://test/k", []byte("old"))

	var called atomic.Bool
	s.SetHooks(Hooks{
		PreCAS: func(scheme, namespace, key string, old, new []byte) error {
			called.Store(true)
			if scheme != "ss" || namespace != "test" || key != "k" {
				t.Errorf("PreCAS args: got (%q,%q,%q)", scheme, namespace, key)
			}
			return nil
		},
	})
	if err := s.CompareAndSwap("ss://test/k", []byte("old"), []byte("new")); err != nil {
		t.Fatalf("CAS: %v", err)
	}
	if !called.Load() {
		t.Error("PreCAS was not called")
	}
}

func TestHook_PreCAS_Aborts(t *testing.T) {
	s := hookStore(t)
	mustSet(t, s, "ss://test/k", []byte("old"))

	s.SetHooks(Hooks{
		PreCAS: func(_, _, _ string, _, _ []byte) error { return errBoom },
	})
	err := s.CompareAndSwap("ss://test/k", []byte("old"), []byte("new"))
	if !errors.Is(err, errBoom) {
		t.Errorf("expected errBoom, got %v", err)
	}
	// Value must be unchanged.
	s.SetHooks(Hooks{})
	if got := string(mustGet(t, s, "ss://test/k")); got != "old" {
		t.Errorf("value corrupted after aborted CAS: got %q", got)
	}
}

// Global Hooks — PostCAS

func TestHook_PostCAS_CalledAfterCommit(t *testing.T) {
	s := hookStore(t)
	mustSet(t, s, "ss://test/k", []byte("old"))

	var called atomic.Bool
	s.SetHooks(Hooks{
		PostCAS: func(scheme, namespace, key string, newVal []byte) {
			called.Store(true)
			if string(newVal) != "new" {
				t.Errorf("PostCAS newVal: got %q, want %q", newVal, "new")
			}
		},
	})
	if err := s.CompareAndSwap("ss://test/k", []byte("old"), []byte("new")); err != nil {
		t.Fatalf("CAS: %v", err)
	}
	if !called.Load() {
		t.Error("PostCAS was not called")
	}
}

func TestHook_PostCAS_NotCalledOnConflict(t *testing.T) {
	s := hookStore(t)
	mustSet(t, s, "ss://test/k", []byte("current"))

	var called atomic.Bool
	s.SetHooks(Hooks{
		PostCAS: func(_, _, _ string, _ []byte) { called.Store(true) },
	})
	// Wrong old value — conflict.
	err := s.CompareAndSwap("ss://test/k", []byte("wrong"), []byte("new"))
	if !errors.Is(err, ErrCASConflict) {
		t.Fatalf("expected ErrCASConflict, got %v", err)
	}
	if called.Load() {
		t.Error("PostCAS must not be called on conflict")
	}
}

// Global Hooks — OnAudit

func TestHook_OnAudit_CalledOnSuccess(t *testing.T) {
	s := hookStore(t)

	var auditActions []string
	s.SetHooks(Hooks{
		OnAudit: func(action, _, _, _ string, success bool, _ time.Duration) {
			if success {
				auditActions = append(auditActions, action)
			}
		},
	})
	mustSet(t, s, "ss://test/k", []byte("v"))
	mustGet(t, s, "ss://test/k")
	s.Delete("ss://test/k") //nolint:errcheck

	found := map[string]bool{}
	for _, a := range auditActions {
		found[a] = true
	}
	for _, want := range []string{"set", "get", "delete"} {
		if !found[want] {
			t.Errorf("OnAudit missing action %q; got %v", want, auditActions)
		}
	}
}

func TestHook_OnAudit_CalledOnFailure(t *testing.T) {
	s := hookStore(t)

	var failuresSeen int
	s.SetHooks(Hooks{
		PreSet: func(_, _, _ string, _ []byte) ([]byte, error) { return nil, errBoom },
		OnAudit: func(action, _, _, _ string, success bool, _ time.Duration) {
			if action == "set" && !success {
				failuresSeen++
			}
		},
	})
	s.Set("ss://test/k", []byte("v")) //nolint:errcheck
	if failuresSeen == 0 {
		t.Error("OnAudit not called on failed Set")
	}
}

// SchemeHandler — per-bucket handler

// testHandler records every hook invocation for assertion in tests.
type testHandler struct {
	preGetCalls     atomic.Int32
	postGetCalls    atomic.Int32
	preSetCalls     atomic.Int32
	postSetCalls    atomic.Int32
	preDeleteCalls  atomic.Int32
	postDeleteCalls atomic.Int32
	preCASCalls     atomic.Int32
	postCASCalls    atomic.Int32

	preGetErr    error
	preSetErr    error
	preDeleteErr error
	preCASErr    error

	// transformSet appends this suffix to the value in PreSet when non-nil.
	transformSet []byte
	// transformGet appends this suffix to the value in PostGet when non-nil.
	transformGet []byte
}

func (h *testHandler) PreGet(_, _, _ string) error {
	h.preGetCalls.Add(1)
	return h.preGetErr
}
func (h *testHandler) PostGet(_, _, _ string, v []byte) ([]byte, error) {
	h.postGetCalls.Add(1)
	if h.transformGet != nil {
		return append(v, h.transformGet...), nil
	}
	return v, nil
}
func (h *testHandler) PreSet(_, _, _ string, v []byte) ([]byte, error) {
	h.preSetCalls.Add(1)
	if h.preSetErr != nil {
		return nil, h.preSetErr
	}
	if h.transformSet != nil {
		return append(v, h.transformSet...), nil
	}
	return v, nil
}
func (h *testHandler) PostSet(_, _, _ string, _ []byte) {
	h.postSetCalls.Add(1)
}
func (h *testHandler) PreDelete(_, _, _ string) error {
	h.preDeleteCalls.Add(1)
	return h.preDeleteErr
}
func (h *testHandler) PostDelete(_, _, _ string) {
	h.postDeleteCalls.Add(1)
}
func (h *testHandler) PreCAS(_, _, _ string, _, _ []byte) error {
	h.preCASCalls.Add(1)
	return h.preCASErr
}
func (h *testHandler) PostCAS(_, _, _ string, _ []byte) {
	h.postCASCalls.Add(1)
}

func TestSchemeHandler_AllHooksCalled(t *testing.T) {
	s := hookStore(t)

	h := &testHandler{}
	if err := s.RegisterBucketHandler("ss", "test", h); err != nil {
		t.Fatalf("RegisterBucketHandler: %v", err)
	}

	mustSet(t, s, "ss://test/k", []byte("v"))
	mustGet(t, s, "ss://test/k")
	s.CompareAndSwap("ss://test/k", []byte("v"), []byte("v2")) //nolint:errcheck
	s.Delete("ss://test/k")                                    //nolint:errcheck

	checks := []struct {
		name string
		got  int32
		want int32
	}{
		{"PreGet", h.preGetCalls.Load(), 1},
		{"PostGet", h.postGetCalls.Load(), 1},
		{"PreSet", h.preSetCalls.Load(), 1},
		{"PostSet", h.postSetCalls.Load(), 1},
		{"PreCAS", h.preCASCalls.Load(), 1},
		{"PostCAS", h.postCASCalls.Load(), 1},
		{"PreDelete", h.preDeleteCalls.Load(), 1},
		{"PostDelete", h.postDeleteCalls.Load(), 1},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("SchemeHandler.%s: called %d times, want %d", c.name, c.got, c.want)
		}
	}
}

func TestSchemeHandler_PreSet_Aborts(t *testing.T) {
	s := hookStore(t)

	h := &testHandler{preSetErr: errBoom}
	if err := s.RegisterBucketHandler("ss", "test", h); err != nil {
		t.Fatalf("RegisterBucketHandler: %v", err)
	}

	err := s.Set("ss://test/k", []byte("v"))
	if !errors.Is(err, errBoom) {
		t.Errorf("expected errBoom, got %v", err)
	}
	if h.postSetCalls.Load() != 0 {
		t.Error("PostSet must not be called when PreSet aborts")
	}
	_, err = s.Get("ss://test/k")
	if !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("key should not exist after aborted Set, got %v", err)
	}
}

func TestSchemeHandler_PreDelete_Aborts(t *testing.T) {
	s := hookStore(t)
	mustSet(t, s, "ss://test/k", []byte("v"))

	h := &testHandler{preDeleteErr: errBoom}
	if err := s.RegisterBucketHandler("ss", "test", h); err != nil {
		t.Fatalf("RegisterBucketHandler: %v", err)
	}

	err := s.Delete("ss://test/k")
	if !errors.Is(err, errBoom) {
		t.Errorf("expected errBoom, got %v", err)
	}
	if h.postDeleteCalls.Load() != 0 {
		t.Error("PostDelete must not be called when PreDelete aborts")
	}
	if string(mustGet(t, s, "ss://test/k")) != "v" {
		t.Error("value should survive aborted delete")
	}
}

func TestSchemeHandler_PreGet_Aborts(t *testing.T) {
	s := hookStore(t)
	mustSet(t, s, "ss://test/k", []byte("v"))

	h := &testHandler{preGetErr: errBoom}
	if err := s.RegisterBucketHandler("ss", "test", h); err != nil {
		t.Fatalf("RegisterBucketHandler: %v", err)
	}

	_, err := s.Get("ss://test/k")
	if !errors.Is(err, errBoom) {
		t.Errorf("expected errBoom, got %v", err)
	}
	if h.postGetCalls.Load() != 0 {
		t.Error("PostGet must not be called when PreGet aborts")
	}
}

func TestSchemeHandler_PreCAS_Aborts(t *testing.T) {
	s := hookStore(t)
	mustSet(t, s, "ss://test/k", []byte("old"))

	h := &testHandler{preCASErr: errBoom}
	if err := s.RegisterBucketHandler("ss", "test", h); err != nil {
		t.Fatalf("RegisterBucketHandler: %v", err)
	}

	err := s.CompareAndSwap("ss://test/k", []byte("old"), []byte("new"))
	if !errors.Is(err, errBoom) {
		t.Errorf("expected errBoom, got %v", err)
	}
	if h.postCASCalls.Load() != 0 {
		t.Error("PostCAS must not be called when PreCAS aborts")
	}
	if string(mustGet(t, s, "ss://test/k")) != "old" {
		t.Error("value corrupted after aborted CAS")
	}
}

func TestSchemeHandler_Transform_Set_Get(t *testing.T) {
	s := hookStore(t)

	h := &testHandler{
		transformSet: []byte("-stored"),
		transformGet: []byte("-read"),
	}
	if err := s.RegisterBucketHandler("ss", "test", h); err != nil {
		t.Fatalf("RegisterBucketHandler: %v", err)
	}

	mustSet(t, s, "ss://test/k", []byte("raw"))
	got := mustGet(t, s, "ss://test/k")
	// raw → PreSet appends "-stored" → stored as "raw-stored"
	// "raw-stored" → PostGet appends "-read" → "raw-stored-read"
	if string(got) != "raw-stored-read" {
		t.Errorf("transform chain: got %q, want %q", got, "raw-stored-read")
	}
}

// Global + SchemeHandler both fire

func TestHook_GlobalAndHandler_BothFire(t *testing.T) {
	s := hookStore(t)

	var globalPreSet atomic.Bool
	s.SetHooks(Hooks{
		PreSet: func(_, _, _ string, v []byte) ([]byte, error) {
			globalPreSet.Store(true)
			return v, nil
		},
	})

	h := &testHandler{}
	if err := s.RegisterBucketHandler("ss", "test", h); err != nil {
		t.Fatalf("RegisterBucketHandler: %v", err)
	}
	mustSet(t, s, "ss://test/k", []byte("v"))

	if !globalPreSet.Load() {
		t.Error("global PreSet hook was not called")
	}
	if h.preSetCalls.Load() == 0 {
		t.Error("handler PreSet hook was not called")
	}
}

// RegisterBucketHandler edge cases

func TestRegisterBucketHandler_NotFound(t *testing.T) {
	s := hookStore(t)
	err := s.RegisterBucketHandler("ss", "nonexistent", &testHandler{})
	if !errors.Is(err, ErrPolicyNotFound) {
		t.Errorf("expected ErrPolicyNotFound, got %v", err)
	}
}

func TestRegisterBucketHandler_NilHandlerIsNoop(t *testing.T) {
	s := hookStore(t)
	if err := s.RegisterBucketHandler("ss", "test", nil); err != nil {
		t.Errorf("nil handler should be a no-op, got %v", err)
	}
}

func TestRegisterBucketHandler_OnlyAffectsTargetBucket(t *testing.T) {
	s := hookStore(t)
	if err := s.CreateBucket("ss", "other", LevelPasswordOnly, "t"); err != nil {
		t.Fatalf("CreateBucket other: %v", err)
	}

	h := &testHandler{}
	if err := s.RegisterBucketHandler("ss", "test", h); err != nil {
		t.Fatalf("RegisterBucketHandler: %v", err)
	}

	// Write to a different bucket — handler must not fire.
	mustSet(t, s, "ss://other/k", []byte("v"))
	if h.preSetCalls.Load() != 0 {
		t.Error("handler called for wrong bucket")
	}

	// Write to the registered bucket — handler must fire.
	mustSet(t, s, "ss://test/k", []byte("v"))
	if h.preSetCalls.Load() != 1 {
		t.Errorf("handler PreSet calls: got %d, want 1", h.preSetCalls.Load())
	}
}
