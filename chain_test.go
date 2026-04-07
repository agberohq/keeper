package keeper

import (
	"path/filepath"
	"testing"
	"time"
)

func TestChain_CreatePolicy_Persists(t *testing.T) {
	store := newUnlockedStore(t)
	if err := store.CreateBucket("s1", "ns1", LevelPasswordOnly, "test"); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	policy, err := store.GetPolicy("s1", "ns1")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if policy.Scheme != "s1" || policy.Namespace != "ns1" {
		t.Errorf("policy fields wrong: got %+v", policy)
	}
	if policy.Level != LevelPasswordOnly {
		t.Errorf("level = %q, want %q", policy.Level, LevelPasswordOnly)
	}
	if policy.ID == "" {
		t.Error("policy ID must be non-empty")
	}
}

func TestChain_CreatePolicy_Immutable(t *testing.T) {
	store := newUnlockedStore(t)
	store.CreateBucket("s1", "ns1", LevelPasswordOnly, "test")
	err := store.CreateBucket("s1", "ns1", LevelPasswordOnly, "test")
	if err != ErrPolicyImmutable {
		t.Errorf("expected ErrPolicyImmutable, got %v", err)
	}
}

func TestChain_CreatePolicy_Validates(t *testing.T) {
	store := newUnlockedStore(t)
	if err := store.CreateBucket("bad/scheme", "ns", LevelPasswordOnly, "t"); err == nil {
		t.Error("expected error for invalid scheme")
	}
	if err := store.CreateBucket("s", "bad\x00ns", LevelPasswordOnly, "t"); err == nil {
		t.Error("expected error for invalid namespace")
	}
	if err := store.CreateBucket("s", "ns", LevelAdminWrapped, "t"); err != nil {
		t.Errorf("valid LevelAdminWrapped bucket creation failed: %v", err)
	}
}

func TestChain_AppendEvent_Basic(t *testing.T) {
	store := newUnlockedStore(t)
	store.CreateBucket("ev", "ns", LevelPasswordOnly, "t")
	if err := store.policyChain.AppendEvent("ev", "ns", "custom_event",
		map[string]string{"k": "v"}); err != nil {
		t.Fatalf("AppendEvent: %v", err)
	}
}

func TestChain_AppendEvent_NoPolicy(t *testing.T) {
	store := newUnlockedStore(t)
	err := store.policyChain.AppendEvent("nopolicy", "ns", "ev", nil)
	if err != ErrPolicyNotFound {
		t.Errorf("expected ErrPolicyNotFound, got %v", err)
	}
}

func TestChain_VerifyChainIntegrity_Empty(t *testing.T) {
	store := newUnlockedStore(t)
	if err := store.policyChain.VerifyChainIntegrity("noscheme", "nons"); err != nil {
		t.Errorf("empty chain should pass: %v", err)
	}
}

func TestChain_VerifyChainIntegrity_SingleEvent(t *testing.T) {
	store := newUnlockedStore(t)
	store.CreateBucket("sc", "ns", LevelPasswordOnly, "t")
	if err := store.policyChain.VerifyChainIntegrity("sc", "ns"); err != nil {
		t.Fatalf("single-event chain should pass: %v", err)
	}
}

func TestChain_VerifyChainIntegrity_MultiEvent(t *testing.T) {
	store := newUnlockedStore(t)
	store.CreateBucket("sc", "ns", LevelPasswordOnly, "t")
	for i := 0; i < 5; i++ {
		if err := store.policyChain.AppendEvent("sc", "ns", "op",
			map[string]string{"i": string(rune('0' + i))}); err != nil {
			t.Fatalf("AppendEvent %d: %v", i, err)
		}
	}
	if err := store.policyChain.VerifyChainIntegrity("sc", "ns"); err != nil {
		t.Fatalf("multi-event chain should pass: %v", err)
	}
}

func TestChain_VerifyChainIntegrity_TamperedChecksum(t *testing.T) {
	store := newUnlockedStore(t)
	store.CreateBucket("sc", "ns", LevelPasswordOnly, "t")
	store.policyChain.AppendEvent("sc", "ns", "ev1", nil)
	events, err := store.loadAuditChain("sc", "ns")
	if err != nil || len(events) == 0 {
		t.Fatalf("loadAuditChain: len=%d err=%v", len(events), err)
	}
	events[0].Checksum = "deadbeef"
	_ = store.auditStore.appendEvent("sc", "ns", events[0])
	err = store.policyChain.VerifyChainIntegrity("sc", "ns")
	if err == nil {
		t.Error("expected chain integrity failure after tamper")
	}
}

func TestChain_PruneEvents_PasswordOnly(t *testing.T) {
	store := newUnlockedStore(t)
	store.CreateBucket("pr", "ns", LevelPasswordOnly, "t")
	for i := 0; i < 3; i++ {
		store.policyChain.AppendEvent("pr", "ns", "op", nil)
	}
	if err := store.policyChain.PruneEvents("pr", "ns", 0, 1); err != nil {
		t.Fatalf("PruneEvents: %v", err)
	}
}

func TestChain_PruneEvents_HSM_Skipped(t *testing.T) {
	store := newUnlockedStore(t)
	store.CreateBucket("sh", "ns", LevelAdminWrapped, "t")
	if err := store.policyChain.PruneEvents("sh", "ns", 0, 0); err != nil {
		t.Fatalf("PruneEvents on AdminWrapped: %v", err)
	}
}

func TestChain_PolicySurvivesReopen(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "s.db")
	s1, _ := New(testConfig(dbPath))
	s1.Unlock([]byte("pass"))
	s1.CreateBucket("ss", "ns", LevelPasswordOnly, "host")
	s1.Close()
	s2, err := Open(testConfig(dbPath))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s2.Close()
	s2.Unlock([]byte("pass"))
	policy, err := s2.GetPolicy("ss", "ns")
	if err != nil {
		t.Fatalf("GetPolicy after reopen: %v", err)
	}
	if policy.Scheme != "ss" || policy.Level != LevelPasswordOnly {
		t.Errorf("policy wrong after reopen: %+v", policy)
	}
}

func TestBucketEvent_ComputeChecksum_Deterministic(t *testing.T) {
	ts := time.Date(2024, 1, 2, 3, 4, 5, 6, time.UTC)
	e := &BucketEvent{
		EventType: "created",
		Details:   []byte(`{"id":"abc"}`),
		Timestamp: ts,
	}
	c1 := e.ComputeChecksum("")
	c2 := e.ComputeChecksum("")
	if c1 != c2 {
		t.Error("ComputeChecksum must be deterministic")
	}
	if len(c1) != 64 {
		t.Errorf("expected 64-char hex SHA-256, got len=%d", len(c1))
	}
}

func TestBucketEvent_ComputeChecksum_DifferentPrev(t *testing.T) {
	ts := time.Now()
	e := &BucketEvent{EventType: "op", Details: []byte("{}"), Timestamp: ts}
	c1 := e.ComputeChecksum("aaa")
	c2 := e.ComputeChecksum("bbb")
	if c1 == c2 {
		t.Error("different prevChecksum must yield different checksum")
	}
}

func TestBucketEvent_VerifyChecksum(t *testing.T) {
	ts := time.Now()
	e := &BucketEvent{EventType: "op", Details: []byte("{}"), Timestamp: ts}
	prev := "prevhash"
	e.PrevChecksum = prev
	e.Checksum = e.ComputeChecksum(prev)
	if !e.VerifyChecksum() {
		t.Error("VerifyChecksum should pass with correct checksum")
	}
	e.Checksum = "wronghash"
	if e.VerifyChecksum() {
		t.Error("VerifyChecksum should fail with wrong checksum")
	}
}

func TestBucketSecurityPolicy_Validate(t *testing.T) {
	base := BucketSecurityPolicy{
		ID:        "uuid-1",
		Scheme:    "s",
		Namespace: "ns",
		Level:     LevelPasswordOnly,
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("valid policy: %v", err)
	}
	p := base
	p.ID = ""
	if err := p.Validate(); err == nil {
		t.Error("empty ID should fail")
	}
	p = base
	p.Level = "unknown"
	if err := p.Validate(); err == nil {
		t.Error("unknown level should fail")
	}
	p = base
	p.Level = LevelAdminWrapped
	p.DEKSalt = nil
	if err := p.Validate(); err == nil {
		t.Error("LevelAdminWrapped without DEKSalt should fail")
	}
	p = base
	p.Level = LevelAdminWrapped
	p.DEKSalt = make([]byte, 32)
	if err := p.Validate(); err != nil {
		t.Errorf("valid LevelAdminWrapped policy: %v", err)
	}
}
