package keeper

import (
	"testing"
	"time"
)

func TestAuditStore_Init(t *testing.T) {
	store := newUnlockedStore(t)
	// init is called inside New(); calling it again must be idempotent.
	if err := store.auditStore.init(); err != nil {
		t.Fatalf("auditStore.init idempotent: %v", err)
	}
}

func TestAuditStore_AppendAndLoad(t *testing.T) {
	store := newUnlockedStore(t)
	store.CreateBucket("as", "ns", LevelPasswordOnly, "t")

	// Append 3 events through the policy chain.
	for i := 0; i < 3; i++ {
		if err := store.policyChain.AppendEvent("as", "ns", "op", i); err != nil {
			t.Fatalf("AppendEvent %d: %v", i, err)
		}
	}

	events, err := store.loadAuditChain("as", "ns")
	if err != nil {
		t.Fatalf("loadAuditChain: %v", err)
	}
	// CreatePolicy appends 1 event; we added 3 more = 4 total.
	if len(events) < 4 {
		t.Errorf("expected >= 4 events, got %d", len(events))
	}
}

func TestAuditStore_LoadChain_Sorted(t *testing.T) {
	store := newUnlockedStore(t)
	store.CreateBucket("sort", "ns", LevelPasswordOnly, "t")

	// Append 5 additional events (CreateBucket already appended 1 for the policy).
	for i := 0; i < 5; i++ {
		if err := store.policyChain.AppendEvent("sort", "ns", "ev", i); err != nil {
			t.Fatalf("AppendEvent %d: %v", i, err)
		}
	}

	events, err := store.loadAuditChain("sort", "ns")
	if err != nil {
		t.Fatalf("loadAuditChain: %v", err)
	}
	if len(events) < 6 {
		t.Fatalf("expected >= 6 events, got %d", len(events))
	}
	// Events must be in strict Seq order (monotonic insertion order).
	for i := 1; i < len(events); i++ {
		if events[i].Seq <= events[i-1].Seq {
			t.Errorf("events not sorted by Seq at index %d: Seq[%d]=%d <= Seq[%d]=%d",
				i, i, events[i].Seq, i-1, events[i-1].Seq)
		}
	}
}

func TestAuditStore_LoadChain_Empty(t *testing.T) {
	store := newUnlockedStore(t)
	events, err := store.loadAuditChain("noscheme", "nons")
	if err != nil {
		t.Fatalf("loadAuditChain on empty: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("expected 0 events, got %d", len(events))
	}
}

func TestAuditStore_GetLastChecksum_Empty(t *testing.T) {
	store := newUnlockedStore(t)
	cs := store.getLastChecksum("noscheme", "nons")
	if cs != "" {
		t.Errorf("expected empty checksum for unknown bucket, got %q", cs)
	}
}

func TestAuditStore_GetLastChecksum_AfterAppend(t *testing.T) {
	store := newUnlockedStore(t)
	store.CreateBucket("cs", "ns", LevelPasswordOnly, "t")

	cs := store.getLastChecksum("cs", "ns")
	if cs == "" {
		t.Error("last checksum should be non-empty after policy creation")
	}
}

func TestAuditStore_PruneEvents_KeepsRecent(t *testing.T) {
	store := newUnlockedStore(t)
	store.CreateBucket("pr", "ns", LevelPasswordOnly, "t")

	for i := 0; i < 5; i++ {
		store.policyChain.AppendEvent("pr", "ns", "op", nil)
		time.Sleep(time.Millisecond)
	}

	// Prune to keep last 3; cutoff=0 means all are "old".
	if err := store.auditStore.pruneEvents("pr", "ns", 0, 3); err != nil {
		t.Fatalf("pruneEvents: %v", err)
	}

	events, _ := store.loadAuditChain("pr", "ns")
	if len(events) > 3 {
		t.Errorf("expected <= 3 events after prune, got %d", len(events))
	}
}

func TestAuditStore_PruneEvents_Empty(t *testing.T) {
	store := newUnlockedStore(t)
	// Prune on non-existent bucket — must not error.
	if err := store.auditStore.pruneEvents("nope", "nope", time.Hour, 10); err != nil {
		t.Fatalf("pruneEvents on missing bucket: %v", err)
	}
}

func TestAuditStore_ChainIndexUpdated(t *testing.T) {
	store := newUnlockedStore(t)
	store.CreateBucket("idx", "ns", LevelPasswordOnly, "t")

	cs1 := store.getLastChecksum("idx", "ns")
	store.policyChain.AppendEvent("idx", "ns", "ev2", nil)
	cs2 := store.getLastChecksum("idx", "ns")

	if cs1 == cs2 {
		t.Error("checksum should change after AppendEvent")
	}
}
