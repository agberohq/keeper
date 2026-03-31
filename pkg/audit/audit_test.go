package audit_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/agberohq/keeper/pkg/audit"
	"github.com/agberohq/keeper/pkg/store"
)

func newStore(t *testing.T) *audit.Store {
	t.Helper()
	s := audit.New(store.NewMemStore())
	if err := s.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return s
}

func chain(s *audit.Store, scheme, namespace string, n int) {
	prev := s.LastChecksum(scheme, namespace)
	for i := 0; i < n; i++ {
		e := &audit.Event{
			ID:           fmt.Sprintf("%s-%s-%d", scheme, namespace, i),
			BucketID:     "b",
			Scheme:       scheme,
			Namespace:    namespace,
			EventType:    "op",
			Details:      []byte("{}"),
			Timestamp:    time.Now(),
			PrevChecksum: prev,
		}
		e.Checksum = e.ComputeChecksum(prev)
		_ = s.Append(scheme, namespace, e)
		prev = e.Checksum
	}
}

func TestAppendAndLoad(t *testing.T) {
	s := newStore(t)
	chain(s, "sc", "ns", 1)
	events, err := s.LoadChain("sc", "ns")
	if err != nil {
		t.Fatalf("LoadChain: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Seq != 1 {
		t.Errorf("Seq = %d, want 1", events[0].Seq)
	}
}

func TestSeqMonotonic(t *testing.T) {
	s := newStore(t)
	chain(s, "sc", "ns", 5)
	events, _ := s.LoadChain("sc", "ns")
	for i := 1; i < len(events); i++ {
		if events[i].Seq <= events[i-1].Seq {
			t.Errorf("non-monotonic Seq at %d: %d <= %d", i, events[i].Seq, events[i-1].Seq)
		}
	}
}

func TestVerifyIntegrity_Valid(t *testing.T) {
	s := newStore(t)
	chain(s, "sc", "ns", 5)
	if err := s.VerifyIntegrity("sc", "ns"); err != nil {
		t.Fatalf("valid chain failed: %v", err)
	}
}

func TestVerifyIntegrity_Tampered(t *testing.T) {
	s := newStore(t)
	chain(s, "sc", "ns", 2)
	events, _ := s.LoadChain("sc", "ns")
	if len(events) == 0 {
		t.Fatal("no events")
	}
	// Re-append first event with corrupted checksum.
	tampered := *events[0]
	tampered.Checksum = "deadbeef"
	_ = s.Append("sc", "ns", &tampered)
	if err := s.VerifyIntegrity("sc", "ns"); err == nil {
		t.Error("expected integrity failure after tamper")
	}
}

func TestLastChecksum_Empty(t *testing.T) {
	s := newStore(t)
	if cs := s.LastChecksum("x", "y"); cs != "" {
		t.Errorf("expected empty, got %q", cs)
	}
}

func TestLastChecksum_AfterAppend(t *testing.T) {
	s := newStore(t)
	chain(s, "sc", "ns", 1)
	if cs := s.LastChecksum("sc", "ns"); cs == "" {
		t.Error("expected non-empty checksum after append")
	}
}

func TestLastChecksum_ChangesOnAppend(t *testing.T) {
	s := newStore(t)
	chain(s, "sc", "ns", 1)
	cs1 := s.LastChecksum("sc", "ns")
	chain(s, "sc", "ns", 1)
	cs2 := s.LastChecksum("sc", "ns")
	if cs1 == cs2 {
		t.Error("checksum must change after each append")
	}
}

func TestPrune(t *testing.T) {
	s := newStore(t)
	chain(s, "pr", "ns", 5)
	if err := s.Prune("pr", "ns", 0, 2); err != nil {
		t.Fatalf("Prune: %v", err)
	}
	events, _ := s.LoadChain("pr", "ns")
	if len(events) > 2 {
		t.Errorf("expected <= 2 after prune, got %d", len(events))
	}
}

func TestLoadChain_Empty(t *testing.T) {
	s := newStore(t)
	events, err := s.LoadChain("x", "y")
	if err != nil || len(events) != 0 {
		t.Errorf("empty: events=%d err=%v", len(events), err)
	}
}

func TestPrune_MissingBucket(t *testing.T) {
	s := newStore(t)
	if err := s.Prune("x", "y", time.Hour, 10); err != nil {
		t.Fatalf("prune on missing bucket: %v", err)
	}
}

func TestComputeChecksum_Deterministic(t *testing.T) {
	ts := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	e := &audit.Event{EventType: "op", Details: []byte("{}"), Timestamp: ts}
	if e.ComputeChecksum("a") != e.ComputeChecksum("a") {
		t.Error("not deterministic")
	}
	if e.ComputeChecksum("a") == e.ComputeChecksum("b") {
		t.Error("different prev should differ")
	}
}
