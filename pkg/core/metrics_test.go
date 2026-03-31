package core

import (
	"testing"
	"time"
)

func TestMetrics_Counters(t *testing.T) {
	m := &Metrics{}

	m.IncrementRead()
	m.IncrementRead()
	m.IncrementWrite()
	m.IncrementDelete()
	m.IncrementList()
	m.IncrementCAS()
	m.IncrementRotation()

	snap := m.Snapshot()
	if snap.ReadsTotal != 2 {
		t.Errorf("ReadsTotal: got %d want 2", snap.ReadsTotal)
	}
	if snap.WritesTotal != 1 {
		t.Errorf("WritesTotal: got %d want 1", snap.WritesTotal)
	}
	if snap.DeletesTotal != 1 {
		t.Errorf("DeletesTotal: got %d want 1", snap.DeletesTotal)
	}
	if snap.ListsTotal != 1 {
		t.Errorf("ListsTotal: got %d want 1", snap.ListsTotal)
	}
	if snap.CASTotal != 1 {
		t.Errorf("CASTotal: got %d want 1", snap.CASTotal)
	}
	if snap.RotationsTotal != 1 {
		t.Errorf("RotationsTotal: got %d want 1", snap.RotationsTotal)
	}
}

func TestMetrics_ErrorCounters(t *testing.T) {
	m := &Metrics{}

	m.IncrementReadError()
	m.IncrementReadError()
	m.IncrementWriteError()
	m.IncrementDecryptError()
	m.IncrementEncryptError()

	snap := m.Snapshot()
	if snap.ReadErrors != 2 {
		t.Errorf("ReadErrors: got %d want 2", snap.ReadErrors)
	}
	if snap.WriteErrors != 1 {
		t.Errorf("WriteErrors: got %d want 1", snap.WriteErrors)
	}
	if snap.DecryptErrors != 1 {
		t.Errorf("DecryptErrors: got %d want 1", snap.DecryptErrors)
	}
	if snap.EncryptErrors != 1 {
		t.Errorf("EncryptErrors: got %d want 1", snap.EncryptErrors)
	}
}

func TestMetrics_ActiveOperations(t *testing.T) {
	m := &Metrics{}

	m.IncrementActive()
	m.IncrementActive()
	m.IncrementActive()

	if m.Snapshot().ActiveOperations != 3 {
		t.Errorf("ActiveOperations: got %d want 3", m.Snapshot().ActiveOperations)
	}

	m.DecrementActive()
	if m.Snapshot().ActiveOperations != 2 {
		t.Errorf("ActiveOperations after decrement: got %d want 2", m.Snapshot().ActiveOperations)
	}
}

func TestMetrics_CacheCounters(t *testing.T) {
	m := &Metrics{}

	m.IncrementCacheHit()
	m.IncrementCacheHit()
	m.IncrementCacheMiss()

	snap := m.Snapshot()
	if snap.CacheHits != 2 {
		t.Errorf("CacheHits: got %d want 2", snap.CacheHits)
	}
	if snap.CacheMisses != 1 {
		t.Errorf("CacheMisses: got %d want 1", snap.CacheMisses)
	}
}

func TestMetrics_LatencyRecording(t *testing.T) {
	m := &Metrics{}

	m.RecordReadLatency(10 * time.Millisecond)
	snap := m.Snapshot()
	if snap.AvgReadLatency == 0 {
		t.Error("AvgReadLatency should be non-zero after recording")
	}

	m.RecordWriteLatency(5 * time.Millisecond)
	snap = m.Snapshot()
	if snap.AvgWriteLatency == 0 {
		t.Error("AvgWriteLatency should be non-zero after recording")
	}
}

func TestMetrics_LatencyEMA_Converges(t *testing.T) {
	m := &Metrics{}

	// Seed with a high value then drive it down; EMA must trend downward.
	m.RecordReadLatency(100 * time.Millisecond)
	before := m.Snapshot().AvgReadLatency

	for i := 0; i < 50; i++ {
		m.RecordReadLatency(1 * time.Millisecond)
	}

	after := m.Snapshot().AvgReadLatency
	if after >= before {
		t.Errorf("EMA did not converge downward: before=%v after=%v", before, after)
	}
}

func TestMetrics_Snapshot_IsPointInTime(t *testing.T) {
	m := &Metrics{}
	m.IncrementRead()

	snap1 := m.Snapshot()
	m.IncrementRead()
	snap2 := m.Snapshot()

	if snap1.ReadsTotal != 1 {
		t.Errorf("snap1.ReadsTotal: got %d want 1", snap1.ReadsTotal)
	}
	if snap2.ReadsTotal != 2 {
		t.Errorf("snap2.ReadsTotal: got %d want 2", snap2.ReadsTotal)
	}
}

func TestMetrics_Zero(t *testing.T) {
	m := &Metrics{}
	snap := m.Snapshot()

	if snap.ReadsTotal != 0 || snap.WritesTotal != 0 || snap.ReadErrors != 0 {
		t.Error("fresh Metrics snapshot should be all zeros")
	}
}
