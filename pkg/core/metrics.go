package core

import (
	"sync/atomic"
	"time"
)

// Metrics provides real-time operational metrics for the store.
// This is separate from Stats() which provides persistent storage metrics.
type Metrics struct {
	// Operation counters
	ReadsTotal     atomic.Int64
	WritesTotal    atomic.Int64
	DeletesTotal   atomic.Int64
	ListsTotal     atomic.Int64
	CASTotal       atomic.Int64
	RotationsTotal atomic.Int64

	// Error counters
	ReadErrors    atomic.Int64
	WriteErrors   atomic.Int64
	DecryptErrors atomic.Int64
	EncryptErrors atomic.Int64

	// Performance metrics
	AvgReadLatency  atomic.Int64 // nanoseconds
	AvgWriteLatency atomic.Int64 // nanoseconds

	// Current state
	ActiveOperations atomic.Int64
	QueueDepth       atomic.Int64

	// Cache metrics (if caching layer added later)
	CacheHits   atomic.Int64
	CacheMisses atomic.Int64
}

// Snapshot returns a point-in-time copy of all metrics.
func (m *Metrics) Snapshot() MetricsSnapshot {
	return MetricsSnapshot{
		ReadsTotal:       m.ReadsTotal.Load(),
		WritesTotal:      m.WritesTotal.Load(),
		DeletesTotal:     m.DeletesTotal.Load(),
		ListsTotal:       m.ListsTotal.Load(),
		CASTotal:         m.CASTotal.Load(),
		RotationsTotal:   m.RotationsTotal.Load(),
		ReadErrors:       m.ReadErrors.Load(),
		WriteErrors:      m.WriteErrors.Load(),
		DecryptErrors:    m.DecryptErrors.Load(),
		EncryptErrors:    m.EncryptErrors.Load(),
		AvgReadLatency:   time.Duration(m.AvgReadLatency.Load()),
		AvgWriteLatency:  time.Duration(m.AvgWriteLatency.Load()),
		ActiveOperations: m.ActiveOperations.Load(),
		QueueDepth:       m.QueueDepth.Load(),
		CacheHits:        m.CacheHits.Load(),
		CacheMisses:      m.CacheMisses.Load(),
	}
}

// MetricsSnapshot is a point-in-time copy of metrics.
type MetricsSnapshot struct {
	// Operation counters
	ReadsTotal     int64 `json:"reads_total"`
	WritesTotal    int64 `json:"writes_total"`
	DeletesTotal   int64 `json:"deletes_total"`
	ListsTotal     int64 `json:"lists_total"`
	CASTotal       int64 `json:"cas_total"`
	RotationsTotal int64 `json:"rotations_total"`

	// Error counters
	ReadErrors    int64 `json:"read_errors"`
	WriteErrors   int64 `json:"write_errors"`
	DecryptErrors int64 `json:"decrypt_errors"`
	EncryptErrors int64 `json:"encrypt_errors"`

	// Performance metrics
	AvgReadLatency  time.Duration `json:"avg_read_latency_ns"`
	AvgWriteLatency time.Duration `json:"avg_write_latency_ns"`

	// Current state
	ActiveOperations int64 `json:"active_operations"`
	QueueDepth       int64 `json:"queue_depth"`

	// Cache metrics
	CacheHits   int64 `json:"cache_hits"`
	CacheMisses int64 `json:"cache_misses"`
}

// recordLatency updates the average latency using exponential moving average.
func (m *Metrics) recordLatency(currentAvg *atomic.Int64, newLatency time.Duration) {
	const alpha = 0.1 // EMA smoothing factor
	current := time.Duration(currentAvg.Load())
	if current == 0 {
		currentAvg.Store(int64(newLatency))
		return
	}
	newAvg := time.Duration(float64(current)*(1-alpha) + float64(newLatency)*alpha)
	currentAvg.Store(int64(newAvg))
}

// IncrementRead increments the read counter.
func (m *Metrics) IncrementRead() {
	m.ReadsTotal.Add(1)
}

// IncrementWrite increments the write counter.
func (m *Metrics) IncrementWrite() {
	m.WritesTotal.Add(1)
}

// IncrementDelete increments the delete counter.
func (m *Metrics) IncrementDelete() {
	m.DeletesTotal.Add(1)
}

// IncrementList increments the list counter.
func (m *Metrics) IncrementList() {
	m.ListsTotal.Add(1)
}

// IncrementCAS increments the compare-and-swap counter.
func (m *Metrics) IncrementCAS() {
	m.CASTotal.Add(1)
}

// IncrementRotation increments the rotation counter.
func (m *Metrics) IncrementRotation() {
	m.RotationsTotal.Add(1)
}

// IncrementReadError increments the read error counter.
func (m *Metrics) IncrementReadError() {
	m.ReadErrors.Add(1)
}

// IncrementWriteError increments the write error counter.
func (m *Metrics) IncrementWriteError() {
	m.WriteErrors.Add(1)
}

// IncrementDecryptError increments the decrypt error counter.
func (m *Metrics) IncrementDecryptError() {
	m.DecryptErrors.Add(1)
}

// IncrementEncryptError increments the encrypt error counter.
func (m *Metrics) IncrementEncryptError() {
	m.EncryptErrors.Add(1)
}

// IncrementActive increments the active operations counter.
func (m *Metrics) IncrementActive() {
	m.ActiveOperations.Add(1)
}

// DecrementActive decrements the active operations counter.
func (m *Metrics) DecrementActive() {
	m.ActiveOperations.Add(-1)
}

// RecordReadLatency records a read operation latency.
func (m *Metrics) RecordReadLatency(latency time.Duration) {
	m.recordLatency(&m.AvgReadLatency, latency)
}

// RecordWriteLatency records a write operation latency.
func (m *Metrics) RecordWriteLatency(latency time.Duration) {
	m.recordLatency(&m.AvgWriteLatency, latency)
}

// IncrementCacheHit increments the cache hit counter.
func (m *Metrics) IncrementCacheHit() {
	m.CacheHits.Add(1)
}

// IncrementCacheMiss increments the cache miss counter.
func (m *Metrics) IncrementCacheMiss() {
	m.CacheMisses.Add(1)
}
