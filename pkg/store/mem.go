package store

import (
	"fmt"
	"sync"
)

// MemStore is an in-memory Store implementation backed by nested maps.
// It is goroutine-safe and is designed for unit tests and embedding use-cases
// where no persistent file is required.
//
// Limitations:
// No durable persistence across process restarts.
// NextSequence values are not snapshotted across transactions.
// ForEach iteration order is not guaranteed (map order).
type MemStore struct {
	mu   sync.RWMutex
	data map[string]*memBucket // top-level buckets keyed by name
}

// NewMemStore creates an empty in-memory store.
func NewMemStore() *MemStore {
	return &MemStore{data: make(map[string]*memBucket)}
}

// Ensure compile-time interface satisfaction.
var _ Store = (*MemStore)(nil)

func (s *MemStore) Update(fn func(Tx) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Copy-on-write: work on a deep clone; commit on success.
	clone := deepCloneBuckets(s.data)
	tx := &memTx{buckets: clone, readOnly: false}
	if err := fn(tx); err != nil {
		return err
	}
	s.data = tx.buckets
	return nil
}

func (s *MemStore) View(fn func(Tx) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tx := &memTx{buckets: s.data, readOnly: true}
	return fn(tx)
}

func (s *MemStore) Close() error { return nil }

type memTx struct {
	buckets  map[string]*memBucket
	readOnly bool
}

var _ Tx = (*memTx)(nil)

func (t *memTx) Bucket(name []byte) Bucket {
	b, ok := t.buckets[string(name)]
	if !ok {
		return nil
	}
	return b
}

func (t *memTx) CreateBucketIfNotExists(name []byte) (Bucket, error) {
	if t.readOnly {
		return nil, fmt.Errorf("cannot create bucket in read-only transaction")
	}
	key := string(name)
	if _, ok := t.buckets[key]; !ok {
		t.buckets[key] = newMemBucket()
	}
	return t.buckets[key], nil
}

func (t *memTx) DeleteBucket(name []byte) error {
	if t.readOnly {
		return fmt.Errorf("cannot delete bucket in read-only transaction")
	}
	key := string(name)
	if _, ok := t.buckets[key]; !ok {
		return fmt.Errorf("bucket %q not found", key)
	}
	delete(t.buckets, key)
	return nil
}

func (t *memTx) ForEach(fn func(name []byte, b Bucket) error) error {
	for name, b := range t.buckets {
		if err := fn([]byte(name), b); err != nil {
			return err
		}
	}
	return nil
}

type memBucket struct {
	kv       map[string][]byte
	children map[string]*memBucket
	seq      uint64
}

func newMemBucket() *memBucket {
	return &memBucket{
		kv:       make(map[string][]byte),
		children: make(map[string]*memBucket),
	}
}

var _ Bucket = (*memBucket)(nil)

func (b *memBucket) Get(key []byte) []byte {
	v, ok := b.kv[string(key)]
	if !ok {
		return nil
	}
	cp := make([]byte, len(v))
	copy(cp, v)
	return cp
}

func (b *memBucket) Put(key, value []byte) error {
	cp := make([]byte, len(value))
	copy(cp, value)
	b.kv[string(key)] = cp
	return nil
}

func (b *memBucket) Delete(key []byte) error {
	delete(b.kv, string(key))
	return nil
}

func (b *memBucket) Bucket(name []byte) Bucket {
	child, ok := b.children[string(name)]
	if !ok {
		return nil
	}
	return child
}

func (b *memBucket) CreateBucketIfNotExists(name []byte) (Bucket, error) {
	key := string(name)
	if _, ok := b.children[key]; !ok {
		b.children[key] = newMemBucket()
	}
	return b.children[key], nil
}

func (b *memBucket) DeleteBucket(name []byte) error {
	key := string(name)
	if _, ok := b.children[key]; !ok {
		return fmt.Errorf("bucket %q not found", key)
	}
	delete(b.children, key)
	return nil
}

func (b *memBucket) ForEach(fn func(k, v []byte) error) error {
	// Key/value pairs first.
	for k, v := range b.kv {
		if err := fn([]byte(k), v); err != nil {
			return err
		}
	}
	// Nested buckets appear with nil value; caller uses Bucket(k) to open them.
	for name := range b.children {
		if err := fn([]byte(name), nil); err != nil {
			return err
		}
	}
	return nil
}

func (b *memBucket) NextSequence() (uint64, error) {
	b.seq++
	return b.seq, nil
}

func deepCloneBuckets(src map[string]*memBucket) map[string]*memBucket {
	dst := make(map[string]*memBucket, len(src))
	for k, v := range src {
		dst[k] = deepCloneBucket(v)
	}
	return dst
}

func deepCloneBucket(src *memBucket) *memBucket {
	dst := &memBucket{
		kv:       make(map[string][]byte, len(src.kv)),
		children: make(map[string]*memBucket, len(src.children)),
		seq:      src.seq,
	}
	for k, v := range src.kv {
		cp := make([]byte, len(v))
		copy(cp, v)
		dst.kv[k] = cp
	}
	for k, child := range src.children {
		dst.children[k] = deepCloneBucket(child)
	}
	return dst
}
