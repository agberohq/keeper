// Package store defines the storage abstraction used by keeper.
// The interface mirrors bbolt's transaction model closely so the bbolt
// implementation is zero-overhead, while alternative backends (in-memory,
// etcd, Badger, …) can be swapped in for testing or production.
package store

// Store is the top-level database handle.
type Store interface {
	// Update executes fn in a read-write transaction.
	// The transaction is committed if fn returns nil, rolled back otherwise.
	Update(fn func(Tx) error) error

	// View executes fn in a read-only transaction.
	View(fn func(Tx) error) error

	// Close releases all resources held by the store.
	Close() error
}

// Tx is a transaction handle.
type Tx interface {
	// Bucket returns the named top-level bucket, or nil if it does not exist.
	Bucket(name []byte) Bucket

	// CreateBucketIfNotExists creates the named top-level bucket if absent.
	CreateBucketIfNotExists(name []byte) (Bucket, error)

	// DeleteBucket removes the named top-level bucket and all its contents.
	DeleteBucket(name []byte) error

	// ForEach iterates over all top-level buckets in the transaction.
	ForEach(fn func(name []byte, b Bucket) error) error
}

// Bucket is a key/value namespace that may contain nested buckets.
type Bucket interface {
	// Get returns the value for key, or nil if the key does not exist.
	// The returned slice is only valid for the lifetime of the transaction.
	Get(key []byte) []byte

	// Put stores key → value.
	Put(key, value []byte) error

	// Delete removes key.
	Delete(key []byte) error

	// Bucket returns a nested bucket by name, or nil if it does not exist.
	Bucket(name []byte) Bucket

	// CreateBucketIfNotExists creates a nested bucket if absent.
	CreateBucketIfNotExists(name []byte) (Bucket, error)

	// DeleteBucket removes a nested bucket and all its contents.
	DeleteBucket(name []byte) error

	// ForEach iterates over all key/value pairs in the bucket.
	// Nested buckets appear with a nil value; use Bucket(k) to open them.
	ForEach(fn func(k, v []byte) error) error

	// NextSequence returns a monotonically increasing integer for the bucket.
	NextSequence() (uint64, error)
}
