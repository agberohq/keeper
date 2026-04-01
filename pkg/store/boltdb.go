package store

import (
	"time"

	bolt "go.etcd.io/bbolt"
)

// BoltStore wraps a bbolt.DB and implements Store.
type BoltStore struct {
	db *bolt.DB
}

// Ensure compile-time interface satisfaction.
var _ Store = (*BoltStore)(nil)

// Open opens (or creates) a bbolt database at path with mode 0600.
// A 5-second timeout is applied so Open never blocks indefinitely when
// another process holds the file lock.
func Open(path string) (*BoltStore, error) {
	db, err := bolt.Open(path, 0600, &bolt.Options{
		Timeout:      5 * time.Second,
		FreelistType: bolt.FreelistMapType,
	})
	if err != nil {
		return nil, err
	}
	return &BoltStore{db: db}, nil
}

// OpenWithOptions opens a bbolt database with caller-supplied options.
// Use this when you need custom page size, read-only mode, etc.
func OpenWithOptions(path string, opts *bolt.Options) (*BoltStore, error) {
	db, err := bolt.Open(path, 0600, opts)
	if err != nil {
		return nil, err
	}
	return &BoltStore{db: db}, nil
}

// DB returns the underlying bbolt.DB for operations not covered by the
// interface (e.g. bolt.DB.Stats()). Use sparingly — callers that reach
// through this accessor cannot be swapped to another backend.
func (s *BoltStore) DB() *bolt.DB {
	return s.db
}

// Update implements Store.
func (s *BoltStore) Update(fn func(Tx) error) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return fn(&boltTx{tx})
	})
}

// View implements Store.
func (s *BoltStore) View(fn func(Tx) error) error {
	return s.db.View(func(tx *bolt.Tx) error {
		return fn(&boltTx{tx})
	})
}

// Close implements Store.
func (s *BoltStore) Close() error {
	return s.db.Close()
}

type boltTx struct{ tx *bolt.Tx }

var _ Tx = (*boltTx)(nil)

func (t *boltTx) Bucket(name []byte) Bucket {
	b := t.tx.Bucket(name)
	if b == nil {
		return nil
	}
	return &boltBucket{b}
}

func (t *boltTx) CreateBucketIfNotExists(name []byte) (Bucket, error) {
	b, err := t.tx.CreateBucketIfNotExists(name)
	if err != nil {
		return nil, err
	}
	return &boltBucket{b}, nil
}

func (t *boltTx) DeleteBucket(name []byte) error {
	return t.tx.DeleteBucket(name)
}

func (t *boltTx) ForEach(fn func(name []byte, b Bucket) error) error {
	return t.tx.ForEach(func(name []byte, b *bolt.Bucket) error {
		return fn(name, &boltBucket{b})
	})
}

type boltBucket struct{ b *bolt.Bucket }

var _ Bucket = (*boltBucket)(nil)

func (bk *boltBucket) Get(key []byte) []byte { return bk.b.Get(key) }

func (bk *boltBucket) Put(key, value []byte) error { return bk.b.Put(key, value) }

func (bk *boltBucket) Delete(key []byte) error { return bk.b.Delete(key) }

func (bk *boltBucket) Bucket(name []byte) Bucket {
	b := bk.b.Bucket(name)
	if b == nil {
		return nil
	}
	return &boltBucket{b}
}

func (bk *boltBucket) CreateBucketIfNotExists(name []byte) (Bucket, error) {
	b, err := bk.b.CreateBucketIfNotExists(name)
	if err != nil {
		return nil, err
	}
	return &boltBucket{b}, nil
}

func (bk *boltBucket) DeleteBucket(name []byte) error {
	return bk.b.DeleteBucket(name)
}

func (bk *boltBucket) ForEach(fn func(k, v []byte) error) error {
	return bk.b.ForEach(fn)
}

func (bk *boltBucket) NextSequence() (uint64, error) {
	return bk.b.NextSequence()
}
