package store_test

import (
	"fmt"
	"testing"

	"github.com/agberohq/keeper/pkg/store"
)

func TestMemStore_BasicOps(t *testing.T) {
	s := store.NewMemStore()
	defer s.Close()

	// Write in Update, read in View.
	if err := s.Update(func(tx store.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("test"))
		if err != nil {
			return err
		}
		return b.Put([]byte("hello"), []byte("world"))
	}); err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	if err := s.View(func(tx store.Tx) error {
		b := tx.Bucket([]byte("test"))
		if b == nil {
			t.Error("bucket not found after update")
			return nil
		}
		val := b.Get([]byte("hello"))
		if string(val) != "world" {
			t.Errorf("Get = %q, want %q", val, "world")
		}
		return nil
	}); err != nil {
		t.Fatalf("View failed: %v", err)
	}
}

func TestMemStore_RollbackOnError(t *testing.T) {
	s := store.NewMemStore()
	defer s.Close()

	// Create bucket.
	s.Update(func(tx store.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("bucket"))
		return err
	})

	// Failed Update must not persist the put.
	s.Update(func(tx store.Tx) error {
		b, _ := tx.CreateBucketIfNotExists([]byte("bucket"))
		b.Put([]byte("key"), []byte("value"))
		return errTest
	})

	s.View(func(tx store.Tx) error {
		b := tx.Bucket([]byte("bucket"))
		if b != nil && b.Get([]byte("key")) != nil {
			t.Error("rolled-back write should not be visible")
		}
		return nil
	})
}

func TestMemStore_NestedBuckets(t *testing.T) {
	s := store.NewMemStore()
	defer s.Close()

	s.Update(func(tx store.Tx) error {
		parent, err := tx.CreateBucketIfNotExists([]byte("parent"))
		if err != nil {
			return err
		}
		child, err := parent.CreateBucketIfNotExists([]byte("child"))
		if err != nil {
			return err
		}
		return child.Put([]byte("deep"), []byte("value"))
	})

	s.View(func(tx store.Tx) error {
		parent := tx.Bucket([]byte("parent"))
		if parent == nil {
			t.Fatal("parent bucket missing")
		}
		child := parent.Bucket([]byte("child"))
		if child == nil {
			t.Fatal("child bucket missing")
		}
		if got := string(child.Get([]byte("deep"))); got != "value" {
			t.Errorf("deep get = %q, want %q", got, "value")
		}
		return nil
	})
}

func TestMemStore_DeleteBucket(t *testing.T) {
	s := store.NewMemStore()
	defer s.Close()

	s.Update(func(tx store.Tx) error {
		b, _ := tx.CreateBucketIfNotExists([]byte("todel"))
		b.Put([]byte("k"), []byte("v"))
		return nil
	})
	s.Update(func(tx store.Tx) error {
		return tx.DeleteBucket([]byte("todel"))
	})
	s.View(func(tx store.Tx) error {
		if b := tx.Bucket([]byte("todel")); b != nil {
			t.Error("deleted bucket still visible")
		}
		return nil
	})
}

func TestMemStore_ForEach(t *testing.T) {
	s := store.NewMemStore()
	defer s.Close()

	s.Update(func(tx store.Tx) error {
		b, _ := tx.CreateBucketIfNotExists([]byte("items"))
		b.Put([]byte("a"), []byte("1"))
		b.Put([]byte("b"), []byte("2"))
		b.Put([]byte("c"), []byte("3"))
		return nil
	})

	var count int
	s.View(func(tx store.Tx) error {
		b := tx.Bucket([]byte("items"))
		return b.ForEach(func(k, v []byte) error {
			count++
			return nil
		})
	})
	if count != 3 {
		t.Errorf("ForEach count = %d, want 3", count)
	}
}

func TestMemStore_ImplementsStore(t *testing.T) {
	var _ store.Store = store.NewMemStore()
}

var errTest = fmt.Errorf("intentional rollback")
