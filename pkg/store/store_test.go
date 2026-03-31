package store

import (
	"os"
	"path/filepath"
	"testing"
)

// ── helpers ───────────────────────────────────────────────────────────────

func tempStore(t *testing.T) (*BoltStore, func()) {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s, func() { s.Close() }
}

// ── Store interface compliance ─────────────────────────────────────────────

func TestStore_InterfaceCompliance(t *testing.T) {
	s, cleanup := tempStore(t)
	defer cleanup()

	var _ Store = s // compile-time check captured at runtime too
	_ = s
}

// ── Open / Close ──────────────────────────────────────────────────────────

func TestOpen_CreatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keeper.db")

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("database file not created: %v", err)
	}
}

func TestClose_Idempotent(t *testing.T) {
	s, _ := tempStore(t)
	if err := s.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	// second close should error (bbolt returns error on closed db) — we just
	// make sure it doesn't panic
	_ = s.Close()
}

// ── Update / View ─────────────────────────────────────────────────────────

func TestUpdate_CreateBucket(t *testing.T) {
	s, cleanup := tempStore(t)
	defer cleanup()

	err := s.Update(func(tx Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("mybucket"))
		return err
	})
	if err != nil {
		t.Fatalf("Update CreateBucket: %v", err)
	}

	// Verify visible in View
	err = s.View(func(tx Tx) error {
		b := tx.Bucket([]byte("mybucket"))
		if b == nil {
			t.Error("bucket not found after creation")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("View: %v", err)
	}
}

func TestUpdate_PutGet(t *testing.T) {
	s, cleanup := tempStore(t)
	defer cleanup()

	key := []byte("hello")
	val := []byte("world")

	_ = s.Update(func(tx Tx) error {
		b, _ := tx.CreateBucketIfNotExists([]byte("kv"))
		return b.Put(key, val)
	})

	var got []byte
	_ = s.View(func(tx Tx) error {
		b := tx.Bucket([]byte("kv"))
		if b == nil {
			t.Error("bucket missing")
			return nil
		}
		v := b.Get(key)
		if v != nil {
			got = make([]byte, len(v))
			copy(got, v)
		}
		return nil
	})

	if string(got) != string(val) {
		t.Fatalf("expected %q got %q", val, got)
	}
}

func TestUpdate_Delete(t *testing.T) {
	s, cleanup := tempStore(t)
	defer cleanup()

	_ = s.Update(func(tx Tx) error {
		b, _ := tx.CreateBucketIfNotExists([]byte("kv"))
		_ = b.Put([]byte("k"), []byte("v"))
		return nil
	})

	_ = s.Update(func(tx Tx) error {
		b := tx.Bucket([]byte("kv"))
		return b.Delete([]byte("k"))
	})

	_ = s.View(func(tx Tx) error {
		b := tx.Bucket([]byte("kv"))
		if b.Get([]byte("k")) != nil {
			t.Error("key should be deleted")
		}
		return nil
	})
}

func TestUpdate_Rollback(t *testing.T) {
	s, cleanup := tempStore(t)
	defer cleanup()

	_ = s.Update(func(tx Tx) error {
		b, _ := tx.CreateBucketIfNotExists([]byte("kv"))
		_ = b.Put([]byte("k"), []byte("v"))
		return nil
	})

	// Simulate a rollback by returning an error
	sentinelErr := os.ErrInvalid
	err := s.Update(func(tx Tx) error {
		b := tx.Bucket([]byte("kv"))
		_ = b.Put([]byte("k"), []byte("changed"))
		return sentinelErr // triggers rollback
	})
	if err != sentinelErr {
		t.Fatalf("expected sentinel error, got: %v", err)
	}

	// Value should be unchanged
	_ = s.View(func(tx Tx) error {
		b := tx.Bucket([]byte("kv"))
		if string(b.Get([]byte("k"))) != "v" {
			t.Error("rollback did not restore original value")
		}
		return nil
	})
}

// ── Bucket operations ──────────────────────────────────────────────────────

func TestBucket_GetMissing(t *testing.T) {
	s, cleanup := tempStore(t)
	defer cleanup()

	_ = s.Update(func(tx Tx) error {
		b, _ := tx.CreateBucketIfNotExists([]byte("kv"))
		if v := b.Get([]byte("no-such-key")); v != nil {
			t.Errorf("expected nil for missing key, got %q", v)
		}
		return nil
	})
}

func TestBucket_NestedBucket(t *testing.T) {
	s, cleanup := tempStore(t)
	defer cleanup()

	_ = s.Update(func(tx Tx) error {
		parent, _ := tx.CreateBucketIfNotExists([]byte("parent"))
		child, err := parent.CreateBucketIfNotExists([]byte("child"))
		if err != nil {
			return err
		}
		return child.Put([]byte("k"), []byte("v"))
	})

	_ = s.View(func(tx Tx) error {
		parent := tx.Bucket([]byte("parent"))
		if parent == nil {
			t.Fatal("parent bucket missing")
		}
		child := parent.Bucket([]byte("child"))
		if child == nil {
			t.Fatal("child bucket missing")
		}
		if string(child.Get([]byte("k"))) != "v" {
			t.Error("nested Put/Get failed")
		}
		return nil
	})
}

func TestBucket_ForEach(t *testing.T) {
	s, cleanup := tempStore(t)
	defer cleanup()

	pairs := map[string]string{"a": "1", "b": "2", "c": "3"}

	_ = s.Update(func(tx Tx) error {
		b, _ := tx.CreateBucketIfNotExists([]byte("kv"))
		for k, v := range pairs {
			_ = b.Put([]byte(k), []byte(v))
		}
		return nil
	})

	seen := map[string]string{}
	_ = s.View(func(tx Tx) error {
		b := tx.Bucket([]byte("kv"))
		return b.ForEach(func(k, v []byte) error {
			seen[string(k)] = string(v)
			return nil
		})
	})

	for k, v := range pairs {
		if seen[k] != v {
			t.Errorf("ForEach: key %q → got %q want %q", k, seen[k], v)
		}
	}
}

func TestBucket_DeleteBucket(t *testing.T) {
	s, cleanup := tempStore(t)
	defer cleanup()

	_ = s.Update(func(tx Tx) error {
		b, _ := tx.CreateBucketIfNotExists([]byte("parent"))
		_, err := b.CreateBucketIfNotExists([]byte("child"))
		return err
	})
	_ = s.Update(func(tx Tx) error {
		b := tx.Bucket([]byte("parent"))
		return b.DeleteBucket([]byte("child"))
	})
	_ = s.View(func(tx Tx) error {
		b := tx.Bucket([]byte("parent"))
		if b.Bucket([]byte("child")) != nil {
			t.Error("child bucket should be deleted")
		}
		return nil
	})
}

func TestTx_DeleteBucket(t *testing.T) {
	s, cleanup := tempStore(t)
	defer cleanup()

	_ = s.Update(func(tx Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("tobedeleted"))
		return err
	})
	_ = s.Update(func(tx Tx) error {
		return tx.DeleteBucket([]byte("tobedeleted"))
	})
	_ = s.View(func(tx Tx) error {
		if tx.Bucket([]byte("tobedeleted")) != nil {
			t.Error("top-level bucket should be deleted")
		}
		return nil
	})
}

func TestTx_ForEach(t *testing.T) {
	s, cleanup := tempStore(t)
	defer cleanup()

	names := []string{"alpha", "beta", "gamma"}
	_ = s.Update(func(tx Tx) error {
		for _, n := range names {
			if _, err := tx.CreateBucketIfNotExists([]byte(n)); err != nil {
				return err
			}
		}
		return nil
	})

	seen := map[string]bool{}
	_ = s.View(func(tx Tx) error {
		return tx.ForEach(func(name []byte, _ Bucket) error {
			seen[string(name)] = true
			return nil
		})
	})

	for _, n := range names {
		if !seen[n] {
			t.Errorf("ForEach missed bucket %q", n)
		}
	}
}

func TestBucket_NextSequence(t *testing.T) {
	s, cleanup := tempStore(t)
	defer cleanup()

	var seq1, seq2 uint64
	_ = s.Update(func(tx Tx) error {
		b, _ := tx.CreateBucketIfNotExists([]byte("seq"))
		var err error
		seq1, err = b.NextSequence()
		if err != nil {
			return err
		}
		seq2, err = b.NextSequence()
		return err
	})

	if seq2 <= seq1 {
		t.Fatalf("NextSequence not monotonic: %d then %d", seq1, seq2)
	}
}

func TestBucket_NilForMissingTopLevel(t *testing.T) {
	s, cleanup := tempStore(t)
	defer cleanup()

	_ = s.View(func(tx Tx) error {
		b := tx.Bucket([]byte("nonexistent"))
		if b != nil {
			t.Error("expected nil for missing top-level bucket")
		}
		return nil
	})
}

// ── OpenWithOptions ────────────────────────────────────────────────────────

func TestOpenWithOptions_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "opts.db")

	s, err := OpenWithOptions(path, nil) // nil opts → bbolt defaults
	if err != nil {
		t.Fatalf("OpenWithOptions: %v", err)
	}
	defer s.Close()

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("database file not created: %v", err)
	}
}

func TestOpenWithOptions_BadPath(t *testing.T) {
	_, err := OpenWithOptions("/nonexistent/deep/path/keeper.db", nil)
	if err == nil {
		t.Fatal("expected error opening db in nonexistent directory")
	}
}

func TestOpen_BadPath(t *testing.T) {
	_, err := Open("/nonexistent/deep/path/keeper.db")
	if err == nil {
		t.Fatal("expected error for bad path")
	}
}

// ── Error propagation ──────────────────────────────────────────────────────

func TestUpdate_PropagatesError(t *testing.T) {
	s, cleanup := tempStore(t)
	defer cleanup()

	sentinel := os.ErrPermission
	err := s.Update(func(tx Tx) error { return sentinel })
	if err != sentinel {
		t.Fatalf("expected sentinel error, got: %v", err)
	}
}

func TestView_PropagatesError(t *testing.T) {
	s, cleanup := tempStore(t)
	defer cleanup()

	sentinel := os.ErrPermission
	err := s.View(func(tx Tx) error { return sentinel })
	if err != sentinel {
		t.Fatalf("expected sentinel error, got: %v", err)
	}
}

// ── ForEach: error propagation ────────────────────────────────────────────

func TestBucket_ForEach_StopsOnError(t *testing.T) {
	s, cleanup := tempStore(t)
	defer cleanup()

	_ = s.Update(func(tx Tx) error {
		b, _ := tx.CreateBucketIfNotExists([]byte("kv"))
		_ = b.Put([]byte("a"), []byte("1"))
		_ = b.Put([]byte("b"), []byte("2"))
		return nil
	})

	sentinel := os.ErrInvalid
	count := 0
	err := s.View(func(tx Tx) error {
		b := tx.Bucket([]byte("kv"))
		return b.ForEach(func(k, v []byte) error {
			count++
			return sentinel
		})
	})
	if err != sentinel {
		t.Fatalf("expected sentinel, got: %v", err)
	}
	if count != 1 {
		t.Fatalf("ForEach should stop after first error, count=%d", count)
	}
}

func TestTx_ForEach_StopsOnError(t *testing.T) {
	s, cleanup := tempStore(t)
	defer cleanup()

	_ = s.Update(func(tx Tx) error {
		_, _ = tx.CreateBucketIfNotExists([]byte("b1"))
		_, _ = tx.CreateBucketIfNotExists([]byte("b2"))
		return nil
	})

	sentinel := os.ErrInvalid
	err := s.View(func(tx Tx) error {
		return tx.ForEach(func(_ []byte, _ Bucket) error {
			return sentinel
		})
	})
	if err != sentinel {
		t.Fatalf("Tx.ForEach should propagate error: %v", err)
	}
}

// ── CreateBucketIfNotExists: duplicate nested ──────────────────────────────

func TestBucket_CreateBucketIfNotExists_Idempotent(t *testing.T) {
	s, cleanup := tempStore(t)
	defer cleanup()

	// Create the same nested bucket twice — must succeed both times
	for i := 0; i < 2; i++ {
		err := s.Update(func(tx Tx) error {
			parent, _ := tx.CreateBucketIfNotExists([]byte("parent"))
			_, err := parent.CreateBucketIfNotExists([]byte("child"))
			return err
		})
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
	}
}

// ── Put then overwrite ─────────────────────────────────────────────────────

func TestBucket_PutOverwrite(t *testing.T) {
	s, cleanup := tempStore(t)
	defer cleanup()

	_ = s.Update(func(tx Tx) error {
		b, _ := tx.CreateBucketIfNotExists([]byte("kv"))
		_ = b.Put([]byte("k"), []byte("v1"))
		return b.Put([]byte("k"), []byte("v2"))
	})

	_ = s.View(func(tx Tx) error {
		b := tx.Bucket([]byte("kv"))
		if string(b.Get([]byte("k"))) != "v2" {
			t.Error("overwrite did not take effect")
		}
		return nil
	})
}

// ── DB() escape hatch ──────────────────────────────────────────────────────

func TestBoltStore_DBAccessor(t *testing.T) {
	s, cleanup := tempStore(t)
	defer cleanup()

	if s.DB() == nil {
		t.Fatal("DB() must return non-nil")
	}
}
