package audit

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/agberohq/keeper/pkg/store"
)

// Event is an append-only audit record with chain integrity.
type Event struct {
	ID           string    `json:"id"`
	BucketID     string    `json:"bucket_id"`
	Scheme       string    `json:"scheme"`
	Namespace    string    `json:"namespace"`
	Seq          int64     `json:"seq"`
	EventType    string    `json:"event_type"`
	Details      []byte    `json:"details"`
	Timestamp    time.Time `json:"timestamp"`
	PrevChecksum string    `json:"prev_checksum"`
	Checksum     string    `json:"checksum"`
	HMAC         string    `json:"hmac,omitempty"`
}

// ComputeChecksum returns SHA256(prevChecksum + details + eventType + timestamp).
// Seq is intentionally excluded so it can be assigned after checksum calculation.
func (e *Event) ComputeChecksum(prevChecksum string) string {
	h := sha256.New()
	h.Write([]byte(prevChecksum))
	h.Write(e.Details)
	h.Write([]byte(e.EventType))
	h.Write([]byte(e.Timestamp.Format(time.RFC3339Nano)))
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyChecksum returns true if e.Checksum matches the computed value.
func (e *Event) VerifyChecksum() bool {
	return e.Checksum == e.ComputeChecksum(e.PrevChecksum)
}

func (e *Event) ComputeHMAC(key []byte) string {
	if len(key) == 0 {
		return ""
	}
	h := hmac.New(sha256.New, key)
	h.Write([]byte(e.ID))
	h.Write([]byte(e.BucketID))
	h.Write([]byte(e.Scheme))
	h.Write([]byte(e.Namespace))
	h.Write([]byte(fmt.Sprintf("%d", e.Seq)))
	h.Write([]byte(e.EventType))
	h.Write(e.Details)
	h.Write([]byte(e.Timestamp.Format(time.RFC3339Nano)))
	h.Write([]byte(e.PrevChecksum))
	h.Write([]byte(e.Checksum))
	return hex.EncodeToString(h.Sum(nil))
}

func (e *Event) VerifyHMAC(key []byte) bool {
	if len(key) == 0 || e.HMAC == "" {
		return true
	}
	return hmac.Equal([]byte(e.HMAC), []byte(e.ComputeHMAC(key)))
}

const (
	rootBucket    = "__audit__"
	chainIndexKey = "__chain_index__"
	snapshotEvery = 1000
)

type chainIndex struct {
	LastID       string `json:"last_id"`
	LastChecksum string `json:"last_checksum"`
	EventCount   int64  `json:"event_count"`
}

// Store handles audit event persistence against a store.Store backend.
type Store struct {
	db         store.Store
	signingKey []byte
}

func New(db store.Store, signingKey []byte) *Store {
	return &Store{db: db, signingKey: signingKey}
}

// Init creates the root audit bucket if it does not exist.
func (a *Store) Init() error {
	return a.db.Update(func(tx store.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(rootBucket))
		return err
	})
}

// Append writes event to the chain for scheme/namespace.
// It assigns event.Seq atomically within the write transaction.
func (a *Store) Append(scheme, namespace string, event *Event) error {
	return a.db.Update(func(tx store.Tx) error {
		root := tx.Bucket([]byte(rootBucket))
		if root == nil {
			return fmt.Errorf("audit bucket not initialised")
		}
		sb, err := root.CreateBucketIfNotExists([]byte(scheme))
		if err != nil {
			return err
		}
		nb, err := sb.CreateBucketIfNotExists([]byte(namespace))
		if err != nil {
			return err
		}

		var idx chainIndex
		if raw := nb.Get([]byte(chainIndexKey)); raw != nil {
			_ = json.Unmarshal(raw, &idx)
		}
		event.Seq = idx.EventCount + 1

		if len(a.signingKey) > 0 {
			event.HMAC = event.ComputeHMAC(a.signingKey)
		}

		data, err := json.Marshal(event)
		if err != nil {
			return err
		}
		if err := nb.Put([]byte(event.ID), data); err != nil {
			return err
		}

		idx.LastID = event.ID
		idx.LastChecksum = event.Checksum
		idx.EventCount = event.Seq
		idxData, _ := json.Marshal(idx)
		if err := nb.Put([]byte(chainIndexKey), idxData); err != nil {
			return err
		}
		return nil
	})
}

// LoadChain returns all events for scheme/namespace in Seq order.
func (a *Store) LoadChain(scheme, namespace string) ([]*Event, error) {
	var events []*Event
	err := a.db.View(func(tx store.Tx) error {
		root := tx.Bucket([]byte(rootBucket))
		if root == nil {
			return nil
		}
		sb := root.Bucket([]byte(scheme))
		if sb == nil {
			return nil
		}
		nb := sb.Bucket([]byte(namespace))
		if nb == nil {
			return nil
		}
		return nb.ForEach(func(k, v []byte) error {
			if bytes.HasPrefix(k, []byte("__")) {
				return nil
			}
			var e Event
			if err := json.Unmarshal(v, &e); err != nil {
				return err
			}
			events = append(events, &e)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(events, func(i, j int) bool {
		si, sj := events[i].Seq, events[j].Seq
		if si != 0 || sj != 0 {
			return si < sj
		}
		return events[i].Timestamp.Before(events[j].Timestamp)
	})
	return events, nil
}

// VerifyIntegrity checks the entire chain for scheme/namespace.
// Returns nil if the chain is intact, ErrChainBroken otherwise.
func (a *Store) VerifyIntegrity(scheme, namespace string) error {
	events, err := a.LoadChain(scheme, namespace)
	if err != nil {
		return err
	}
	var prev string
	for i, e := range events {
		if !e.VerifyChecksum() {
			return fmt.Errorf("%w: event %d (seq %d) checksum invalid", ErrChainBroken, i, e.Seq)
		}
		if i > 0 && e.PrevChecksum != prev {
			return fmt.Errorf("%w: event %d (seq %d) prev_checksum mismatch", ErrChainBroken, i, e.Seq)
		}
		if len(a.signingKey) > 0 && !e.VerifyHMAC(a.signingKey) {
			return fmt.Errorf("%w: event %d (seq %d) HMAC verification failed", ErrChainBroken, i, e.Seq)
		}
		prev = e.Checksum
	}
	return nil
}

// LastChecksum returns the checksum of the most recently appended event,
// or "" if no events exist for this scheme/namespace.
func (a *Store) LastChecksum(scheme, namespace string) string {
	var cs string
	_ = a.db.View(func(tx store.Tx) error {
		root := tx.Bucket([]byte(rootBucket))
		if root == nil {
			return nil
		}
		sb := root.Bucket([]byte(scheme))
		if sb == nil {
			return nil
		}
		nb := sb.Bucket([]byte(namespace))
		if nb == nil {
			return nil
		}
		if raw := nb.Get([]byte(chainIndexKey)); raw != nil {
			var idx chainIndex
			_ = json.Unmarshal(raw, &idx)
			cs = idx.LastChecksum
		}
		return nil
	})
	return cs
}

func (a *Store) Prune(scheme, namespace string, olderThan time.Duration, keepLastN int) error {
	if keepLastN < 0 {
		keepLastN = 0
	}
	cutoff := time.Now().Add(-olderThan)
	return a.db.Update(func(tx store.Tx) error {
		root := tx.Bucket([]byte(rootBucket))
		if root == nil {
			return nil
		}
		sb := root.Bucket([]byte(scheme))
		if sb == nil {
			return nil
		}
		nb := sb.Bucket([]byte(namespace))
		if nb == nil {
			return nil
		}
		var toDelete [][]byte
		var recent []*Event
		err := nb.ForEach(func(k, v []byte) error {
			if bytes.HasPrefix(k, []byte("__")) {
				return nil
			}
			var e Event
			if err := json.Unmarshal(v, &e); err != nil {
				return err
			}
			if e.Timestamp.After(cutoff) {
				recent = append(recent, &e)
			} else {
				cp := make([]byte, len(k))
				copy(cp, k)
				toDelete = append(toDelete, cp)
			}
			return nil
		})
		if err != nil {
			return err
		}
		if len(recent) > keepLastN {
			for _, e := range recent[:len(recent)-keepLastN] {
				toDelete = append(toDelete, []byte(e.ID))
			}
		}
		for _, key := range toDelete {
			if err := nb.Delete(key); err != nil {
				return err
			}
		}
		return nil
	})
}

var ErrChainBroken = fmt.Errorf("audit chain integrity check failed")
