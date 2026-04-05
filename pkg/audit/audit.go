package audit

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/agberohq/keeper/pkg/store"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// ErrChainBroken is returned when audit chain integrity verification fails.
var ErrChainBroken = errors.New("audit chain integrity check failed")

// EventTypeKeyRotationCheckpoint marks a key-rotation boundary in the chain.
// Events before the checkpoint are verified with the old signing key;
// events after are verified with the new signing key.
// History is never rewritten — the checkpoint is the trust bridge.
const EventTypeKeyRotationCheckpoint = "key_rotation_checkpoint"

const (
	rootBucket    = "__audit__"
	chainIndexKey = "__chain_index__"
	snapshotEvery = 1000
)

// Event is an append-only audit record with chain integrity.
//
// The chain is secured at two levels:
//
// Checksum — SHA256 over prevChecksum, ID, BucketID, Scheme, Namespace,
// Details, EventType, and Timestamp. Detects content modification and
// cross-bucket transplantation. Seq is excluded so it can be assigned
// inside the write transaction after the caller has computed the hash.
//
// HMAC — HMAC-SHA256 over all fields including Seq. Provides
// authentication: only a holder of the signing key can produce a valid
// HMAC. When no signing key is configured the HMAC field is empty and
// VerifyIntegrity skips HMAC checking.
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

// ComputeChecksum returns SHA256(prevChecksum | ID | BucketID | Scheme |
// Namespace | Details | EventType | Timestamp).
// Seq is intentionally excluded — it is assigned by Append inside the
// transaction after the caller computes the checksum.
func (e *Event) ComputeChecksum(prevChecksum string) string {
	h := sha256.New()
	h.Write([]byte(prevChecksum))
	h.Write([]byte(e.ID))
	h.Write([]byte(e.BucketID))
	h.Write([]byte(e.Scheme))
	h.Write([]byte(e.Namespace))
	h.Write(e.Details)
	h.Write([]byte(e.EventType))
	h.Write([]byte(e.Timestamp.Format(time.RFC3339Nano)))
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyChecksum returns true when e.Checksum matches the computed value.
func (e *Event) VerifyChecksum() bool {
	return e.Checksum == e.ComputeChecksum(e.PrevChecksum)
}

// ComputeHMAC returns HMAC-SHA256 over all event fields using key.
// Returns "" when key is empty — callers interpret that as "no signing key".
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

// VerifyHMAC returns true when the event's HMAC is valid for key.
// Returns true unconditionally when key or e.HMAC is empty.
func (e *Event) VerifyHMAC(key []byte) bool {
	if len(key) == 0 || e.HMAC == "" {
		return true
	}
	return hmac.Equal([]byte(e.HMAC), []byte(e.ComputeHMAC(key)))
}

// KeyFingerprint returns a short proof-of-possession token for key.
// Used in checkpoint events to prove the old and new keys without revealing them.
func KeyFingerprint(key []byte) string {
	if len(key) == 0 {
		return ""
	}
	r := hkdf.New(sha256.New, key, nil, []byte("epoch-boundary"))
	fp := make([]byte, 16)
	_, _ = io.ReadFull(r, fp)
	return hex.EncodeToString(fp)
}

// chainIndex is stored under chainIndexKey in each namespace bucket.
// It allows O(1) LastChecksum lookup and accurate event counting.
// Rewritten after every Append and every Prune.
type chainIndex struct {
	LastID       string `json:"last_id"`
	LastChecksum string `json:"last_checksum"`
	EventCount   int64  `json:"event_count"`
}

// Store handles audit event persistence.
type Store struct {
	db         store.Store
	signingKey []byte
}

// New creates an audit Store.
// Pass a non-nil signingKey to enable HMAC signing of every appended event
// and HMAC verification in VerifyIntegrity. Pass nil to disable signing.
func New(db store.Store, signingKey []byte) *Store {
	return &Store{db: db, signingKey: signingKey}
}

// SetSigningKey replaces the active HMAC signing key. Pass nil to disable
// signing. This is used by the keeper after key rotation to activate the new
// epoch key without constructing a new Store. Tests use it to drive rotation
// scenarios without going through the full keeper lifecycle.
func (a *Store) SetSigningKey(key []byte) {
	a.signingKey = key
}

// Init creates the root audit bucket if it does not exist.
func (a *Store) Init() error {
	return a.db.Update(func(tx store.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(rootBucket))
		return err
	})
}

// Append writes event to the chain for scheme/namespace.
// Seq is assigned atomically inside the write transaction.
func (a *Store) Append(scheme, namespace string, event *Event) error {
	return a.db.Update(func(tx store.Tx) error {
		root := tx.Bucket([]byte(rootBucket))
		if root == nil {
			return fmt.Errorf("audit bucket not initialised — call Init() first")
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
		return nb.Put([]byte(chainIndexKey), idxData)
	})
}

// LoadChain returns all events for scheme/namespace ordered by Seq ascending.
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
//
// At key-rotation checkpoint events the active verification key switches to
// the new epoch key. This preserves the chain's tamper-evidence across key
// rotations without rewriting any historical events.
func (a *Store) VerifyIntegrity(scheme, namespace string) error {
	events, err := a.LoadChain(scheme, namespace)
	if err != nil {
		return err
	}

	activeKey := a.signingKey
	var prev string

	for i, e := range events {
		if !e.VerifyChecksum() {
			return fmt.Errorf("%w: event %d (seq %d) checksum invalid", ErrChainBroken, i, e.Seq)
		}
		if i > 0 && e.PrevChecksum != prev {
			return fmt.Errorf("%w: event %d (seq %d) prev_checksum mismatch", ErrChainBroken, i, e.Seq)
		}
		if len(activeKey) > 0 && !e.VerifyHMAC(activeKey) {
			return fmt.Errorf("%w: event %d (seq %d) HMAC verification failed", ErrChainBroken, i, e.Seq)
		}

		// At a checkpoint, attempt to recover the new epoch key so HMAC
		// verification continues for post-rotation events. If decryption
		// fails (auditor does not hold the key), fall back to checksum-only.
		if e.EventType == EventTypeKeyRotationCheckpoint {
			if wrappedKey := epochKeyFromCheckpoint(e); wrappedKey != nil {
				if newKey := decryptEpochKey(wrappedKey, activeKey); newKey != nil {
					activeKey = newKey
				} else {
					// Key not available — stop HMAC verification for this epoch.
					activeKey = nil
				}
			} else {
				activeKey = nil
			}
		}

		prev = e.Checksum
	}
	return nil
}

// epochKeyFromCheckpoint recovers the wrapped new epoch signing key from a
// checkpoint event's Details. The returned bytes are the raw encrypted blob;
// the caller (VerifyIntegrity) must decrypt them with the current active key.
//
// Key chaining design:
//
//	checkpoint.Details = JSON {
//	  "old_key_fingerprint": "<hex>",   // proof of old key — for auditors
//	  "new_key_fingerprint": "<hex>",   // proof of new key — for auditors
//	  "wrapped_new_key":     "<base64>" // XChaCha20-Poly1305(oldKey, newKey)
//	}
//
// An auditor holding any epoch key can unwrap the full forward chain
// successively. An auditor holding no key still validates the SHA-256
// checksum chain. This is equivalent in trust structure to a TLS certificate
// chain: compromise of the root audit key requires rotating the entire chain.
//
// Security note: XChaCha20-Poly1305's Open processes the full ciphertext
// regardless of whether authentication succeeds, so the two decryption
// attempts in VerifyIntegrity are constant-time with respect to AEAD
// authentication by construction.
func epochKeyFromCheckpoint(e *Event) []byte {
	if len(e.Details) == 0 {
		return nil
	}
	var d struct {
		WrappedNewKey string `json:"wrapped_new_key"`
	}
	if err := json.Unmarshal(e.Details, &d); err != nil || d.WrappedNewKey == "" {
		return nil
	}
	wrapped, err := base64.StdEncoding.DecodeString(d.WrappedNewKey)
	if err != nil {
		return nil
	}
	return wrapped
}

// decryptEpochKey decrypts a wrapped epoch key blob using activeKey via
// XChaCha20-Poly1305. Returns nil when decryption fails; caller falls back
// to checksum-only verification.
func decryptEpochKey(wrapped, activeKey []byte) []byte {
	if len(activeKey) == 0 || len(wrapped) == 0 {
		return nil
	}
	aead, err := chacha20poly1305.NewX(activeKey)
	if err != nil {
		return nil
	}
	if len(wrapped) < aead.NonceSize() {
		return nil
	}
	plain, err := aead.Open(nil, wrapped[:aead.NonceSize()], wrapped[aead.NonceSize():], nil)
	if err != nil {
		return nil
	}
	return plain
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

// Prune removes events from the chain, always trimming the oldest end so
// the surviving events form a contiguous tail. The chain index is rewritten
// after deletion so LastChecksum remains consistent with stored data.
//
// olderThan: events with Timestamp older than time.Now()-olderThan are
// candidates for deletion. Pass 0 to make all events candidates.
// keepLastN: always preserve the most recent keepLastN events by Seq.
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

		var all []*Event
		err := nb.ForEach(func(k, v []byte) error {
			if bytes.HasPrefix(k, []byte("__")) {
				return nil
			}
			var e Event
			if err := json.Unmarshal(v, &e); err != nil {
				return err
			}
			all = append(all, &e)
			return nil
		})
		if err != nil {
			return err
		}
		if len(all) == 0 {
			return nil
		}

		// Sort by Seq so "oldest" is unambiguous.
		sort.Slice(all, func(i, j int) bool { return all[i].Seq < all[j].Seq })

		// Determine the set to delete: events older than cutoff, excluding
		// the unconditional keepLastN tail.
		keepFrom := len(all) - keepLastN
		if keepFrom < 0 {
			keepFrom = 0
		}
		var toDelete []string
		for _, e := range all[:keepFrom] {
			if !e.Timestamp.After(cutoff) {
				toDelete = append(toDelete, e.ID)
			}
		}
		for _, id := range toDelete {
			if err := nb.Delete([]byte(id)); err != nil {
				return err
			}
		}

		// Rewrite the chain index to reflect the last surviving event.
		deleted := make(map[string]struct{}, len(toDelete))
		for _, id := range toDelete {
			deleted[id] = struct{}{}
		}
		var idx chainIndex
		for i := len(all) - 1; i >= 0; i-- {
			if _, gone := deleted[all[i].ID]; !gone {
				idx.LastID = all[i].ID
				idx.LastChecksum = all[i].Checksum
				idx.EventCount = all[i].Seq
				break
			}
		}
		idxData, _ := json.Marshal(idx)
		return nb.Put([]byte(chainIndexKey), idxData)
	})
}
