package audit

import (
	"bytes"
	"crypto/hmac"
	cryptorand "crypto/rand"
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
// Scheme and Namespace are always plaintext strings — they identify the bucket
// and are used for routing, display, and chain verification without a key.
//
// When Encrypted is true, EncScheme, EncNamespace, and EncDetails hold the
// ciphertext of those fields; Details is cleared. When Encrypted is false all
// three Enc* fields are nil and Details holds plaintext JSON.
//
// The chain is secured at two levels:
//
// Checksum — SHA256 over prevChecksum, ID, BucketID, the stored form of
// Scheme/Namespace/Details (ciphertext when Encrypted=true), EventType, and
// Timestamp. Detects content modification and cross-bucket transplantation.
// Seq is excluded — it is assigned inside the write transaction.
//
// HMAC — HMAC-SHA256 over all fields including Seq. Only a holder of the
// signing key can produce a valid HMAC.
type Event struct {
	ID           string    `json:"id"`
	BucketID     string    `json:"bucket_id"`
	Scheme       string    `json:"scheme"`    // always plaintext
	Namespace    string    `json:"namespace"` // always plaintext
	Seq          int64     `json:"seq"`
	EventType    string    `json:"event_type"`
	Details      []byte    `json:"details,omitempty"` // plaintext JSON; nil when Encrypted=true
	Timestamp    time.Time `json:"timestamp"`
	PrevChecksum string    `json:"prev_checksum"`
	Checksum     string    `json:"checksum"`
	HMAC         string    `json:"hmac,omitempty"`
	Encrypted    bool      `json:"encrypted"`               // true = Enc* fields are populated
	EncScheme    []byte    `json:"enc_scheme,omitempty"`    // ciphertext of Scheme
	EncNamespace []byte    `json:"enc_namespace,omitempty"` // ciphertext of Namespace
	EncDetails   []byte    `json:"enc_details,omitempty"`   // ciphertext of Details
}

// storedScheme returns the UTF-8 bytes of Scheme, which is always preserved
// as a plaintext string regardless of encryption state. Checksums are computed
// over the plaintext so they remain stable across encrypt/decrypt round-trips.
func (e *Event) storedScheme() []byte {
	return []byte(e.Scheme)
}

// storedNamespace returns the UTF-8 bytes of Namespace, always plaintext.
func (e *Event) storedNamespace() []byte {
	return []byte(e.Namespace)
}

// storedDetails returns the bytes used for checksum/HMAC computation over the
// Details field. When Encrypted=true the plaintext Details have been cleared
// and EncDetails holds the ciphertext; we use EncDetails in that case so the
// checksum remains stable after a load-decrypt-verify round-trip (EncDetails
// are preserved through JSON even when decKey is nil). When not encrypted,
// the plaintext Details bytes are used directly.
func (e *Event) storedDetails() []byte {
	if e.Encrypted {
		return e.EncDetails
	}
	return e.Details
}

// ComputeChecksum returns SHA256 over the stored bytes of each field.
// When Encrypted=true the Enc* fields are hashed, so verification works
// for public-tier auditors who hold no decryption key.
func (e *Event) ComputeChecksum(prevChecksum string) string {
	h := sha256.New()
	h.Write([]byte(prevChecksum))
	h.Write([]byte(e.ID))
	h.Write([]byte(e.BucketID))
	h.Write(e.storedScheme())
	h.Write(e.storedNamespace())
	h.Write(e.storedDetails())
	h.Write([]byte(e.EventType))
	h.Write([]byte(e.Timestamp.Format(time.RFC3339Nano)))
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyChecksum returns true when e.Checksum matches the computed value.
func (e *Event) VerifyChecksum() bool {
	return e.Checksum == e.ComputeChecksum(e.PrevChecksum)
}

// ComputeHMAC returns HMAC-SHA256 over all event fields using key.
// Returns "" when key is empty.
func (e *Event) ComputeHMAC(key []byte) string {
	if len(key) == 0 {
		return ""
	}
	h := hmac.New(sha256.New, key)
	h.Write([]byte(e.ID))
	h.Write([]byte(e.BucketID))
	h.Write(e.storedScheme())
	h.Write(e.storedNamespace())
	h.Write([]byte(fmt.Sprintf("%d", e.Seq)))
	h.Write([]byte(e.EventType))
	h.Write(e.storedDetails())
	h.Write([]byte(e.Timestamp.Format(time.RFC3339Nano)))
	h.Write([]byte(e.PrevChecksum))
	h.Write([]byte(e.Checksum))
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyHMAC returns true when the event's HMAC is valid for key.
// Returns true unconditionally when key or e.HMAC is empty.
func (e *Event) VerifyHMAC(key []byte) bool {
	if len(key) == 0 {
		return true // No key available
	}
	if e.HMAC == "" {
		return false
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
// When encKey is non-nil, Scheme, Namespace, and Details are encrypted into
// the Enc* fields; the plaintext string fields are preserved for routing and
// the Details field is cleared. Encrypted is set to true.
// Checksum and HMAC are computed over the stored (Enc*) bytes so
// VerifyIntegrity never needs to decrypt.
// Seq is assigned atomically inside the write transaction.
func (a *Store) Append(scheme, namespace string, event *Event, encKey []byte) error {
	// Re-store path: if the event is already encrypted (e.g. loaded then re-saved
	// during tamper testing or rotation), write it back as-is without re-encrypting
	// or reassigning Seq/PrevChecksum/Checksum. The caller's values are preserved
	// verbatim so VerifyIntegrity can detect any Checksum corruption.
	if event.Encrypted {
		// Ensure routing fields are consistent with the call arguments.
		event.Scheme = scheme
		event.Namespace = namespace
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
			data, err := json.Marshal(event)
			if err != nil {
				return err
			}
			return nb.Put([]byte(event.ID), data)
		})
	}

	// New event path: encrypt fields, assign Seq/PrevChecksum, compute Checksum.
	if len(encKey) > 0 {
		encScheme, err := a.encryptField([]byte(scheme), encKey)
		if err != nil {
			return fmt.Errorf("audit: encrypt scheme: %w", err)
		}
		encNS, err := a.encryptField([]byte(namespace), encKey)
		if err != nil {
			return fmt.Errorf("audit: encrypt namespace: %w", err)
		}
		event.EncScheme = encScheme
		event.EncNamespace = encNS
		if len(event.Details) > 0 {
			encDet, err := a.encryptField(event.Details, encKey)
			if err != nil {
				return fmt.Errorf("audit: encrypt details: %w", err)
			}
			event.EncDetails = encDet
			event.Details = nil
		}
		event.Encrypted = true
	}
	// Scheme and Namespace remain as plaintext strings regardless of encryption —
	// they are needed for bucket routing inside the bbolt transaction.
	event.Scheme = scheme
	event.Namespace = namespace

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

		// Checksum and PrevChecksum are assigned here, after encryption, so
		// they are always computed over the final stored bytes.
		event.PrevChecksum = idx.LastChecksum
		event.Checksum = event.ComputeChecksum(event.PrevChecksum)

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

// encryptField encrypts a single plaintext field using the store's cipher.
// Wire format: nonce(cipher.NonceSize()) || AEAD-ciphertext.
func (a *Store) encryptField(plaintext, key []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(cryptorand.Reader, nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

// decryptField decrypts a single field blob produced by encryptField.
func (a *Store) decryptField(blob, key []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(blob) < aead.NonceSize() {
		return nil, fmt.Errorf("audit: encrypted field too short")
	}
	return aead.Open(nil, blob[:aead.NonceSize()], blob[aead.NonceSize():], nil)
}

// LoadChain returns all events for scheme/namespace ordered by Seq ascending.
// When decKey is non-nil and event.Encrypted is true, Scheme, Namespace, and
// Details are decrypted before returning. When decKey is nil, encrypted fields
// are returned as opaque blobs (public-tier: checksum verification only).
func (a *Store) LoadChain(scheme, namespace string, decKey []byte) ([]*Event, error) {
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
			// Decrypt Enc* fields into their plaintext counterparts when
			// decKey is provided and the event was written encrypted.
			if e.Encrypted && len(decKey) > 0 {
				// Decrypt into the plaintext fields. EncScheme/EncNamespace are
				// cleared because Scheme/Namespace now hold the authoritative value.
				// EncDetails is intentionally KEPT alongside the decrypted Details:
				// storedDetails() uses EncDetails for checksum computation so the
				// checksum is stable regardless of whether decKey was provided.
				if dec, err := a.decryptField(e.EncScheme, decKey); err == nil {
					e.Scheme = string(dec)
					e.EncScheme = nil
				}
				if dec, err := a.decryptField(e.EncNamespace, decKey); err == nil {
					e.Namespace = string(dec)
					e.EncNamespace = nil
				}
				if len(e.EncDetails) > 0 {
					if dec, err := a.decryptField(e.EncDetails, decKey); err == nil {
						e.Details = dec
						// EncDetails preserved — storedDetails() uses it for checksum.
					}
				}
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
// Operates over the stored bytes — no decryption needed. Checksums and HMACs
// are computed over ciphertext blobs when events are encrypted, so verification
// works for the public tier (no key) as well as authenticated tiers.
func (a *Store) VerifyIntegrity(scheme, namespace string) error {
	events, err := a.LoadChain(scheme, namespace, nil) // nil = no decryption
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
