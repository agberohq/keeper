package audit

// epochKeyFromCheckpoint was a stub returning nil unconditionally, causing
// VerifyIntegrity to silently pass HMAC checks on all post-rotation events
// because VerifyHMAC(nil) returns true unconditionally. An attacker could
// forge any post-rotation audit event without detection.
//
// After the fix, checkpoint events carry a wrapped_new_key field encrypted
// with the old audit key. VerifyIntegrity decrypts it to recover the new
// epoch key and continues enforcing HMACs through the full chain.
//
// Key invariant for tests:
//   VerifyIntegrity starts with activeKey = store.signingKey.
//   The verifier store must be constructed with the key that was active at
//   the very beginning of the chain (oldKey / key1). wrapped_new_key fields
//   let VerifyIntegrity walk forward through key epochs automatically.

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/agberohq/keeper/pkg/store"
	"golang.org/x/crypto/chacha20poly1305"
)

func makeKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatalf("makeKey: %v", err)
	}
	return k
}

func appendEvent(t *testing.T, s *Store, scheme, namespace, id string) {
	t.Helper()
	prev := s.LastChecksum(scheme, namespace)
	e := &Event{
		ID:           id,
		BucketID:     "b",
		Scheme:       scheme,
		Namespace:    namespace,
		EventType:    "op",
		Details:      []byte("{}"),
		Timestamp:    time.Now(),
		PrevChecksum: prev,
	}
	e.Checksum = e.ComputeChecksum(prev)
	if err := s.Append(scheme, namespace, e, nil); err != nil {
		t.Fatalf("Append %s: %v", id, err)
	}
}

func wrapKey(t *testing.T, oldKey, newKey []byte) string {
	t.Helper()
	aead, err := chacha20poly1305.NewX(oldKey)
	if err != nil {
		t.Fatalf("wrapKey NewX: %v", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("wrapKey rand: %v", err)
	}
	ct := aead.Seal(nonce, nonce, newKey, nil)
	return base64.StdEncoding.EncodeToString(ct)
}

// appendCheckpoint writes a key-rotation checkpoint signed with oldKey,
// carrying wrapped_new_key so VerifyIntegrity can recover newKey.
// After this call the caller must s.SetSigningKey(newKey).
func appendCheckpoint(t *testing.T, s *Store, scheme, namespace string, oldKey, newKey []byte) {
	t.Helper()
	s.SetSigningKey(oldKey) // checkpoint is the last event of the old epoch

	type details struct {
		OldKeyFp      string `json:"old_key_fingerprint"`
		NewKeyFp      string `json:"new_key_fingerprint"`
		WrappedNewKey string `json:"wrapped_new_key"`
	}
	d := details{
		OldKeyFp:      KeyFingerprint(oldKey),
		NewKeyFp:      KeyFingerprint(newKey),
		WrappedNewKey: wrapKey(t, oldKey, newKey),
	}
	detailsJSON, _ := json.Marshal(d)

	prev := s.LastChecksum(scheme, namespace)
	e := &Event{
		ID:           fmt.Sprintf("ckpt-%s", KeyFingerprint(newKey)[:8]),
		BucketID:     "b",
		Scheme:       scheme,
		Namespace:    namespace,
		EventType:    EventTypeKeyRotationCheckpoint,
		Details:      detailsJSON,
		Timestamp:    time.Now(),
		PrevChecksum: prev,
	}
	e.Checksum = e.ComputeChecksum(prev)
	if err := s.Append(scheme, namespace, e, nil); err != nil {
		t.Fatalf("appendCheckpoint: %v", err)
	}
}

// tests

// TestVerifyIntegrity_PostRotationEventsVerified is the primary regression test.
// The verifier is constructed with oldKey (first epoch). VerifyIntegrity must
// recover newKey from wrapped_new_key and verify all post-rotation events.
func TestVerifyIntegrity_PostRotationEventsVerified(t *testing.T) {
	oldKey := makeKey(t)
	newKey := makeKey(t)
	db := store.NewMemStore()

	live := New(db, oldKey)
	live.Init() //nolint:errcheck
	appendEvent(t, live, "sc", "ns", "ev-1")
	appendEvent(t, live, "sc", "ns", "ev-2")
	appendCheckpoint(t, live, "sc", "ns", oldKey, newKey)
	live.SetSigningKey(newKey)
	appendEvent(t, live, "sc", "ns", "ev-3")
	appendEvent(t, live, "sc", "ns", "ev-4")

	// Verifier constructed with oldKey — the first epoch key.
	// Must walk wrapped_new_key chain to reach newKey and verify ev-3, ev-4.
	verifier := New(db, oldKey)
	if err := verifier.VerifyIntegrity("sc", "ns"); err != nil {
		t.Errorf("VerifyIntegrity should pass for valid chain across rotation: %v", err)
	}
}

// TestVerifyIntegrity_ForgedPostRotationEventDetected verifies that a forged
// post-rotation event (signed with the wrong key) is caught after the fix.
func TestVerifyIntegrity_ForgedPostRotationEventDetected(t *testing.T) {
	oldKey := makeKey(t)
	newKey := makeKey(t)
	badKey := makeKey(t)
	db := store.NewMemStore()

	live := New(db, oldKey)
	live.Init() //nolint:errcheck
	appendEvent(t, live, "sc", "ns", "ev-1")
	appendCheckpoint(t, live, "sc", "ns", oldKey, newKey)
	live.SetSigningKey(newKey)
	appendEvent(t, live, "sc", "ns", "ev-2")

	// Force-sign one event with badKey — HMAC won't verify under newKey.
	live.SetSigningKey(badKey)
	appendEvent(t, live, "sc", "ns", "ev-forged")

	verifier := New(db, oldKey)
	if err := verifier.VerifyIntegrity("sc", "ns"); err == nil {
		t.Error("VerifyIntegrity should detect HMAC failure on forged post-rotation event")
	}
}

// TestVerifyIntegrity_CheckpointWithoutWrappedKey verifies backward compatibility:
// old-format checkpoints (no wrapped_new_key) degrade to checksum-only
// verification rather than failing.
func TestVerifyIntegrity_CheckpointWithoutWrappedKey(t *testing.T) {
	oldKey := makeKey(t)
	db := store.NewMemStore()

	live := New(db, oldKey)
	live.Init() //nolint:errcheck
	appendEvent(t, live, "sc", "ns", "ev-1")

	live.SetSigningKey(oldKey)
	prev := live.LastChecksum("sc", "ns")
	detailsJSON, _ := json.Marshal(map[string]string{
		"old_key_fingerprint": KeyFingerprint(oldKey),
		"new_key_fingerprint": "somefingerprint",
		// wrapped_new_key intentionally absent
	})
	ckpt := &Event{
		ID:           "ckpt-old-format",
		BucketID:     "b",
		Scheme:       "sc",
		Namespace:    "ns",
		EventType:    EventTypeKeyRotationCheckpoint,
		Details:      detailsJSON,
		Timestamp:    time.Now(),
		PrevChecksum: prev,
	}
	ckpt.Checksum = ckpt.ComputeChecksum(prev)
	live.Append("sc", "ns", ckpt, nil) //nolint:errcheck

	verifier := New(db, oldKey)
	if err := verifier.VerifyIntegrity("sc", "ns"); err != nil {
		t.Errorf("old-format checkpoint should degrade gracefully, not error: %v", err)
	}
}

// TestVerifyIntegrity_MultipleRotationsChain verifies two sequential rotations:
// key1 → key2 → key3. VerifyIntegrity must follow both wrapped_new_key hops.
func TestVerifyIntegrity_MultipleRotationsChain(t *testing.T) {
	key1 := makeKey(t)
	key2 := makeKey(t)
	key3 := makeKey(t)
	db := store.NewMemStore()

	live := New(db, key1)
	live.Init() //nolint:errcheck
	appendEvent(t, live, "sc", "ns", "ev-epoch1")
	appendCheckpoint(t, live, "sc", "ns", key1, key2)
	live.SetSigningKey(key2)
	appendEvent(t, live, "sc", "ns", "ev-epoch2")
	appendCheckpoint(t, live, "sc", "ns", key2, key3)
	live.SetSigningKey(key3)
	appendEvent(t, live, "sc", "ns", "ev-epoch3")

	// Verifier starts at key1 and must walk to key3.
	verifier := New(db, key1)
	if err := verifier.VerifyIntegrity("sc", "ns"); err != nil {
		t.Errorf("multi-rotation chain failed VerifyIntegrity: %v", err)
	}
}

// TestVerifyIntegrity_WrongStartKeyFails ensures a verifier with the wrong
// initial key fails — the fix must not make everything pass regardless of key.
func TestVerifyIntegrity_WrongStartKeyFails(t *testing.T) {
	oldKey := makeKey(t)
	wrongKey := makeKey(t)
	db := store.NewMemStore()

	live := New(db, oldKey)
	live.Init() //nolint:errcheck
	appendEvent(t, live, "sc", "ns", "ev-1")

	verifier := New(db, wrongKey)
	if err := verifier.VerifyIntegrity("sc", "ns"); err == nil {
		t.Error("VerifyIntegrity with wrong start key should fail, but passed")
	}
}
