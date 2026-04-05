package keeper

import (
	"fmt"
	"sync"

	"github.com/awnumar/memguard"
)

// Envelope is the in-memory secure vault for Data Encryption Keys (DEKs).
//
// Every unlocked bucket has exactly one entry here. The DEK is sealed inside
// a memguard Enclave which:
// mlocks the memory so the OS never pages it to disk
// mprotects the pages read-only when not in active use
// zeros the memory on release
//
// Replaces the previous plain-map bucketKeys — Go's GC gave no guarantee
// that key bytes would ever be zeroed.
type Envelope struct {
	mu   sync.RWMutex
	deks map[string]*memguard.Enclave // "scheme:namespace" → sealed DEK
}

// NewEnvelope creates an empty, ready-to-use Envelope.
func NewEnvelope() *Envelope {
	return &Envelope{deks: make(map[string]*memguard.Enclave)}
}

// Hold seals a DEK into a memguard Enclave.
// buf is sealed (and thus destroyed) by this call — do not use it after.
func (e *Envelope) Hold(scheme, namespace string, buf *memguard.LockedBuffer) {
	e.mu.Lock()
	defer e.mu.Unlock()

	key := envelopeKey(scheme, namespace)
	// Nothing to clean up on the old Enclave — it is already sealed/immutable.
	// Just overwrite the map entry.
	e.deks[key] = buf.Seal()
}

// HoldBytes seals raw key bytes into the Envelope, then zeros the source slice.
func (e *Envelope) HoldBytes(scheme, namespace string, dek []byte) {
	buf := memguard.NewBufferFromBytes(dek) // copies + wipes src
	e.Hold(scheme, namespace, buf)
}

// HoldEnclave opens a sealed Enclave and places its contents into the Envelope.
// enc is consumed — the Envelope re-seals the data under its own map entry.
func (e *Envelope) HoldEnclave(scheme, namespace string, enc *memguard.Enclave) error {
	buf, err := enc.Open()
	if err != nil {
		return fmt.Errorf("envelope: failed to open enclave: %w", err)
	}
	e.Hold(scheme, namespace, buf)
	return nil
}

// Retrieve opens the Enclave and returns a LockedBuffer.
// The caller MUST call buf.Destroy() when done — typically via defer.
//
//	buf, err := env.Retrieve(scheme, ns)
//	if err != nil { return err }
//	defer buf.Destroy()
//	useBytes(buf.Bytes())
func (e *Envelope) Retrieve(scheme, namespace string) (*memguard.LockedBuffer, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	enc, ok := e.deks[envelopeKey(scheme, namespace)]
	if !ok {
		return nil, ErrBucketLocked
	}
	buf, err := enc.Open()
	if err != nil {
		return nil, fmt.Errorf("envelope: failed to open enclave for %s:%s: %w", scheme, namespace, err)
	}
	return buf, nil
}

// IsHeld reports whether a DEK for this scheme/namespace is currently sealed.
func (e *Envelope) IsHeld(scheme, namespace string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	_, ok := e.deks[envelopeKey(scheme, namespace)]
	return ok
}

// Drop removes the sealed DEK for a single bucket.
// The Enclave is dropped from the map; memguard cleans up on GC.
func (e *Envelope) Drop(scheme, namespace string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.deks, envelopeKey(scheme, namespace))
}

// DropAdminWrapped removes DEKs for all buckets whose policy is LevelAdminWrapped.
// LevelPasswordOnly (system/vault://) buckets are intentionally preserved so
// background jobs keep running after an admin session times out.
func (e *Envelope) DropAdminWrapped(registry map[string]*BucketSecurityPolicy) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for k, policy := range registry {
		if policy.Level == LevelAdminWrapped {
			delete(e.deks, k)
		}
	}
}

// DropAll removes every DEK from the Envelope.
func (e *Envelope) DropAll() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.deks = make(map[string]*memguard.Enclave)
}

// HeldKeys returns the scheme:namespace keys currently in the Envelope.
// Intended for status/introspection only.
func (e *Envelope) HeldKeys() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]string, 0, len(e.deks))
	for k := range e.deks {
		out = append(out, k)
	}
	return out
}

func envelopeKey(scheme, namespace string) string {
	return scheme + ":" + namespace
}
