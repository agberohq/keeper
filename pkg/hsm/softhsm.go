// Package hsm provides HSMProvider implementations for use with keeper.
// SoftHSM is an in-process provider backed by memguard, intended for
// testing and CI environments. It must not be used in production.
package hsm

import (
	"context"
	"crypto/rand"
	"fmt"
	"sync"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/chacha20poly1305"
)

// SoftHSM is a purely in-process HSMProvider backed by a random wrapping key
// held in a memguard Enclave. It satisfies the keeper.HSMProvider interface
// and is safe for concurrent use, but provides no hardware-level protection.
type SoftHSM struct {
	mu          sync.Mutex
	wrappingKey *memguard.Enclave
}

// NewSoftHSM generates a random 32-byte wrapping key and seals it into a
// memguard Enclave. The returned SoftHSM is ready to use immediately.
func NewSoftHSM() (*SoftHSM, error) {
	raw := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("softhsm: failed to generate wrapping key: %w", err)
	}
	enc := memguard.NewEnclave(raw)
	for i := range raw {
		raw[i] = 0
	}
	return &SoftHSM{wrappingKey: enc}, nil
}

// WrapDEK encrypts dek with the internal wrapping key using XChaCha20-Poly1305.
// The returned bytes are [24-byte nonce || ciphertext || 16-byte tag].
func (h *SoftHSM) WrapDEK(dek []byte) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	buf, err := h.wrappingKey.Open()
	if err != nil {
		return nil, fmt.Errorf("softhsm: failed to open wrapping key: %w", err)
	}
	defer buf.Destroy()

	aead, err := chacha20poly1305.NewX(buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("softhsm: failed to create cipher: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("softhsm: failed to generate nonce: %w", err)
	}
	return aead.Seal(nonce, nonce, dek, nil), nil
}

// UnwrapDEK decrypts a wrapped DEK produced by WrapDEK.
// Returns an error if authentication fails or the data is malformed.
func (h *SoftHSM) UnwrapDEK(wrapped []byte) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	buf, err := h.wrappingKey.Open()
	if err != nil {
		return nil, fmt.Errorf("softhsm: failed to open wrapping key: %w", err)
	}
	defer buf.Destroy()

	aead, err := chacha20poly1305.NewX(buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("softhsm: failed to create cipher: %w", err)
	}
	if len(wrapped) < aead.NonceSize() {
		return nil, fmt.Errorf("softhsm: wrapped DEK too short")
	}
	nonce, ct := wrapped[:aead.NonceSize()], wrapped[aead.NonceSize():]
	plain, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("softhsm: DEK authentication failed: %w", err)
	}
	return plain, nil
}

// Ping always returns nil for an in-process provider.
// It satisfies the keeper.HSMProvider interface for health monitoring.
func (h *SoftHSM) Ping(_ context.Context) error {
	return nil
}
