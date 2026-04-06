package crypt

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// ErrDecrypt is returned when authenticated decryption fails.
var ErrDecrypt = errors.New("decryption failed")

// XChacha20Cipher implements Cipher using XChaCha20-Poly1305.
// It is the default cipher for keeper.
type XChacha20Cipher struct {
	aead cipher.AEAD
}

// Ensure compile-time interface satisfaction.
var _ Cipher = (*XChacha20Cipher)(nil)

// NewCipher creates an XChacha20Cipher from a human-readable secret.
// It first tries to decode secret as standard Base64; if that fails or the
// decoded key is not exactly 32 bytes it hashes the string with SHA-256
// to produce a 32-byte key.
func NewCipher(secret string) (*XChacha20Cipher, error) {
	if secret == "" {
		return nil, errors.New("secret cannot be empty")
	}

	var key []byte

	decoded, err := base64.StdEncoding.DecodeString(secret)
	if err != nil || len(decoded) != chacha20poly1305.KeySize {
		h := sha256.Sum256([]byte(secret))
		key = h[:]
	} else {
		key = decoded
	}

	return newFromKey(key)
}

// NewCipherFromKey creates an XChacha20Cipher directly from a 32-byte key.
func NewCipherFromKey(key []byte) (*XChacha20Cipher, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, errors.New("key must be 32 bytes")
	}
	return newFromKey(key)
}

func newFromKey(key []byte) (*XChacha20Cipher, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return &XChacha20Cipher{aead: aead}, nil
}

// KeySize implements Cipher. XChaCha20-Poly1305 requires a 32-byte key.
func (c *XChacha20Cipher) KeySize() int { return chacha20poly1305.KeySize }

// Encrypt implements Cipher. A random nonce is prepended to the ciphertext.
func (c *XChacha20Cipher) Encrypt(plaintext []byte) ([]byte, error) {
	if c == nil || c.aead == nil {
		return nil, errors.New("cipher not initialized")
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return c.aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt implements Cipher.
func (c *XChacha20Cipher) Decrypt(ciphertext []byte) ([]byte, error) {
	if c == nil || c.aead == nil {
		return nil, errors.New("cipher not initialized")
	}
	nonceSize := c.aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, ErrDecrypt
	}
	nonce, encrypted := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := c.aead.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plaintext, nil
}
