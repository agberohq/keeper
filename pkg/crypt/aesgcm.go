package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// AES256GCMCipher implements Cipher using AES-256-GCM.
//
// AES-256-GCM is approved under FIPS 140-2 / FIPS 140-3 when used with a
// FIPS-validated cryptographic module. Use this cipher (paired with
// PBKDF2SHA256KDF) when operating in a FIPS-restricted environment.
//
// Key size must be exactly 32 bytes (256 bits).
// Nonce size is 12 bytes (96 bits) as recommended by NIST SP 800-38D.
type AES256GCMCipher struct {
	aead cipher.AEAD
}

// Ensure compile-time interface satisfaction.
var _ Cipher = (*AES256GCMCipher)(nil)

// NewAES256GCMCipher creates an AES256GCMCipher from a 32-byte key.
// Returns an error if key is not exactly 32 bytes.
func NewAES256GCMCipher(key []byte) (*AES256GCMCipher, error) {
	if len(key) != 32 {
		return nil, errors.New("aes-256-gcm: key must be exactly 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &AES256GCMCipher{aead: aead}, nil
}

// Encrypt implements Cipher. A random 12-byte nonce is prepended to the
// ciphertext. The nonce is generated using crypto/rand.
func (c *AES256GCMCipher) Encrypt(plaintext []byte) ([]byte, error) {
	if c == nil || c.aead == nil {
		return nil, errors.New("aes-256-gcm: cipher not initialized")
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return c.aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt implements Cipher. Returns ErrDecrypt on authentication failure,
// truncation, or any other decryption error.
func (c *AES256GCMCipher) Decrypt(ciphertext []byte) ([]byte, error) {
	if c == nil || c.aead == nil {
		return nil, errors.New("aes-256-gcm: cipher not initialized")
	}
	nonceSize := c.aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, ErrDecrypt
	}
	plaintext, err := c.aead.Open(nil, ciphertext[:nonceSize], ciphertext[nonceSize:], nil)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plaintext, nil
}
