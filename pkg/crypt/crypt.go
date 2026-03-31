// Package crypt defines pluggable encryption and key-derivation interfaces.
// Implementations can swap in NACL, AES-GCM (FIPS 140), or any AEAD primitive
// without touching keeper internals.
package crypt

// Cipher is the encryption contract used throughout keeper.
// Any authenticated-encryption scheme (XChaCha20-Poly1305, AES-256-GCM,
// NaCl secretbox, …) must satisfy this interface.
type Cipher interface {
	// Encrypt returns authenticated ciphertext for plaintext.
	// The implementation is responsible for generating and prepending a nonce.
	Encrypt(plaintext []byte) ([]byte, error)

	// Decrypt recovers plaintext from ciphertext produced by Encrypt.
	// Returns ErrDecrypt on authentication failure or truncation.
	Decrypt(ciphertext []byte) ([]byte, error)
}

// KDF is the key-derivation contract.
// Swap between scrypt, Argon2id, PBKDF2, or an HSM-backed KDF without
// changing caller code.
type KDF interface {
	// DeriveKey derives a key of keyLen bytes from password and salt.
	DeriveKey(password, salt []byte, keyLen int) ([]byte, error)
}
