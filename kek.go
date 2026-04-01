package keeper

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/awnumar/memguard"
	"github.com/olekukonko/zero"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// DeriveKEK derives a Key Encryption Key from master key + admin credential + salt.
// Uses HKDF-SHA256. The KEK must be used immediately and then zeroed — never stored.
//
// Neither masterKey alone nor adminCred alone can derive the KEK.
// Changing admin password requires only re-wrapping the DEK, not re-encrypting secrets.
func DeriveKEK(masterKey, adminCred, salt []byte) ([]byte, error) {
	if len(masterKey) == 0 {
		return nil, errors.New("kek: masterKey must not be empty")
	}
	if len(adminCred) == 0 {
		return nil, errors.New("kek: adminCred must not be empty")
	}
	if len(salt) == 0 {
		return nil, errors.New("kek: salt must not be empty")
	}

	ikm := make([]byte, len(masterKey)+len(adminCred))
	copy(ikm, masterKey)
	copy(ikm[len(masterKey):], adminCred)
	defer zero.Bytes(ikm)

	r := hkdf.New(sha256.New, ikm, salt, []byte(hkdfInfoKEK))
	kek := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(r, kek); err != nil {
		return nil, fmt.Errorf("kek: HKDF expansion failed: %w", err)
	}
	return kek, nil
}

// GenerateDEKSalt generates a fresh random salt for a new bucket's DEK.
func GenerateDEKSalt() ([]byte, error) {
	salt := make([]byte, dekSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("kek: failed to generate salt: %w", err)
	}
	return salt, nil
}

// GenerateDEK generates a fresh random 32-byte Data Encryption Key.
// Returns it sealed in a memguard Enclave — protected from birth.
func GenerateDEK() (*memguard.Enclave, error) {
	buf := memguard.NewBufferRandom(chacha20poly1305.KeySize)
	if buf.Size() == 0 {
		return nil, fmt.Errorf("kek: failed to allocate DEK buffer")
	}
	enc := buf.Seal()
	if enc == nil {
		return nil, fmt.Errorf("kek: failed to seal DEK")
	}
	return enc, nil
}

// WrapDEK encrypts a DEK (from its Enclave) with a KEK.
// Format: [24-byte nonce][ciphertext+16-byte tag].
// kek is zeroed after use.
func WrapDEK(dek *memguard.Enclave, kek []byte) ([]byte, error) {
	defer zero.Bytes(kek)

	aead, err := chacha20poly1305.NewX(kek)
	if err != nil {
		return nil, fmt.Errorf("kek: failed to create cipher: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("kek: failed to generate nonce: %w", err)
	}

	dekBuf, err := dek.Open()
	if err != nil {
		return nil, fmt.Errorf("kek: failed to open DEK enclave: %w", err)
	}
	defer dekBuf.Destroy()

	return aead.Seal(nonce, nonce, dekBuf.Bytes(), nil), nil
}

// UnwrapDEK decrypts a wrapped DEK. Returns it sealed in a new Enclave.
// kek is zeroed after use. Returns ErrInvalidPassphrase on authentication failure.
func UnwrapDEK(wrapped, kek []byte) (*memguard.Enclave, error) {
	defer zero.Bytes(kek)

	aead, err := chacha20poly1305.NewX(kek)
	if err != nil {
		return nil, fmt.Errorf("kek: failed to create cipher: %w", err)
	}
	if len(wrapped) < aead.NonceSize() {
		return nil, fmt.Errorf("kek: wrapped DEK too short")
	}

	raw, err := aead.Open(nil, wrapped[:aead.NonceSize()], wrapped[aead.NonceSize():], nil)
	if err != nil {
		return nil, ErrInvalidPassphrase
	}
	defer zero.Bytes(raw)

	buf := memguard.NewBufferFromBytes(raw)
	if buf.Size() == 0 {
		return nil, fmt.Errorf("kek: failed to allocate buffer for unwrapped DEK")
	}
	enc := buf.Seal()
	if enc == nil {
		return nil, fmt.Errorf("kek: failed to seal unwrapped DEK")
	}
	return enc, nil
}
