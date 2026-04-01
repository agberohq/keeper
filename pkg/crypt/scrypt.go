package crypt

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/scrypt"
)

// ScryptKDF implements KDF using scrypt. It exists solely for backward
// compatibility with databases that were created with scrypt-derived keys.
// New deployments should use DefaultArgon2KDF instead.
//
// Recommended migration path:
// Open the existing database with a ScryptKDF in Config.KDF.
// Call Rotate with the same passphrase — this re-derives with Argon2id and
//
//	re-encrypts all secrets in one atomic operation.
//
// Replace ScryptKDF with DefaultArgon2KDF in your Config going forward.
type ScryptKDF struct {
	// N is the CPU/memory cost parameter. Must be a power of 2 (≥2).
	N int
	// R is the block size parameter.
	R int
	// P is the parallelisation parameter.
	P int
}

// Ensure compile-time interface satisfaction.
var _ KDF = (*ScryptKDF)(nil)

// DefaultScryptKDF returns a ScryptKDF with the same defaults that the old
// keeper hard-coded (N=32768, r=8, p=1).
func DefaultScryptKDF() *ScryptKDF {
	return &ScryptKDF{N: 32768, R: 8, P: 1}
}

// DeriveKey implements KDF.
func (s *ScryptKDF) DeriveKey(password, salt []byte, keyLen int) ([]byte, error) {
	if len(password) == 0 {
		return nil, errors.New("password must not be empty")
	}
	if len(salt) == 0 {
		return nil, errors.New("salt must not be empty")
	}
	if keyLen <= 0 {
		return nil, errors.New("keyLen must be positive")
	}
	if s.N <= 0 || s.R <= 0 || s.P <= 0 {
		return nil, fmt.Errorf("scrypt parameters must be positive (N=%d r=%d p=%d)", s.N, s.R, s.P)
	}
	key, err := scrypt.Key(password, salt, s.N, s.R, s.P, keyLen)
	if err != nil {
		return nil, fmt.Errorf("scrypt key derivation failed: %w", err)
	}
	return key, nil
}
