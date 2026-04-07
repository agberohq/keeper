package crypt

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

// PBKDF2SHA256KDF implements KDF using PBKDF2 with HMAC-SHA-256.
//
// PBKDF2-SHA-256 is approved under FIPS 140-2 / FIPS 140-3. Pair this with
// AES256GCMCipher when FIPS compliance is required.
//
// NIST SP 800-132 recommends a minimum of 1000 iterations; for interactive
// authentication use at least 210,000 (OWASP 2023 recommendation).
// DefaultPBKDF2KDF uses 600,000 iterations as a conservative default.
//
// For non-FIPS deployments prefer DefaultArgon2KDF — it provides stronger
// memory-hardness guarantees against GPU/ASIC attacks.
type PBKDF2SHA256KDF struct {
	// Iterations is the PBKDF2 iteration count.
	// Must be ≥ 1. Higher values increase resistance to brute-force attacks.
	Iterations int
}

// Ensure compile-time interface satisfaction.
var _ KDF = (*PBKDF2SHA256KDF)(nil)

// DefaultPBKDF2KDF returns a PBKDF2SHA256KDF with 600,000 iterations —
// the OWASP-recommended minimum as of 2023 for PBKDF2-HMAC-SHA256.
func DefaultPBKDF2KDF() *PBKDF2SHA256KDF {
	return &PBKDF2SHA256KDF{Iterations: 600_000}
}

// DeriveKey implements KDF using PBKDF2-HMAC-SHA256.
func (p *PBKDF2SHA256KDF) DeriveKey(password, salt []byte, keyLen int) ([]byte, error) {
	if len(password) == 0 {
		return nil, errors.New("pbkdf2: password must not be empty")
	}
	if len(salt) == 0 {
		return nil, errors.New("pbkdf2: salt must not be empty")
	}
	if keyLen <= 0 {
		return nil, errors.New("pbkdf2: keyLen must be positive")
	}
	if p.Iterations < 1 {
		return nil, fmt.Errorf("pbkdf2: iterations must be ≥ 1, got %d", p.Iterations)
	}
	return pbkdf2.Key(password, salt, p.Iterations, keyLen, sha256.New), nil
}
