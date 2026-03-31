package crypt

import (
	"errors"

	"golang.org/x/crypto/argon2"
)

// Argon2KDF implements KDF using Argon2id — the recommended password-hashing
// algorithm for new systems (winner of the Password Hashing Competition).
//
// To meet FIPS 140 requirements swap this for a PBKDF2-SHA-256 implementation
// that satisfies the same KDF interface.
type Argon2KDF struct {
	Time        uint32
	Memory      uint32
	Parallelism uint8
}

// Ensure compile-time interface satisfaction.
var _ KDF = (*Argon2KDF)(nil)

// DefaultArgon2KDF returns a KDF with sensible interactive defaults.
// Tune for your threat model: higher Time/Memory → slower but stronger.
func DefaultArgon2KDF() *Argon2KDF {
	return &Argon2KDF{
		Time:        3,
		Memory:      64 * 1024, // 64 MiB
		Parallelism: 4,
	}
}

// DeriveKey implements KDF.
func (a *Argon2KDF) DeriveKey(password, salt []byte, keyLen int) ([]byte, error) {
	if len(password) == 0 {
		return nil, errors.New("password must not be empty")
	}
	if len(salt) == 0 {
		return nil, errors.New("salt must not be empty")
	}
	if keyLen <= 0 {
		return nil, errors.New("keyLen must be positive")
	}
	key := argon2.IDKey(password, salt, a.Time, a.Memory, a.Parallelism, uint32(keyLen))
	return key, nil
}
