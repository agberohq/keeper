package crypt

// fips_test.go — tests for FIPS 140-2 approved primitives:
//   AES256GCMCipher  (Cipher interface, FIPS-approved)
//   PBKDF2SHA256KDF  (KDF interface, FIPS-approved)
//
// Both implementations must satisfy the same compliance suites used by the
// existing XChaCha20 and Argon2 tests (cipherCompliance / kdfCompliance),
// ensuring they are drop-in replacements via the shared interfaces.

import (
	"bytes"
	"testing"
)

// AES-256-GCM

func TestAES256GCM_InterfaceCompliance(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	c, err := NewAES256GCMCipher(key)
	if err != nil {
		t.Fatalf("NewAES256GCMCipher: %v", err)
	}
	cipherCompliance(t, c)
}

func TestAES256GCM_WrongKeyLength(t *testing.T) {
	for _, n := range []int{0, 16, 24, 31, 33, 64} {
		_, err := NewAES256GCMCipher(bytes.Repeat([]byte{0x01}, n))
		if err == nil {
			t.Errorf("key length %d should be rejected", n)
		}
	}
}

func TestAES256GCM_ExactlyThirtyTwoBytes(t *testing.T) {
	key := bytes.Repeat([]byte{0xAB}, 32)
	c, err := NewAES256GCMCipher(key)
	if err != nil {
		t.Fatalf("32-byte key must be accepted: %v", err)
	}
	cipherCompliance(t, c)
}

func TestAES256GCM_WrongKeyDecrypt(t *testing.T) {
	key1 := bytes.Repeat([]byte{0x11}, 32)
	key2 := bytes.Repeat([]byte{0x22}, 32)
	c1, _ := NewAES256GCMCipher(key1)
	c2, _ := NewAES256GCMCipher(key2)

	ct, _ := c1.Encrypt([]byte("secret"))
	if _, err := c2.Decrypt(ct); err == nil {
		t.Fatal("decrypting with wrong key must fail")
	}
}

func TestAES256GCM_NilCipherEncrypt(t *testing.T) {
	var c *AES256GCMCipher
	if _, err := c.Encrypt([]byte("x")); err == nil {
		t.Fatal("nil cipher Encrypt must error")
	}
}

func TestAES256GCM_NilCipherDecrypt(t *testing.T) {
	var c *AES256GCMCipher
	if _, err := c.Decrypt([]byte("x")); err == nil {
		t.Fatal("nil cipher Decrypt must error")
	}
}

func TestAES256GCM_UninitializedAEAD(t *testing.T) {
	c := &AES256GCMCipher{aead: nil}
	if _, err := c.Encrypt([]byte("x")); err == nil {
		t.Fatal("uninitialized aead Encrypt must error")
	}
	if _, err := c.Decrypt([]byte("x")); err == nil {
		t.Fatal("uninitialized aead Decrypt must error")
	}
}

func TestAES256GCM_EncryptEmpty(t *testing.T) {
	key := bytes.Repeat([]byte{0x55}, 32)
	c, _ := NewAES256GCMCipher(key)
	ct, err := c.Encrypt([]byte{})
	if err != nil {
		t.Fatalf("Encrypt empty: %v", err)
	}
	got, err := c.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt empty: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty plaintext, got %d bytes", len(got))
	}
}

func TestAES256GCM_LargePlaintext(t *testing.T) {
	key := bytes.Repeat([]byte{0x77}, 32)
	c, _ := NewAES256GCMCipher(key)
	large := bytes.Repeat([]byte("B"), 1<<20) // 1 MiB
	ct, err := c.Encrypt(large)
	if err != nil {
		t.Fatalf("Encrypt large: %v", err)
	}
	got, err := c.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt large: %v", err)
	}
	if !bytes.Equal(got, large) {
		t.Fatal("large round-trip mismatch")
	}
}

// TestAES256GCM_ErrDecryptOnTamper verifies ErrDecrypt is returned (not a
// wrapped or different error) so callers using errors.Is(err, ErrDecrypt) work.
func TestAES256GCM_ErrDecryptOnTamper(t *testing.T) {
	key := bytes.Repeat([]byte{0x33}, 32)
	c, _ := NewAES256GCMCipher(key)
	ct, _ := c.Encrypt([]byte("data"))
	ct[len(ct)-1] ^= 0xFF
	if _, err := c.Decrypt(ct); err != ErrDecrypt {
		t.Fatalf("tampered ciphertext: want ErrDecrypt, got %v", err)
	}
}

// TestFIPSPipeline_PBKDF2_AES verifies the full FIPS pipeline:
// PBKDF2-SHA256 derives the key, AES-256-GCM encrypts/decrypts.
func TestFIPSPipeline_PBKDF2_AES(t *testing.T) {
	kdf := &PBKDF2SHA256KDF{Iterations: 1000} // low for test speed
	key, err := kdf.DeriveKey([]byte("fips-passphrase"), []byte("unique-salt-1234"), 32)
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}
	c, err := NewAES256GCMCipher(key)
	if err != nil {
		t.Fatalf("NewAES256GCMCipher: %v", err)
	}
	secret := []byte("FIPS-approved secret data")
	ct, err := c.Encrypt(secret)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := c.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatal("FIPS pipeline round-trip failed")
	}
}

// PBKDF2-SHA-256

func TestPBKDF2SHA256KDF_InterfaceCompliance(t *testing.T) {
	kdf := &PBKDF2SHA256KDF{Iterations: 1000}
	kdfCompliance(t, kdf)
}

func TestPBKDF2SHA256KDF_DefaultParams(t *testing.T) {
	kdf := DefaultPBKDF2KDF()
	if kdf.Iterations < 600_000 {
		t.Errorf("default iterations should be ≥ 600000, got %d", kdf.Iterations)
	}
}

func TestPBKDF2SHA256KDF_EmptyPassword(t *testing.T) {
	kdf := DefaultPBKDF2KDF()
	if _, err := kdf.DeriveKey([]byte{}, []byte("salt"), 32); err == nil {
		t.Fatal("empty password must error")
	}
}

func TestPBKDF2SHA256KDF_EmptySalt(t *testing.T) {
	kdf := DefaultPBKDF2KDF()
	if _, err := kdf.DeriveKey([]byte("pass"), []byte{}, 32); err == nil {
		t.Fatal("empty salt must error")
	}
}

func TestPBKDF2SHA256KDF_ZeroKeyLen(t *testing.T) {
	kdf := DefaultPBKDF2KDF()
	if _, err := kdf.DeriveKey([]byte("pass"), []byte("salt"), 0); err == nil {
		t.Fatal("zero keyLen must error")
	}
}

func TestPBKDF2SHA256KDF_ZeroIterations(t *testing.T) {
	kdf := &PBKDF2SHA256KDF{Iterations: 0}
	if _, err := kdf.DeriveKey([]byte("pass"), []byte("salt"), 32); err == nil {
		t.Fatal("zero iterations must error")
	}
}

func TestPBKDF2SHA256KDF_VariousKeyLengths(t *testing.T) {
	kdf := &PBKDF2SHA256KDF{Iterations: 1000}
	for _, n := range []int{16, 24, 32, 64} {
		key, err := kdf.DeriveKey([]byte("p"), []byte("s"), n)
		if err != nil {
			t.Fatalf("DeriveKey(keyLen=%d): %v", n, err)
		}
		if len(key) != n {
			t.Fatalf("expected %d bytes, got %d", n, len(key))
		}
	}
}

func TestPBKDF2SHA256KDF_ImplementsKDF(t *testing.T) {
	var _ KDF = DefaultPBKDF2KDF()
}

func TestPBKDF2SHA256KDF_Deterministic(t *testing.T) {
	kdf := &PBKDF2SHA256KDF{Iterations: 1000}
	k1, _ := kdf.DeriveKey([]byte("pass"), []byte("salt1234"), 32)
	k2, _ := kdf.DeriveKey([]byte("pass"), []byte("salt1234"), 32)
	if !bytes.Equal(k1, k2) {
		t.Fatal("PBKDF2 must be deterministic")
	}
}

func TestPBKDF2SHA256KDF_DifferentSaltsProduceDifferentKeys(t *testing.T) {
	kdf := &PBKDF2SHA256KDF{Iterations: 1000}
	k1, _ := kdf.DeriveKey([]byte("pass"), []byte("salt-aaa"), 32)
	k2, _ := kdf.DeriveKey([]byte("pass"), []byte("salt-bbb"), 32)
	if bytes.Equal(k1, k2) {
		t.Fatal("different salts must produce different keys")
	}
}

func TestPBKDF2SHA256KDF_DifferentPasswordsProduceDifferentKeys(t *testing.T) {
	kdf := &PBKDF2SHA256KDF{Iterations: 1000}
	k1, _ := kdf.DeriveKey([]byte("password-one"), []byte("saltsalt"), 32)
	k2, _ := kdf.DeriveKey([]byte("password-two"), []byte("saltsalt"), 32)
	if bytes.Equal(k1, k2) {
		t.Fatal("different passwords must produce different keys")
	}
}
