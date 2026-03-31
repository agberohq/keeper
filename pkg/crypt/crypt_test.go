package crypt

import (
	"bytes"
	"strings"
	"testing"
)

// cipherCompliance runs a standard suite against any Cipher implementation.
func cipherCompliance(t *testing.T, c Cipher) {
	t.Helper()

	plaintext := []byte("the quick brown fox jumps over the lazy dog")

	// Round-trip
	ct, err := c.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Equal(ct, plaintext) {
		t.Fatal("ciphertext must differ from plaintext")
	}

	got, err := c.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, plaintext)
	}

	// Nonce freshness — two encryptions of the same plaintext must differ
	ct2, _ := c.Encrypt(plaintext)
	if bytes.Equal(ct, ct2) {
		t.Fatal("repeated Encrypt must produce different ciphertext (nonce reuse)")
	}

	// Tamper detection
	tampered := make([]byte, len(ct))
	copy(tampered, ct)
	tampered[len(tampered)-1] ^= 0xFF
	if _, err := c.Decrypt(tampered); err == nil {
		t.Fatal("expected error decrypting tampered ciphertext")
	}

	// Truncation guard
	if _, err := c.Decrypt(ct[:4]); err == nil {
		t.Fatal("expected error decrypting truncated ciphertext")
	}
}

func TestXChacha20_InterfaceCompliance(t *testing.T) {
	c, err := NewCipher("test-secret-key")
	if err != nil {
		t.Fatal(err)
	}
	cipherCompliance(t, c)
}

func TestNewCipher_StringSecret(t *testing.T) {
	c, err := NewCipher("my-passphrase")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c == nil {
		t.Fatal("expected non-nil cipher")
	}
}

func TestNewCipher_Base64Secret(t *testing.T) {
	// A valid base64-encoded 32-byte key
	b64Key := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // 32 zero bytes in base64
	c, err := NewCipher(b64Key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cipherCompliance(t, c)
}

func TestNewCipher_EmptySecret(t *testing.T) {
	_, err := NewCipher("")
	if err == nil {
		t.Fatal("expected error for empty secret")
	}
}

func TestNewCipherFromKey_WrongLength(t *testing.T) {
	_, err := NewCipherFromKey([]byte("too-short"))
	if err == nil {
		t.Fatal("expected error for wrong-length key")
	}
}

func TestNewCipherFromKey_Valid(t *testing.T) {
	key := bytes.Repeat([]byte{0xAB}, 32)
	c, err := NewCipherFromKey(key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cipherCompliance(t, c)
}

func TestXChacha20_WrongKeyDecrypt(t *testing.T) {
	c1, _ := NewCipher("key-alpha")
	c2, _ := NewCipher("key-beta")

	ct, _ := c1.Encrypt([]byte("secret"))
	_, err := c2.Decrypt(ct)
	if err == nil {
		t.Fatal("expected error decrypting with wrong key")
	}
	if err != ErrDecrypt {
		t.Fatalf("expected ErrDecrypt, got: %v", err)
	}
}

func TestXChacha20_EncryptEmpty(t *testing.T) {
	c, _ := NewCipher("key")
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

func TestXChacha20_LargePlaintext(t *testing.T) {
	c, _ := NewCipher("large-test")
	large := bytes.Repeat([]byte("A"), 1<<20) // 1 MiB
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

func TestXChacha20_DifferentSecretsProduceDifferentCiphers(t *testing.T) {
	c1, _ := NewCipher("secret-one")
	c2, _ := NewCipher("secret-two")

	pt := []byte("same plaintext")
	ct1, _ := c1.Encrypt(pt)
	ct2, _ := c2.Encrypt(pt)

	// Both should decrypt correctly with their own key
	got1, _ := c1.Decrypt(ct1)
	got2, _ := c2.Decrypt(ct2)
	if !bytes.Equal(got1, pt) || !bytes.Equal(got2, pt) {
		t.Fatal("round-trip failed for one of the ciphers")
	}
}

// kdfCompliance runs a standard suite against any KDF implementation.
func kdfCompliance(t *testing.T, kdf KDF) {
	t.Helper()
	password := []byte("hunter2")
	salt := []byte("saltsaltsaltsalt")

	key, err := kdf.DeriveKey(password, salt, 32)
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(key))
	}

	// Determinism
	key2, _ := kdf.DeriveKey(password, salt, 32)
	if !bytes.Equal(key, key2) {
		t.Fatal("DeriveKey must be deterministic")
	}

	// Different salt → different key
	key3, _ := kdf.DeriveKey(password, []byte("differentsaltslt"), 32)
	if bytes.Equal(key, key3) {
		t.Fatal("different salt must produce different key")
	}

	// Different password → different key
	key4, _ := kdf.DeriveKey([]byte("other-password"), salt, 32)
	if bytes.Equal(key, key4) {
		t.Fatal("different password must produce different key")
	}
}

func TestArgon2KDF_InterfaceCompliance(t *testing.T) {
	kdf := DefaultArgon2KDF()
	kdfCompliance(t, kdf)
}

func TestArgon2KDF_EmptyPassword(t *testing.T) {
	kdf := DefaultArgon2KDF()
	_, err := kdf.DeriveKey([]byte{}, []byte("salt"), 32)
	if err == nil {
		t.Fatal("expected error for empty password")
	}
}

func TestArgon2KDF_EmptySalt(t *testing.T) {
	kdf := DefaultArgon2KDF()
	_, err := kdf.DeriveKey([]byte("pass"), []byte{}, 32)
	if err == nil {
		t.Fatal("expected error for empty salt")
	}
}

func TestArgon2KDF_InvalidKeyLen(t *testing.T) {
	kdf := DefaultArgon2KDF()
	_, err := kdf.DeriveKey([]byte("pass"), []byte("salt"), 0)
	if err == nil {
		t.Fatal("expected error for zero keyLen")
	}
}

func TestArgon2KDF_VariousKeyLengths(t *testing.T) {
	kdf := DefaultArgon2KDF()
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

func TestArgon2KDF_DefaultParams(t *testing.T) {
	kdf := DefaultArgon2KDF()
	if kdf.Time == 0 {
		t.Fatal("Time must be non-zero")
	}
	if kdf.Memory == 0 {
		t.Fatal("Memory must be non-zero")
	}
	if kdf.Parallelism == 0 {
		t.Fatal("Parallelism must be non-zero")
	}
}

func TestKDFThenCipher(t *testing.T) {
	kdf := DefaultArgon2KDF()
	key, err := kdf.DeriveKey([]byte("my-passphrase"), []byte("unique-salt-1234"), 32)
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}

	c, err := NewCipherFromKey(key)
	if err != nil {
		t.Fatalf("NewCipherFromKey: %v", err)
	}

	secret := []byte("TOP SECRET: launch codes 00000")
	ct, err := c.Encrypt(secret)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	got, err := c.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatal("pipeline round-trip failed")
	}
}

func TestXChacha20_NilCipherEncrypt(t *testing.T) {
	var c *XChacha20Cipher
	_, err := c.Encrypt([]byte("data"))
	if err == nil {
		t.Fatal("Encrypt on nil cipher must return error")
	}
}

func TestXChacha20_NilCipherDecrypt(t *testing.T) {
	var c *XChacha20Cipher
	_, err := c.Decrypt([]byte("data"))
	if err == nil {
		t.Fatal("Decrypt on nil cipher must return error")
	}
}

func TestXChacha20_UninitializedAEAD(t *testing.T) {
	c := &XChacha20Cipher{aead: nil}
	_, errEnc := c.Encrypt([]byte("x"))
	_, errDec := c.Decrypt([]byte("x"))
	if errEnc == nil || errDec == nil {
		t.Fatal("uninitialized aead must return errors")
	}
}

func TestNewCipher_Base64WrongLength(t *testing.T) {
	// Valid base64 but only 16 bytes — must fall back to SHA-256 hash path
	b64Short := "AAAAAAAAAAAAAAAAAAAAAA==" // 16 zero bytes in base64
	c, err := NewCipher(b64Short)
	if err != nil {
		t.Fatalf("should succeed via hash fallback: %v", err)
	}
	cipherCompliance(t, c)
}

func TestErrDecryptSentinel(t *testing.T) {
	if ErrDecrypt == nil {
		t.Fatal("ErrDecrypt must be non-nil")
	}
	if !strings.Contains(ErrDecrypt.Error(), "decryption") {
		t.Fatalf("unexpected ErrDecrypt message: %q", ErrDecrypt.Error())
	}
}
