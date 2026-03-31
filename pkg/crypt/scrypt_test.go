package crypt_test

import (
	"bytes"
	"testing"

	"github.com/agberohq/keeper/pkg/crypt"
)

func TestScryptKDF_DeriveKey(t *testing.T) {
	kdf := crypt.DefaultScryptKDF()
	password := []byte("testpassword")
	salt := []byte("testsalt1234567")

	key, err := kdf.DeriveKey(password, salt, 32)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("key length = %d, want 32", len(key))
	}

	// Deterministic.
	key2, _ := kdf.DeriveKey(password, salt, 32)
	if !bytes.Equal(key, key2) {
		t.Error("DeriveKey is not deterministic")
	}

	// Different salt → different key.
	key3, _ := kdf.DeriveKey(password, []byte("differentsalt12"), 32)
	if bytes.Equal(key, key3) {
		t.Error("different salts should produce different keys")
	}
}

func TestScryptKDF_Errors(t *testing.T) {
	kdf := crypt.DefaultScryptKDF()
	salt := []byte("salt")

	if _, err := kdf.DeriveKey(nil, salt, 32); err == nil {
		t.Error("empty password should fail")
	}
	if _, err := kdf.DeriveKey([]byte("pass"), nil, 32); err == nil {
		t.Error("nil salt should fail")
	}
	if _, err := kdf.DeriveKey([]byte("pass"), salt, 0); err == nil {
		t.Error("zero keyLen should fail")
	}
}

func TestScryptKDF_ImplementsKDF(t *testing.T) {
	var _ crypt.KDF = crypt.DefaultScryptKDF()
}
