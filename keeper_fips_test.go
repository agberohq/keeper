package keeper

// The keeper's Cipher and KDF are pluggable via Config.NewCipher and
// Config.KDF. These tests exercise the full lifecycle — unlock, set, get,
// rotate, reopen — using the FIPS implementations instead of the defaults
// (XChaCha20-Poly1305 + Argon2id).

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/agberohq/keeper/pkg/crypt"
)

// fipsConfig returns a Config wired to use FIPS-approved primitives:
// PBKDF2-SHA-256 for key derivation and AES-256-GCM for encryption.
// Uses low iteration count for test speed — production should use
// crypt.DefaultPBKDF2KDF() (600,000 iterations).
func fipsConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		DBPath: filepath.Join(t.TempDir(), "fips.db"),
		KDF:    &crypt.PBKDF2SHA256KDF{Iterations: 1000},
		NewCipher: func(key []byte) (crypt.Cipher, error) {
			return crypt.NewAES256GCMCipher(key)
		},
	}
}

// TestFIPS_UnlockAndBasicRoundTrip verifies that a keeper configured with
// FIPS algorithms can unlock, store a secret, and retrieve it correctly.
func TestFIPS_UnlockAndBasicRoundTrip(t *testing.T) {
	s, err := New(fipsConfig(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()

	if err := s.Unlock([]byte("fips-passphrase")); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	if err := s.Set("apikey", []byte("top-secret-value")); err != nil {
		t.Fatalf("Set: %v", err)
	}

	val, err := s.Get("apikey")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(val) != "top-secret-value" {
		t.Errorf("Get: want %q, got %q", "top-secret-value", val)
	}
}

// TestFIPS_BinaryValueRoundTrip verifies that arbitrary binary data (including
// null bytes and non-UTF-8 sequences) survives a round-trip with AES-256-GCM.
func TestFIPS_BinaryValueRoundTrip(t *testing.T) {
	s, err := New(fipsConfig(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()
	s.Unlock([]byte("pass")) //nolint:errcheck

	binary := []byte{0x00, 0x01, 0xFE, 0xFF, 0x80, 0x81, 0xC0, 0xC1}
	s.Set("bin", binary) //nolint:errcheck

	got, err := s.Get("bin")
	if err != nil {
		t.Fatalf("Get binary: %v", err)
	}
	if !bytes.Equal(got, binary) {
		t.Errorf("binary round-trip failed: got %v, want %v", got, binary)
	}
}

// TestFIPS_SurvivesReopen verifies that data encrypted with FIPS algorithms
// is readable after the store is closed and reopened with the same config.
func TestFIPS_SurvivesReopen(t *testing.T) {
	cfg := fipsConfig(t)
	passphrase := []byte("fips-reopen-pass")

	// First session: write.
	{
		s, err := New(cfg)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		s.Unlock(passphrase)                      //nolint:errcheck
		s.Set("persistent", []byte("still-here")) //nolint:errcheck
		s.Close()
	}

	// Second session: read back.
	{
		s, err := New(cfg)
		if err != nil {
			t.Fatalf("New (reopen): %v", err)
		}
		defer s.Close()
		if err := s.Unlock(passphrase); err != nil {
			t.Fatalf("Unlock (reopen): %v", err)
		}
		val, err := s.Get("persistent")
		if err != nil {
			t.Fatalf("Get (reopen): %v", err)
		}
		if string(val) != "still-here" {
			t.Errorf("reopen: want %q, got %q", "still-here", val)
		}
	}
}

// TestFIPS_WrongPassphraseRejected confirms that PBKDF2 + AES-256-GCM
// correctly rejects a wrong passphrase on the second unlock attempt.
func TestFIPS_WrongPassphraseRejected(t *testing.T) {
	cfg := fipsConfig(t)

	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// First unlock establishes the verification hash.
	s.Unlock([]byte("correct-pass")) //nolint:errcheck
	s.Lock()                         //nolint:errcheck

	if err := s.Unlock([]byte("wrong-pass")); err == nil {
		t.Error("wrong passphrase must be rejected")
	}
	s.Close()
}

// TestFIPS_RotatePassphrase verifies that Rotate works with FIPS algorithms:
// the new passphrase unlocks successfully and data is accessible.
func TestFIPS_RotatePassphrase(t *testing.T) {
	s, err := New(fipsConfig(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()

	s.Unlock([]byte("old-pass"))     //nolint:errcheck
	s.Set("secret", []byte("value")) //nolint:errcheck

	if err := s.Rotate([]byte("new-pass")); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	// Old passphrase must now be rejected.
	s.Lock() //nolint:errcheck
	if err := s.Unlock([]byte("old-pass")); err == nil {
		t.Error("old passphrase should be rejected after rotation")
	}

	// New passphrase unlocks and data is readable.
	if err := s.Unlock([]byte("new-pass")); err != nil {
		t.Fatalf("Unlock with new-pass: %v", err)
	}
	val, err := s.Get("secret")
	if err != nil || string(val) != "value" {
		t.Errorf("data after rotation: %v %q", err, val)
	}
}

// TestFIPS_MultipleSecrets verifies that multiple secrets can be stored and
// retrieved independently — ensures there's no key or nonce reuse issue with
// AES-256-GCM across multiple encrypt operations.
func TestFIPS_MultipleSecrets(t *testing.T) {
	s, err := New(fipsConfig(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()
	s.Unlock([]byte("pass")) //nolint:errcheck

	secrets := map[string]string{
		"dbhost":     "localhost",
		"dbport":     "5432",
		"dbpassword": "hunter2",
		"apikey":     "sk-live-abc123",
		"apisecret":  "shh",
	}

	for k, v := range secrets {
		if err := s.Set(k, []byte(v)); err != nil {
			t.Fatalf("Set %s: %v", k, err)
		}
	}

	for k, want := range secrets {
		got, err := s.Get(k)
		if err != nil {
			t.Errorf("Get %s: %v", k, err)
			continue
		}
		if string(got) != want {
			t.Errorf("Get %s: want %q, got %q", k, want, got)
		}
	}
}

// TestFIPS_NamespacedBucket verifies FIPS algorithms work correctly with
// named LevelPasswordOnly buckets (not just the default namespace).
func TestFIPS_NamespacedBucket(t *testing.T) {
	s, err := New(fipsConfig(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()
	s.Unlock([]byte("pass")) //nolint:errcheck

	if err := s.CreateBucket("app", "prod", LevelPasswordOnly, "test"); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	if err := s.SetNamespacedFull("app", "prod", "token", []byte("prod-token")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	val, err := s.GetNamespacedFull("app", "prod", "token")
	if err != nil || string(val) != "prod-token" {
		t.Errorf("Get namespaced: %v %q", err, val)
	}
}
