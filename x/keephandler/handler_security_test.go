package keephandler

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/agberohq/keeper"
)

// helpers

func assertNoStore(t *testing.T, resp *http.Response, route string) {
	t.Helper()
	cc := resp.Header.Get("Cache-Control")
	pragma := resp.Header.Get("Pragma")
	if cc == "" {
		t.Errorf("%s: missing Cache-Control header", route)
	} else if cc != "no-store, no-cache" {
		t.Errorf("%s: Cache-Control = %q, want \"no-store, no-cache\"", route, cc)
	}
	if pragma == "" {
		t.Errorf("%s: missing Pragma header", route)
	}
}

// newTestServerWithBucket creates a test server with an unlocked store that
// already has a PasswordOnly bucket registered so all operations work.
func newTestServerWithBucket(t *testing.T, opts ...Option) (*http.Client, string, *keeper.Keeper) {
	t.Helper()
	srv, store := newTestServer(t, opts...)
	t.Cleanup(srv.Close)
	return srv.Client(), srv.URL, store
}

// Cache-Control headers

// TestGet_NoCacheHeaders verifies the GET /keys/{key} response always carries
// Cache-Control: no-store so secret values are never cached by proxies.
func TestGet_NoCacheHeaders(t *testing.T) {
	client, base, store := newTestServerWithBucket(t)
	store.Set("cachekey", []byte("cachevalue")) //nolint:errcheck

	req, _ := http.NewRequest("GET", base+"/keeper/keys/cachekey", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	assertNoStore(t, resp, "GET /keys/{key}")
}

// TestSet_NoCacheHeaders verifies POST /keys carries no-store even though it
// does not return the value — the response confirms the key name which could
// leak metadata to caches.
func TestSet_NoCacheHeaders(t *testing.T) {
	client, base, _ := newTestServerWithBucket(t)

	req, _ := http.NewRequest("POST", base+"/keeper/keys", strings.NewReader(`{"key":"k","value":"v"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	assertNoStore(t, resp, "POST /keys")
}

// TestUnlock_NoCacheHeaders verifies the unlock response is not cached —
// it confirms the store is now accessible which is sensitive state.
func TestUnlock_NoCacheHeaders(t *testing.T) {
	srv := newLockedServer(t)
	defer srv.Close()

	req, _ := http.NewRequest("POST", srv.URL+"/keeper/unlock", strings.NewReader(`{"passphrase":"testpass"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("unlock: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	assertNoStore(t, resp, "POST /unlock")
}

// TestRotate_NoCacheHeaders verifies rotate response carries no-store.
func TestRotate_NoCacheHeaders(t *testing.T) {
	client, base, _ := newTestServerWithBucket(t)

	req, _ := http.NewRequest("POST", base+"/keeper/rotate", strings.NewReader(`{"new_passphrase":"newpass"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	assertNoStore(t, resp, "POST /rotate")
}

// TestRotateSalt_NoCacheHeaders verifies rotate-salt response carries no-store.
func TestRotateSalt_NoCacheHeaders(t *testing.T) {
	client, base, _ := newTestServerWithBucket(t)

	req, _ := http.NewRequest("POST", base+"/keeper/rotate/salt", strings.NewReader(`{"passphrase":"testpass"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("rotate-salt: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	assertNoStore(t, resp, "POST /rotate/salt")
}

// base64 value encoding

// TestGet_ValueIsBase64Encoded is the primary regression test. Before the fix,
// string(val) was returned which corrupts binary secrets that contain non-UTF-8
// bytes. After the fix the value is base64-encoded and an "encoding":"base64"
// field is included so clients know to decode it.
func TestGet_ValueIsBase64Encoded(t *testing.T) {
	client, base, store := newTestServerWithBucket(t)

	want := []byte("plain text value")
	store.Set("enckey", want) //nolint:errcheck

	req, _ := http.NewRequest("GET", base+"/keeper/keys/enckey", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// "encoding" field must be present and set to "base64".
	enc, _ := m["encoding"].(string)
	if enc != "base64" {
		t.Errorf("encoding field: want \"base64\", got %q", enc)
	}

	// "value" must be valid base64 that decodes to the original bytes.
	rawVal, _ := m["value"].(string)
	if rawVal == "" {
		t.Fatal("value field is empty")
	}
	decoded, err := base64.StdEncoding.DecodeString(rawVal)
	if err != nil {
		t.Fatalf("value is not valid base64: %v", err)
	}
	if string(decoded) != string(want) {
		t.Errorf("decoded value = %q, want %q", decoded, want)
	}
}

// TestGet_BinaryValueRoundTrip is the critical safety test: a value containing
// arbitrary bytes (including 0x00, 0xFF, and invalid UTF-8 sequences) must
// survive a Set → GET round-trip without corruption.
//
// Before the fix, string(val) would silently corrupt non-UTF-8 bytes.
func TestGet_BinaryValueRoundTrip(t *testing.T) {
	client, base, store := newTestServerWithBucket(t)

	// Bytes that are invalid UTF-8 and would be corrupted by string(val).
	binary := []byte{0x00, 0x01, 0xFE, 0xFF, 0x80, 0x81, 0xC0, 0xC1}
	store.Set("binkey", binary) //nolint:errcheck

	req, _ := http.NewRequest("GET", base+"/keeper/keys/binkey", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET binary: %v", err)
	}
	defer resp.Body.Close()

	var m map[string]any
	json.NewDecoder(resp.Body).Decode(&m) //nolint:errcheck

	rawVal, _ := m["value"].(string)
	decoded, err := base64.StdEncoding.DecodeString(rawVal)
	if err != nil {
		t.Fatalf("binary value not valid base64: %v", err)
	}

	if len(decoded) != len(binary) {
		t.Errorf("length mismatch: got %d, want %d", len(decoded), len(binary))
	}
	for i := range binary {
		if i >= len(decoded) || decoded[i] != binary[i] {
			t.Errorf("byte %d corrupted: got 0x%02X, want 0x%02X", i, decoded[i], binary[i])
		}
	}
}

// TestGet_NullByteValue verifies that a value containing the null byte (0x00)
// is not truncated — string(val) would not truncate it but JSON encoding might
// if the value is treated as a C string somewhere.
func TestGet_NullByteValue(t *testing.T) {
	client, base, store := newTestServerWithBucket(t)

	val := []byte("before\x00after")
	store.Set("nullkey", val) //nolint:errcheck

	req, _ := http.NewRequest("GET", base+"/keeper/keys/nullkey", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	var m map[string]any
	json.NewDecoder(resp.Body).Decode(&m) //nolint:errcheck

	rawVal, _ := m["value"].(string)
	decoded, _ := base64.StdEncoding.DecodeString(rawVal)
	if string(decoded) != string(val) {
		t.Errorf("null-byte value corrupted: got %q, want %q", decoded, val)
	}
}

// TestGet_ResponseHasKeyField verifies the key field is still present in the
// response alongside the new encoding field — no regression in response shape.
func TestGet_ResponseHasKeyField(t *testing.T) {
	client, base, store := newTestServerWithBucket(t)
	store.Set("mykey", []byte("myvalue")) //nolint:errcheck

	req, _ := http.NewRequest("GET", base+"/keeper/keys/mykey", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	var m map[string]any
	json.NewDecoder(resp.Body).Decode(&m) //nolint:errcheck

	if m["key"] != "mykey" {
		t.Errorf("key field: want \"mykey\", got %v", m["key"])
	}
	if m["encoding"] != "base64" {
		t.Errorf("encoding field: want \"base64\", got %v", m["encoding"])
	}
	if m["value"] == "" {
		t.Error("value field should be non-empty")
	}
}
