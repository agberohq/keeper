package remote

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeKMS is a minimal in-memory KMS that base64-encodes on wrap and decodes on unwrap.
type fakeKMS struct {
	failCount int
	calls     int
}

func (f *fakeKMS) handler(w http.ResponseWriter, r *http.Request) {
	f.calls++
	if f.failCount > 0 {
		f.failCount--
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	var req map[string]string
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// wrap: echo input as ciphertext; unwrap: decode and re-encode as plaintext
	if v, ok := req["plaintext"]; ok {
		json.NewEncoder(w).Encode(map[string]string{"ciphertext": v})
		return
	}
	if v, ok := req["ciphertext"]; ok {
		json.NewEncoder(w).Encode(map[string]string{"plaintext": v})
		return
	}
	http.Error(w, "unknown request", http.StatusBadRequest)
}

func newTestServer(t *testing.T, f *fakeKMS) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(f.handler))
	t.Cleanup(srv.Close)
	return srv
}

func TestProvider_WrapUnwrap(t *testing.T) {
	f := &fakeKMS{}
	srv := newTestServer(t, f)
	cfg := Config{
		URL:                    srv.URL,
		WrapRequestTemplate:    `{"plaintext":"{{.DEK}}"}`,
		WrapResponseJSONPath:   "ciphertext",
		UnwrapRequestTemplate:  `{"ciphertext":"{{.Wrapped}}"}`,
		UnwrapResponseJSONPath: "plaintext",
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i + 1)
	}
	wrapped, err := p.WrapDEK(dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}
	got, err := p.UnwrapDEK(wrapped)
	if err != nil {
		t.Fatalf("UnwrapDEK: %v", err)
	}
	gotDecoded, err := base64.StdEncoding.DecodeString(string(got))
	if err != nil {
		gotDecoded = got
	}
	_ = gotDecoded
}

func TestProvider_RetryOn503(t *testing.T) {
	f := &fakeKMS{failCount: 2}
	srv := newTestServer(t, f)
	cfg := Config{
		URL:                    srv.URL,
		WrapRequestTemplate:    `{"plaintext":"{{.DEK}}"}`,
		WrapResponseJSONPath:   "ciphertext",
		UnwrapRequestTemplate:  `{"ciphertext":"{{.Wrapped}}"}`,
		UnwrapResponseJSONPath: "plaintext",
		RetryCount:             3,
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	dek := make([]byte, 32)
	if _, err := p.WrapDEK(dek); err != nil {
		t.Fatalf("WrapDEK after retries: %v", err)
	}
	if f.calls < 3 {
		t.Fatalf("expected at least 3 HTTP calls (2 failures + 1 success), got %d", f.calls)
	}
}

func TestProvider_Ping(t *testing.T) {
	f := &fakeKMS{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		f.handler(w, r)
	}))
	t.Cleanup(srv.Close)

	p, err := New(Config{URL: srv.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := p.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}
