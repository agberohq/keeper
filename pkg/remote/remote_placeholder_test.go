package remote

import (
	"strings"
	"testing"
)

// TestBuildRequest_MissingDEKPlaceholder is the primary regression test.
// Before the fix, a WrapRequestTemplate without {{.DEK}} would silently send
// the literal template to the KMS. After the fix it must return an error.
func TestBuildRequest_MissingDEKPlaceholder(t *testing.T) {
	p := &Provider{cfg: Config{
		URL:                 "http://kms.example.com/wrap",
		WrapRequestTemplate: `{"key":"hardcoded","value":"no-placeholder-here"}`,
	}}

	_, err := p.buildRequest([]byte("sekret"), `{"key":"hardcoded","value":"no-placeholder-here"}`, "DEK")
	if err == nil {
		t.Fatal("expected error when DEK placeholder is absent, got nil")
	}
	if !strings.Contains(err.Error(), "{{.DEK}}") {
		t.Errorf("error should mention the missing placeholder, got: %v", err)
	}
}

// TestBuildRequest_MissingWrappedPlaceholder covers the unwrap template path.
func TestBuildRequest_MissingWrappedPlaceholder(t *testing.T) {
	p := &Provider{cfg: Config{}}
	_, err := p.buildRequest([]byte("blob"), `{"ciphertext":"static"}`, "Wrapped")
	if err == nil {
		t.Fatal("expected error when Wrapped placeholder is absent, got nil")
	}
	if !strings.Contains(err.Error(), "{{.Wrapped}}") {
		t.Errorf("error should mention {{.Wrapped}}, got: %v", err)
	}
}

// TestBuildRequest_ValidDEKTemplate verifies that a well-formed template
// is rendered correctly — the placeholder is replaced with the base64 payload.
func TestBuildRequest_ValidDEKTemplate(t *testing.T) {
	p := &Provider{cfg: Config{}}
	payload := []byte("my-dek-bytes")
	tmpl := `{"dek":"{{.DEK}}"}`

	body, err := p.buildRequest(payload, tmpl, "DEK")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	bodyStr := string(body)
	if strings.Contains(bodyStr, "{{.DEK}}") {
		t.Error("placeholder was not substituted in the output")
	}
	// The base64 of "my-dek-bytes" must appear in the body.
	if !strings.Contains(bodyStr, "bXktZGVrLWJ5dGVz") { // base64("my-dek-bytes")
		t.Errorf("base64 payload not found in rendered body: %s", bodyStr)
	}
}

// TestBuildRequest_EmptyTemplate returns the raw base64 payload when no
// template is configured — this is the documented fallback behaviour.
func TestBuildRequest_EmptyTemplate(t *testing.T) {
	p := &Provider{cfg: Config{}}
	payload := []byte("rawbytes")

	body, err := p.buildRequest(payload, "", "DEK")
	if err != nil {
		t.Fatalf("empty template should not error: %v", err)
	}
	// Should be pure base64, no JSON wrapper.
	if strings.Contains(string(body), "{") {
		t.Errorf("empty template should return raw base64, got: %s", body)
	}
}

// TestBuildRequest_PlaceholderAppearsTwice verifies that multiple occurrences
// of the placeholder are all replaced (strings.ReplaceAll semantics).
func TestBuildRequest_PlaceholderAppearsTwice(t *testing.T) {
	p := &Provider{cfg: Config{}}
	tmpl := `{"a":"{{.DEK}}","b":"{{.DEK}}"}`

	body, err := p.buildRequest([]byte("x"), tmpl, "DEK")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Count(string(body), "{{.DEK}}") != 0 {
		t.Error("not all placeholder occurrences were replaced")
	}
}

// TestBuildRequest_WrongPlaceholderName catches the case where the template
// uses a different field name than expected (e.g. {{.Key}} vs {{.DEK}}).
func TestBuildRequest_WrongPlaceholderName(t *testing.T) {
	p := &Provider{cfg: Config{}}
	tmpl := `{"key":"{{.Key}}"}`

	_, err := p.buildRequest([]byte("payload"), tmpl, "DEK")
	if err == nil {
		t.Fatal("template with wrong placeholder name should error")
	}
}
