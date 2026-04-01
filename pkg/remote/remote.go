// Package remote provides a configurable HTTPS-based HSMProvider that delegates
// DEK wrap and unwrap operations to any remote KMS service over TLS.
// For production use, configure TLSClientCert and TLSClientKey to enable mTLS
// so the remote service can authenticate the caller.
package remote

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Config holds all parameters for a RemoteKMSProvider.
// URL and at least one of WrapResponseJSONPath/UnwrapResponseJSONPath are required.
type Config struct {
	// URL is the HTTPS endpoint for wrap operations. Required.
	URL string

	// UnwrapURL overrides URL for unwrap operations when the service uses
	// separate endpoints. Defaults to URL when empty.
	UnwrapURL string

	// Method is the HTTP verb used for wrap and unwrap requests. Defaults to POST.
	Method string

	// Headers are static HTTP headers added to every request.
	// Use this for Authorization, X-Vault-Token, and similar.
	Headers map[string]string

	// TLSCACert is the path to a PEM-encoded CA certificate bundle for
	// private or custom PKI. Uses the system root pool when empty.
	TLSCACert string

	// TLSClientCert and TLSClientKey enable mutual TLS authentication.
	// Both must be set together; if either is empty mTLS is not configured.
	TLSClientCert string
	TLSClientKey  string

	// InsecureSkipVerify disables TLS certificate verification.
	// This MUST NOT be used in production. It exists only for local test servers.
	InsecureSkipVerify bool

	// Timeout is the per-request deadline. Defaults to defaultRequestTimeout.
	Timeout time.Duration

	// WrapRequestTemplate is a Go text/template rendered before the wrap POST.
	// The template receives a single string field {{.DEK}} which is the
	// base64-encoded DEK bytes. When empty, the raw base64 DEK is sent as
	// the request body with Content-Type: text/plain.
	WrapRequestTemplate string

	// WrapResponseJSONPath is a dot-separated key path into the JSON response
	// body to extract the wrapped ciphertext, e.g. "ciphertext" or "data.ciphertext".
	// When empty the entire response body is treated as base64 ciphertext.
	WrapResponseJSONPath string

	// UnwrapRequestTemplate mirrors WrapRequestTemplate for the unwrap request.
	// The template field is {{.Wrapped}} (base64-encoded wrapped ciphertext).
	UnwrapRequestTemplate string

	// UnwrapResponseJSONPath mirrors WrapResponseJSONPath for the unwrap response.
	// The extracted value must be the base64-encoded plaintext DEK.
	UnwrapResponseJSONPath string

	// ExpectedStatusCodes lists HTTP status codes treated as success.
	// Defaults to [200, 204] when nil.
	ExpectedStatusCodes []int

	// RetryCount is the number of retry attempts on transient errors. Default 3.
	RetryCount int

	// RetryBackoff is the initial wait between retries. Default 500 ms.
	// Retries use exponential backoff capped at 8 × RetryBackoff.
	RetryBackoff time.Duration
}

const (
	defaultRequestTimeout = 10 * time.Second
	defaultRetryCount     = 3
	defaultRetryBackoff   = 500 * time.Millisecond
	maxBackoffMultiplier  = 8
)

// Provider implements keeper.HSMProvider by delegating to a remote KMS service.
// It is safe for concurrent use.
type Provider struct {
	cfg    Config
	client *http.Client
}

// New constructs a Provider from cfg, building the TLS-aware http.Client.
// Returns an error if the TLS configuration is invalid or cert files cannot be read.
func New(cfg Config) (*Provider, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("remote: URL is required")
	}
	if cfg.Method == "" {
		cfg.Method = http.MethodPost
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultRequestTimeout
	}
	if cfg.RetryCount <= 0 {
		cfg.RetryCount = defaultRetryCount
	}
	if cfg.RetryBackoff <= 0 {
		cfg.RetryBackoff = defaultRetryBackoff
	}
	if len(cfg.ExpectedStatusCodes) == 0 {
		cfg.ExpectedStatusCodes = []int{http.StatusOK, http.StatusNoContent}
	}

	tlsCfg := &tls.Config{
		InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec // intentional, documented risk
	}

	if cfg.TLSCACert != "" {
		pem, err := os.ReadFile(cfg.TLSCACert)
		if err != nil {
			return nil, fmt.Errorf("remote: failed to read CA cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("remote: no valid CA certificates found in %s", cfg.TLSCACert)
		}
		tlsCfg.RootCAs = pool
	}

	if cfg.TLSClientCert != "" && cfg.TLSClientKey != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSClientCert, cfg.TLSClientKey)
		if err != nil {
			return nil, fmt.Errorf("remote: failed to load mTLS key pair: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	client := &http.Client{
		Timeout:   cfg.Timeout,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}
	return &Provider{cfg: cfg, client: client}, nil
}

// WrapDEK base64-encodes dek, sends it to the configured wrap endpoint, and
// returns the base64-decoded ciphertext from the response.
func (p *Provider) WrapDEK(dek []byte) ([]byte, error) {
	body, err := p.buildRequest(dek, p.cfg.WrapRequestTemplate, "DEK")
	if err != nil {
		return nil, fmt.Errorf("remote: wrap request build failed: %w", err)
	}
	resp, err := p.doWithRetry(p.cfg.URL, body)
	if err != nil {
		return nil, fmt.Errorf("remote: wrap request failed: %w", err)
	}
	return p.extractBase64(resp, p.cfg.WrapResponseJSONPath)
}

// UnwrapDEK base64-encodes wrapped, sends it to the configured unwrap endpoint,
// and returns the decoded plaintext DEK bytes. The plaintext DEK must not be
// logged or stored beyond the immediate caller's stack frame.
func (p *Provider) UnwrapDEK(wrapped []byte) ([]byte, error) {
	body, err := p.buildRequest(wrapped, p.cfg.UnwrapRequestTemplate, "Wrapped")
	if err != nil {
		return nil, fmt.Errorf("remote: unwrap request build failed: %w", err)
	}
	target := p.cfg.URL
	if p.cfg.UnwrapURL != "" {
		target = p.cfg.UnwrapURL
	}
	resp, err := p.doWithRetry(target, body)
	if err != nil {
		return nil, fmt.Errorf("remote: unwrap request failed: %w", err)
	}
	return p.extractBase64(resp, p.cfg.UnwrapResponseJSONPath)
}

// Ping sends a HEAD request to the configured URL to verify reachability.
// Used by the jack.Doctor health patient.
func (p *Provider) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, p.cfg.URL, nil)
	if err != nil {
		return fmt.Errorf("remote: ping request build failed: %w", err)
	}
	for k, v := range p.cfg.Headers {
		req.Header.Set(k, v)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("remote: ping failed: %w", err)
	}
	resp.Body.Close()
	if !p.isSuccess(resp.StatusCode) {
		return fmt.Errorf("remote: ping returned status %d", resp.StatusCode)
	}
	return nil
}

// buildRequest renders the request body. When tmpl is empty the raw base64
// of payload is used as the body. Otherwise the template is rendered with
// a single field named fieldName set to the base64-encoded payload.
func (p *Provider) buildRequest(payload []byte, tmpl, fieldName string) ([]byte, error) {
	encoded := base64.StdEncoding.EncodeToString(payload)
	if tmpl == "" {
		return []byte(encoded), nil
	}
	replaced := strings.ReplaceAll(tmpl, "{{."+fieldName+"}}", encoded)
	return []byte(replaced), nil
}

// doWithRetry executes the configured HTTP method against url with body,
// retrying on network errors or 5xx responses up to cfg.RetryCount times.
func (p *Provider) doWithRetry(url string, body []byte) ([]byte, error) {
	var lastErr error
	backoff := p.cfg.RetryBackoff
	for attempt := 0; attempt <= p.cfg.RetryCount; attempt++ {
		if attempt > 0 {
			time.Sleep(backoff)
			backoff *= 2
			if backoff > time.Duration(maxBackoffMultiplier)*p.cfg.RetryBackoff {
				backoff = time.Duration(maxBackoffMultiplier) * p.cfg.RetryBackoff
			}
		}
		resp, err := p.executeOnce(url, body)
		if err != nil {
			lastErr = err
			continue
		}
		return resp, nil
	}
	return nil, lastErr
}

// executeOnce performs a single HTTP request and reads the response body.
func (p *Provider) executeOnce(url string, body []byte) ([]byte, error) {
	req, err := http.NewRequest(p.cfg.Method, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("request build: %w", err)
	}
	for k, v := range p.cfg.Headers {
		req.Header.Set(k, v)
	}
	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if !p.isSuccess(resp.StatusCode) {
		return nil, fmt.Errorf("unexpected status %d from %s", resp.StatusCode, url)
	}
	return io.ReadAll(resp.Body)
}

// extractBase64 extracts a field from a JSON response body using a dot-separated
// jsonPath, then base64-decodes the string value. When jsonPath is empty the
// entire body is treated as the base64 value.
func (p *Provider) extractBase64(body []byte, jsonPath string) ([]byte, error) {
	var raw string
	if jsonPath == "" {
		raw = strings.TrimSpace(string(body))
	} else {
		var data map[string]interface{}
		if err := json.Unmarshal(body, &data); err != nil {
			return nil, fmt.Errorf("remote: failed to parse JSON response: %w", err)
		}
		val, err := traverseJSON(data, strings.Split(jsonPath, "."))
		if err != nil {
			return nil, fmt.Errorf("remote: JSONPath %q not found: %w", jsonPath, err)
		}
		s, ok := val.(string)
		if !ok {
			return nil, fmt.Errorf("remote: JSONPath %q is not a string", jsonPath)
		}
		raw = s
	}
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("remote: base64 decode failed: %w", err)
	}
	return decoded, nil
}

// traverseJSON walks a nested map using a sequence of keys.
func traverseJSON(data map[string]interface{}, keys []string) (interface{}, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("empty key path")
	}
	val, ok := data[keys[0]]
	if !ok {
		return nil, fmt.Errorf("key %q not found", keys[0])
	}
	if len(keys) == 1 {
		return val, nil
	}
	nested, ok := val.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("key %q is not an object", keys[0])
	}
	return traverseJSON(nested, keys[1:])
}

// isSuccess reports whether status is in the configured ExpectedStatusCodes.
func (p *Provider) isSuccess(status int) bool {
	for _, code := range p.cfg.ExpectedStatusCodes {
		if status == code {
			return true
		}
	}
	return false
}
