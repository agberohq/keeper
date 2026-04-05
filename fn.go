package keeper

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strings"
)

func mustJSON(v interface{}) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Errorf("json marshal failed: %w", err))
	}
	return data
}

func generateUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failure means the OS entropy source is broken.
		// An all-zero UUID would silently overwrite other audit events in
		// bbolt (same key = last-write-wins). The store cannot be trusted
		// at all in this state — panic is the correct response.
		panic(fmt.Sprintf("keeper: crypto/rand unavailable: %v", err))
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func validateConfig(config *Config) error {
	if config.DBPath == "" {
		return fmt.Errorf("%w: DBPath is required", ErrInvalidConfig)
	}
	if config.KeyLen == 0 {
		config.KeyLen = masterKeyLen
	}
	if config.AutoLockInterval < 0 {
		return fmt.Errorf("%w: AutoLockInterval cannot be negative", ErrInvalidConfig)
	}
	if config.DefaultNamespace != "" && !isValidNamespace(config.DefaultNamespace) {
		return fmt.Errorf("%w: DefaultNamespace contains invalid characters", ErrInvalidConfig)
	}
	return nil
}

func isValidScheme(scheme string) bool {
	if scheme == "" {
		return false
	}
	invalidChars := "/:\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
	return !strings.ContainsAny(scheme, invalidChars)
}

func isValidNamespace(ns string) bool {
	if ns == "" {
		return false
	}
	invalidChars := "/\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
	return !strings.ContainsAny(ns, invalidChars)
}

func parseKey(fullKey string) (namespace, key string) {
	if idx := strings.Index(fullKey, namespaceSeparator); idx > 0 {
		return fullKey[:idx], fullKey[idx+1:]
	}
	return "", fullKey
}

func bucketName(namespace string) []byte {
	if namespace == "" {
		return []byte(defaultNamespace)
	}
	return []byte(namespace)
}

// isPolicyHashKey reports whether a policy bucket key is a metadata entry
// (:hash or :hmac suffix) that should be skipped during policy iteration.
func isPolicyHashKey(key string) bool {
	return strings.HasSuffix(key, policyHashSuffix) || strings.HasSuffix(key, policyHMACSuffix)
}

// parseKeyExtended extracts scheme, namespace, and key from input string.
// Format: [scheme://][namespace/]key
func parseKeyExtended(fullKey string) (scheme, namespace, key string) {
	rest := fullKey
	if idx := strings.Index(rest, schemeSeparator); idx > 0 {
		scheme = rest[:idx]
		rest = rest[idx+len(schemeSeparator):]
	}
	namespace, key = parseKey(rest)
	if scheme == "" {
		scheme = defaultScheme
	}
	return scheme, namespace, key
}
