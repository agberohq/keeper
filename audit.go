// Package keeper — audit bridge connecting Keeper to pkg/audit.
package keeper

import (
	"crypto/sha256"
	"fmt"
	"io"
	"time"

	pkgaudit "github.com/agberohq/keeper/pkg/audit"
	pkgstore "github.com/agberohq/keeper/pkg/store"
	"golang.org/x/crypto/hkdf"
)

// AuditEvent is the public-facing audit record re-exported from pkg/audit.
type AuditEvent = pkgaudit.Event

// auditStore wraps pkg/audit.Store for use within the keeper package.
// It manages the audit signing key lifecycle: the key is derived from
// the master key after UnlockDatabase and cleared on Lock.
type auditStore struct {
	db    pkgstore.Store
	inner *pkgaudit.Store
}

func newAuditStore(db pkgstore.Store) *auditStore {
	return &auditStore{
		db:    db,
		inner: pkgaudit.New(db, nil),
	}
}

// setSigningKey rebuilds the inner audit.Store with the supplied HMAC key.
// Pass nil to disable signing (called from Lock).
// The caller is responsible for zeroing key after this call.
func (a *auditStore) setSigningKey(key []byte) {
	a.inner = pkgaudit.New(a.db, key)
}

// deriveAuditKey produces a 32-byte HMAC signing key from the master key.
// Uses HKDF-SHA256 with hkdfInfoAuditKey as the domain-separation info string.
// The returned key must be zeroed by the caller after use.
func deriveAuditKey(masterBytes []byte) ([]byte, error) {
	if len(masterBytes) == 0 {
		return nil, fmt.Errorf("audit: masterBytes must not be empty")
	}
	r := hkdf.New(sha256.New, masterBytes, nil, []byte(hkdfInfoAuditKey))
	key := make([]byte, masterKeyLen)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("audit: HKDF expansion failed: %w", err)
	}
	return key, nil
}

func (a *auditStore) init() error {
	return a.inner.Init()
}

func (a *auditStore) appendEvent(scheme, namespace string, event *BucketEvent) error {
	return a.inner.Append(scheme, namespace, event)
}

func (a *auditStore) loadChain(scheme, namespace string) ([]*BucketEvent, error) {
	return a.inner.LoadChain(scheme, namespace)
}

func (a *auditStore) pruneEvents(scheme, namespace string, olderThan time.Duration, keepLastN int) error {
	return a.inner.Prune(scheme, namespace, olderThan, keepLastN)
}

func (a *auditStore) getLastChecksum(scheme, namespace string) string {
	return a.inner.LastChecksum(scheme, namespace)
}
