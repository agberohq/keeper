package keeper

import (
	"crypto/sha256"
	"fmt"
	"io"
	"time"

	pkgaudit "github.com/agberohq/keeper/pkg/audit"
	pkgstore "github.com/agberohq/keeper/pkg/store"
	"github.com/olekukonko/zero"
	"golang.org/x/crypto/hkdf"
)

// AuditEvent is the public-facing audit record re-exported from pkg/audit.
type AuditEvent = pkgaudit.Event

// auditStore wraps pkg/audit.Store for use within the keeper package.
// It manages both the audit signing key and the audit encryption key lifecycles:
// both are derived from the master key after UnlockDatabase and cleared on Lock.
type auditStore struct {
	db     pkgstore.Store
	inner  *pkgaudit.Store
	encKey []byte // auditEncKey; nil when locked
}

func newAuditStore(db pkgstore.Store) *auditStore {
	return &auditStore{
		db:    db,
		inner: pkgaudit.New(db, nil),
	}
}

// setSigningKey updates the active HMAC signing key on the inner audit.Store.
// Pass nil to disable signing (called from Lock).
// The caller is responsible for zeroing key after this call.
func (a *auditStore) setSigningKey(key []byte) {
	a.inner.SetSigningKey(key)
}

// setEncKey sets the audit field encryption key.
// Pass nil to disable encryption (called from Lock).
func (a *auditStore) setEncKey(key []byte) {
	if len(key) == 0 {
		zero.Bytes(a.encKey)
		a.encKey = nil
		return
	}
	cp := make([]byte, len(key))
	copy(cp, key)
	a.encKey = cp
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
	return a.inner.Append(scheme, namespace, event, a.encKey)
}

func (a *auditStore) loadChain(scheme, namespace string) ([]*BucketEvent, error) {
	return a.inner.LoadChain(scheme, namespace, a.encKey)
}

func (a *auditStore) pruneEvents(scheme, namespace string, olderThan time.Duration, keepLastN int) error {
	return a.inner.Prune(scheme, namespace, olderThan, keepLastN)
}

func (a *auditStore) getLastChecksum(scheme, namespace string) string {
	return a.inner.LastChecksum(scheme, namespace)
}
