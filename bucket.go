package keeper

import (
	"fmt"
	"time"

	pkgaudit "github.com/agberohq/keeper/pkg/audit"
	"github.com/olekukonko/errors"
)

// BucketEvent is an audit event (alias of pkg/audit.Event).
type BucketEvent = pkgaudit.Event

// BucketSecurityPolicy is immutable after creation.
type BucketSecurityPolicy struct {
	ID                string        `json:"id"`
	Scheme            string        `json:"scheme"`
	Namespace         string        `json:"namespace"`
	Level             SecurityLevel `json:"level"`
	CreatedAt         time.Time     `json:"created_at"`
	CreatedBy         string        `json:"created_by"`
	EncryptionVersion int           `json:"encryption_version"`

	// LastRekeyed records when RotateAdminWrappedDEK last succeeded.
	// A zero value means the bucket predates this field and should be treated
	// as needing re-keying when NeedsAdminRekey is called after a salt rotation.
	LastRekeyed time.Time `json:"last_rekeyed,omitempty"`

	// LevelAdminWrapped only:
	DEKSalt     []byte            `json:"dek_salt,omitempty"`
	WrappedDEKs map[string][]byte `json:"wrapped_deks,omitempty"`

	// HSMProvider is required for LevelHSM and LevelRemote buckets.
	// It is excluded from JSON serialisation — callers must register it via
	// Keeper.RegisterHSMProvider after opening the database.
	HSMProvider HSMProvider `json:"-"`

	// Handler provides optional pre/post-processing hooks for this bucket.
	Handler SchemeHandler `json:"-"`
}

// Validate checks policy constraints before creation.
func (p *BucketSecurityPolicy) Validate() error {
	if p.ID == "" {
		return errors.New("policy ID required")
	}
	if p.Scheme == "" {
		return errors.New("scheme required")
	}
	if p.Namespace == "" {
		return errors.New("namespace required")
	}
	if !isValidScheme(p.Scheme) {
		return ErrSchemeInvalid
	}
	if !isValidNamespace(p.Namespace) {
		return ErrNamespaceInvalid
	}
	switch p.Level {
	case LevelPasswordOnly, LevelAdminWrapped, LevelHSM, LevelRemote:
		// valid
	default:
		return fmt.Errorf("invalid security level: %q", p.Level)
	}
	if p.Level == LevelAdminWrapped {
		if len(p.DEKSalt) == 0 {
			return errors.New("LevelAdminWrapped requires a DEKSalt")
		}
	}
	if p.Level == LevelHSM || p.Level == LevelRemote {
		if p.HSMProvider == nil {
			return ErrHSMProviderNil
		}
	}
	return nil
}

// HasAdmin reports whether adminID has a wrapped DEK copy in this policy.
func (p *BucketSecurityPolicy) HasAdmin(adminID string) bool {
	_, ok := p.WrappedDEKs[adminID]
	return ok
}
