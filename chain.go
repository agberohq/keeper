package keeper

import (
	"errors"
	"fmt"
	"time"

	pkgaudit "github.com/agberohq/keeper/pkg/audit"
)

// Chain manages immutable policy storage and append-only audit events.
type Chain struct {
	store *Keeper
}

// NewPolicyChainManager creates a new chain manager.
func NewPolicyChainManager(store *Keeper) *Chain {
	return &Chain{store: store}
}

// CreatePolicy registers a new immutable bucket policy.
func (m *Chain) CreatePolicy(policy *BucketSecurityPolicy) error {
	if err := policy.Validate(); err != nil {
		return err
	}
	existing, err := m.GetPolicy(policy.Scheme, policy.Namespace)
	if err == nil && existing != nil {
		return ErrPolicyImmutable
	}
	if err := m.store.savePolicy(policy); err != nil {
		return fmt.Errorf("failed to save policy: %w", err)
	}

	event := &BucketEvent{
		ID:           generateUUID(),
		BucketID:     policy.ID,
		Scheme:       policy.Scheme,
		Namespace:    policy.Namespace,
		EventType:    "created",
		Details:      mustJSON(policy),
		Timestamp:    time.Now(),
		PrevChecksum: m.getLastChecksum(policy.Scheme, policy.Namespace),
	}
	event.Checksum = event.ComputeChecksum(event.PrevChecksum)
	if err := m.store.appendAuditEvent(event); err != nil {
		return fmt.Errorf("failed to append policy event: %w", err)
	}
	return nil
}

// GetPolicy retrieves a bucket policy (read-only).
func (m *Chain) GetPolicy(scheme, namespace string) (*BucketSecurityPolicy, error) {
	return m.store.loadPolicy(scheme, namespace)
}

// AppendEvent adds a new audit event to the bucket's chain.
func (m *Chain) AppendEvent(scheme, namespace, eventType string, details interface{}) error {
	policy, err := m.GetPolicy(scheme, namespace)
	if err != nil {
		return err
	}
	event := &BucketEvent{
		ID:           generateUUID(),
		BucketID:     policy.ID,
		Scheme:       scheme,
		Namespace:    namespace,
		EventType:    eventType,
		Details:      mustJSON(details),
		Timestamp:    time.Now(),
		PrevChecksum: m.getLastChecksum(scheme, namespace),
	}
	event.Checksum = event.ComputeChecksum(event.PrevChecksum)
	return m.store.appendAuditEvent(event)
}

// VerifyChainIntegrity checks the entire audit chain for a bucket.
func (m *Chain) VerifyChainIntegrity(scheme, namespace string) error {
	err := m.store.auditStore.inner.VerifyIntegrity(scheme, namespace)
	if err != nil && errors.Is(err, pkgaudit.ErrChainBroken) {
		return fmt.Errorf("%w: %s", ErrChainBroken, err.Error())
	}
	return err
}

// PruneEvents removes old events; never prunes high-security buckets.
func (m *Chain) PruneEvents(scheme, namespace string, olderThan time.Duration, keepLastN int) error {
	policy, err := m.GetPolicy(scheme, namespace)
	if err != nil {
		return err
	}
	if policy.Level == LevelHSM {
		return nil
	}
	return m.store.pruneAuditEvents(scheme, namespace, olderThan, keepLastN)
}

func (m *Chain) getLastChecksum(scheme, namespace string) string {
	return m.store.getLastChecksum(scheme, namespace)
}
