package keeper

import (
	"context"
	"time"

	jack "github.com/olekukonko/jack"
)

// newHealthPatient creates a jack.Patient suitable for keeper health monitoring.
// The patient uses a 30-second check interval, 5-second accelerated interval on
// degradation, a 5-second per-check timeout, and escalates to Failed after 3
// consecutive failures.
func newHealthPatient(id string, check func(ctx context.Context) error) *jack.Patient {
	const (
		checkInterval = 30 * time.Second
		accelerated   = 5 * time.Second
		checkTimeout  = 5 * time.Second
		maxFailures   = 3
	)
	return jack.NewPatient(jack.PatientConfig{
		ID:          id,
		Interval:    checkInterval,
		Accelerated: accelerated,
		Timeout:     checkTimeout,
		MaxFailures: maxFailures,
		Check:       check,
	})
}
