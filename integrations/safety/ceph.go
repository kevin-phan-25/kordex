package safety

import (
	"strings"
	"time"
)

type CephEvidence struct {
	Health             string    `json:"health"`
	OSDExpected        int       `json:"osdExpected"`
	OSDUp              int       `json:"osdUp"`
	OSDIn              int       `json:"osdIn"`
	RecoveryActive     bool      `json:"recoveryActive"`
	BackfillActive     bool      `json:"backfillActive"`
	MaintenanceOwner   string    `json:"maintenanceOwner,omitempty"`
	NooutSet           bool      `json:"nooutSet"`
	NooutOwner         string    `json:"nooutOwner,omitempty"`
	ObservedAt         time.Time `json:"observedAt"`
	EvidenceValidFor   time.Duration `json:"evidenceValidFor"`
}

// EvaluateCephEvidence only evaluates a captured snapshot; it makes no Ceph API calls.
func EvaluateCephEvidence(e CephEvidence, now time.Time) Result {
	if e.ObservedAt.IsZero() || e.EvidenceValidFor <= 0 || now.Before(e.ObservedAt) || now.Sub(e.ObservedAt) > e.EvidenceValidFor {
		return Unknown("CephEvidenceStaleOrInvalid", now)
	}
	if e.OSDExpected < 1 || e.OSDUp < 0 || e.OSDIn < 0 || e.OSDUp > e.OSDExpected || e.OSDIn > e.OSDExpected || e.OSDUp != e.OSDExpected || e.OSDIn != e.OSDExpected {
		return Block("CephOSDAvailabilityUnsafe", e.ObservedAt)
	}
	if e.RecoveryActive || e.BackfillActive {
		return Block("CephRecoveryActive", e.ObservedAt)
	}
	if strings.TrimSpace(e.Health) != "HEALTH_OK" {
		return Block("CephHealthNotOK", e.ObservedAt)
	}
	if e.NooutSet && (e.NooutOwner == "" || e.NooutOwner != e.MaintenanceOwner) {
		return Block("CephNooutOwnedByAnotherOperation", e.ObservedAt)
	}
	if e.MaintenanceOwner == "" && e.NooutSet {
		return Block("CephNooutOwnershipUnknown", e.ObservedAt)
	}
	return Pass("CephHealthAndOSDsHealthy", e.ObservedAt, e.EvidenceValidFor)
}
