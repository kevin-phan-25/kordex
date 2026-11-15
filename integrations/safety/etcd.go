package safety

import "time"

type EtcdMember struct {
	ID      string `json:"id"`
	Healthy bool   `json:"healthy"`
}

type EtcdEvidence struct {
	Members          []EtcdMember  `json:"members"`
	ObservedAt       time.Time     `json:"observedAt"`
	EvidenceValidFor time.Duration `json:"evidenceValidFor"`
}

// EvaluateEtcdEvidence requires an observed majority after taking the target member offline.
func EvaluateEtcdEvidence(e EtcdEvidence, targetID string, now time.Time) Result {
	if e.ObservedAt.IsZero() || e.EvidenceValidFor <= 0 || now.Before(e.ObservedAt) || now.Sub(e.ObservedAt) > e.EvidenceValidFor {
		return Unknown("EtcdEvidenceStaleOrInvalid", now)
	}
	if len(e.Members) < 1 || targetID == "" {
		return Unknown("EtcdMembershipUnknown", e.ObservedAt)
	}
	seen := make(map[string]struct{}, len(e.Members))
	healthy := 0
	targetFound := false
	for _, member := range e.Members {
		if member.ID == "" {
			return Unknown("EtcdMemberIdentityUnknown", e.ObservedAt)
		}
		if _, exists := seen[member.ID]; exists {
			return Unknown("EtcdMembershipContradictory", e.ObservedAt)
		}
		seen[member.ID] = struct{}{}
		if member.ID == targetID {
			targetFound = true
			continue
		}
		if member.Healthy {
			healthy++
		}
	}
	if !targetFound {
		return Unknown("EtcdTargetNotInMembership", e.ObservedAt)
	}
	quorum := len(e.Members)/2 + 1
	if healthy < quorum {
		return Block("EtcdQuorumWouldBeLost", e.ObservedAt)
	}
	return Pass("EtcdMajorityRemainsWithoutTarget", e.ObservedAt, e.EvidenceValidFor)
}
