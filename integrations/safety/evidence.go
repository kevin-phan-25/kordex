// Package safety defines provider-neutral, fail-closed infrastructure evidence.
package safety

import "time"

type Decision string

const (
	DecisionPass    Decision = "Pass"
	DecisionBlock   Decision = "Block"
	DecisionUnknown Decision = "Unknown"
)

// Result is suitable for reporting, but it does not grant operation authority.
type Result struct {
	Decision  Decision  `json:"decision"`
	Reason    string    `json:"reason"`
	CheckedAt time.Time `json:"checkedAt"`
	ValidFor  time.Duration `json:"validFor"`
}

func Pass(reason string, checkedAt time.Time, validFor time.Duration) Result {
	return Result{Decision: DecisionPass, Reason: reason, CheckedAt: checkedAt.UTC(), ValidFor: validFor}
}

func Block(reason string, checkedAt time.Time) Result {
	return Result{Decision: DecisionBlock, Reason: reason, CheckedAt: checkedAt.UTC()}
}

func Unknown(reason string, checkedAt time.Time) Result {
	return Result{Decision: DecisionUnknown, Reason: reason, CheckedAt: checkedAt.UTC()}
}

func (r Result) Fresh(now time.Time) bool {
	return r.CheckedAt.IsZero() == false && r.ValidFor > 0 && !now.Before(r.CheckedAt) && now.Sub(r.CheckedAt) <= r.ValidFor
}
