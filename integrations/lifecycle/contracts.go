// Package lifecycle contains narrow contracts for optional local infrastructure adapters.
package lifecycle

import (
	"context"
	"time"

	"kordex.local/integrations/safety"
)

type Operation struct {
	ID        string
	ClusterID string
	NodeName  string
	NodeUID   string
	Action    string
}

type Evidence struct {
	Provider  string
	Reference string
	ObservedAt time.Time
	ValidFor  time.Duration
	Details   map[string]string
}

type Storage interface {
	Preflight(context.Context, Operation, Evidence) (safety.Result, error)
	EnterMaintenance(context.Context, Operation) (ownershipToken string, err error)
	ObserveRecovery(context.Context, Operation, ownershipToken string) (safety.Result, error)
	ExitMaintenance(context.Context, Operation, ownershipToken string) error
}

type Quorum interface {
	Preflight(context.Context, Operation) (safety.Result, error)
	ObserveRecovery(context.Context, Operation) (safety.Result, error)
}

type NodeLifecycle interface {
	Preflight(context.Context, Operation) (Evidence, safety.Result, error)
	Execute(context.Context, Operation, string) (operationReference string, err error)
	Observe(context.Context, Operation, string) (Evidence, safety.Result, error)
}

type PackagePlan struct {
	Manager      string
	Current      string
	Target       string
	RequiresReboot bool
	Packages     []string
}

type PackageManager interface {
	Plan(context.Context, Operation, []string) (PackagePlan, error)
	Apply(context.Context, Operation, PackagePlan) error
	Verify(context.Context, Operation, PackagePlan) (Evidence, safety.Result, error)
}
