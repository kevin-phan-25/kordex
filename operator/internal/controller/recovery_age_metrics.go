package controller

import (
	"context"
	"log/slog"
	"time"

	operations "kordex.local/api/operations/v1alpha1"
	"kordex.local/operator/internal/observability"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const recoveryAgeSnapshotInterval = 15 * time.Second

// RecoveryAgePublisher refreshes aggregate recovery-age metrics from durable
// NodeMaintenance status. It reads only the operator namespace and runs under
// manager leader election, so replica metrics do not publish competing
// snapshots. The API reader avoids presenting a lagging cache as current state.
type RecoveryAgePublisher struct {
	Reader    client.Reader
	Namespace string
	Logger    *slog.Logger
	Now       func() time.Time
}

func (p *RecoveryAgePublisher) NeedLeaderElection() bool { return true }

func (p *RecoveryAgePublisher) Start(ctx context.Context) error {
	defer observability.SetRecoveryAgeSnapshotSuccess(false)
	if err := p.refresh(ctx); err != nil && p.Logger != nil {
		p.Logger.WarnContext(ctx, "refresh active recovery age metrics", "error", err.Error())
	}
	ticker := time.NewTicker(recoveryAgeSnapshotInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := p.refresh(ctx); err != nil && p.Logger != nil {
				p.Logger.WarnContext(ctx, "refresh active recovery age metrics", "error", err.Error())
			}
		}
	}
}

func (p *RecoveryAgePublisher) refresh(ctx context.Context) error {
	var list operations.NodeMaintenanceList
	if err := p.Reader.List(ctx, &list, client.InNamespace(p.Namespace)); err != nil {
		observability.SetRecoveryAgeSnapshotSuccess(false)
		return err
	}
	now := time.Now().UTC()
	if p.Now != nil {
		now = p.Now().UTC()
	}
	active, invalid, oldest := summarizeActiveRecoveryAge(list.Items, now)
	observability.SetActiveRecoveryAgeSnapshot(active, invalid, oldest, float64(now.Unix()))
	return nil
}

func summarizeActiveRecoveryAge(items []operations.NodeMaintenance, now time.Time) (active, invalid int, oldestAgeSeconds float64) {
	for i := range items {
		item := &items[i]
		if item.Status.Phase != "RecoveryRequired" {
			continue
		}
		active++
		started := item.Status.RecoveryStartedAt
		if started == nil || started.IsZero() || started.After(now) {
			invalid++
			continue
		}
		age := now.Sub(started.Time).Seconds()
		if age > oldestAgeSeconds {
			oldestAgeSeconds = age
		}
	}
	return active, invalid, oldestAgeSeconds
}

var _ interface {
	Start(context.Context) error
	NeedLeaderElection() bool
} = (*RecoveryAgePublisher)(nil)
