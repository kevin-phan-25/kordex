package controller

import (
	"context"
	"log/slog"
	"strconv"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/typed/coordination/v1"

	"kordex.local/api/protocol"
)

const OperatorCapabilitiesLease = "kordex-operator-capabilities"

// CapabilityPublisher exposes short-lived local executor configuration to the
// outbound agent. Hub admission uses it to avoid offering commands that the
// local operator will certainly reject. The operator still rechecks locally.
type CapabilityPublisher struct {
	Leases             v1.LeaseInterface
	NodeMaintenance    bool
	HostUpgrades       bool
	GKENodePoolUpgrade bool
	Logger             *slog.Logger
}

func (p *CapabilityPublisher) NeedLeaderElection() bool { return true }

func (p *CapabilityPublisher) Start(ctx context.Context) error {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		if err := p.publish(ctx); err != nil && p.Logger != nil {
			p.Logger.WarnContext(ctx, "publish operator capabilities", "error", err.Error())
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (p *CapabilityPublisher) publish(ctx context.Context) error {
	lease, err := p.Leases.Get(ctx, OperatorCapabilitiesLease, metav1.GetOptions{})
	if err != nil {
		return err // installation owns creation; the operator has update-only RBAC.
	}
	if lease.Annotations == nil {
		lease.Annotations = map[string]string{}
	}
	lease.Annotations["operations.kordex.local/node-maintenance"] = strconv.FormatBool(p.NodeMaintenance)
	lease.Annotations["operations.kordex.local/host-upgrades"] = strconv.FormatBool(p.HostUpgrades)
	lease.Annotations["operations.kordex.local/gke-node-pool-upgrade"] = strconv.FormatBool(p.GKENodePoolUpgrade)
	duration := int32(protocol.OperatorCapabilityLifetime / time.Second)
	now := metav1.NewMicroTime(time.Now().UTC())
	lease.Spec.HolderIdentity = stringPointer("kordex-operator")
	lease.Spec.LeaseDurationSeconds = &duration
	lease.Spec.RenewTime = &now
	_, err = p.Leases.Update(ctx, lease, metav1.UpdateOptions{})
	return err
}

func stringPointer(value string) *string { return &value }

var _ interface{ Start(context.Context) error } = (*CapabilityPublisher)(nil)
