package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"kordex.local/api/protocol"
)

// UpgradeAdmissionError identifies the evidence that changed between campaign
// approval and command issuance. It is intentionally safe to expose as a
// bounded campaign reason and never contains request payloads or credentials.
type UpgradeAdmissionError struct {
	Reason string
}

func (e *UpgradeAdmissionError) Error() string        { return e.Reason }
func (e *UpgradeAdmissionError) Is(target error) bool { return target == ErrUpgradeAdmission }

func (s *Store) validateUpgradeAdmission(ctx context.Context, tx pgx.Tx, clusterID string, request protocol.MaintenanceRequest, now time.Time) error {
	if request.Action != protocol.UpgradePackages && request.Action != protocol.UpgradeNodePool {
		return nil
	}
	var provider, clusterName string
	var data []byte
	var observedAt *time.Time
	if err := tx.QueryRow(ctx, `SELECT provider,name,maintenance_policy_catalog,maintenance_policy_catalog_observed_at FROM clusters WHERE id=$1`, clusterID).Scan(&provider, &clusterName, &data, &observedAt); err != nil {
		return err
	}
	if len(data) == 0 || observedAt == nil || observedAt.After(now.Add(protocol.ClockSkew)) || now.Sub(*observedAt) > 90*time.Second {
		return upgradeAdmissionFailure("PolicyCatalogStaleAtAdmission")
	}
	var catalog protocol.MaintenancePolicyCatalog
	if err := json.Unmarshal(data, &catalog); err != nil || catalog.Items == nil || catalog.Validate(catalog.ObservedAt) != nil {
		return upgradeAdmissionFailure("PolicyCatalogInvalidAtAdmission")
	}
	if catalog.ObservedAt.IsZero() || catalog.ObservedAt.After(now.Add(protocol.ClockSkew)) || now.Sub(catalog.ObservedAt) > 90*time.Second || absDuration(catalog.ObservedAt.Sub(*observedAt)) > 5*time.Second {
		return upgradeAdmissionFailure("PolicyCatalogStaleAtAdmission")
	}
	if catalog.Capabilities == nil || !catalog.Capabilities.Fresh(now) {
		return upgradeAdmissionFailure("OperatorCapabilitiesStaleAtAdmission")
	}
	if request.Action == protocol.UpgradePackages && !catalog.Capabilities.HostUpgrades || request.Action == protocol.UpgradeNodePool && !catalog.Capabilities.GKENodePoolUpgrade {
		return upgradeAdmissionFailure("UpgradeExecutorUnavailableAtAdmission")
	}

	var selected *protocol.MaintenancePolicyCatalogEntry
	for i := range catalog.Items {
		if catalog.Items[i].Policy.Name == request.Policy.Name {
			if selected != nil {
				return upgradeAdmissionFailure("PolicyCatalogDuplicateAtAdmission")
			}
			selected = &catalog.Items[i]
		}
	}
	if selected == nil || selected.Policy != request.Policy {
		return upgradeAdmissionFailure("UpgradePolicyIdentityChangedAtAdmission")
	}
	if selected.Suspended {
		return upgradeAdmissionFailure("UpgradePolicySuspendedAtAdmission")
	}
	selector, err := metav1.LabelSelectorAsSelector(&selected.NodeSelector)
	if err != nil {
		return upgradeAdmissionFailure("UpgradePolicySelectorInvalidAtAdmission")
	}
	var inventoryData []byte
	if err = tx.QueryRow(ctx, `SELECT inventory FROM nodes WHERE cluster_id=$1 AND uid=$2 AND name=$3`, clusterID, request.NodeUID, request.NodeName).Scan(&inventoryData); err != nil {
		return ErrSnapshotChanged
	}
	var node protocol.Node
	if err = json.Unmarshal(inventoryData, &node); err != nil || node.UID != request.NodeUID || node.Name != request.NodeName || !selector.Matches(labels.Set(node.Labels)) {
		return upgradeAdmissionFailure("UpgradeTargetPolicyMismatchAtAdmission")
	}
	if !node.Ready {
		return upgradeAdmissionFailure("UpgradeTargetNotReadyAtAdmission")
	}

	switch request.Action {
	case protocol.UpgradePackages:
		if selected.Upgrade == nil || selected.UpgradePlanInvalid {
			return upgradeAdmissionFailure("UpgradePlanUnavailableAtAdmission")
		}
		digest, err := selected.Upgrade.Digest()
		if err != nil || digest != selected.UpgradePlanDigest || digest != request.PlanDigest {
			return upgradeAdmissionFailure("UpgradePlanChangedAtAdmission")
		}
		if !selected.Upgrade.MatchesNodeOS(node) {
			return upgradeAdmissionFailure("UpgradePlanOSFamilyMismatchAtAdmission")
		}
	case protocol.UpgradeNodePool:
		if selected.ProviderUpgrade == nil || selected.ProviderPlanInvalid {
			return upgradeAdmissionFailure("ProviderPlanUnavailableAtAdmission")
		}
		digest, err := selected.ProviderUpgrade.Digest()
		if err != nil || digest != selected.ProviderPlanDigest || digest != request.PlanDigest || selected.ProviderUpgrade.Provider != provider || !selected.ProviderUpgrade.MatchesInventory(provider, clusterName, node) {
			return upgradeAdmissionFailure("ProviderPlanChangedAtAdmission")
		}
	}
	return nil
}

func upgradeAdmissionFailure(reason string) error {
	return &UpgradeAdmissionError{Reason: reason}
}

func absDuration(value time.Duration) time.Duration {
	if value < 0 {
		return -value
	}
	return value
}
