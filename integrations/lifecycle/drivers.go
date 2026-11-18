package lifecycle

import (
	"context"
	model "kordex.local/api/lifecycle"
)

// DriverPlan binds the adapter identity to the same immutable host, signed
// policy and plan identity used by the existing EE workflow. Implementations
// cannot replace one driver with another after Prepare has been persisted.
type DriverPlan struct {
	Operation Operation
	Host      HostIdentity
	Binding   model.Binding
	Policy    UpgradePolicy
}

type PreparedUpgrade struct {
	Plan      DriverPlan
	Evidence  Evidence
	Reference string
}

type ImageUpgradePlan struct {
	Operation    Operation
	Host         HostIdentity
	Binding      model.Binding
	DesiredImage string // Digest-pinned OCI identity, validated by the vendor adapter.
}
type PreparedImageUpgrade struct {
	Plan      ImageUpgradePlan
	Evidence  Evidence
	Reference string
}
type KubernetesUpgradePlan struct {
	Operation      Operation
	Binding        model.Binding
	Distribution   string
	Scope          model.Operation
	CurrentVersion string
	TargetVersion  string
	Resource       string
}
type PreparedKubernetesUpgrade struct {
	Plan      KubernetesUpgradePlan
	Evidence  Evidence
	Reference string
}

// OSUpgradeDriver is a contract, not a new execution authorization. Existing
// APT/DNF execution remains in the fixed Ansible catalogs and local controller.
// Other adapters must supply fixed, tested operations; generic shell commands
// and automatic replay after an ambiguous Execute result are prohibited.
type OSUpgradeDriver interface {
	Descriptor() model.Descriptor
	Detect(context.Context, HostIdentity) (model.Host, error)
	Preflight(context.Context, DriverPlan) (Evidence, error)
	Prepare(context.Context, DriverPlan) (PreparedUpgrade, error)
	Execute(context.Context, PreparedUpgrade) (ExecutionReceipt, error)
	Verify(context.Context, PreparedUpgrade) (Evidence, error)
	RecoveryStatus(context.Context, PreparedUpgrade) (Evidence, error)
}

// ImageOSDriver keeps image staging, activation, boot verification and native
// rollback separate. An adapter must not assume SSH or package-manager access.
// Rollback is unavailable unless explicitly declared and independently verified.
type ImageOSDriver interface {
	Descriptor() model.Descriptor
	Discover(context.Context, HostIdentity) (Evidence, error)
	Stage(context.Context, ImageUpgradePlan) (PreparedImageUpgrade, error)
	Activate(context.Context, PreparedImageUpgrade) (ExecutionReceipt, error)
	VerifyBootedImage(context.Context, PreparedImageUpgrade) (Evidence, error)
	RecoveryStatus(context.Context, PreparedImageUpgrade) (Evidence, error)
}

// KubernetesUpgradeDriver separates managed control planes and node pools from
// host package updates. Supported version transitions require native evidence.
// This contract grants no new provider credentials or execution capabilities.
type KubernetesUpgradeDriver interface {
	Descriptor() model.Descriptor
	Discover(context.Context, Operation) (Evidence, error)
	ValidateUpgrade(context.Context, KubernetesUpgradePlan) (Evidence, error)
	Prepare(context.Context, KubernetesUpgradePlan) (PreparedKubernetesUpgrade, error)
	Execute(context.Context, PreparedKubernetesUpgrade) (ExecutionReceipt, error)
	Observe(context.Context, PreparedKubernetesUpgrade) (Evidence, error)
	Verify(context.Context, PreparedKubernetesUpgrade) (Evidence, error)
}
