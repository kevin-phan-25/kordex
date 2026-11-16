// Package v1alpha1 defines local maintenance reconciliation contracts.
// +kubebuilder:object:generate=true
// +groupName=operations.kordex.local
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"kordex.local/api/protocol"
)

var GroupVersion = schema.GroupVersion{Group: protocol.OperationGroup, Version: protocol.OperationVersion}
var SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)
var AddToScheme = SchemeBuilder.AddToScheme

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=nm
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.reason`
type NodeMaintenance struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              NodeMaintenanceSpec   `json:"spec"`
	Status            NodeMaintenanceStatus `json:"status,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="operation authorization is immutable"
type NodeMaintenanceSpec struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=8192
	Authorization string `json:"authorization"`
	// +kubebuilder:validation:MinLength=86
	// +kubebuilder:validation:MaxLength=86
	Signature string `json:"signature"`
}

func (s NodeMaintenanceSpec) Command() protocol.MaintenanceCommand {
	return protocol.MaintenanceCommand{Authorization: s.Authorization, Signature: s.Signature}
}

type WorkloadReference struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	UID       string `json:"uid"`
	Replicas  int32  `json:"replicas"`
}
type EvictionRecord struct {
	Namespace string            `json:"namespace"`
	Name      string            `json:"name"`
	UID       string            `json:"uid"`
	Workload  WorkloadReference `json:"workload"`
}
type NodeMaintenanceStatus struct {
	ObservedGeneration    int64        `json:"observedGeneration,omitempty"`
	OperationID           string       `json:"operationId,omitempty"`
	TargetNodeName        string       `json:"targetNodeName,omitempty"`
	TargetNodeUID         string       `json:"targetNodeUid,omitempty"`
	Phase                 string       `json:"phase,omitempty"`
	Reason                string       `json:"reason,omitempty"`
	Sequence              int64        `json:"sequence,omitempty"`
	ResumePhase           string       `json:"resumePhase,omitempty"`
	FailureReason         string       `json:"failureReason,omitempty"`
	Outcome               string       `json:"outcome,omitempty"`
	OriginalUnschedulable *bool        `json:"originalUnschedulable,omitempty"`
	OriginalBootID        string       `json:"originalBootId,omitempty"`
	RecoverySeconds       int32        `json:"recoverySeconds,omitempty"`
	RecoveryStartedAt     *metav1.Time `json:"recoveryStartedAt,omitempty"`
	// +kubebuilder:validation:MaxItems=128
	Evictions []EvictionRecord `json:"evictions,omitempty"`
	// +kubebuilder:validation:MaxItems=256
	Events     []protocol.PhaseEvent `json:"events,omitempty"`
	Conditions []metav1.Condition    `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
type NodeMaintenanceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NodeMaintenance `json:"items"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
type MaintenancePolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              MaintenancePolicySpec `json:"spec"`
	Status            PolicyStatus          `json:"status,omitempty"`
}
type MaintenancePolicySpec struct {
	NodeSelector metav1.LabelSelector `json:"nodeSelector"`
	Suspended    bool                 `json:"suspended,omitempty"`
	// AllowGKESystemWorkloads enables the narrowly scoped GKE add-on evidence
	// evaluator. It is false by default; ordinary workloads still require PDBs.
	AllowGKESystemWorkloads bool `json:"allowGKESystemWorkloads,omitempty"`
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=10
	// +kubebuilder:default=1
	GKESystemWorkloadMinAvailable int32 `json:"gkeSystemWorkloadMinAvailable,omitempty"`
	// +kubebuilder:validation:Minimum=10
	// +kubebuilder:validation:Maximum=300
	// +kubebuilder:default=10
	RecoverySeconds int32 `json:"recoverySeconds,omitempty"`
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=120
	// +kubebuilder:default=30
	GracePeriodSeconds int64 `json:"gracePeriodSeconds,omitempty"`
}
type PolicyStatus struct {
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
type MaintenancePolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []MaintenancePolicy `json:"items"`
}

// MaintenanceCampaign is reserved local intent; fleet scheduling is not implemented.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
type MaintenanceCampaign struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              MaintenanceCampaignSpec `json:"spec"`
	Status            PolicyStatus            `json:"status,omitempty"`
}
type MaintenanceCampaignSpec struct {
	PolicyName string               `json:"policyName"`
	Selector   metav1.LabelSelector `json:"selector"`
}

// +kubebuilder:object:root=true
type MaintenanceCampaignList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []MaintenanceCampaign `json:"items"`
}

func addKnownTypes(s *runtime.Scheme) error {
	s.AddKnownTypes(GroupVersion, &NodeMaintenance{}, &NodeMaintenanceList{}, &MaintenancePolicy{}, &MaintenancePolicyList{}, &MaintenanceCampaign{}, &MaintenanceCampaignList{})
	metav1.AddToGroupVersion(s, GroupVersion)
	return nil
}
