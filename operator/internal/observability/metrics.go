package observability

import (
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	maintenanceTransitions = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "kordex_operator_maintenance_transitions_total",
		Help: "Persisted maintenance status transitions, grouped by bounded phase and reason.",
	}, []string{"phase", "reason"})
	maintenanceBlocked = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "kordex_operator_maintenance_blocked_total",
		Help: "Maintenance operations newly blocked by local safety or authorization gates.",
	}, []string{"phase", "reason"})
	maintenancePhaseDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "kordex_operator_maintenance_phase_duration_seconds",
		Help:    "Elapsed time between persisted maintenance phase changes.",
		Buckets: []float64{5, 10, 30, 60, 120, 300, 600, 1800, 3600, 14400},
	}, []string{"from_phase", "to_phase"})
	recoveryBlocked = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "kordex_operator_recovery_blocked_total",
		Help: "Recovery reconciliations blocked by a local safety check.",
	}, []string{"reason"})
	recoveryDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "kordex_operator_recovery_duration_seconds",
		Help:    "Time from entering RecoveryRequired until verified terminal recovery.",
		Buckets: []float64{10, 30, 60, 120, 300, 600, 1800, 3600},
	})
)

func init() {
	ctrlmetrics.Registry.MustRegister(maintenanceTransitions, maintenanceBlocked, maintenancePhaseDuration, recoveryBlocked, recoveryDuration)
}

// RecordMaintenanceTransition records only bounded phase and reason values.
// Tenant, cluster, node, operation, and user identifiers are deliberately absent.
func RecordMaintenanceTransition(phase, reason string) {
	maintenanceTransitions.WithLabelValues(boundedPhase(phase), boundedReason(reason)).Inc()
}

func RecordMaintenanceBlocked(phase, reason string) {
	maintenanceBlocked.WithLabelValues(boundedPhase(phase), boundedReason(reason)).Inc()
}

func ObserveMaintenancePhase(from, to string, seconds float64) {
	if seconds >= 0 {
		maintenancePhaseDuration.WithLabelValues(boundedPhase(from), boundedPhase(to)).Observe(seconds)
	}
}

// RecoveryBlocked records only a bounded reason label. Unknown reasons map to
// other so API values can never create unbounded Prometheus time series.
func RecoveryBlocked(reason string) {
	recoveryBlocked.WithLabelValues(boundedReason(reason)).Inc()
}

func ObserveRecoveryDuration(seconds float64) {
	if seconds >= 0 {
		recoveryDuration.Observe(seconds)
	}
}

func boundedReason(reason string) string {
	known := map[string]struct{}{
		"APIServerHealthUnknown": {}, "AuthorizationExpired": {}, "AuthorizationExpiredBeforeDelivery": {},
		"CancelledByHub": {}, "ClusterConcurrencyLimit": {}, "ClusterDeploymentDegraded": {},
		"ClusterIdentityChanged": {}, "ClusterWorkloadDegraded": {}, "CordonOwnershipChanged": {},
		"EvictionAccepted": {}, "EvictionIntentPersisted": {}, "EvictionPDBBlocked": {},
		"GKEOperationAccepted": {}, "GKEOperationCompleted": {}, "GKEOperationRecovered": {},
		"GKEUpdateIntentPersisted": {}, "GKEUpgradeRunning": {}, "GKESystemWorkloadDegraded": {},
		"GKESystemWorkloadIdentityUnknown": {}, "LocalOrPersistentDataPresent": {},
		"ManagementDisconnected": {}, "NodeCordoned": {}, "NodeHeartbeatStale": {},
		"NodeIdentityChanged": {}, "NodeNotReady": {}, "NoAvailableWorkerPeer": {},
		"OtherNodeCordoned": {}, "PDBBlocked": {}, "PersistentVolumeUsedOnTargetNode": {},
		"PolicyGenerationChanged": {}, "ProviderNodePoolEmpty": {}, "ProviderNodePoolSizeMismatch": {},
		"RecoverySafetyUnknown": {}, "SafetyRestored": {}, "SlotReserved": {},
		"StorageHealthUnknown": {}, "UnexpectedNodeReboot": {}, "UpgradeExecutionAmbiguous": {},
		"WorkloadIdentityChanged": {}, "WorkloadRecoveryPending": {}, "WorkloadRecoveryVerified": {},
	}
	normalized := strings.TrimSpace(reason)
	if _, ok := known[normalized]; ok {
		return normalized
	}
	return "other"
}

func boundedPhase(phase string) string {
	switch strings.TrimSpace(phase) {
	case "Pending", "Validating", "SafetyChecking", "Blocked", "Preflighting", "Cordoning", "Draining", "Executing", "Rebooting", "VerifyingNode", "VerifyingWorkloads", "Uncordoning", "RecoveryRequired", "Succeeded", "Failed", "Cancelled":
		return strings.TrimSpace(phase)
	default:
		return "other"
	}
}
