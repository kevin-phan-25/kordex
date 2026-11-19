package observability

import (
	"encoding/json"
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
	maintenanceOutcomes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "kordex_operator_maintenance_operations_total",
		Help: "Terminal maintenance operation outcomes recorded on durable phase transitions.",
	}, []string{"action", "outcome"})
	maintenanceRecoveryRequired = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "kordex_operator_maintenance_recovery_required_total",
		Help: "Maintenance operations that entered RecoveryRequired, by bounded action.",
	}, []string{"action"})
	maintenanceOperationDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "kordex_operator_maintenance_operation_duration_seconds",
		Help:    "Elapsed time from the first durable operation event to a terminal phase.",
		Buckets: []float64{10, 30, 60, 120, 300, 600, 1800, 3600, 14400, 28800},
	}, []string{"action", "outcome"})
	maintenanceDrainDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "kordex_operator_maintenance_drain_duration_seconds",
		Help:    "Time spent in the Draining phase before a verified drain completes.",
		Buckets: []float64{1, 5, 10, 30, 60, 120, 300, 600, 1800},
	}, []string{"action"})
	maintenanceRebootDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "kordex_operator_maintenance_reboot_duration_seconds",
		Help:    "Time from the Rebooting phase until verified host reboot evidence is received.",
		Buckets: []float64{10, 30, 60, 120, 300, 600, 1800, 3600},
	}, []string{"action"})
	recoveryBlocked = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "kordex_operator_recovery_blocked_total",
		Help: "Recovery reconciliations blocked by a local safety check.",
	}, []string{"reason"})
	recoveryDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "kordex_operator_recovery_duration_seconds",
		Help:    "Time from entering RecoveryRequired until verified terminal recovery.",
		Buckets: []float64{10, 30, 60, 120, 300, 600, 1800, 3600},
	})
	activeRecoveryOperations = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kordex_operator_active_recovery_operations",
		Help: "Current count of NodeMaintenance operations in RecoveryRequired.",
	})
	oldestActiveRecoveryAge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kordex_operator_oldest_active_recovery_age_seconds",
		Help: "Age of the oldest active RecoveryRequired operation with a valid durable start time.",
	})
	recoveryAgeSnapshotSuccess = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kordex_operator_recovery_age_snapshot_success",
		Help: "Whether the most recent active recovery age snapshot was read successfully from the Kubernetes API.",
	})
	recoveryAgeSnapshotComplete = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kordex_operator_recovery_age_snapshot_complete",
		Help: "Whether every active RecoveryRequired operation had a valid durable start time in the latest snapshot.",
	})
	recoveryAgeSnapshotInvalidOperations = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kordex_operator_recovery_age_snapshot_invalid_operations",
		Help: "Active RecoveryRequired operations with a missing or future durable start time in the latest successful snapshot.",
	})
	recoveryAgeSnapshotTimestamp = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kordex_operator_recovery_age_snapshot_timestamp_seconds",
		Help: "Unix timestamp of the most recent successful active recovery age snapshot.",
	})
)

func init() {
	ctrlmetrics.Registry.MustRegister(maintenanceTransitions, maintenanceBlocked, maintenancePhaseDuration, maintenanceOutcomes, maintenanceRecoveryRequired, maintenanceOperationDuration, maintenanceDrainDuration, maintenanceRebootDuration, recoveryBlocked, recoveryDuration, activeRecoveryOperations, oldestActiveRecoveryAge, recoveryAgeSnapshotSuccess, recoveryAgeSnapshotComplete, recoveryAgeSnapshotInvalidOperations, recoveryAgeSnapshotTimestamp)
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

// ActionFromAuthorization extracts only the fixed action enum from the immutable
// signed authorization. Malformed or future values collapse to "other".
func ActionFromAuthorization(authorization string) string {
	var payload struct {
		Action string `json:"action"`
	}
	if json.Unmarshal([]byte(authorization), &payload) != nil {
		return "other"
	}
	return boundedAction(payload.Action)
}

// RecordMaintenanceOutcome records a bounded terminal outcome and its
// end-to-end duration.
func RecordMaintenanceOutcome(action, outcome string, seconds float64) {
	action, outcome = boundedAction(action), boundedOutcome(outcome)
	maintenanceOutcomes.WithLabelValues(action, outcome).Inc()
	if seconds >= 0 {
		maintenanceOperationDuration.WithLabelValues(action, outcome).Observe(seconds)
	}
}

func RecordMaintenanceRecoveryRequired(action string) {
	maintenanceRecoveryRequired.WithLabelValues(boundedAction(action)).Inc()
}

func ObserveMaintenanceDrain(action string, seconds float64) {
	if seconds >= 0 {
		maintenanceDrainDuration.WithLabelValues(boundedAction(action)).Observe(seconds)
	}
}

func ObserveMaintenanceReboot(action string, seconds float64) {
	if seconds >= 0 {
		maintenanceRebootDuration.WithLabelValues(boundedAction(action)).Observe(seconds)
	}
}

func boundedAction(action string) string {
	switch strings.TrimSpace(action) {
	case "ValidateOnly", "DrainAndVerify", "UpgradePackages", "UpgradeNodePool":
		return strings.TrimSpace(action)
	default:
		return "other"
	}
}

func boundedOutcome(outcome string) string {
	switch strings.TrimSpace(outcome) {
	case "Succeeded", "Failed", "Cancelled":
		return strings.TrimSpace(outcome)
	default:
		return "other"
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

// SetActiveRecoveryAgeSnapshot publishes an aggregate Kubernetes API snapshot.
// No operation, node, cluster, organization, or user identifier is exposed.
// On read failure callers update only success via SetRecoveryAgeSnapshotSuccess
// and retain the last known values and timestamp for staleness detection.
func SetActiveRecoveryAgeSnapshot(active, invalid int, oldestAgeSeconds, observedAtUnix float64) {
	activeRecoveryOperations.Set(float64(active))
	oldestActiveRecoveryAge.Set(oldestAgeSeconds)
	recoveryAgeSnapshotInvalidOperations.Set(float64(invalid))
	recoveryAgeSnapshotSuccess.Set(1)
	if invalid == 0 {
		recoveryAgeSnapshotComplete.Set(1)
	} else {
		recoveryAgeSnapshotComplete.Set(0)
	}
	recoveryAgeSnapshotTimestamp.Set(observedAtUnix)
}

func SetRecoveryAgeSnapshotSuccess(success bool) {
	if success {
		recoveryAgeSnapshotSuccess.Set(1)
		return
	}
	recoveryAgeSnapshotSuccess.Set(0)
	recoveryAgeSnapshotComplete.Set(0)
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
