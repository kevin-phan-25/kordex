package observability

import (
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
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
	ctrlmetrics.Registry.MustRegister(recoveryBlocked, recoveryDuration)
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
		"ClusterDeploymentDegraded": {}, "ClusterWorkloadDegraded": {},
		"CordonOwnershipChanged": {}, "GKESystemWorkloadDegraded": {},
		"GKESystemWorkloadIdentityUnknown": {}, "LocalOrPersistentDataPresent": {},
		"NodeIdentityChanged": {}, "NoAvailableWorkerPeer": {},
		"OtherNodeCordoned": {}, "PersistentStorageAdapterRequired": {},
		"RecoverySafetyUnknown": {}, "StorageHealthUnknown": {},
		"UnexpectedNodeReboot": {}, "WorkloadIdentityChanged": {},
		"WorkloadRecoveryPending": {},
	}
	if _, ok := known[strings.TrimSpace(reason)]; ok {
		return reason
	}
	return "other"
}
