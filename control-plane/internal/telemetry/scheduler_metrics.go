package telemetry

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"

	"kordex.local/control-plane/internal/store"
)

var schedulerDurationBuckets = []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

type schedulerTick struct {
	count uint64
	sum   float64
	bins  []uint64
}

type SchedulerMetrics struct {
	mu             sync.Mutex
	ticks          map[string]schedulerTick
	operations     uint64
	lastTick       time.Time
	queueAge       float64
	activeReserve  int64
	fleet          store.SchedulerSnapshot
	snapshotAt     time.Time
	blockedReasons map[string]int64
	errors         map[string]uint64
}

func NewSchedulerMetrics() *SchedulerMetrics {
	return &SchedulerMetrics{ticks: make(map[string]schedulerTick), blockedReasons: make(map[string]int64), errors: make(map[string]uint64)}
}

func (m *SchedulerMetrics) RecordError(class string) {
	if _, ok := schedulerErrorClasses[class]; !ok {
		class = "other"
	}
	m.mu.Lock()
	m.errors[class]++
	m.mu.Unlock()
}

func (m *SchedulerMetrics) RecordTick(result string, elapsed time.Duration, admitted int) {
	if result != "claimed" && result != "idle" && result != "error" {
		result = "other"
	}
	seconds := elapsed.Seconds()
	m.mu.Lock()
	value := m.ticks[result]
	if value.bins == nil {
		value.bins = make([]uint64, len(schedulerDurationBuckets))
	}
	value.count++
	value.sum += seconds
	for i, bound := range schedulerDurationBuckets {
		if seconds <= bound {
			value.bins[i]++
		}
	}
	m.ticks[result] = value
	if admitted > 0 {
		m.operations += uint64(admitted)
	}
	m.lastTick = time.Now().UTC()
	m.mu.Unlock()
}

func (m *SchedulerMetrics) SetSnapshot(snapshot store.SchedulerSnapshot) {
	m.mu.Lock()
	m.queueAge = snapshot.QueueAgeSeconds
	m.activeReserve = snapshot.ActiveReservations
	m.fleet = snapshot
	m.snapshotAt = time.Now().UTC()
	m.blockedReasons = make(map[string]int64, len(snapshot.BlockedByReason))
	for reason, count := range snapshot.BlockedByReason {
		m.blockedReasons[reason] = count
	}
	m.mu.Unlock()
}

func (m *SchedulerMetrics) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		m.mu.Lock()
		ticks := make(map[string]schedulerTick, len(m.ticks))
		for key, value := range m.ticks {
			ticks[key] = value
		}
		operations, lastTick, queueAge, reservations := m.operations, m.lastTick, m.queueAge, m.activeReserve
		fleet, snapshotAt := m.fleet, m.snapshotAt
		errorsByClass := make(map[string]uint64, len(m.errors))
		for class, count := range m.errors {
			errorsByClass[class] = count
		}
		blocked := make(map[string]int64, len(m.blockedReasons))
		for key, value := range m.blockedReasons {
			blocked[key] = value
		}
		m.mu.Unlock()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = fmt.Fprintln(w, "# HELP kordex_scheduler_ticks_total Scheduler iterations by outcome.")
		_, _ = fmt.Fprintln(w, "# TYPE kordex_scheduler_ticks_total counter")
		_, _ = fmt.Fprintln(w, "# HELP kordex_scheduler_tick_duration_seconds Scheduler transaction duration in seconds.")
		_, _ = fmt.Fprintln(w, "# TYPE kordex_scheduler_tick_duration_seconds histogram")
		results := make([]string, 0, len(ticks))
		for result := range ticks {
			results = append(results, result)
		}
		sort.Strings(results)
		for _, result := range results {
			value := ticks[result]
			labels := fmt.Sprintf(`result=%q`, result)
			_, _ = fmt.Fprintf(w, "kordex_scheduler_ticks_total{%s} %d\n", labels, value.count)
			for i, bound := range schedulerDurationBuckets {
				_, _ = fmt.Fprintf(w, "kordex_scheduler_tick_duration_seconds_bucket{%s,le=%q} %d\n", labels, strconv.FormatFloat(bound, 'f', -1, 64), value.bins[i])
			}
			_, _ = fmt.Fprintf(w, "kordex_scheduler_tick_duration_seconds_bucket{%s,le=\"+Inf\"} %d\n", labels, value.count)
			_, _ = fmt.Fprintf(w, "kordex_scheduler_tick_duration_seconds_sum{%s} %.9f\n", labels, value.sum)
			_, _ = fmt.Fprintf(w, "kordex_scheduler_tick_duration_seconds_count{%s} %d\n", labels, value.count)
		}
		_, _ = fmt.Fprintln(w, "# HELP kordex_scheduler_operations_admitted_total Operations admitted by the scheduler.")
		_, _ = fmt.Fprintf(w, "# TYPE kordex_scheduler_operations_admitted_total counter\nkordex_scheduler_operations_admitted_total %d\n", operations)
		_, _ = fmt.Fprintln(w, "# HELP kordex_scheduler_errors_total Scheduler failures by bounded error class.")
		_, _ = fmt.Fprintln(w, "# TYPE kordex_scheduler_errors_total counter")
		classes := make([]string, 0, len(errorsByClass))
		for class := range errorsByClass {
			classes = append(classes, class)
		}
		sort.Strings(classes)
		for _, class := range classes {
			_, _ = fmt.Fprintf(w, "kordex_scheduler_errors_total{class=%q} %d\n", class, errorsByClass[class])
		}
		_, _ = fmt.Fprintln(w, "# HELP kordex_scheduler_queue_age_seconds Oldest overdue active organization scheduler tick.")
		_, _ = fmt.Fprintf(w, "# TYPE kordex_scheduler_queue_age_seconds gauge\nkordex_scheduler_queue_age_seconds %.3f\n", queueAge)
		_, _ = fmt.Fprintln(w, "# HELP kordex_scheduler_active_reservations Active operation reservations retained by durable state.")
		_, _ = fmt.Fprintln(w, "# TYPE kordex_scheduler_active_reservations gauge")
		if !snapshotAt.IsZero() {
			_, _ = fmt.Fprintf(w, "kordex_scheduler_active_reservations %d\n", reservations)
		}
		_, _ = fmt.Fprintln(w, "# HELP kordex_scheduler_oldest_reservation_age_seconds Age of the oldest active operation reservation retained by durable state.")
		_, _ = fmt.Fprintln(w, "# TYPE kordex_scheduler_oldest_reservation_age_seconds gauge")
		if !snapshotAt.IsZero() {
			_, _ = fmt.Fprintf(w, "kordex_scheduler_oldest_reservation_age_seconds %.3f\n", fleet.OldestReservationAge)
		}
		_, _ = fmt.Fprintln(w, "# HELP kordex_fleet_clusters_total Clusters present in the durable fleet inventory.")
		_, _ = fmt.Fprintln(w, "# TYPE kordex_fleet_clusters_total gauge")
		_, _ = fmt.Fprintln(w, "# HELP kordex_fleet_clusters_connected Clusters with a recent heartbeat and active agent identity.")
		_, _ = fmt.Fprintln(w, "# TYPE kordex_fleet_clusters_connected gauge")
		_, _ = fmt.Fprintln(w, "# HELP kordex_fleet_nodes_total Nodes present in the durable fleet inventory.")
		_, _ = fmt.Fprintln(w, "# TYPE kordex_fleet_nodes_total gauge")
		_, _ = fmt.Fprintln(w, "# HELP kordex_fleet_nodes_healthy Nodes with fresh inventory and ready=true.")
		_, _ = fmt.Fprintln(w, "# TYPE kordex_fleet_nodes_healthy gauge")
		_, _ = fmt.Fprintln(w, "# HELP kordex_fleet_nodes_unhealthy Nodes with fresh inventory and ready=false.")
		_, _ = fmt.Fprintln(w, "# TYPE kordex_fleet_nodes_unhealthy gauge")
		_, _ = fmt.Fprintln(w, "# HELP kordex_fleet_nodes_unknown Nodes with stale inventory or no valid readiness value.")
		_, _ = fmt.Fprintln(w, "# TYPE kordex_fleet_nodes_unknown gauge")
		_, _ = fmt.Fprintln(w, "# HELP kordex_fleet_oldest_heartbeat_age_seconds Age of the oldest cluster heartbeat, using cluster creation time before a first heartbeat.")
		_, _ = fmt.Fprintln(w, "# TYPE kordex_fleet_oldest_heartbeat_age_seconds gauge")
		_, _ = fmt.Fprintln(w, "# HELP kordex_fleet_oldest_inventory_age_seconds Age of the oldest cluster inventory observation, using cluster creation time before a first observation.")
		_, _ = fmt.Fprintln(w, "# TYPE kordex_fleet_oldest_inventory_age_seconds gauge")
		_, _ = fmt.Fprintln(w, "# HELP kordex_scheduler_snapshot_timestamp_seconds Unix timestamp when durable scheduler and fleet gauges were last refreshed.")
		_, _ = fmt.Fprintln(w, "# TYPE kordex_scheduler_snapshot_timestamp_seconds gauge")
		if !snapshotAt.IsZero() {
			_, _ = fmt.Fprintf(w, "kordex_fleet_clusters_total %d\n", fleet.ClustersTotal)
			_, _ = fmt.Fprintf(w, "kordex_fleet_clusters_connected %d\n", fleet.ClustersConnected)
			_, _ = fmt.Fprintf(w, "kordex_fleet_nodes_total %d\n", fleet.NodesTotal)
			_, _ = fmt.Fprintf(w, "kordex_fleet_nodes_healthy %d\n", fleet.HealthyNodes)
			_, _ = fmt.Fprintf(w, "kordex_fleet_nodes_unhealthy %d\n", fleet.UnhealthyNodes)
			_, _ = fmt.Fprintf(w, "kordex_fleet_nodes_unknown %d\n", fleet.UnknownNodes)
			_, _ = fmt.Fprintf(w, "kordex_fleet_oldest_heartbeat_age_seconds %.3f\n", fleet.OldestHeartbeatAge)
			_, _ = fmt.Fprintf(w, "kordex_fleet_oldest_inventory_age_seconds %.3f\n", fleet.OldestInventoryAge)
			_, _ = fmt.Fprintf(w, "kordex_scheduler_snapshot_timestamp_seconds %.3f\n", float64(snapshotAt.UnixNano())/1e9)
		}
		_, _ = fmt.Fprintln(w, "# HELP kordex_scheduler_blocked_operations Operations currently blocked by bounded reason.")
		_, _ = fmt.Fprintln(w, "# TYPE kordex_scheduler_blocked_operations gauge")
		reasons := make([]string, 0, len(blocked))
		for reason := range blocked {
			reasons = append(reasons, reason)
		}
		sort.Strings(reasons)
		for _, reason := range reasons {
			_, _ = fmt.Fprintf(w, "kordex_scheduler_blocked_operations{reason=%q} %d\n", reason, blocked[reason])
		}
		_, _ = fmt.Fprintln(w, "# HELP kordex_scheduler_last_tick_timestamp_seconds Unix timestamp of the last scheduler iteration.")
		_, _ = fmt.Fprintf(w, "# TYPE kordex_scheduler_last_tick_timestamp_seconds gauge\n")
		if !lastTick.IsZero() {
			_, _ = fmt.Fprintf(w, "kordex_scheduler_last_tick_timestamp_seconds %.3f\n", float64(lastTick.UnixNano())/1e9)
		}
	})
}
