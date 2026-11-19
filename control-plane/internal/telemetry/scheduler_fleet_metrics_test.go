package telemetry

import (
	"net/http/httptest"
	"strings"
	"testing"

	"kordex.local/control-plane/internal/store"
)

func TestSchedulerFleetMetricsExposeAggregateSnapshot(t *testing.T) {
	metrics := NewSchedulerMetrics()
	metrics.SetSnapshot(store.SchedulerSnapshot{
		ClustersTotal: 3, ClustersConnected: 2,
		NodesTotal: 7, HealthyNodes: 4, UnhealthyNodes: 1, UnknownNodes: 2,
		OldestHeartbeatAge: 121, OldestInventoryAge: 182,
		ActiveReservations: 2, OldestReservationAge: 91,
	})
	response := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(response, httptest.NewRequest("GET", "/metrics", nil))
	body := response.Body.String()
	for _, want := range []string{
		"\nkordex_fleet_clusters_total 3",
		"\nkordex_fleet_clusters_connected 2",
		"\nkordex_fleet_nodes_total 7",
		"\nkordex_fleet_nodes_healthy 4",
		"\nkordex_fleet_nodes_unhealthy 1",
		"\nkordex_fleet_nodes_unknown 2",
		"\nkordex_fleet_oldest_heartbeat_age_seconds 121.000",
		"\nkordex_fleet_oldest_inventory_age_seconds 182.000",
		"\nkordex_scheduler_active_reservations 2",
		"\nkordex_scheduler_oldest_reservation_age_seconds 91.000",
		"\nkordex_scheduler_snapshot_timestamp_seconds ",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics response missing %q:\n%s", want, body)
		}
	}
	for _, forbidden := range []string{"organization_id=", "cluster_id=", "node_id=", "operation_id="} {
		if strings.Contains(body, forbidden) {
			t.Errorf("high-cardinality label %q leaked into metrics:\n%s", forbidden, body)
		}
	}
}

func TestSchedulerFleetMetricsAreAbsentBeforeFirstSnapshot(t *testing.T) {
	response := httptest.NewRecorder()
	NewSchedulerMetrics().Handler().ServeHTTP(response, httptest.NewRequest("GET", "/metrics", nil))
	body := response.Body.String()
	if strings.Contains(body, "\nkordex_fleet_nodes_healthy ") || strings.Contains(body, "\nkordex_scheduler_snapshot_timestamp_seconds ") || strings.Contains(body, "\nkordex_scheduler_active_reservations ") || strings.Contains(body, "\nkordex_scheduler_oldest_reservation_age_seconds ") {
		t.Fatalf("missing DB snapshot appeared as a zero-valued healthy fleet:\n%s", body)
	}
}
