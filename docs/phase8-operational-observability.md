# Phase 8 — operational observability (initial implementation)

The numbered MVP roadmap ends at Phase 7. Phase 8 is a follow-on qualification milestone, beginning with scheduler and local recovery signals needed to diagnose real operations.

## Signals

The scheduler metrics endpoint reports bounded outcome counters, tick duration, operations admitted, age of the oldest overdue active organization scheduler tick, active durable reservations, blocked operations by normalized reason, and the last scheduler tick timestamp. Queue/reservation/block snapshots refresh every 15 seconds from PostgreSQL. They are aggregate values and intentionally omit tenant, cluster, node, operation and user identifiers.

The operator reports recovery safety blocks by a fixed allowlist of reason values and completed recovery duration from the first `RecoveryRequired` event to the terminal transition. Unknown reasons map to `other`. Block counters increment only when the recorded blocker changes, avoiding a counter increase on every two-second reconciliation.

## Deployment

Metrics are disabled by default and bind to loopback. Set `metrics.enabled=true` in the self-hosted control-plane and operator Helm releases to create private ClusterIP scrape Services and NetworkPolicies. Configure `metrics.namespaceSelector` to match only the monitoring namespace. NetworkPolicy enforcement depends on the installed CNI; do not expose metrics through public ingress.

Import `deployments/monitoring/grafana/kordex-operations.json` and review `deployments/monitoring/prometheus/kordex-operations-alerts.yaml`. The alert thresholds are starting points, not SLOs. Tune them from pilot evidence.

## Limits and next work

The scheduler metrics are process-local counters and reset on restart; PostgreSQL-derived gauges repopulate on the next snapshot. Operator counters and histograms reset when its leader process restarts. The operator metrics are per cluster; attach cluster identity as a Prometheus target label in scrape configuration if fleet comparison is needed. No metric label contains that identity.

This does not replace audit history or the dashboard. It does not yet expose campaign-stage progress, storage evidence, or active recovery age as a live gauge. Establish operational SLOs, exercise metrics across scheduler failover and operator restart, validate the scrape policies on the selected CNI, then extend signals only where pilot operations show a need.
