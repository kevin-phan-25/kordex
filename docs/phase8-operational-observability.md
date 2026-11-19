# Phase 8 — operational observability (initial implementation)

The numbered MVP roadmap ends at Phase 7. Phase 8 is a follow-on qualification milestone, beginning with scheduler and local recovery signals needed to diagnose real operations.

## Signals

The scheduler metrics endpoint reports bounded outcome counters, tick duration, operations admitted, age of the oldest overdue active organization scheduler tick, active durable reservations, blocked operations by normalized reason, and the last scheduler tick timestamp. Queue/reservation/block snapshots refresh every 15 seconds from PostgreSQL. They are aggregate values and intentionally omit tenant, cluster, node, operation and user identifiers.

The operator reports recovery safety blocks by a fixed allowlist of reason values and completed recovery duration from the first `RecoveryRequired` event to the terminal transition. It also publishes the aggregate count and oldest age of active `RecoveryRequired` operations from a 15-second leader-elected Kubernetes API snapshot. Snapshot success, freshness, and completeness are separate metrics; a failed read preserves the last known values and timestamp while marking the snapshot unsuccessful, leader loss marks that replica's snapshot inactive, and missing/future recovery start times mark it incomplete. The example dashboard filters out inactive replicas. No resource identifiers are metric labels. Unknown reasons map to `other`. Block counters increment only when the recorded blocker changes, avoiding a counter increase on every two-second reconciliation.

The control-plane API and scheduler, plus the operator's maintenance
reconciler, emit sampled OpenTelemetry spans. Attributes are bounded to route
templates, fixed operation phases/actions/outcomes, normalized error classes,
and aggregate counts; request payloads, raw URLs, operation/node identifiers,
and raw errors are excluded. Agent calls use an allowlisted route set and
propagate W3C trace context to the API. OTLP/HTTP is opt-in and disabled by
default in Helm and Kustomize.

## Deployment

Metrics are disabled by default and bind to loopback. Set `metrics.enabled=true` in the self-hosted control-plane and operator Helm releases to create private ClusterIP scrape Services and NetworkPolicies. Configure `metrics.namespaceSelector` to match only the monitoring namespace. NetworkPolicy enforcement depends on the installed CNI; do not expose metrics through public ingress.

Import `deployments/monitoring/grafana/kordex-operations.json` and review `deployments/monitoring/prometheus/kordex-operations-alerts.yaml`. The alert thresholds are starting points, not SLOs. Tune them from pilot evidence.

## Limits and next work

The scheduler metrics are process-local counters and reset on restart; PostgreSQL-derived gauges repopulate on the next snapshot. Operator counters and histograms reset when its leader process restarts. The operator metrics are per cluster; attach cluster identity as a Prometheus target label in scrape configuration if fleet comparison is needed. No metric label contains that identity. Trace continuity from agent through API is implemented but has not been exercised with a collector; operator reconciliation is not correlated to the originating hub trace. Collector TLS/egress, export delivery under failure, and retention have not been qualified.

This does not replace audit history or the dashboard. It does not yet expose campaign-stage progress or storage evidence. Establish operational SLOs, exercise metrics across scheduler failover and operator restart, validate the scrape policies on the selected CNI, then extend signals only where pilot operations show a need.
