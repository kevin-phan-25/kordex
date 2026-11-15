# Prometheus and Grafana examples

Enable the control-plane chart's private metrics Service (`metrics.enabled=true`) and configure its namespace selector to permit only the trusted monitoring namespace. The metrics listener is HTTP and has no application authentication; network policy, namespace RBAC, and private cluster networking are its security boundary. Never route it through public ingress. CNI NetworkPolicy behavior must be validated in your cluster.

The Service has Prometheus scrape annotations. Configure your Prometheus installation to discover annotated Services in the Kordex namespace, or use your Prometheus Operator's `ServiceMonitor` with namespace and release labels appropriate to your cluster. Apply `prometheus/kordex-alerts.yaml` only after matching its `release` label and reviewing the initial thresholds against observed traffic.

Import `grafana/kordex-overview.json` to view request rate, 5xx rate, and p99 request latency. These are API-level starting points, not an SLO. Scheduler queue age, blocked-operation reasons, reservation retention, campaign stage progress, and node recovery duration are not exposed as metrics yet. Use the dashboard and audit events for those signals until dedicated bounded-cardinality metrics are designed.

Both the dashboard and alert thresholds require validation with the installed Prometheus/Grafana versions, scrape interval, traffic volume, and organizational SLOs. No monitoring stack is installed by the Kordex Helm charts.
