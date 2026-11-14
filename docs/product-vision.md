# Product vision

Kordex coordinates enterprise infrastructure maintenance across self-managed Kubernetes, GKE, EKS, AKS, bare metal, and VMs. It provides inventory, health, policy, approvals, campaigns, and auditable node lifecycle operations across organizations, fleets, sites, and clusters.

The design target is hundreds of clusters and 4,000+ nodes. That is a planning target, not a tested capacity claim. First release scope favors a small number of safe, observable workflows. Generic Kubernetes resource federation, multi-cluster workload placement, and service mesh features are excluded.

Operators must be able to answer: what is unhealthy, what can safely change, who approved it, what is happening now, and how can work be stopped or recovered? Central coordination never overrides local safety. A stale authorization or unknown safety signal stops new disruptive work.

Future dashboard pages include overview counts, fleet/site/cluster inventory, OS and Kubernetes versions, connectivity, campaign creation and scheduling, current phases, blocks, approvals, failures, and audit history. Use a consistent responsive enterprise design with explicit health and freshness indicators. Never represent stale inventory as current health.

Branding is presentation configuration. API compatibility and identity must survive renaming.
