# Shared API contracts

Go module kordex.local/api contains signed agent and maintenance protocols, campaign contracts, the key generator and operations/v1alpha1 CRD types. OpenAPI is openapi/v1.json, pre-release 0.7.0 with 48 operations. CRDs and deep-copy code are generated with controller-gen v0.23.0. Runtime protocol remains v1. The private operations.kordex.local group is a pilot identifier pending public domain/conversion decisions.

The campaign package defines normalization, explicit IANA windows, immutable target planning, retry and failure thresholds. The protocol adds exact-command signed withdrawal and optional campaign provenance. Runtime v1 and CRD v1alpha1 remain stable; deploy matching 0.4 hub/agent/operator binaries before campaign use. See [campaigns](../docs/campaigns.md).


Version 0.5 adds organization-scoped dashboard summary and inventory reads, including node health/freshness and audit listing. The dashboard uses these APIs through a server-only proxy; browser clients never receive management API bearer tokens. See [dashboard configuration](../dashboard/README.md).

The agent can optionally report the local `MaintenancePolicy` catalog when `KORDEX_ENABLE_MAINTENANCE=true`; organization members can read its last observation and freshness through the cluster policy catalog endpoint. Upgrade campaign planning binds the local policy UID, generation, selector, and plan digest from a fresh catalog. Operation reports can carry validated durable upgrade checkpoints into the hub and dashboard history. These are contract and visibility foundations only: upgrade actions remain rejected by the operator until the executor lifecycle is wired and qualified.
