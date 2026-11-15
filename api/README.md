# Shared API contracts

Go module kordex.local/api contains signed agent and maintenance protocols, the key generator and operations/v1alpha1 CRD types. OpenAPI is openapi/v1.json, pre-release 0.4.0 with 37 operations. CRDs and deep-copy code are generated with controller-gen v0.23.0. Runtime protocol remains v1. The private operations.kordex.local group is a pilot identifier pending public domain/conversion decisions.

The campaign package defines normalization, explicit IANA windows, immutable target planning, retry and failure thresholds. The protocol adds exact-command signed withdrawal and optional campaign provenance. Runtime v1 and CRD v1alpha1 remain stable; deploy matching 0.4 hub/agent/operator binaries before campaign use. See [campaigns](../docs/campaigns.md).
