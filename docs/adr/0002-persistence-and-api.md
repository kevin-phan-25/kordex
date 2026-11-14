# ADR 0002: explicit PostgreSQL migrations and versioned REST

Status: accepted.

Use pgx with parameterized SQL, explicit migrations in an independent job, a transaction advisory lock, immutable checksums and atomic audit writes. Keep one Go module for the implemented service in go.work; add agent/operator modules only when code exists. Contracts live under api/ and are versioned independently of branding.

REST paths use /v1 with OpenAPI 3.0.3. The pre-release contract version is 0.1.0; additive optional fields are compatible, removals/semantic changes need a new major protocol or explicit pre-release migration note. CRDs start v1alpha1 and require conversion/storage-version planning before promotion. Public Go module ownership and Kubernetes API group domain remain unresolved.

Offset pagination is acceptable for initial admin lists, bounded to 500 per page and offset 100000. Future node inventory needs stable cursor pagination. No command protocol or operational tables are invented in Phase 1.
