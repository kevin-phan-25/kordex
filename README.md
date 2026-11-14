# Kordex

Enterprise infrastructure lifecycle and fleet orchestration, built around safe local execution and centralized coordination. The product name is configurable with `KORDEX_PRODUCT_NAME`; internal protocol and module identifiers remain stable across branding changes.

**Status: Phase 1 foundation. Not ready for production deployment or maintenance execution.** The implemented service persists organizations, sites, and transactional audit records in PostgreSQL. Agents, operators, campaigns, and the dashboard have design boundaries only; their directories contain explicit scope notes.

## Local quick start

Requirements: GNU Make, Go 1.26.0 or later (CI pins 1.26.11), Docker with Compose v2, Python 3 for the contract check. Podman can also run the standalone PostgreSQL tests.

```sh
cp deployments/local/.env.example deployments/local/.env
# Generate distinct secrets and insert them into .env:
openssl rand -hex 32
openssl rand -hex 32
docker compose --env-file deployments/local/.env -f deployments/local/compose.yaml up --build -d
```

Set `KORDEX_ADMIN_TOKEN` and `POSTGRES_PASSWORD` in that ignored file before starting. The migration service must finish before the API starts. The API is bound to host loopback on port 8080; PostgreSQL to host loopback on 5432. The explicit local-development setting allows HTTP and database TLS disablement only within the isolated Compose development network. Never expose this bootstrap API publicly.

```sh
curl http://127.0.0.1:8080/healthz
curl http://127.0.0.1:8080/readyz
# Set KORDEX_ADMIN_TOKEN in your shell from the same secret source first.
curl -H "Authorization: Bearer $KORDEX_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' -d '{"name":"Example"}' \
  http://127.0.0.1:8080/v1/organizations
```

For a host Go process, provide `DATABASE_URL`, `KORDEX_ADMIN_TOKEN`, and `KORDEX_LOCAL_DEVELOPMENT=true` (only for local development), then run:

```sh
go run ./control-plane/cmd/kordex -migrate
go run ./control-plane/cmd/kordex
```

The default listen address is `127.0.0.1:8080`. Without the local-development opt-in, non-loopback binding is refused and PostgreSQL requires `sslmode=verify-full`. HTTP must terminate at a trusted TLS proxy in future production deployments; production authorization is not implemented yet.

## Verification

```sh
make test                         # unit/API tests; DB integration skips without DSN
make build
make vet
python3 scripts/check-openapi.py
# Disposable PostgreSQL only; tests create rows and exercise migrations:
KORDEX_TEST_DATABASE_URL='postgres://postgres@127.0.0.1:55432/kordex?sslmode=disable' make integration
```

CI runs race tests against PostgreSQL, vet, build, contract checks, dependency vulnerability scanning, and container scanning. A skipped database suite is not evidence of a passing integration run. See [verification](docs/verification.md) for the actual environment and results.

## Repository

| Path | Responsibility |
| --- | --- |
| `control-plane/` | REST service, PostgreSQL persistence, audit, future scheduler |
| `agent/` | Future outbound identity, inventory, command delivery and durable inbox |
| `operator/` | Future controller-runtime CRDs and local safety reconciliation |
| `dashboard/` | Future Next.js operational UI; no cluster credentials |
| `api/` | Versioned OpenAPI and future shared wire contracts |
| `integrations/` | Future cloud, storage, quorum, OS adapters |
| `deployments/` | Local Compose; future Helm packaging |
| `infrastructure/` | Future Terraform; no resources provisioned |
| `docs/` | Product, architecture, security, failure model, ADRs, roadmap |
| `tests/` | Cross-component test plans; Go tests live with packages |
| `scripts/` | Repository verification utilities |

Read the [vision](docs/product-vision.md), [architecture](docs/architecture.md), [security model](docs/security.md), [failure model](docs/failure-recovery.md), [plan](docs/mvp-plan.md), and [OpenAPI](api/openapi/v1.json). No infrastructure has been provisioned.
