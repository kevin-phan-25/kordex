# Phase 5 dashboard verification (0.5.0)

This record covers source-level and production bundle checks for the Phase 5 dashboard. It is not a production acceptance test.

## Verified

- `npm ci --ignore-scripts` completed from `dashboard/package-lock.json`.
- `npm run typecheck` passed.
- `npm run lint` passed without warnings after cleanup.
- `npm run build` generated a successful optimized Next.js standalone build and enumerated all dashboard and API routes.
- `PATH=/tmp/go/bin:$PATH GOCACHE=/tmp/kordex-go-cache GOMODCACHE=/tmp/kordex-go-mod go build ./control-plane/...` passed after adding dashboard data endpoints.
- `python3 scripts/check-openapi.py` passed with 45 operations, valid local references, and organization auth declarations.
- `git diff --check` passed.

## Not verified in this environment

- Interactive OIDC login against a real provider, token audience alignment, logout behavior through a public TLS ingress, and multi-replica session-key rotation.
- End-to-end browser behavior, responsive/accessibility review with assistive technology, or API calls against a configured PostgreSQL-backed management plane.
- Helm rendering/linting and installation: Helm was unavailable in the environment.
- Container image scanning, deployment, Cloud Run, and GCP integrations.
- Automated tests were not added or run for the dashboard in this phase. Existing Go/API/database/controller suites were not run as part of this dashboard update.

`npm ci` reported eight moderate dependency advisories. They were not auto-updated; inspect the pinned transitive advisories and select compatible patched versions before production release.
