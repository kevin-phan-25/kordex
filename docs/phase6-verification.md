# Phase 6 verification record

Phase 6 implementation scope: database-backed append-only/hash-chained audit writes and export verification; backup/restore helper scripts; API request throttling; a private Prometheus metrics listener; separate migration/runtime database URLs in the control-plane chart; and deployment/security documentation.

This record distinguishes code-level checks from operational evidence. No cloud account, customer cluster, immutable object store, production OIDC, or isolated recovery target is configured in this repository environment. Therefore no production backup restore, external retention, TLS ingress, global rate limiting, HA/SLO, or signed artifact claim is made.

## Verification status

Commands executed:

* `cd control-plane && PATH=/tmp/go/bin:$PATH GOCACHE=/tmp/kordex-go-cache GOMODCACHE=/tmp/kordex-go-mod go build ./...` — passed.
* `PATH=/tmp/go/bin:$PATH GOCACHE=/tmp/kordex-go-cache GOMODCACHE=/tmp/kordex-go-mod go build -trimpath -o /tmp/kordex-phase6 ./control-plane/cmd/kordex` — passed.
* `PATH=/tmp/go/bin:$PATH GOCACHE=/tmp/kordex-go-cache GOMODCACHE=/tmp/kordex-go-mod go build -trimpath -o /tmp/kordex-audit-verify ./control-plane/cmd/kordex-audit-verify` — passed.
* `python3 scripts/check-openapi.py` — passed (45 operations).
* `bash -n scripts/export-audit.sh scripts/backup-postgres.sh scripts/restore-drill.sh` — passed.
* Python YAML parse of `.github/workflows/*.yaml` — passed.
* `git diff --check` — passed.
* Helm lint/template and Docker image build/scan — unavailable; `helm` and `docker` are not installed in this workspace.
* Tests were not run as part of this work session.

## Known limitations

* Existing audit history predates the hash chain and is not retroactively authenticated.
* The hash chain is not a digital signature; a sufficiently privileged database owner can rewrite data and recompute hashes. Independent immutable exports are required.
* Rate limits are process-local and subject-keyed; gateway enforcement is required for global quotas and agent traffic.
* Metrics are in-memory per API replica and reset on restart. They do not yet provide scheduler or recovery-specific operational signals.
* Backup script supports logical archives, not PITR configuration or a proven RPO/RTO.
* Image signatures/provenance and air-gapped deployment remain open work.
