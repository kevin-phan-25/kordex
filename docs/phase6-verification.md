# Phase 6 verification record

Phase 6 implementation scope: database-backed append-only/hash-chained audit writes and export verification; backup/restore helper scripts; API request throttling; a private Prometheus metrics listener; separate migration/runtime database URLs in the control-plane chart; and deployment/security documentation.

This record distinguishes code-level checks from operational evidence. No cloud account, customer cluster, immutable object store, production OIDC, or isolated recovery target is configured in this repository environment. Tenant and platform security export signatures have local code/test evidence; no production key-custody, external-retention, release-signature, backup-restore, TLS-ingress, global-rate-limit, or HA/SLO claim is made.

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

## Follow-up: restore schema verification

The current `restore-drill.sh` derives the required schema from the contiguous
SQL migrations shipped with this checkout and verifies every restored version
and migration checksum. This replaces the former hard-coded minimum of schema
version 7, which could report success for a backup older than the current
application schema. It uses the portable `sha256sum -c` form supported by the
BusyBox utility in the project's Alpine PostgreSQL image. Regression coverage
now runs in `make test` and CI.

* `bash -n scripts/restore-drill.sh scripts/test-restore-drill.sh` — passed.
* `bash scripts/test-restore-drill.sh` — passed for stale/incomplete migration
  history, migration checksum mismatch, same/unknown-server and nonempty-target
  rejection, archive checksum rejection, and successful isolated transactional
  restore flow using command doubles.
* `bash scripts/test-backup-postgres.sh` — passed for private service-file mode,
  two backups in the same second without collision, portable checksums, manifest
  contents, mode-0600 archive/sidecars, and cleanup after an unreadable dump.
* A subsequent disposable PostgreSQL 17-alpine drill created a logical backup,
  restored it to a separate target PostgreSQL server, verified
  all nine migration checksums, and reran the store suite against the restored
  database with `go test -count=1 ./control-plane/internal/store` — passed. The
  temporary containers and data were removed. This is local recovery evidence,
  not production HA, PITR, RPO/RTO, or off-host disaster-recovery evidence.

## Follow-up: authenticated authorization-denial evidence

The current checkout adds migration 010 for an append-only, platform-wide
security chain. Authenticated membership and role denials are appended in a
transaction serialized by a chain head; unauthenticated credential failures
remain structured logs. `kordex-security-audit-export` exports a fixed
high-water bundle after verifying the chain and checkpoint. Its platform
security manifest is Ed25519-signed using a dedicated file key, and the
verifier requires an independently supplied public trust bundle. This is
code-level coverage only; no PostgreSQL-backed export or independent immutable
retention test was performed in this environment.

* `go test ./control-plane/internal/store ./control-plane/internal/httpapi ./control-plane/cmd/kordex-security-audit-export ./control-plane/cmd/kordex-audit-verify` — passed before export signing was added; at that point the store integration test was skipped because `KORDEX_TEST_DATABASE_URL` was unset.
* `make test` — passed, including local backup/restore/export guards and repository unit tests.
* `make vet build contract` — passed; includes the new exporter binary and API contract checks.
* `docker build --tag kordex-control-plane:security-audit-local --file control-plane/Dockerfile .` — passed using the local Docker-compatible Podman CLI; both audit binaries were built into the image.
* `docker run --rm --entrypoint /kordex-security-audit-export kordex-control-plane:security-audit-local -h` — passed; confirms the exporter is executable in the runtime image.
* `bash scripts/test-offline-bundle-integrity.sh` and `bash -n` for changed shell scripts — passed.
* `git diff --check` — passed.
* After adding Ed25519 manifest signing and independent trust-bundle verification, `go test ./control-plane/internal/auditchain ./control-plane/cmd/kordex-security-audit-export ./control-plane/cmd/kordex-audit-verify` — passed. Coverage includes signature field binding, tampered checkpoint rejection, missing/untrusted keys, duplicate trust-bundle members, trust key-ID validation, private-key file mode/symlink rejection, and unsigned security-bundle rejection.
* A new local PostgreSQL 17 Alpine container bound only to loopback was used for `KORDEX_LOCAL_DEVELOPMENT=true KORDEX_TEST_DATABASE_URL=… go test -count=1 ./control-plane/internal/store` — passed (13.080s). This exercised migration 010, concurrent migration readiness, security-denial persistence, chain verification, append-only enforcement, and database reopen behavior. The temporary container was removed by the test wrapper; no shared development database or cloud service was used.
* Current-worktree `make test` — passed (exit 0); `make vet build contract` — passed (exit 0), including all binaries and the 50-operation OpenAPI contract; `git diff --check` — passed.
* `docker build --tag kordex-control-plane:security-audit-signed-local --file control-plane/Dockerfile .` — passed with the Docker-compatible Podman CLI. `docker run --rm --entrypoint /kordex-security-audit-export kordex-control-plane:security-audit-signed-local -h` — passed; the exporter is present and executable in the image.
* `bash scripts/test-offline-bundle-integrity.sh` — passed against the updated offline bundle tooling.
* Tenant export checkpoint follow-up: `bash scripts/test-export-audit.sh` — passed. The script built a temporary signer, verifier, and key generator; generated a unique Ed25519 key pair; exported the mocked tenant snapshot; verified the signed checkpoint and external high-water ID; and rejected a tampered NDJSON copy. Existing artifact overwrite, incomplete-page, mode, checksum, and cleanup checks passed. No API server or external archive was used.
* Current-worktree `make test` — passed (exit 0); `make vet build contract` — passed (exit 0), including the signer and 50-operation OpenAPI check. `docker build --tag kordex-control-plane:tenant-audit-signed-local --file control-plane/Dockerfile .` — passed using Podman; the verifier and signer executables are included in the image. `bash scripts/test-offline-bundle-integrity.sh` — passed with signer inventory coverage.

## Known limitations

* Existing audit history predates the hash chain and is not retroactively authenticated.
* The CLI tenant audit archive, platform security export, and dashboard API bundle are Ed25519-signed. A database owner could rewrite the chain and ask an exporter to sign the rewritten state. Independent immutable retention and comparison to an independently retained checkpoint remain required. Signing-key custody and rotation are file-based and have not been qualified with KMS or a secret manager. The browser does not perform cryptographic verification; use `kordex-audit-verify` with an independently distributed trust bundle.
* Rate limits are process-local and subject-keyed; gateway enforcement is required for global quotas and agent traffic.
* Metrics are in-memory per API replica and reset on restart. They do not yet provide scheduler or recovery-specific operational signals.
* Backup script supports logical archives, not PITR configuration or a proven RPO/RTO.
* Image signatures/provenance and air-gapped deployment remain open work.
