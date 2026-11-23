# M3 control-plane deployment and migration 016

This is the customer-operated deployment procedure for the repository's
existing control-plane Helm chart. It does not deploy a GCP control plane: the
chart targets a customer-provided Kubernetes cluster and customer-provided
PostgreSQL, OIDC, TLS ingress, registry, and secret management. No deployment
target or credentials are checked into this repository.

## What this revision deploys

The chart is `deployments/helm/kordex-control-plane` (`Chart.yaml` version `0.7.0`,
`appVersion` `0.8.0`). It creates API and scheduler Deployments, a ClusterIP API
Service, probes, disruption budgets, and an optional ingress/network policy.
Production values require an immutable image digest. The current repository
revision is not a version tag and no image digest or signed release evidence
for this revision was supplied. Do not deploy the default tag or invent a
digest. A release custodian must publish an approved version from the exact
reviewed source revision using the manually gated `release-images` workflow in
`.github/workflows/ci.yaml`; retain and independently verify its digest,
signature, provenance, and SBOM evidence. The workflow currently publishes
`ghcr.io/<repository-owner>/kordex-control-plane` as a multi-platform image.
Mirror the verified digest to the customer's private registry if required.

The chart has a Helm `pre-install,pre-upgrade` hook Job named
`<release>-migrate`. Helm runs `/kordex -migrate` from the same digest-pinned
image before changing the API or scheduler workloads and waits for the hook.
There is no separate migration Job command. The migration uses the Secret's
`migrationDatabaseURL`; the service workloads use `databaseURL`. Both must use
PostgreSQL TLS verification (`sslmode=verify-full`). The migration binary
embeds ordered SQL files and applies pending migrations under a PostgreSQL
advisory lock and one transaction. Migration 016 creates the cluster-scoped
`lab_lifecycle` barrier table. Its source SHA-256 at this revision is
`b98fff6f64ac5268f951d6ddc17bcc8331f49839d5f743f472ca9df5daab8b4d`.
Readiness verifies the complete migration sequence and each stored checksum.

## Customer inputs required before deployment

The platform owner must provide a customer-controlled Kubernetes context and
pre-created namespace, a reviewed release chart/image and immutable digest,
private registry pull access if needed, an existing PostgreSQL database and restricted runtime
and migration roles, a securely provisioned credentials Secret, OIDC issuer
and audience, HTTPS ingress/DNS/certificate configuration, and a tested
database backup/restore procedure. In `access_token` mode, also provide the
access client ID and required scopes. The credentials Secret must contain
`databaseURL`, `migrationDatabaseURL`, and `maintenanceSigningKey`; if signed
audit export is enabled, it must also contain the configured audit signing key.
Create the Secret through the customer secret manager or approved secret
workflow. Never put values in Helm values, shell arguments, Git, or this doc.

The deployment principal needs only the customer's Kubernetes permissions for
the chart's namespaced resources and the separately approved database/secret
workflow. The chart does not call GCP APIs, create GCP resources, use a GCP
service account, or require project IAM roles. No GCP API enablement is needed
for this chart deployment. Keep `automountServiceAccountToken: false`; no
Kubernetes API access is granted to the application pods by this chart.

## Executable preflight and deployment

The local controller is `scripts/control_plane_deploy.py`; its strict input
contract is [control-plane-deployment-inputs-v1.json](schemas/control-plane-deployment-inputs-v1.json).
Populate it from customer-approved records, not status strings. The checked-in
[synthetic example](examples/control-plane-deployment-inputs.synthetic.json)
is deliberately rejected because it has `fixtureOnly: true` and synthetic
paths/identities. It cannot pass preflight.

Install no tools during preflight. The operator must already have `kubectl`,
Helm, `cosign`, GitHub CLI (`gh`), `psql`, and OpenSSL. The tool checks the
current Kubernetes context against the independently supplied
`--expected-api-server` and `--expected-cluster-uid` values, and confirms the
`kube-system` namespace UID, namespace, server version (Kubernetes 1.21+),
required API capabilities/permissions, and live allocatable capacity after
existing pod requests and rendered rollout surge. The independent endpoint and
UID must come from the platform owner through a separate trusted channel; a
manifest assertion alone does not establish cluster identity.

The release check requires the exact signed image repository and digest, a
clean checkout at the semver tag's exact source commit, Cosign verification
against the Kordex GitHub Actions identity, and `gh attestation verify` bound
to `kevin-phan-25/kordex`, `.github/workflows/ci.yaml`, the tag, and commit.
All verification tools must be present locally; the controller downloads
nothing. The database probe uses a mode-0600 libpq service file and requires
`sslmode=verify-full`, PostgreSQL 10 or newer (the migration syntax minimum),
TLS, and an existing migration ledger that is an exact checksum-valid prefix
of this release. A current-version ledger is okay; the Helm hook will observe
016 already applied and will not duplicate it.

The controller reads Secret data only into memory, checks required key names,
nonempty values, PostgreSQL URL/TLS settings, same runtime/migration database
target, and the Ed25519 key encoding. It never includes Secret bytes, database
URLs, token contents, external command output, or response bodies in its
report. It checks OIDC discovery/JWKS over verified HTTPS, the ingress TLS
Secret's hostname, key match, expiry and CA chain, runs `helm lint` and render,
checks the exact image and OIDC configuration, and validates the rendered
objects with Kubernetes server-side dry-run. It compares the rendered
requests/limits and rollout surge to current schedulable capacity.

Database backup/restore evidence must be a fresh (24-hour) detached-signed JSON
document. The operator supplies the independently received public-key SHA-256
on the command line, not from the manifest. Its signed `fields` must bind the
database target fingerprint and include `restoreTestPassed: true`, a backup
reference, and a restore test timestamp within 90 days. Preflight reports each
missing or failed check as `NOT PROVIDED`, `NOT VERIFIED`, or `FAIL`; only all
`PASS` permits deploy. Preflight reports are created with mode 0600 and are
never overwritten. The deployment report is created mode 0600 as
`IN_PROGRESS` before Helm starts, then atomically replaced with the final,
pre-mutation-aborted, or recovery-required result.

First run read-only preflight, supplying the endpoint, cluster UID and backup
signer fingerprint obtained independently:

```sh
python3 scripts/control_plane_deploy.py preflight \
  --inputs /secure/customer/control-plane-inputs.json \
  --expected-api-server 'https://<approved-api-endpoint>' \
  --expected-cluster-uid '<approved-kube-system-namespace-uid>' \
  --backup-key-sha256 '<64-hex-out-of-band-public-key-fingerprint>' \
  --report /secure/customer/control-plane-preflight.json
```

The command can reach the configured Kubernetes API, PostgreSQL, OIDC issuer,
registry attestations, and ingress Secret for read-only verification. It was
not run here because no customer inputs or deployment target were supplied.
The independent GCP lab readiness report is separate and makes no cloud calls:

```sh
python3 scripts/control_plane_deploy.py gcp-readiness \
  --report /secure/customer/m3-gcp-readiness.json
```

Only after every preflight row is `PASS`, a release owner has supplied the
signed artifact, and the deployment owner approves the exact target, run the
command below. The
deployment report path is required and must not already exist; it is created
mode 0600 with `deploymentState: IN_PROGRESS` before Helm runs. If the process
is interrupted, that durable report remains an unresolved deployment fence and
must be reconciled before retrying:

```sh
python3 scripts/control_plane_deploy.py deploy \
  --inputs /secure/customer/control-plane-inputs.json \
  --expected-api-server 'https://<approved-api-endpoint>' \
  --expected-cluster-uid '<approved-kube-system-namespace-uid>' \
  --backup-key-sha256 '<64-hex-out-of-band-public-key-fingerprint>' \
  --report /secure/customer/control-plane-deployment.json
```

The command repeats preflight and prompts for the exact target-bound phrase
`APPROVE_KORDEX_CONTROL_PLANE_DEPLOY <cluster_uid> <namespace> <release_name> <sha256:image_digest> <manifest_sha256> <helm_values_sha256>`.
It then runs Helm without `--atomic`, verifies migration 016 and health,
confirms an authenticated organization-administrator lifecycle authorization
probe, checks that a verified non-admin read-only authorization probe receives
403 without calling a lifecycle mutation, and performs a rolling API restart
to compare persisted state before and after. On any failed post-deployment check
or interrupted Helm command, the report sets `recoveryRequired`; it never
retries, rolls back, or proceeds to later checks automatically. A failed
migration hook blocks Helm workload replacement; do not mistake readiness of
an older already-running binary for proof that the new migration succeeded.
The authorization probe requires a customer OIDC organization
administrator; a bootstrap token is explicitly rejected.

## Deployment command is authoritative

Do not deploy by copying a standalone `helm upgrade` command. That bypasses
release provenance, cluster binding, database backup, target authorization,
and post-deployment checks. `scripts/control_plane_deploy.py deploy` is the
repository-supported deployment path; it renders and validates the exact
configuration during preflight and requires target-bound authorization
immediately before Helm runs. On interruption, inspect the Helm release,
migration hook, and database ledger before any separately approved retry.

## Post-deployment verification

Capture the release status, image references, rollout, and probe results:

```sh
helm status "$RELEASE" --namespace "$NAMESPACE"
kubectl get deployments,pods,service -n "$NAMESPACE" \
  -l "app.kubernetes.io/instance=$RELEASE" -o wide
kubectl rollout status deployment/"$RELEASE"-api -n "$NAMESPACE" --timeout=5m
kubectl rollout status deployment/"$RELEASE"-scheduler -n "$NAMESPACE" --timeout=5m
kubectl port-forward -n "$NAMESPACE" "service/$RELEASE-api" 18080:8080
```

In another terminal, require health `200` and `{"status":"ready"}`. The
ready endpoint verifies PostgreSQL connectivity and the complete migration
history:

```sh
curl --fail --silent --show-error http://127.0.0.1:18080/healthz
curl --fail --silent --show-error http://127.0.0.1:18080/readyz
```

Using the customer's restricted migration-audit connection (never echo its
connection string), verify that exactly one version-16 row has the expected
checksum. The deployment command performs this query after Helm; the SQL below
is a manual audit reference:

```sql
SELECT version, checksum, applied_at
FROM schema_migrations
WHERE version = 16;
```

Expected checksum:
`b98fff6f64ac5268f951d6ddc17bcc8331f49839d5f743f472ca9df5daab8b4d`.
Also verify `lab_lifecycle` exists. A missing row for a cluster means legacy
`RUNNING` until an administrator requests a stop; do not insert or edit rows
manually.

For authenticated, read-only lifecycle verification, install the reviewed
checkout's Python dependencies (the client itself uses the standard library),
set the control-plane origin, exact organization/cluster UUIDs, private token
file path, and independently pinned TLS certificate SHA-256, then run the
existing TLS-pinned client. This call does not access GCP:

```sh
PYTHONPATH=scripts python3 - <<'PY'
import json
import os
from pathlib import Path
from m3_lab_lifecycle import ControlPlaneClient

client = ControlPlaneClient(
    os.environ["KORDEX_CONTROL_PLANE_URL"],
    os.environ["KORDEX_ORGANIZATION_ID"],
    os.environ["KORDEX_CLUSTER_ID"],
    Path(os.environ["KORDEX_TOKEN_FILE"]),
    os.environ["KORDEX_CONTROL_PLANE_CERT_SHA256"],
)
print(json.dumps(client.request(), sort_keys=True))
PY
```

The token file must be a private regular file owned by the invoking user; the
client checks this and never prints the token. Verify the returned lifecycle
state and generation against the database/audit record. Verify the customer
OIDC subject maps to the intended organization administrator. Separately use
use a verified non-administrator identity against the read-only lifecycle
`/authorization` probe; expect HTTP 403. The probe does not call a lifecycle
mutation. Do not test an unauthorized identity by submitting a stop request.
Do not use a bootstrap token for normal verification.

To verify persistence across an API process restart, record the signed/audited
GET response, perform a separately approved rolling restart of one API replica
using the customer's normal deployment controller, wait for readiness, then
repeat the same GET and compare state/generation and audit history. This is a
deployment operation and was not performed as part of this repository change.

## Upgrade recovery and rollback

Take and verify a PostgreSQL backup before every production upgrade. The
migrations are forward-only and Helm does not reverse them. Migration 016 is
transactional, so failure before commit leaves its table/data changes
uncommitted; verify `schema_migrations` and database logs before retrying.
After version 016 is committed, an older binary whose embedded migration plan
does not know version 016 fails readiness. Do not use `helm rollback` to
pretend the schema was reverted. Preferred recovery is a reviewed forward fix
using a compatible newer image. If the customer must return to the pre-016
application, restore the pre-upgrade database backup and the matching old
chart/image as a coordinated, separately approved recovery. Preserve audit
records and never edit `schema_migrations` by hand.

## Status in this repository

The migration hook, chart, lifecycle API, PostgreSQL barrier, and TLS-pinned
read-only client are implemented. Chart metadata is 0.7.0 / appVersion 0.8.0,
but no signed image digest for the exact reviewed revision,
customer deployment target, database, OIDC configuration, secret, cluster
credentials, or deployment authorization was supplied. Migration 016, API
health, organization-admin authentication, non-admin denial, and restart
persistence are therefore **NOT RUN** and not customer-verified. No GCP API
or project permission is required by this Helm path. All 22 real-host
qualification rows remain NOT RUN.
