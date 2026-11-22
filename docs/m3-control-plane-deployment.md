# M3 control-plane deployment and migration 016

This is the customer-operated deployment procedure for the repository's
existing control-plane Helm chart. It does not deploy a GCP control plane: the
chart targets a customer-provided Kubernetes cluster and customer-provided
PostgreSQL, OIDC, TLS ingress, registry, and secret management. No deployment
target or credentials are checked into this repository.

## What this revision deploys

At repository revision `81743bbbe3a55af73a908ab69ad275448839ce7b`, the chart
is `deployments/helm/kordex-control-plane` (`Chart.yaml` version `0.7.0`,
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
pre-created namespace, a reviewed release chart/image and immutable digest, private registry
pull access if needed, an existing PostgreSQL database and restricted runtime
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

## Render, review, and deploy

Run these from the exact reviewed repository checkout. Replace the placeholders
only with verified customer values. Keep the values file outside Git with mode
0600; it must contain references and non-secret configuration only, not Secret
payloads.

```sh
set -eu
NAMESPACE='<customer-namespace>'
RELEASE='kordex-control-plane'
IMAGE_REPOSITORY='<approved-private-or-release-repository-without-tag>'
IMAGE_DIGEST='sha256:<64-lowercase-hex-digest>'
VALUES='/secure/customer/path/kordex-control-plane-values.yaml'

kubectl config current-context
kubectl get namespace "$NAMESPACE"
helm lint deployments/helm/kordex-control-plane \
  --values "$VALUES" \
  --set-string image.repository="$IMAGE_REPOSITORY" \
  --set-string image.digest="$IMAGE_DIGEST" \
  --set image.requireDigest=true
helm template "$RELEASE" deployments/helm/kordex-control-plane \
  --namespace "$NAMESPACE" --values "$VALUES" \
  --set-string image.repository="$IMAGE_REPOSITORY" \
  --set-string image.digest="$IMAGE_DIGEST" \
  --set image.requireDigest=true > /secure/customer/path/kordex-control-plane-rendered.yaml
```

Independently inspect the rendered resource names, image references, ingress,
network policies, Secret references, and security contexts. Confirm every
container uses `IMAGE_REPOSITORY@IMAGE_DIGEST` and no secret value is rendered.
Record hashes of the reviewed chart tree, values file (after excluding any
customer-secret material; secret values must not be in that file), rendered
manifest, image digest, and source revision in customer change control.

After the customer's deployment approval, deploy through Helm. Do not use
`--atomic`: a successful database migration cannot be undone by Helm rollback.

```sh
helm upgrade --install "$RELEASE" deployments/helm/kordex-control-plane \
  --namespace "$NAMESPACE" \
  --values "$VALUES" \
  --set-string image.repository="$IMAGE_REPOSITORY" \
  --set-string image.digest="$IMAGE_DIGEST" \
  --set image.requireDigest=true \
  --wait --timeout 10m
```

Helm waits for the pre-upgrade migration hook. The successful hook Job is
deleted by its hook policy; a failed Job is retained for diagnosis until the
next hook creation. On failure, do not blindly rerun or roll back. Preserve
Helm output and failed Job events/logs, inspect PostgreSQL migration history,
and follow the database recovery procedure below.

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
checksum:

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
a verified non-administrator identity to submit a stop request against the
reviewed disposable cluster; expect HTTP 403 and confirm the administrator's
subsequent GET shows no changed generation/state. Run this authorization probe
only after the platform owner approves this test and confirms the cluster has
no operation in progress; if it unexpectedly succeeds, keep the lab fenced and
have an administrator reconcile it before any VM action. Do not use a bootstrap
token for normal verification.

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
read-only client are implemented. At the revision above, chart metadata is
0.7.0 / appVersion 0.8.0, but no signed image digest for that exact revision,
customer deployment target, database, OIDC configuration, secret, cluster
credentials, or deployment authorization was supplied. Migration 016, API
health, organization-admin authentication, non-admin denial, and restart
persistence are therefore **NOT RUN** and not customer-verified. No GCP API
or project permission is required by this Helm path. All 22 real-host
qualification rows remain NOT RUN.
