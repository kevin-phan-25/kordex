# Customer deployment rehearsal

This is a repeatable acceptance procedure for an independent platform team. It
is a test plan, not evidence that Kordex has passed a customer deployment. Use
a customer-controlled disposable Kubernetes environment and customer-owned
identity, database, registry, certificates, secrets, and signing keys.

## Procedure

1. **Establish release trust.** Obtain the release public key, offline-tools
   acquisition public key, Helm signer allowlist, and release bundle from
   independently approved channels. Verify the bundle with the trusted
   verifier and the signed image lock before loading or rendering images. Do
   not trust public keys copied only from the bundle being verified.
2. **Prepare customer services.** Provision PostgreSQL with TLS verification,
   separate runtime and migration roles, backups, and recovery. Configure the
   customer's OIDC issuer, client/audience contract, callback origins, and
   HTTPS ingress. Verify discovery and JWKS from the API and dashboard
   networks.
3. **Provision secrets and signing trust.** Use the customer's secret manager
   to provide database URLs, stable dashboard session secret, and the existing
   maintenance signing seed to the management plane. Keep the corresponding
   public trust bundle separately backed up. Provide registry credentials and
   TLS trust only through the customer's secret/certificate process. Never put
   secret values in Helm values, Kustomize patches, Git, or release bundles.
4. **Install the hub.** Render the digest-pinned production profiles. Install
   the control-plane chart and wait for its migration hook to finish before
   serving traffic; install the dashboard chart and configure separate API and
   dashboard HTTPS hosts. Validate readiness, database connectivity, OIDC
   login, and membership-scoped authorization. Initial organization creation
   and the first OIDC administrator membership require a separate, temporary
   bootstrap step: run the API against the same TLS-verified database with
   OIDC unset, a customer-held bootstrap token, and its listener bound only to
   `127.0.0.1`. Create the organization and grant membership to the actual OIDC
   subject, then stop the bootstrap process and remove its token from the
   temporary runtime before serving OIDC traffic. Never expose a bootstrap
   listener through a Service or Ingress. The Helm charts do not automate this
   step; the customer deployment rehearsal must verify it explicitly.
5. **Register and connect a cluster.** Create or select the organization,
   fleet, site, and cluster records through authorized APIs. Issue a
   short-lived enrollment token, deliver it through the customer's secret
   workflow, and install the agent chart. Verify agent identity, fresh
   heartbeats, and persisted node inventory. Install the operator only when
   required, with the matching public trust bundle and default-off execution
   gates.
6. **Exercise an approved maintenance operation.** On a separately qualified
   disposable target, validate policy, independent approval, local safety
   checks, operation ownership, cancellation, and recovery evidence. Record
   the signed plan, operation ID, checkpoints, and verifier output. Do not use
   this rehearsal to bypass the M3 Ubuntu qualification matrix.
7. **Upgrade and recover.** Back up PostgreSQL and retain the prior release
   digests/configuration. Verify and render the new signed release, run the
   migration in the documented order, then check API, dashboard, enrollment,
   and inventory. Test a failed rollout in the disposable environment. Roll
   workloads back only when schema compatibility permits; otherwise restore
   the verified database backup and prior release according to the reviewed
   recovery plan. Never assume a Helm rollback reverses database migrations.
8. **Archive evidence.** Record release and chart versions, digests, database
   migration result, OIDC and authorization results, agent/cluster identity,
   inventory freshness, maintenance evidence, upgrade/recovery result, and
   deviations. Have a second customer engineer reproduce verification from
   the archived trust inputs and evidence.

## Current boundaries and missing proof

- The repository has separate Helm charts for control plane, dashboard, agent,
  and operator. The control-plane chart includes API/scheduler workloads and a
  migration hook. PostgreSQL, OIDC, ingress controllers, certificates, and
  customer secret management remain external; there is no umbrella chart or
  single-command installer.
- Existing docs cover hub configuration, chart values, offline verification,
  enrollment, and operator operation. The sequence above still requires
  customer-specific values, secret provisioning, database services, ingress,
  DNS, identity-provider setup, and cluster access. No customer team has
  completed this end-to-end rehearsal.
- Helm production profiles require image digests, but signature/provenance
  admission is not enforced by Helm itself. Verify release signatures before
  installation and use the separately documented admission integration only
  where the customer operates and qualifies it.
- Air-gapped packaging and verification have local fixture tests. Installation
  and host package execution with external connectivity disabled remain
  unqualified.
- A customer deployment rehearsal is M6 packaging/onboarding qualification.
  Real Ubuntu 24.04 package, reboot, recovery, failure-injection, and evidence
  results remain M3. Campaign waves, concurrency, pause/resume, and multi-
  cluster orchestration remain M4. HA/DR, immutable audit retention, security
  review, and operational monitoring remain M5.
