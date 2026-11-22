# M3 readiness and plan input binding

This document describes the local readiness report and its relationship to the
self-managed Terraform plan. It does not authorize a Terraform plan, apply,
deployment, or host operation. M3 remains **NOT COMPLETE**; all canonical
Debian 13 and RHEL 9.8-or-later cases remain **NOT RUN**.

## Readiness result states

Each schema-version 2 check records a requirement ID, applicable platforms,
logical input/evidence reference, verification method, timestamp when a check
was performed, result, reason, and whether independent review remains
required.

| State | Meaning |
|---|---|
| `PASS` | An available local or independent check verified this exact requirement. |
| `PROVIDED` | An input exists and passed structural/binding checks, but is not independently verified. |
| `NOT PROVIDED` | A required input is absent. |
| `BLOCKED` | Completion requires an external service, owner decision, or independent review unavailable to the local check. |
| `FAIL` | A check was performed and found an invalid, stale, conflicting, or mismatched value. |

The summary command is read-only and does not call Google Cloud, DNS, mirrors,
registries, or customer services:

```sh
python3 scripts/m3_deployment_readiness.py \
  --project-id kordex-fleet-platform-515416 \
  --network-inputs /secure/m3/network-inputs.json \
  --artifact-inputs /secure/m3/customer-artifact-inputs.json \
  --artifact-report /secure/m3/artifact-preflight.json \
  --terraform-inputs /secure/m3/terraform-inputs.json \
  --image-approval /secure/m3/image-approval.json \
  --output /secure/m3/deployment-readiness.json
```

The complete Terraform JSON file must contain every variable declared by the
lab module, including defaults that the operator intends to use. It contains
non-secret configuration only. Unknown or omitted fields, duplicate JSON
keys, mixed recovery and normal-plan settings, profile conflicts, unapproved
URLs, changed artifact locks, or a mismatched project fail closed. The report
stores canonical SHA-256 bindings, not the variable values or local paths.
The output file is mode `0600` and is never overwritten.

The report may remain `BLOCKED` because live project designation, APIs/IAM,
network reachability, billing, trust custody, and independent image review are
not established by local checks. A `PASS` for `planInputBinding` means only
that the local non-secret inputs and source/artifact references are internally
bound. It is not cloud approval or permission to provision.

Three configuration-only checks may report `PROVIDED`: `actualTerraformInputs`,
`customerNetworkInputs`, and `selectedLabOSProfile`. That status means the
customer supplied values that were structurally validated and bound; it does
not mean Kordex independently verified the live network or the owner's image
claims. No other readiness check may be `PROVIDED` for plan authorization. A
separate, short-lived signature from a trust-configured customer deployment
approver must approve the exact report and plan-binding digests. The report
retains `PROVIDED` for those inputs after approval; the signature authorizes
the reviewed values without relabeling them as independently verified. Missing,
blocked, failed, or conflicting checks remain non-authorizable.

## Canonical binding and drift checks

Canonical JSON uses UTF-8, sorted object keys, compact separators, and rejects
non-finite numbers and duplicate keys. Order-insensitive CIDR/DNS collections
are sorted before hashing. The plan binding covers:

- Exact complete non-secret Terraform variable values.
- Canonical network input values.
- Artifact input-map values and the canonical artifact preflight report.
- Terraform source, startup templates, embedded helper files, the locked
  provider declaration, and the local readiness/plan authorization and artifact
  verifier code invoked by the guarded path.
- Exact selected image self-link and server-assigned Compute image ID.
- Image-owner record digest and reference.
- K3s version, binary digest, system-image bundle digest, and package policy
  digest.

The guarded `plan` command rereads every bound file, re-runs signed K3s binary
and system-image verification, regenerates the consolidated artifact report,
validates the live disposable project designation through Terraform's
read-only data sources, and checks that no value changed during preflight. It
rejects a readiness report older than four hours. `apply` repeats the checks
after the exact interactive project confirmation and before applying its
saved plan. A changed input, report, source file, selected image identity, or
approval record requires a newly generated readiness report and a newly
reviewed plan.

The SHA-256 bindings detect drift; they are not signatures and do not prove
who created or approved an input. An independent owner/reviewer must verify
the cited evidence through a customer-controlled channel.

The helper does not open or fingerprint ignored `terraform.tfvars`. Terraform
may auto-load that file from its working directory when a future plan runs;
the guarded command also passes a complete explicit variable file containing
every declared input at higher CLI precedence, so the ignored file cannot
change the bound declared values. Do not put secrets there or rely on it for
reviewed plan settings. The file is not used as an input to readiness.

## Exact image approval

Google's Debian image-family endpoint is not used for canonical Debian
qualification. Debian 13 and RHEL 9 qualification both require an exact
Compute Engine image self-link. The customer image owner obtains the image's
server-assigned numeric `id` from the approved image metadata and records it
with independent OS release and architecture evidence. The Terraform data
source resolves the exact image name and its `image_id`; a precondition
requires equality with the owner-approved ID. The saved plan therefore binds
the self-link and checked resource identity. The guarded apply path re-resolves
the self-link, project, numeric ID, and architecture immediately before apply,
then checks that the in-process saved plan hash is unchanged.

Compute Engine boot-disk configuration consumes an image self-link/name; the
current implementation does not use or claim an immutable image-ID reference
for boot creation. A deletion/recreation between the final identity query and
the Compute Engine disk-create request is therefore a residual
time-of-check/time-of-use race. The immediate apply-time re-resolution narrows
that interval but cannot eliminate it. A plan or apply remains blocked if the
image is inaccessible, deleted, replaced, or its ID changes. Google image
metadata does not prove the in-guest Debian point release or RHEL minor; that
claim requires customer image-owner evidence independently reviewed by an
authorized reviewer.

Google image metadata does not independently establish the image's in-guest
Debian point release or RHEL minor. The image owner must inspect/test the
approved image and cite evidence. The owner record and separate reviewer
decision must be signed by identities in the customer-rooted trust config; the
approval package and its trust digest are bound into readiness. Missing or
unverified owner evidence prevents plan authorization. The customer-signed
owner record is public/non-secret canonical
JSON with exactly these fields. It has a detached signature at `<record>.sig`;
a separate accepted review record `<record-stem>.review.json` and detached
signature are required. The owner and reviewer must be distinct customer-trusted
identities with the `image-approver` and `reviewer` roles:

```json
{
  "schemaVersion": 1,
  "projectId": "<qualification-project-id>",
  "approvalStatus": "approved",
  "approvalReference": "<customer-change-or-approval-reference>",
  "platformProfile": "<debian-13-or-rhel-9>",
  "imageSelfLink": "<exact-compute-image-self-link>",
  "imageUniqueId": "<server-assigned-decimal-image-id>",
  "osId": "<debian-or-rhel>",
  "osVersion": "<13-or-9.minor>",
  "pointRelease": "<13.point-or-9.minor>",
  "architecture": "linux/amd64",
  "imageOwner": "<customer-image-owner-identity>",
  "approverIdentity": "<customer-image-approver-identity>",
  "approvedAt": "<RFC3339 timestamp with timezone>",
  "expiresAt": "<RFC3339 timestamp with timezone, no more than 30 days later>",
  "evidenceReference": "<customer-controlled image inspection evidence reference>",
  "rationale": "<reviewable approval rationale>"
}
```

The separate review JSON contains `schemaVersion`, `approvalSha256` (the
SHA-256 of the canonical owner record), `reviewerIdentity`, `decision` set to
`accepted`, `reviewedAt`, and a rationale. The plan binding hashes the complete
approval package (owner record, both signatures, review record, and customer
trust digest), so changing either approval or review invalidates readiness.
Set `qualification_image_approval_sha256` in the complete Terraform JSON to
this complete package digest. Set
`qualification_image_unique_id` to the same decimal ID. The independently
reviewed plan output includes `boot_image_id` and `boot_image_unique_id`; final
qualification evidence records both. Do not invent an image name, ID, OS
point release, or evidence reference. No customer image approval is currently
provided.

## Separate plan review

After required owner decisions and cloud approvals are independently
confirmed, the guarded command accepts these exact input paths:

```sh
python3 scripts/self_managed_lab.py plan \
  --project-id kordex-fleet-platform-515416 \
  --k3s-binary /approved-transfer/k3s \
  --k3s-artifact-lock /approved-transfer/k3s.artifact-lock \
  --k3s-artifact-signature /approved-transfer/k3s.artifact-lock.sig \
  --k3s-artifact-trust /independent-trust/artifact-approval.trust \
  --k3s-system-images-bundle /approved-transfer/k3s-airgap-images-amd64.tar \
  --k3s-system-images-lock /approved-transfer/k3s-system-images.lock \
  --k3s-system-images-signature /approved-transfer/k3s-system-images.lock.sig \
  --k3s-system-images-trust /independent-trust/artifact-approval.trust \
  --m3-artifact-inputs /secure/m3/customer-artifact-inputs.json \
  --m3-artifact-report /secure/m3/artifact-preflight.json \
  --readiness-report /secure/m3/deployment-readiness.json \
  --terraform-inputs /secure/m3/terraform-inputs.json \
  --network-inputs /secure/m3/network-inputs.json \
  --image-approval /secure/m3/image-approval.json
```

This command performs Terraform planning and cloud read operations. It is not
run by this documentation change and requires separate explicit
authorization. Review the exact project, image self-link and unique ID,
package policy, network rules, service identities, costs, and all planned
resources. Terraform apply remains a distinct, separately authorized action.
Do not run raw Terraform plan/apply to bypass these checks.

## Evidence provenance and reviewer acceptance

Evidence trust is rooted at the customer-installed, root-owned files
`/etc/kordex/m3/qualification-root.pub`,
`/etc/kordex/m3/qualification-trust.json`, and
`/etc/kordex/m3/qualification-trust.json.sig`. The public root is distributed
independently. The root-signed, canonical trust configuration authorizes exact
Ed25519 fingerprints and identities for `collector`, `reviewer`,
`corroborator`, `image-approver`, and `replay-registry` roles. It is versioned,
time-bounded, and digest-bound into each signed manifest and review. The CLI
does not accept caller-selected public key or fingerprint arguments. Root or
key rotation requires an independently approved customer change and trust
configuration update. No production trust material is supplied by Kordex.

Create and reserve the unique run context **before** any scenario begins. The
command requires customer-rooted trust and atomically reserves the random
256-bit nonce, UUID run ID and canonical matrix digest in the configured
customer durable replay registry. The registry must return a signed
`newly-reserved` receipt; a repeated or previously accepted ID/nonce must
return a different status that the tool rejects. The receipt is recorded in
the context. The context expires after seven days, is
created mode `0600`, and cannot be overwritten:

```sh
python3 scripts/verify-m3-evidence-provenance.py new-run \
  --output /secure/m3/qualification-run.json
```

Then execute and collect the unchanged 22 Debian/RHEL matrix records, keeping
fixture data outside the real evidence directory. After collection, create a
canonical unsigned manifest:

```sh
python3 scripts/verify-m3-evidence-provenance.py prepare \
  --evidence-directory /secure/m3/evidence \
  --collector-identity <customer-collector-identity> \
  --collected-at <RFC3339-UTC-time> \
  --run-context /secure/m3/qualification-run.json \
  --output /secure/m3/evidence-manifest.json
```

The customer collector signs the manifest. The signed manifest includes the
pre-run registry reservation receipt. For **each** scenario/platform
pair, an independently authorized customer corroborator creates a canonical
record under the separate corroboration directory and signs it. Each record
binds run ID/nonce, matrix digest, scenario, platform and exact OS version,
approved image self-link and image ID, package policy, host/machine and
Kubernetes Node identities, exact architecture and OS release, image approval
reference and digest, artifact-preflight/package archive/repository snapshot
digests, operation ID, plan digest, evidence digest, collector identity,
collection time, fault method/operator when applicable, customer source-system
reference, and corroboration decision. Extra, missing, duplicate, or unsafe
corroboration files are rejected.
The reviewer signs a separate decision after corroboration and binds the
manifest digest, trust configuration digest, and hash of all 22 corroboration
records. Collector, reviewer, and corroborator public keys must be distinct.

Verification takes only the manifest/signature, review/signature, evidence
directory, and signed corroboration directory; the public keys are resolved
from the fixed customer trust root. The command performs an HTTPS claim against
the replay registry configured in the root-signed trust document. The registry
must durably and atomically reject previously accepted run IDs, nonces, and
manifest digests, and return a fresh signed `newly-accepted` receipt bound to
the verifier's unpredictable challenge and consumes the run reservation exactly
once. The registry must reject duplicate run IDs/nonces both at reservation and
acceptance. Redirects and ambient HTTP proxies are refused. If the trust root, corroboration, current review, or durable registry
is absent or unavailable, verification fails and `qualificationAccepted`
cannot be true. No local-file or in-memory replay fallback exists.

The verifier reports separate structural, artifact-hash, collector signature,
reviewer signature, customer corroboration, freshness, and durable replay
results. It checks run/collection/signing/corroboration/review ordering,
future skew, seven-day expiry, all 22 unique matrix pairs, and current key
authorization. A signature/hash still does not prove physical host origin by
itself: the customer-authorized corroborator must compare the run with
independent cloud, host, Kubernetes, and control-plane records. Synthetic
tests use disposable generated keys and fixture records only; they cannot
produce production acceptance. The customer retains all private signing keys.
