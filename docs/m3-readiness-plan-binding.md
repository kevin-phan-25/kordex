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

## Canonical binding and drift checks

Canonical JSON uses UTF-8, sorted object keys, compact separators, and rejects
non-finite numbers and duplicate keys. Order-insensitive CIDR/DNS collections
are sorted before hashing. The plan binding covers:

- Exact complete non-secret Terraform variable values.
- Canonical network input values.
- Artifact input-map values and the canonical artifact preflight report.
- Terraform source, startup templates, embedded helper files, and the locked
  provider declaration.
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
the self-link and the immutable resource identity; replacing an image under
the same name changes the ID and fails closed.

Google image metadata does not independently establish the image's in-guest
Debian point release or RHEL minor. The image owner must inspect/test the
approved image and cite evidence. The owner record is structurally checked,
hashed, and marked `PROVIDED`; an independent reviewer must still verify the
image evidence. The owner record is public/non-secret JSON with exactly these
fields:

```json
{
  "schemaVersion": 1,
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
  "approvedAt": "<RFC3339 timestamp with timezone>",
  "evidenceReference": "<customer-controlled image inspection evidence reference>"
}
```

Set `qualification_image_approval_sha256` in the complete Terraform JSON to
the SHA-256 of canonical JSON for this record (sorted keys, compact
separators, UTF-8, no trailing newline). Set
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

`scripts/verify-m3-evidence-provenance.py prepare` runs the existing
structural verifier and produces a canonical manifest binding the canonical
matrix digest, all evidence-file hashes, scenario/platform pairs, exact image
identity, image-owner approval reference and digest, artifact-preflight and
package-archive digests, package policy, host/machine identity, Kubernetes
Node UID, operation/plan IDs, collection identity/time, and case-specific
fault method and operator. The manifest is unsigned until the customer-controlled
collector signs it with an Ed25519 key. `verify` checks the collector's
detached signature and independently supplied public-key fingerprint, then
checks a separately signed reviewer decision bound to the manifest digest.
The collector and reviewer must use distinct key fingerprints; a rejected
review is a failing result.

A content hash detects later edits but does not establish evidence origin.
A collector signature attests the collector's statement but does not prove a
physical host produced the data. Only records emitted by the guarded
`--execute` path carry the required explicit `real-host` claim; this is still
a claim, not cryptographic proof of physical origin. The independent reviewer must compare the
manifest with customer-controlled cloud/host control-plane records and raw
fault logs. The verifier distinguishes structural validity, hashes, binding,
collector signature, and reviewer acceptance. Synthetic fixtures cannot be
included in the canonical real-host evidence manifest. No customer signature
or review is created by repository tests.

```sh
python3 scripts/verify-m3-evidence-provenance.py prepare \
  --evidence-directory /secure/m3/evidence \
  --collector-identity <customer-collector-identity> \
  --collected-at <RFC3339-UTC-time> \
  --output /secure/m3/evidence-manifest.json
```

Sign and verify the manifest and reviewer decision using the customer's
approved signing process. Keep private signing keys in customer key custody;
only public keys, signatures, manifest/review records, and fingerprints are
inputs to verification. See the command's `verify --help` for exact required
flags. Public trust fingerprints must be obtained independently of the
evidence package.
