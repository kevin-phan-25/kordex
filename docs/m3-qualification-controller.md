# M3 qualification controller and customer execution sequence

This is the operator entry point for moving from local checks to customer
qualification. It composes existing checks and keeps each approval boundary
separate. It never calls GCP, Terraform, a customer registry, a private
registry, or a host. A `PASS` from `inspect` means only that local repository
and tool checks passed. A file hash means only that the referenced bytes match
the manifest. Neither is customer verification or host qualification.

The controller is `scripts/m3_qualification.py`. Run from the repository root.
Its JSON output has one explicit stage status and next action. A nonzero exit
means that stage is not ready. It does not progress automatically:

```sh
python3 scripts/m3_qualification.py inspect
python3 scripts/m3_qualification.py schema > /secure/m3-customer-inputs-v1.schema.json
python3 scripts/m3_qualification.py example > /tmp/m3-customer-inputs.synthetic.json
python3 scripts/m3_qualification.py inputs --manifest /secure/m3/customer-inputs.json
python3 scripts/m3_qualification.py status --manifest /secure/m3/customer-inputs.json
```

The version-1 machine-readable schema and a `fixtureOnly: true` example are
checked in at [`docs/schemas/m3-customer-inputs-v1.json`](schemas/m3-customer-inputs-v1.json)
and [`docs/examples/m3-customer-inputs.synthetic.json`](examples/m3-customer-inputs.synthetic.json).
The status report expands the pinned matrix into 22 separate records with
scenario, OS, acceptance criteria, selected-image claim (marked unverified),
host/node identity, operation, evidence references, execution, verification,
review, acceptance, blocker, and owner fields. With no signed evidence package
the row remains `NOT RUN`; no status command can promote it.

The dependency DAG is
[`docs/m3-qualification-dependencies.json`](m3-qualification-dependencies.json).
The status report validates its schema and acyclicity, includes its canonical
SHA-256, and lists unresolved nodes with their owner, required input, consumer,
validation entry point, fail-closed behavior, and next action. `status` is
deterministic for the same validated inputs and current expiry state; it never
queries a cloud or customer service. The configured project/region/zone shown
in the report are repository targets, not live GCP verification.

`example` is deliberately `fixtureOnly: true` and cannot pass production
readiness. Copy the schema, create a customer-owned manifest with every
required slot, and set `fixtureOnly` to false only for real customer inputs.
Each populated slot has exactly `reference`, `sha256`, and `expiresAt`. The
reference is relative to the manifest directory, points to a regular file,
and must remain within that directory. Secret files and Terraform variable or
state files are prohibited. The controller calculates the file hash again;
the supplied hash is not accepted as a signature, approval, or proof of origin.
The manifest never accepts a caller-provided status field.

The manifest carries separate Debian and RHEL artifact-preflight input maps
and reports. The controller reuses the local readiness helper to check report
freshness, input/file binding, selected OS release, architecture, and package
policy. This operation is read-only and makes no registry or mirror request.
Because the report is unsigned and its origin is not established by a local
hash, a successful recheck is still reported as `UNVERIFIED`; it cannot make
the inputs or qualification stage pass. The customer must retain the exact
preflight command output and separately establish the trust/signature and
registry results through their existing verifier workflow.

Input states are calculated by the controller:

| State | Meaning |
|---|---|
| `NOT_PROVIDED` | Required slot is null. |
| `INVALID` | Schema, file safety, or digest verification failed. |
| `EXPIRED` | The supplied evidence expiry has passed. |
| `UNVERIFIED` | File and digest match; its domain verifier and independent review have not run. |
| `VERIFIED` | Reserved for a domain verifier that actually establishes the binding. A file hash alone never sets it. |
| `APPROVED` | Reserved for the applicable authorized signed approval. A supplied string never sets it. |
| `BLOCKED` | The check requires a customer backend, live service, or approval not available to this local controller. |

## Dependency sequence and ownership

Each cloud or host action is a separate approval boundary. The exact human
message must match the phrase and scope below; the controller does not consume
these phrases as a shortcut around input or evidence verification.

| Boundary | Exact phrase | Scope |
|---|---|---|
| Project review | `APPROVE_M3_PROJECT_REVIEW kordex-fleet-platform-515416` | Read-only project review only. |
| Terraform plan | `APPROVE_M3_PLAN kordex-fleet-platform-515416` | Plan only; no apply. |
| Terraform apply | `APPROVE_M3_APPLY kordex-fleet-platform-515416` | The separately reviewed plan only. |
| Connectivity | `APPROVE_M3_CONNECTIVITY_TEST` | Live approved private connectivity test only. |
| Preflight | `APPROVE_M3_PREFLIGHT` | Read-only preflight only. |
| Scenario execution | `APPROVE_M3_EXECUTE <scenario_id> <os_id>` | One scenario on one OS. |
| Fault injection | `APPROVE_M3_FAULT_INJECT <scenario_id> <os_id>` | One approved injection on one OS. |
| Evidence acceptance | `APPROVE_M3_EVIDENCE_ACCEPT <scenario_id> <os_id>` | Review of that row only. |
| M3 sign-off | `APPROVE_M3_SIGNOFF` | Final package only after all criteria pass. |

No matching approval phrase was supplied for the later phases in this Phase A
work. The first potential future approval is project review, but it must not be
requested or acted on until Phase B customer inputs and trust have been
validated.

The stages are dependencies, not a single green preflight. `status` is the
last controller stage and aggregates them; it reports
`qualificationAccepted: false` until the complete real-host package has passed
the existing customer-rooted verifier and durable replay registry. Final evidence
acceptance remains the existing customer-rooted provenance verifier plus the
durable replay registry.

| Order / class | Owner | Exact deliverable and consumer | Verification and expected result | Current state / unlocks |
|---|---|---|---|---|
| 1. Repository implementation complete | Kordex maintainer | Controller, input schema, trust-state adapter, existing artifact/readiness/evidence verifiers | `python3 scripts/m3_qualification.py inspect`; local `PASS` is limited to repository/tool checks | Implemented locally; unlocks intake bookkeeping only |
| 2. Customer decision required | Customer security/platform owner | Select HTTPS durable CAS trust-state backend and HTTPS durable replay-registry backend; provide customer, backend, namespace, and authorized identity bindings | Deploy backend in an isolated conformance namespace; run the relevant conformance suite below and obtain an independent signed conformance review | `BLOCKED`; unlocks customer trust verification and replay testing |
| 3. Customer artifact required | Security, release, Debian, RHEL and K3s custodians | Root-signed trust config; signed release and digest lock; provenance lock; exact Debian 13 image and point release; exact RHEL 9.8+ image/release; signed APT/RPM metadata; package policies and actual packages; K3s binary/system-image locks and archives; Helm allowlist | `python3 scripts/m3_artifact_preflight.py --inputs <customer-artifact-inputs.json> --report <artifact-preflight.json>`; require `PASS`, then independently review signer, policy and source | `NOT PROVIDED`; unlocks profile-specific input review |
| 4. Customer artifact required | Private registry administrator | Customer-ingested OCI images at exact approved private destinations; destination digest report | Existing read-only private-registry verifier through artifact preflight must verify all locked references/digests; archive staging alone is insufficient | `NOT PROVIDED`; unlocks bootstrap inputs |
| 5. External service integration required | Customer network/PKI owner | Private workstation-to-relay route, DNS, relay/client certificates and CA, URI SAN cluster mapping, mirror route, firewall approval, IAP/OS Login and serial recovery evidence | Run the installed agent `connectivity-check --allowed-cidr <approved-private-cidr>` on the customer route with approved mTLS environment; require JSON `status: verified`; retain relay and API evidence | `BLOCKED`; unlocks deployed agent connectivity |
| 6. GCP approval required | GCP project, security and billing owners | Confirm project `kordex-fleet-platform-515416`, project number/labels, APIs/IAM, principal/impersonation, quota, image availability, recovery, cost and $300 hard ceiling | Customer-run read-only review; independently verify outputs and principal attestation. No GCP query is run by this controller | `BLOCKED`; unlocks separate Terraform plan authorization |
| 7. GCP approval required | Independent deployment reviewer, then separate apply approver | Exact reviewed plan digest and signed plan approval; separate authorization to apply that exact plan | `python3 scripts/self_managed_lab.py validate` is local backend-disabled validation. Only after all earlier gates, the guarded `plan` command produces a plan for independent review. `apply` needs a separate explicit approval and confirmation | `BLOCKED`; no plan or apply was run |
| 8. Real-host execution required | Customer cluster and maintenance owners | Approved disposable three-node Debian 13 hosts, then exact RHEL 9.8+ hosts; host/Node identity inventory; package/window/recovery approvals | `python3 scripts/self_managed_lab.py preflight ...`, then one approved `execute` per matrix row; all operations require the existing guards and default-off execution gate | `NOT RUN`; unlocks per-platform scenarios |
| 9. Independent evidence acceptance required | Collector, distinct customer corroborator and independent reviewer | Fresh run ID/nonce, 22 signed evidence rows, host-origin corroboration, artifact hashes, recovery evidence, signed review, durable replay receipts | `python3 scripts/verify-m3-evidence-provenance.py verify ...`; acceptance requires all 22 original rows, distinct authorized identities, fresh trust, customer corroboration and a durable registry receipt | `BLOCKED`; unlocks M3 sign-off only after every check passes |

## Customer trust-state adapter contract

`scripts/m3_trust_state.py` exposes `CustomerTrustStateClient` and the
`TrustStateTransport` protocol for a customer-selected backend. A transport
must identify the exact protocol, customer, backend, namespace and HTTPS
endpoint reference; implement a durable read and atomic compare-and-swap; and
return Ed25519-signed receipts. The key fingerprint is calculated from actual
public-key bytes and must be pinned independently by the customer. Receipts
bind action, customer, namespace, backend, deterministic transition ID,
sequence, configuration digest, durable state, timestamps and audit ID.

The client accepts only the same generation/digest or the next consecutive
generation. It rejects rollback, sequence reuse with a different digest,
skipped generations, stale/future receipts, invalid signatures and backend
outages. A lost update acknowledgment is resolved by one signed read; the
client never blindly repeats the mutation. There is no reset API. Customer
break-glass recovery must require separate customer authorization and produce
an independently reviewed audit record.

The client does **not** prove that a backend's `durable` claim is true. The
customer must provide a production backend, demonstrate persistence across
service/process restart and independent operator instances, test concurrent
compare-and-swap and interrupted writes, and have its storage/backup/restore
controls independently reviewed. Synthetic tests below exercise the client
protocol only and are not production conformance.

The root-signed `qualification-trust.json` must include a `trustState` object
with exactly `backendIdentity`, `namespace`, `endpointReference`,
`attestorIdentity`, `conformanceReportSha256`, `conformanceReviewerIdentity`,
`conformanceReviewedAt`, and `conformanceExpiresAt`. The attestor key has the
`trust-state-attestor` role; exactly one such key is permitted. The conformance
reviewer must be a distinct authorized `reviewer`. The signed report is read
from `/etc/kordex/m3/trust-state-conformance.json` with its detached signature
at `/etc/kordex/m3/trust-state-conformance.json.sig`; the report digest,
protocol, backend, endpoint, conformance namespace, suite digest, reviewer,
decision and expiry must match the root-signed configuration. Production
loading goes through `m3_trust_state.load_customer_trust(transport, ...)`,
which verifies root signature and the report before asking the adapter to
advance the monotonic state. There is no selected customer transport adapter
in this repository, so the production trust stage remains blocked.

The customer adapter can call the test harness in its own isolated test
namespace. The entry point is
`scripts/m3_trust_state_conformance.py:run_conformance`; pass a
`transport_factory(namespace)` that reconnects to the same durable backend
state after constructing a fresh adapter, plus the customer ID, configured
backend identity, HTTPS endpoint reference, root-pinned attestor public key
and fingerprint, and the customer evidence reference. The returned candidate
has `decision: pending-independent-review`; a separate authorized reviewer
must inspect the test evidence, issue the accepted signed report, and the
customer root custodian must include that report digest in the next signed
trust configuration. The harness result always has
`productionTrustAccepted: false`. Synthetic/local database tests cannot
establish customer durability.

The replay-registry interface and conformance harness already exist in
`scripts/verify-m3-evidence-provenance.py` and
`scripts/m3_replay_registry_conformance.py`. They require signed receipts,
atomic uniqueness, restart durability, duplicate run/nonce rejection,
concurrent claim behavior, idempotent retry and lost-ack recovery. Only an
isolated synthetic adapter has been exercised locally. Production acceptance
remains blocked until a customer-operated service passes the conformance
harness and an independent reviewer accepts its durability and authorization
evidence.

## Stage commands

These commands are local/read-only unless otherwise stated. No controller
stage performs a destructive or externally modifying operation.

```sh
python3 scripts/m3_qualification.py inspect
python3 scripts/m3_qualification.py inputs --manifest /secure/m3/customer-inputs.json
python3 scripts/m3_qualification.py trust
python3 scripts/m3_qualification.py cloud-review
python3 scripts/m3_qualification.py plan-review
python3 scripts/m3_qualification.py connectivity
python3 scripts/m3_qualification.py qualification --evidence-directory /secure/m3/evidence
python3 scripts/m3_qualification.py evidence
python3 scripts/m3_qualification.py status --manifest /secure/m3/customer-inputs.json \
  --evidence-directory /secure/m3/evidence
```

The qualification stage invokes only the existing structural verifier. Its
`UNVERIFIED` result is not a host-origin claim. The evidence stage does not
submit a registry claim. After customer trust, signatures, corroboration and
registry conformance are ready, the designated customer evidence operator must
run the existing explicit verifier:

```sh
python3 scripts/verify-m3-evidence-provenance.py verify \
  --evidence-directory /secure/m3/evidence \
  --manifest /secure/m3/evidence/manifest.json \
  --manifest-signature /secure/m3/evidence/manifest.sig \
  --review /secure/m3/evidence/review.json \
  --review-signature /secure/m3/evidence/review.sig \
  --corroboration-directory /secure/m3/evidence/corroboration
```

That final command may contact and mutate the explicitly configured customer
replay registry when the review is accepted. Do not run it until the customer
registry owner and evidence reviewer authorize that exact package. Expected
success is JSON with `qualificationAccepted: true` and 22 corroborated rows;
any missing, stale, replayed, untrusted, conflicting or fixture record must
fail closed.

## Plan, deployment and spend boundary

The designated project, region and zone above are repository/user-provided
values, not proof of live state. The $300 figure is a hard maximum, not
confirmed credit. Before any cloud-mutating action, the customer must provide
current billing headroom and an itemized maximum estimate for three VMs,
three disks, snapshots and retention, artifact/registry storage, image and
package transfer, logs/monitoring, DNS and recovery access. Include the expected
runtime and teardown date. Stop if the estimate or actual spend may exceed the
ceiling.

The guarded lab commands are separate approvals: `validate` is local and does
not create a plan; `plan` is a cloud read operation requiring separate user
approval; `apply` creates resources and requires its own approval; `destroy`
deletes resources and requires another approval. This document and the
controller authorize none of them. Never use raw Terraform commands for this
qualification workflow. The operator credential/IAM boundary must independently
prevent unauthorized infrastructure changes; wrapper checks alone cannot
prevent a sufficiently privileged operator from invoking Terraform directly.

## Qualification acceptance

The immutable canonical matrix is
`tests/integration/host_upgrade_failure_matrix.json`. Keep all 11 scenarios
separate for Debian 13 and RHEL 9.8+: `clean-upgrade`,
`cancel-during-executing`, `cancel-during-reboot`,
`operator-restart-during-executing`, `ssh-loss-during-apply`,
`partial-package-application`, `reboot-never-returns`,
`ssh-loss-after-reboot-request`, `wrong-machine-id`,
`node-replaced-during-recovery`, and `wrong-kernel-after-reboot`.

Every row is currently **NOT RUN**. The seven external fault scenarios require
approved, disposable-only mechanisms with strict duration limits, tested
restoration and independent target identity confirmation. Do not improvise an
unbounded shutdown, route/firewall change or reboot suppression. Use the
existing per-scenario runbooks and abort if restoration cannot be guaranteed.
Ubuntu 24.04 remains supplemental only. M3 is **NOT COMPLETE** until all 22
real-host rows have passed, customer trust and replay protections are verified,
host-origin corroboration and independent review are accepted, and recovery
and cleanup evidence is retained in customer custody.

The stage controller requires every manifest reference to be independently
`VERIFIED` or `APPROVED`, both platform target approvals to be independently
verified, and a separate signed residual-risk acceptance for each exact image
before the qualification stage can inspect evidence. The current controller
does not promote hash-only references or execute customer domain verifiers on
the customer's behalf; those results remain `UNVERIFIED` until their existing
domain-specific verifiers and independent review run. The image acceptance
must state that boot-disk `sourceImage`/`sourceImageId` verification detects a
substitution after creation but does not eliminate the GCE image
create-time identity race. No such customer acceptance is present.

`inspect` verifies tracked source and local tools and explicitly reports the
configured project target as not live-verified. It also checks that
`KORDEX_ENABLE_HOST_UPGRADES` remains default-off in the operator source. It
does not query GCP or enable the gate.

Phase A is repository-only. No GCP query, Terraform operation, connectivity
test, host mutation, qualification, or fault injection was performed. Before
any project review, complete customer input and trust intake; then the exact
first GCP approval boundary is `APPROVE_M3_PROJECT_REVIEW
kordex-fleet-platform-515416`. That phrase authorizes project review only.
