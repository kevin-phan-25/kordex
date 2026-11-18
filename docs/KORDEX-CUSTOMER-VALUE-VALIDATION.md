# Customer value validation

**Can Kordex Fleet Platform make a difficult, high-risk enterprise maintenance
operation dramatically safer, easier, and more auditable than the multiple tools
customers currently use? Not yet demonstrated.** Local implementation and
regression evidence is promising engineering evidence, not a measured customer
outcome or a production qualification.

## Paired reference workflow

Use the same disposable worker image, exact packages/kernel, workload/PDB,
network conditions and independent reviewer for both workflows. Restore the
baseline between runs and retain the raw observations. Never use initial
customer production infrastructure for this comparison.

Document the conventional baseline before measuring it: inventory/CMDB lookup,
health inspection, change approval, package planning/staging, kubectl cordon and
eviction, SSH or existing automation apply, reboot, identity/package/kernel
inspection, workload recovery, uncordon and audit/report assembly. Record the
actual tools in that organization; do not assume it needs paid products.

For Kordex, measure the corresponding inventory → plan → preview → independent
approval → campaign → checkpoint/recovery → audit export workflow. Include any
required out-of-console intervention; do not omit setup, manual SSH, recovery
or evidence collection steps merely to improve the comparison.

| Measure | Source / definition | Current result |
|---|---|---|
| Manual actions | Timestamped observer log; one deliberate operator interaction per action | NOT MEASURED |
| Tool/context switches | Chronological changes in actual tools used | NOT MEASURED |
| Active operator effort | Observed working intervals, separate from approval/reboot waiting | NOT MEASURED |
| Maintenance/disruption/recovery duration | Durable event and receipt times, plus observer log | NOT MEASURED |
| Unauthorized disruption / unsafe blocking | Signed negative cases and observed host/node state | Local tests only; real workflow NOT RUN |
| Audit completeness | Reconstruct actor, approval, target/policy, actions, receipts, recovery and release independently | Local tests only; reference export NOT RUN |
| Restart/partition recovery | Same operation identity, no duplicate mutation, retained fences until verification | Local tests only; real failure matrix NOT RUN |
| Cost impact | Customer-provided license/infrastructure/hourly assumptions and measured effort | NOT MEASURED; no savings claim |

Retain a CSV or JSON observation log with run ID, UTC timestamp, actor, action,
tool, start/end, outcome and evidence reference. Publish raw logs, hashes,
environment identities, measurement definitions and paired results before any
percentage or cost claim. Hypothetical assumptions must be labeled separately
from measured results. No licensing feature may inhibit ongoing recovery.
