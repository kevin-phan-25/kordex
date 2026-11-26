# Kordex Antigravity + Codex Engineering Model

## Purpose

Antigravity is the technical lead for architecture coordination, infrastructure
orchestration, real-host campaigns, evidence collection, and milestone tracking.
Codex is the principal software engineer and independent technical reviewer
for implementation, tests, security, and reliability. Each has separate task
ownership; neither may silently overwrite the other's conclusions.

The current shared environment has Antigravity CLI `agy 1.5.16` and Codex CLI
`0.171.0`. Both expose MCP server registration commands for local stdio
servers. Antigravity independently read and appended to the shared event
journal; Codex verified the resulting hash chain and independently confirmed
the installed CLI commands. This proves shared-file access, not cryptographic
agent identity. Neither CLI currently has a Kordex coordination MCP server
configured; implementation and client-level verification are still pending.

## File-backed coordination contract

- Board implementation: `scripts/multi_agent_board.py`.
- Event journal: `docs/engineering/multi-agent-events.jsonl`.
- Human task projection: `docs/engineering/multi-agent-task-board.md`.
- Decision record: `docs/engineering/multi-agent-decisions.md`.
- Each record contains agent identity, task ID, UTC timestamp, files/resources,
  finding, recommendation where applicable, evidence references, requested
  action, and current board status.
- The journal is JSON Lines with a sequential SHA-256 hash chain and advisory
  file locking. The CLI only appends. Readers and writers reject malformed,
  partial, reordered, duplicated, or hash-mismatched journal entries.
- Hash chaining detects accidental edits; it is not a digital signature,
  identity proof, authorization system, or defense against an actor who can
  rewrite and recompute the whole file. Agent names are self-declared. Use Git
  review and established human authorization for consequential decisions.
- Keep secrets, credentials, private keys, full evidence packages, customer
  data, and signing material out of the journal. Record redacted references and
  digests only. Coordination handoff approval is never cloud, fault-injection,
  evidence-acceptance, or M3 signoff authorization.
- The journal assumes a shared local filesystem with POSIX advisory-lock
  semantics. A synced copy on separate workspaces does not provide safe
  concurrent writes. If either agent cannot open this exact working tree, stop
  and agree on a supported shared MCP service before enabling parallel work.

Use `python3 scripts/multi_agent_board.py --help` for exact arguments. The
implemented operations are `get_tasks`, `claim_task`, `release_task`,
`post_finding`, `post_recommendation`, `request_review`, `post_feedback`,
`approve_handoff`, `get_status`, `get_decisions`, `record_test_result`,
`record_integration_result`, `record_deployment_result`, and
`record_blocker`. `create_task` initializes a record with owner, reviewer,
priority, dependencies, affected files/resources, acceptance criteria, test
requirements, deployment requirements, and blockers. Every write also requires
the shared message fields. For example:

```sh
python3 scripts/multi_agent_board.py get_tasks
python3 scripts/multi_agent_board.py claim_task \
  --agent codex --task-id M3-EXAMPLE \
  --finding 'Approved implementation task is ready.' \
  --requested-action 'Implement only assigned files.' --status 'In Progress'
```

`approve_handoff` records only engineering handoff. The CLI explicitly records
that it does not authorize cloud mutation or qualification evidence acceptance.
Task completion is rejected until the implementation owner records passing
tests, the separate reviewer accepts the handoff and integration digest, and
deployment-required tasks record a verified deployment result.

## Collaboration sequence

1. Antigravity creates/proposes a task with context, acceptance criteria,
   dependencies, owner, reviewer, and evidence references.
2. Codex independently reviews and posts findings/recommendations; disagreements
   remain visible in separate events.
3. Antigravity records which recommendations it accepts and why, then publishes
   the agreed specification.
4. The implementation owner claims the approved task, changes only assigned
   files, records tests and a handoff.
5. The integration owner inspects the actual diff and records integration or
   runtime results.
6. The reviewer checks the integrated diff and exact test evidence. A local
   handoff event does not count as external trust review or qualification
   acceptance.
7. Close only after implementation, required tests, integration, independent
   verification, and any required runtime evidence are recorded.

## Ownership

Antigravity owns GCP, Terraform plan/apply orchestration, lab infrastructure,
three-node K3s deployments, scenario execution/fault injection, evidence
collection, acceptance tracking, and integration/execution reports. Codex owns
Go/Python/Terraform source changes, bootstrap and application code, automated
tests, security review, and defect fixes. Codex does not independently perform
cloud mutations or real-host operations. Antigravity does not author or approve
its own independent evidence review. Shared files are edited serially: the
listed owner edits; the other reviewer comments without editing; ownership is
transferred in a new event before a second editor makes changes.

## Current gate

Direct shared-journal collaboration is **VERIFIED** by independent Antigravity
and Codex observations. The MCP server is **NOT STARTED** pending review of its
transport, per-process identity, and tool schemas. The requested M3 demo found
a real Terraform CIDR validation defect and a proposed defensive RHEL minor
conversion guard. Codex reproduced the CIDR failure with Terraform 1.17.2 and
challenged the claim that the conversion currently crashes Debian/Ubuntu plans.
That change is waiting for Antigravity's response before implementation. M3
remains the only project milestone in scope and remains incomplete until its 22
real-host rows are independently accepted. Host-upgrade and provider-upgrade
defaults remain off.
