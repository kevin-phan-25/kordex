#!/usr/bin/env python3
"""Append-only file-backed coordination board for Antigravity and Codex.

This is a coordination log, not an authentication, approval, deployment, or
qualification system. Agent names are self-declared; never put secrets or
private evidence payloads in the log.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import uuid
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOG = ROOT / "docs/engineering/multi-agent-events.jsonl"
AGENTS = {"antigravity", "codex"}
BOARD_STATES = {
    "Backlog",
    "Proposed",
    "Awaiting Codex Review",
    "Approved",
    "In Progress",
    "Awaiting Integration",
    "Awaiting Independent Verification",
    "Blocked",
    "Complete",
}
GENESIS_HASH = "0" * 64
ID_RE = re.compile(r"^[A-Z0-9][A-Z0-9._-]{1,63}$")


class BoardError(ValueError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BoardError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _parse_log(raw: bytes) -> list[dict[str, Any]]:
    if raw and not raw.endswith(b"\n"):
        raise BoardError("coordination log has an incomplete final record; refusing to append")
    events: list[dict[str, Any]] = []
    prior_hash = GENESIS_HASH
    identifiers: set[str] = set()
    for line_number, line in enumerate(raw.splitlines(), 1):
        try:
            event = json.loads(line, object_pairs_hook=_no_duplicate_keys)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise BoardError(f"invalid coordination event at line {line_number}") from error
        if not isinstance(event, dict) or not isinstance(event.get("eventSha256"), str):
            raise BoardError(f"invalid coordination event envelope at line {line_number}")
        supplied_hash = event.pop("eventSha256")
        expected_hash = hashlib.sha256(_canonical(event)).hexdigest()
        event["eventSha256"] = supplied_hash
        if supplied_hash != expected_hash:
            raise BoardError(f"coordination event hash mismatch at line {line_number}")
        if event.get("sequence") != line_number:
            raise BoardError(f"coordination sequence mismatch at line {line_number}")
        if event.get("previousEventSha256") != prior_hash:
            raise BoardError(f"coordination chain mismatch at line {line_number}")
        event_id = event.get("eventId")
        if not isinstance(event_id, str) or event_id in identifiers:
            raise BoardError(f"missing or duplicate event ID at line {line_number}")
        identifiers.add(event_id)
        _validate_event(event, line_number)
        prior_hash = supplied_hash
        events.append(event)
    return events


def _validate_event(event: dict[str, Any], line_number: int) -> None:
    required = {
        "schemaVersion", "eventId", "sequence", "timestamp", "agent", "taskId",
        "eventType", "files", "resources", "finding", "evidence", "requestedAction",
        "status", "payload", "previousEventSha256", "eventSha256",
    }
    missing = required - set(event)
    if missing:
        raise BoardError(f"coordination event line {line_number} lacks {sorted(missing)}")
    if (event["schemaVersion"] != 1 or not isinstance(event["agent"], str)
            or event["agent"] not in AGENTS or not isinstance(event["status"], str)
            or event["status"] not in BOARD_STATES):
        raise BoardError(f"unsupported agent, status, or schema at line {line_number}")
    if not isinstance(event["taskId"], str) or not ID_RE.fullmatch(event["taskId"]):
        raise BoardError(f"invalid task ID at line {line_number}")
    if (not isinstance(event["finding"], str) or not event["finding"].strip()
            or not isinstance(event["requestedAction"], str) or not event["requestedAction"].strip()):
        raise BoardError(f"empty finding or requested action at line {line_number}")
    if not isinstance(event["timestamp"], str):
        raise BoardError(f"invalid timestamp at line {line_number}")
    try:
        timestamp = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
    except ValueError as error:
        raise BoardError(f"invalid timestamp at line {line_number}") from error
    if timestamp.tzinfo is None:
        raise BoardError(f"timestamp must include a timezone at line {line_number}")
    for name in ("files", "resources", "evidence"):
        if not isinstance(event[name], list) or any(not isinstance(v, str) or not v.strip() for v in event[name]):
            raise BoardError(f"invalid {name} at line {line_number}")
    if not isinstance(event["payload"], dict):
        raise BoardError(f"invalid payload at line {line_number}")


def read_events(path: Path = DEFAULT_LOG) -> list[dict[str, Any]]:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return []
    except OSError as error:
        raise BoardError("coordination log must be a regular file, not a symlink") from error
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise BoardError("coordination log is not a regular file")
        fcntl.flock(descriptor, fcntl.LOCK_SH)
        chunks = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        events = _parse_log(b"".join(chunks))
        _tasks(events)
        return events
    finally:
        os.close(descriptor)


def _append(path: Path, *, agent: str, task_id: str, event_type: str,
            finding: str, requested_action: str, status: str,
            files: list[str] | None = None, resources: list[str] | None = None,
            evidence: list[str] | None = None, payload: dict[str, Any] | None = None,
            recommendation: str | None = None) -> dict[str, Any]:
    if agent not in AGENTS:
        raise BoardError("agent must be antigravity or codex")
    if not ID_RE.fullmatch(task_id):
        raise BoardError("task ID must use 2-64 uppercase letters, digits, dot, underscore, or hyphen")
    if status not in BOARD_STATES:
        raise BoardError(f"status must be one of {sorted(BOARD_STATES)}")
    if not finding.strip() or not requested_action.strip():
        raise BoardError("finding and requested action are required")
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o644)
    except OSError as error:
        raise BoardError("cannot safely open coordination log") from error
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise BoardError("coordination log is not a regular file")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        os.lseek(descriptor, 0, os.SEEK_SET)
        chunks = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        events = _parse_log(b"".join(chunks))
        previous_hash = events[-1]["eventSha256"] if events else GENESIS_HASH
        body: dict[str, Any] = {
            "schemaVersion": 1,
            "eventId": str(uuid.uuid4()),
            "sequence": len(events) + 1,
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "agent": agent,
            "taskId": task_id,
            "eventType": event_type,
            "files": files or [],
            "resources": resources or [],
            "finding": finding,
            "evidence": evidence or [],
            "requestedAction": requested_action,
            "status": status,
            "payload": payload or {},
            "previousEventSha256": previous_hash,
        }
        if recommendation is not None:
            body["recommendation"] = recommendation
        body["eventSha256"] = hashlib.sha256(_canonical(body)).hexdigest()
        _validate_event(body, len(events) + 1)
        os.lseek(descriptor, 0, os.SEEK_END)
        data = _canonical(body) + b"\n"
        written = 0
        while written < len(data):
            written += os.write(descriptor, data[written:])
        os.fsync(descriptor)
        return body
    finally:
        os.close(descriptor)


def _tasks(events: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    tasks: dict[str, dict[str, Any]] = {}
    for event in events:
        task_id = event["taskId"]
        if event["eventType"] == "task_created":
            if task_id in tasks:
                raise BoardError(f"duplicate task creation: {task_id}")
            task = {**event["payload"], "taskId": task_id, "status": event["status"],
                              "lastUpdated": event["timestamp"], "lastEventSha256": event["eventSha256"]}
            # Older tasks predate an explicit deployment owner. In this repo,
            # Antigravity owns runtime deployment; new tasks record this role.
            task.setdefault("deploymentOwner", "antigravity" if task.get("deploymentRequirements") else task.get("owner"))
            tasks[task_id] = task
            continue
        if task_id not in tasks:
            raise BoardError(f"event references task before creation: {task_id}")
        task = tasks[task_id]
        if event["eventType"] == "task_created":
            raise BoardError(f"duplicate task creation: {task_id}")
        if event["eventType"] == "task_claimed":
            if task.get("claimedBy") and task["claimedBy"] != event["agent"]:
                raise BoardError(f"conflicting task claims: {task_id}")
            task["claimedBy"] = event["agent"]
            task["status"] = "In Progress"
        elif event["eventType"] == "task_released":
            task["claimedBy"] = None
            task["status"] = event["status"]
        elif event["eventType"] in {"review_requested", "handoff_decision", "task_completed"}:
            task["status"] = event["status"]
        elif event["eventType"] == "record_blocker":
            task["status"] = "Blocked"
        elif event["eventType"] == "record_integration_result":
            if event["payload"].get("result") == "ACCEPTED":
                task["status"] = "Awaiting Independent Verification"
            else:
                task["status"] = "In Progress"
        task["lastUpdated"] = event["timestamp"]
        task["lastEventSha256"] = event["eventSha256"]
    return tasks


def _task(events: list[dict[str, Any]], task_id: str) -> dict[str, Any]:
    try:
        return _tasks(events)[task_id]
    except KeyError as error:
        raise BoardError(f"unknown task: {task_id}") from error


def _common(parser: argparse.ArgumentParser, *, require_status: bool = True) -> None:
    parser.add_argument("--agent", required=True, choices=sorted(AGENTS))
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--finding", required=True)
    parser.add_argument("--requested-action", required=True)
    parser.add_argument("--file", action="append", default=[])
    parser.add_argument("--resource", action="append", default=[])
    parser.add_argument("--evidence", action="append", default=[])
    if require_status:
        parser.add_argument("--status", required=True, choices=sorted(BOARD_STATES))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--board", type=Path, default=DEFAULT_LOG)
    commands = parser.add_subparsers(dest="command", required=True)

    create = commands.add_parser("create_task")
    _common(create)
    create.add_argument("--title", required=True)
    create.add_argument("--owner", required=True, choices=sorted(AGENTS))
    create.add_argument("--reviewer", required=True, choices=sorted(AGENTS))
    create.add_argument("--deployment-owner", choices=sorted(AGENTS))
    create.add_argument("--priority", required=True, choices=["P0", "P1", "P2", "P3"])
    create.add_argument("--dependency", action="append", default=[])
    create.add_argument("--acceptance-criterion", action="append", required=True)
    create.add_argument("--test-requirement", action="append", default=[])
    create.add_argument("--deployment-requirement", action="append", default=[])
    create.add_argument("--blocked-by", action="append", default=[])

    for name in ("claim_task", "release_task", "post_finding", "post_recommendation",
                 "request_review", "post_feedback", "approve_handoff", "record_test_result",
                 "record_integration_result", "record_deployment_result", "record_blocker"):
        command = commands.add_parser(name)
        _common(command)
        if name == "release_task":
            command.add_argument("--release-status", required=True, choices=sorted(BOARD_STATES))
        elif name == "post_recommendation":
            command.add_argument("--recommendation", required=True)
        elif name == "approve_handoff":
            command.add_argument("--decision", required=True,
                                 choices=["APPROVED", "ACCEPTED", "REJECTED", "CHANGES_REQUESTED"])
        elif name == "record_test_result":
            command.add_argument("--command", dest="test_command", required=True)
            command.add_argument("--exit-code", required=True, type=int)
            command.add_argument("--passed", required=True, type=int)
            command.add_argument("--failed", required=True, type=int)
            command.add_argument("--skipped", required=True, type=int)
        elif name == "record_integration_result":
            command.add_argument("--result", required=True, choices=["ACCEPTED", "REJECTED", "CHANGES_REQUESTED"])
            command.add_argument("--reviewed-diff-sha256", required=True)
        elif name == "record_deployment_result":
            command.add_argument("--operation", required=True)
            command.add_argument("--result", required=True)
            command.add_argument("--cost-usd", type=float)
        elif name == "record_blocker":
            command.add_argument("--owner-role", required=True)
            command.add_argument("--dependency", required=True)

    commands.add_parser("get_tasks")
    commands.add_parser("get_status")
    commands.add_parser("get_decisions")
    return parser


def execute(args: argparse.Namespace) -> Any:
    events = read_events(args.board)
    command = args.command
    if command == "get_tasks":
        return sorted(_tasks(events).values(), key=lambda task: task["taskId"])
    if command == "get_status":
        tasks = list(_tasks(events).values())
        counts = {state: sum(task["status"] == state for task in tasks) for state in sorted(BOARD_STATES)}
        return {"taskCount": len(tasks), "statusCounts": counts,
                "lastEventSha256": events[-1]["eventSha256"] if events else None,
                "collaborationAuthenticated": False}
    if command == "get_decisions":
        return [event for event in events if event["eventType"] in {"handoff_decision", "decision"}]

    task_id = args.task_id
    payload: dict[str, Any] = {}
    event_type = command
    status = args.status
    recommendation = None
    finding = args.finding
    requested_action = args.requested_action
    if command == "create_task":
        if args.owner == args.reviewer:
            raise BoardError("task owner and reviewer must be distinct agents")
        if status not in {"Proposed", "Backlog"}:
            raise BoardError("tasks must be created as Proposed or Backlog")
        if task_id in _tasks(events):
            raise BoardError(f"task already exists: {task_id}")
        event_type = "task_created"
        deployment_owner = args.deployment_owner or ("antigravity" if args.deployment_requirement else args.owner)
        payload = {"title": args.title, "owner": args.owner, "reviewer": args.reviewer,
                   "deploymentOwner": deployment_owner,
                   "priority": args.priority, "dependencies": args.dependency,
                   "acceptanceCriteria": args.acceptance_criterion,
                   "testRequirements": args.test_requirement,
                   "deploymentRequirements": args.deployment_requirement,
                   "blockedBy": args.blocked_by}
    else:
        task = _task(events, task_id)
        if command == "claim_task":
            if args.agent != task["owner"]:
                raise BoardError("only the assigned task owner can claim it")
            if task.get("status") not in {"Proposed", "Approved"}:
                raise BoardError("only Proposed or Approved tasks can be claimed")
            if task.get("claimedBy"):
                raise BoardError("task is already claimed")
            status, event_type = "In Progress", "task_claimed"
        elif command == "release_task":
            if args.agent != task["owner"]:
                raise BoardError("only the task owner can release it")
            status, event_type = args.release_status, "task_released"
            if status == "Complete":
                raise BoardError("task completion requires the reviewed completion handoff")
            payload = {"claimedBy": None}
        elif command == "request_review":
            if args.agent != task["owner"] or args.agent == task["reviewer"]:
                raise BoardError("review must be requested by the owner for a distinct reviewer")
            if task["status"] not in {"Proposed", "Approved", "In Progress"}:
                raise BoardError("review can be requested only from Proposed, Approved, or In Progress")
            status, event_type = "Awaiting Codex Review" if task["reviewer"] == "codex" else "Awaiting Independent Verification", "review_requested"
        elif command == "post_feedback":
            if args.agent not in {task["owner"], task["reviewer"]}:
                raise BoardError("feedback must come from the task owner or assigned reviewer")
            event_type = "review_feedback" if args.agent == task["reviewer"] else "owner_response"
            if status == "Complete":
                if args.agent != task["reviewer"]:
                    raise BoardError("only the assigned reviewer can close a task")
                task_events = [event for event in events if event["taskId"] == task_id]
                handoff_accepted = any(event["eventType"] == "handoff_decision"
                                       and event["payload"].get("decision") == "ACCEPTED"
                                       and event["agent"] == task["reviewer"] for event in task_events)
                tests_passed = any(event["eventType"] == "record_test_result"
                                   and event["agent"] == task["owner"]
                                   and event["payload"].get("exitCode") == 0
                                   and event["payload"].get("failed") == 0
                                   and event["payload"].get("passed", 0) > 0 for event in task_events)
                integration_accepted = any(event["eventType"] == "record_integration_result"
                                           and event["agent"] == task["reviewer"]
                                           and event["payload"].get("result") == "ACCEPTED"
                                           for event in task_events)
                if not (handoff_accepted and tests_passed and integration_accepted):
                    raise BoardError("task cannot complete before owner tests, reviewer handoff approval, and reviewer integration acceptance")
                if not args.evidence:
                    raise BoardError("task completion needs a reference to the independent verification evidence")
                if task.get("deploymentRequirements") and not any(
                    event["eventType"] == "record_deployment_result"
                    and event["payload"].get("result") in {"PASS", "VERIFIED"}
                    and event["evidence"]
                    for event in task_events
                ):
                    raise BoardError("deployment-required task needs a verified deployment result before completion")
                event_type = "task_completed"
            elif status != task["status"]:
                raise BoardError("feedback cannot change task status")
        elif command == "approve_handoff":
            event_type = "handoff_decision"
            payload = {"decision": args.decision, "authorizesCloudMutation": False,
                       "authorizesQualificationAcceptance": False}
            if args.decision == "APPROVED":
                if args.agent != "antigravity":
                    raise BoardError("only the Antigravity technical lead can approve a proposal")
                if task["status"] not in {"Proposed", "Awaiting Codex Review", "Blocked"}:
                    raise BoardError("proposal approval requires Proposed, Awaiting Codex Review, or Blocked state")
                if not args.evidence:
                    raise BoardError("approved proposal must reference the review evidence")
                status = "Approved"
            else:
                if args.agent != task["reviewer"]:
                    raise BoardError("only the assigned reviewer can decide a coordination handoff")
                if task["status"] not in {"Awaiting Codex Review", "Awaiting Independent Verification"}:
                    raise BoardError("handoff decision requires a pending review state")
            if args.decision == "APPROVED":
                pass
            elif args.decision == "ACCEPTED":
                if not args.evidence:
                    raise BoardError("accepted handoff must reference the review evidence")
                status = "Awaiting Integration"
            elif args.decision == "CHANGES_REQUESTED":
                status = "In Progress"
            else:
                status = "Blocked"
        elif command == "post_recommendation":
            if status != task["status"]:
                raise BoardError("findings and recommendations cannot change task status")
            recommendation = args.recommendation
        elif command == "record_test_result":
            if args.agent != task["owner"]:
                raise BoardError("test results must be recorded by the assigned implementation owner")
            if min(args.passed, args.failed, args.skipped) < 0:
                raise BoardError("test counts cannot be negative")
            if not args.evidence:
                raise BoardError("test result must reference captured command output or report")
            if status != task["status"]:
                raise BoardError("test result cannot change task status")
            payload = {"command": args.test_command, "exitCode": args.exit_code,
                       "passed": args.passed, "failed": args.failed, "skipped": args.skipped}
        elif command == "record_integration_result":
            if args.agent != task["reviewer"]:
                raise BoardError("integration result must be recorded by the distinct assigned reviewer")
            if not re.fullmatch(r"[a-f0-9]{64}", args.reviewed_diff_sha256):
                raise BoardError("reviewed diff digest must be a lowercase SHA-256 value")
            if args.result == "ACCEPTED" and not args.evidence:
                raise BoardError("accepted integration review must reference its review evidence")
            event_type = "record_integration_result"
            status = "Awaiting Independent Verification" if args.result == "ACCEPTED" else "In Progress"
            payload = {"result": args.result, "reviewedDiffSha256": args.reviewed_diff_sha256}
        elif command == "record_deployment_result":
            if args.agent != task.get("deploymentOwner", task["owner"]):
                raise BoardError("deployment results must be recorded by the assigned deployment owner")
            if args.cost_usd is not None and args.cost_usd < 0:
                raise BoardError("deployment cost cannot be negative")
            if status != task["status"]:
                raise BoardError("deployment result cannot change task status")
            payload = {"operation": args.operation, "result": args.result,
                       "costUsd": args.cost_usd}
        elif command == "record_blocker":
            status = "Blocked"
            payload = {"ownerRole": args.owner_role, "dependency": args.dependency}
        elif command == "post_finding":
            if status != task["status"]:
                raise BoardError("findings cannot change task status")

    if status == "Complete" and command != "post_feedback":
        raise BoardError("only the reviewed completion handoff can mark a task complete")

    return _append(args.board, agent=args.agent, task_id=task_id, event_type=event_type,
                   finding=finding, requested_action=requested_action, status=status,
                   files=args.file, resources=args.resource, evidence=args.evidence,
                   payload=payload, recommendation=recommendation)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        print(json.dumps(execute(args), ensure_ascii=False, sort_keys=True, indent=2))
    except BoardError as error:
        print(f"coordination board error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
