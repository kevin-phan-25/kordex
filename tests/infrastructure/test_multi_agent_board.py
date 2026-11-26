"""Tests for local coordination integrity only; not agent authentication."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import multi_agent_board as board  # noqa: E402


class MultiAgentBoardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "events.jsonl"
        board.execute(board.build_parser().parse_args([
            "--board", str(self.path), "create_task",
            "--agent", "codex", "--task-id", "DEMO-001",
            "--finding", "Create a safe coordination test task.",
            "--requested-action", "Antigravity reviews and proposes the next step.",
            "--status", "Proposed", "--title", "Coordination demo placeholder",
            "--owner", "antigravity", "--reviewer", "codex", "--priority", "P1",
            "--acceptance-criterion", "Both installed agents exchange independently authored events.",
        ]))

    def tearDown(self) -> None:
        self.temp.cleanup()

    def args(self, command: str, *extra: str):
        base = ["--board", str(self.path), command, "--agent", "antigravity",
                "--task-id", "DEMO-001", "--finding", "Coordination event.",
                "--requested-action", "Continue the reviewed handoff.", "--status", "Proposed"]
        return board.build_parser().parse_args(base + list(extra))

    def test_event_has_required_envelope_and_hash_chain(self) -> None:
        event = board.execute(self.args("post_finding", "--evidence", "test evidence"))
        events = board.read_events(self.path)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[-1]["eventSha256"], event["eventSha256"])
        for key in ("agent", "taskId", "timestamp", "files", "resources", "finding",
                    "evidence", "requestedAction", "status"):
            self.assertIn(key, event)

    def test_production_journal_replays_all_events(self) -> None:
        events = board.read_events(board.DEFAULT_LOG)
        self.assertGreaterEqual(len(events), 21)
        self.assertEqual([event["sequence"] for event in events],
                         list(range(1, len(events) + 1)))

    def test_tampered_event_is_rejected_before_append(self) -> None:
        raw = self.path.read_text()
        changed = raw.replace("Create a safe coordination test task.", "silently changed finding")
        self.path.write_text(changed)
        with self.assertRaisesRegex(board.BoardError, "hash mismatch"):
            board.execute(self.args("post_finding"))

    def test_partial_final_record_fails_closed(self) -> None:
        with self.path.open("ab") as stream:
            stream.write(b'{"partial":true}')
        with self.assertRaisesRegex(board.BoardError, "incomplete final record"):
            board.read_events(self.path)

    def test_fifo_is_rejected_without_blocking_read_or_append(self) -> None:
        fifo = Path(self.temp.name) / "events.fifo"
        fifo.parent.mkdir(parents=True, exist_ok=True)
        os.mkfifo(fifo)
        with self.assertRaisesRegex(board.BoardError, "regular file"):
            board.read_events(fifo)
        with self.assertRaisesRegex(board.BoardError, "regular file"):
            board._append(fifo, agent="codex", task_id="DEMO-001", event_type="post_finding",
                          finding="Reject special file.", requested_action="Keep the journal safe.",
                          status="Proposed")

    def test_task_owner_can_claim_but_other_agent_cannot(self) -> None:
        wrong_owner = self.args("claim_task")
        wrong_owner.agent = "codex"
        with self.assertRaisesRegex(board.BoardError, "assigned task owner"):
            board.execute(wrong_owner)
        args = self.args("claim_task")
        args.agent = "antigravity"
        event = board.execute(args)
        self.assertEqual(event["status"], "In Progress")
        self.assertEqual(board.execute(board.build_parser().parse_args(["--board", str(self.path), "get_tasks"]))[0]["claimedBy"], "antigravity")

    def test_owner_and_reviewer_must_be_distinct(self) -> None:
        with self.assertRaisesRegex(board.BoardError, "distinct agents"):
            board.execute(board.build_parser().parse_args([
                "--board", str(self.path), "create_task", "--agent", "codex",
                "--task-id", "BAD-001", "--finding", "finding", "--requested-action", "act",
                "--status", "Proposed", "--title", "bad", "--owner", "codex",
                "--reviewer", "codex", "--priority", "P1", "--acceptance-criterion", "criterion",
            ]))

    def test_handoff_approval_is_distinct_and_does_not_authorize_cloud(self) -> None:
        recommendation = self.args("post_recommendation", "--recommendation", "Use the existing locked JSONL design.")
        board.execute(recommendation)
        board.execute(self.args("request_review"))
        challenge = self.args("post_feedback")
        challenge.agent = "codex"
        challenge.status = "Awaiting Codex Review"
        board.execute(challenge)
        response = self.args("post_feedback")
        response.status = "Awaiting Codex Review"
        board.execute(response)
        args = self.args("approve_handoff", "--decision", "ACCEPTED", "--evidence", "review: " + "b" * 64)
        args.agent = "codex"
        event = board.execute(args)
        self.assertFalse(event["payload"]["authorizesCloudMutation"])
        self.assertFalse(event["payload"]["authorizesQualificationAcceptance"])
        with self.assertRaisesRegex(board.BoardError, "assigned reviewer"):
            board.execute(self.args("approve_handoff", "--decision", "ACCEPTED"))

    def test_test_and_deployment_results_preserve_exact_fields(self) -> None:
        test = board.execute(self.args("record_test_result", "--command", "python -m unittest",
                                       "--exit-code", "1", "--passed", "4", "--failed", "1", "--skipped", "0",
                                       "--evidence", "test output: " + "c" * 64))
        self.assertEqual(test["payload"]["exitCode"], 1)
        deployment = board.execute(self.args("record_deployment_result", "--operation", "read-only inspect",
                                             "--result", "NO MUTATION", "--cost-usd", "0"))
        self.assertEqual(deployment["payload"]["costUsd"], 0.0)

    def test_infrastructure_owner_can_record_deployment_for_code_owned_task(self) -> None:
        create = board.build_parser().parse_args([
            "--board", str(self.path), "create_task", "--agent", "codex",
            "--task-id", "DEPLOY-001", "--finding", "Create deployment review task.",
            "--requested-action", "Antigravity owns runtime deployment.",
            "--status", "Proposed", "--title", "Deployment ownership separation",
            "--owner", "codex", "--reviewer", "antigravity", "--priority", "P1",
            "--acceptance-criterion", "Runtime owner records its own deployment result.",
            "--deployment-requirement", "Antigravity performs runtime validation.",
        ])
        board.execute(create)
        codex_result = board.build_parser().parse_args([
            "--board", str(self.path), "record_deployment_result", "--agent", "codex",
            "--task-id", "DEPLOY-001", "--finding", "Attempt to report deployment as implementer.",
            "--requested-action", "Reject because Antigravity owns runtime work.",
            "--status", "Proposed", "--operation", "deployment test", "--result", "PASS",
        ])
        with self.assertRaisesRegex(board.BoardError, "assigned deployment owner"):
            board.execute(codex_result)
        antigravity_result = board.build_parser().parse_args([
            "--board", str(self.path), "record_deployment_result", "--agent", "antigravity",
            "--task-id", "DEPLOY-001", "--finding", "Runtime deployment verified.",
            "--requested-action", "Attach actual deployment output.",
            "--status", "Proposed", "--operation", "deployment test", "--result", "PASS",
        ])
        result = board.execute(antigravity_result)
        self.assertEqual(result["agent"], "antigravity")
        self.assertEqual(board.execute(board.build_parser().parse_args([
            "--board", str(self.path), "get_tasks"]))[-1]["deploymentOwner"], "antigravity")

    def test_comment_cannot_change_projected_task_status(self) -> None:
        claim = self.args("claim_task")
        claim.agent = "antigravity"
        board.execute(claim)
        finding = self.args("post_finding")
        finding.status = "Blocked"
        with self.assertRaisesRegex(board.BoardError, "cannot change task status"):
            board.execute(finding)
        tasks = board.execute(board.build_parser().parse_args(["--board", str(self.path), "get_tasks"]))
        self.assertEqual(tasks[0]["status"], "In Progress")

    def test_recommendation_cannot_change_projected_task_status(self) -> None:
        claim = self.args("claim_task")
        claim.agent = "antigravity"
        board.execute(claim)
        recommendation = self.args("post_recommendation", "--recommendation", "Keep the task in progress.")
        recommendation.status = "Blocked"
        event_count = len(board.read_events(self.path))
        with self.assertRaisesRegex(board.BoardError, "recommendations cannot change task status"):
            board.execute(recommendation)
        self.assertEqual(len(board.read_events(self.path)), event_count)
        tasks = board.execute(board.build_parser().parse_args(["--board", str(self.path), "get_tasks"]))
        self.assertEqual(tasks[0]["status"], "In Progress")
        same_status = self.args("post_recommendation", "--recommendation", "Keep the task in progress.")
        same_status.status = "In Progress"
        recorded = board.execute(same_status)
        self.assertEqual(recorded["status"], "In Progress")
        self.assertEqual(board.execute(board.build_parser().parse_args([
            "--board", str(self.path), "get_tasks"]))[0]["status"], "In Progress")

    def test_technical_lead_approves_proposal_before_owner_claims(self) -> None:
        create = board.build_parser().parse_args([
            "--board", str(self.path), "create_task", "--agent", "antigravity",
            "--task-id", "LEAD-001", "--finding", "Proposed implementation task.",
            "--requested-action", "Codex implements after lead approval.",
            "--status", "Proposed", "--title", "Approved proposal", "--owner", "codex",
            "--reviewer", "antigravity", "--priority", "P1",
            "--acceptance-criterion", "Only the lead can approve the proposal before claim.",
        ])
        board.execute(create)
        approved = board.build_parser().parse_args([
            "--board", str(self.path), "approve_handoff", "--agent", "antigravity",
            "--task-id", "LEAD-001", "--finding", "Proposal reviewed and approved.",
            "--requested-action", "Codex may claim implementation.", "--status", "Proposed",
            "--decision", "APPROVED",
        ])
        with self.assertRaisesRegex(board.BoardError, "must reference the review evidence"):
            board.execute(approved)
        approved.evidence = ["proposal review: " + "a" * 64]
        event = board.execute(approved)
        self.assertEqual(event["status"], "Approved")
        self.assertFalse(event["payload"]["authorizesCloudMutation"])
        self.assertFalse(event["payload"]["authorizesQualificationAcceptance"])
        claim = board.build_parser().parse_args([
            "--board", str(self.path), "claim_task", "--agent", "codex",
            "--task-id", "LEAD-001", "--finding", "Claim approved implementation.",
            "--requested-action", "Implement accepted specification.", "--status", "Approved",
        ])
        self.assertEqual(board.execute(claim)["status"], "In Progress")

    def test_only_technical_lead_can_approve_proposal(self) -> None:
        approved = self.args("approve_handoff", "--decision", "APPROVED")
        approved.agent = "codex"
        with self.assertRaisesRegex(board.BoardError, "technical lead"):
            board.execute(approved)

    def test_blocker_event_moves_task_to_blocked(self) -> None:
        args = ["--board", str(self.path), "record_blocker", "--agent", "antigravity",
                "--task-id", "DEMO-001", "--finding", "External dependency blocks progress.",
                "--requested-action", "Owner supplies the required input.", "--status", "Proposed",
                "--owner-role", "artifact-owner", "--dependency", "approved artifact digest"]
        board.execute(board.build_parser().parse_args(args))
        tasks = board.execute(board.build_parser().parse_args(["--board", str(self.path), "get_tasks"]))
        self.assertEqual(tasks[0]["status"], "Blocked")
        approve = self.args("approve_handoff", "--decision", "APPROVED",
                            "--evidence", "blocker resolution review: " + "b" * 64)
        approve.status = "Blocked"
        approve.agent = "antigravity"
        approved = board.execute(approve)
        self.assertEqual(approved["status"], "Approved")
        self.assertFalse(approved["payload"]["authorizesCloudMutation"])
        self.assertFalse(approved["payload"]["authorizesQualificationAcceptance"])
        claim = self.args("claim_task")
        claim.status = "Approved"
        self.assertEqual(board.execute(claim)["status"], "In Progress")

    def test_technical_lead_approves_awaiting_codex_review_before_owner_claims(self) -> None:
        board.execute(board.build_parser().parse_args([
            "--board", str(self.path), "request_review", "--agent", "antigravity",
            "--task-id", "DEMO-001", "--finding", "Implementation proposal is ready.",
            "--requested-action", "Technical lead reviews and approves the proposal.",
            "--status", "Proposed",
        ]))
        approval = self.args("approve_handoff", "--decision", "APPROVED",
                             "--evidence", "proposal review: " + "c" * 64)
        approval.agent = "antigravity"
        approval.status = "Awaiting Codex Review"
        event = board.execute(approval)
        self.assertEqual(event["status"], "Approved")
        claim = self.args("claim_task")
        claim.status = "Approved"
        self.assertEqual(board.execute(claim)["status"], "In Progress")

    def test_decisions_and_status_are_derived_from_immutable_events(self) -> None:
        board.execute(self.args("request_review"))
        approved = self.args("approve_handoff", "--decision", "ACCEPTED", "--evidence", "review: " + "b" * 64)
        approved.agent = "codex"
        board.execute(approved)
        decisions = board.execute(board.build_parser().parse_args(["--board", str(self.path), "get_decisions"]))
        status = board.execute(board.build_parser().parse_args(["--board", str(self.path), "get_status"]))
        self.assertEqual(len(decisions), 1)
        self.assertEqual(status["statusCounts"]["Awaiting Integration"], 1)
        self.assertFalse(status["collaborationAuthenticated"])

    def test_completion_requires_tests_handoff_and_separate_integration_review(self) -> None:
        create = board.build_parser().parse_args([
            "--board", str(self.path), "create_task", "--agent", "codex",
            "--task-id", "DEMO-002", "--finding", "Approved implementation task.",
            "--requested-action", "Implement and return for independent integration review.",
            "--status", "Proposed", "--title", "Completion gate test", "--owner", "antigravity",
            "--reviewer", "codex", "--priority", "P1", "--acceptance-criterion", "Reviewed completion.",
        ])
        board.execute(create)
        owner_args = ["--board", str(self.path), "claim_task", "--agent", "antigravity",
                      "--task-id", "DEMO-002", "--finding", "Claim implementation.",
                      "--requested-action", "Implement task.", "--status", "Proposed"]
        board.execute(board.build_parser().parse_args(owner_args))
        close_args = ["--board", str(self.path), "post_feedback", "--agent", "antigravity",
                      "--task-id", "DEMO-002", "--finding", "Attempt early close.",
                      "--requested-action", "Close task.", "--status", "Complete"]
        with self.assertRaisesRegex(board.BoardError, "only the assigned reviewer"):
            board.execute(board.build_parser().parse_args(close_args))
        reviewer_close_args = close_args.copy()
        reviewer_close_args[reviewer_close_args.index("antigravity")] = "codex"
        with self.assertRaisesRegex(board.BoardError, "owner tests"):
            board.execute(board.build_parser().parse_args(reviewer_close_args))

        test_args = ["--board", str(self.path), "record_test_result", "--agent", "antigravity",
                     "--task-id", "DEMO-002", "--finding", "Focused regression suite passed.",
                     "--requested-action", "Request review.", "--status", "In Progress",
                     "--evidence", "test report: " + "d" * 64,
                     "--command", "python -m unittest", "--exit-code", "0", "--passed", "8",
                     "--failed", "0", "--skipped", "0"]
        board.execute(board.build_parser().parse_args(test_args))
        review_request = ["--board", str(self.path), "request_review", "--agent", "antigravity",
                          "--task-id", "DEMO-002", "--finding", "Implementation and tests are ready for review.",
                          "--requested-action", "Review the exact diff and test report.", "--status", "In Progress"]
        board.execute(board.build_parser().parse_args(review_request))
        handoff = ["--board", str(self.path), "approve_handoff", "--agent", "codex",
                   "--task-id", "DEMO-002", "--finding", "Diff reviewed.",
                   "--requested-action", "Antigravity integrates the accepted change.",
                   "--status", "Awaiting Codex Review", "--decision", "ACCEPTED",
                   "--evidence", "review record: " + "e" * 64]
        board.execute(board.build_parser().parse_args(handoff))
        integration = ["--board", str(self.path), "record_integration_result", "--agent", "codex",
                       "--task-id", "DEMO-002", "--finding", "Integrated diff checked.",
                       "--requested-action", "Owner performs final independent verification.",
                       "--status", "Awaiting Independent Verification", "--result", "ACCEPTED",
                       "--reviewed-diff-sha256", "a" * 64, "--evidence", "integration report: " + "f" * 64]
        board.execute(board.build_parser().parse_args(integration))
        close_args += ["--evidence", "reviewed diff sha256: " + "a" * 64]
        with self.assertRaisesRegex(board.BoardError, "only the assigned reviewer"):
            board.execute(board.build_parser().parse_args(close_args))
        close_args[close_args.index("antigravity")] = "codex"
        completed = board.execute(board.build_parser().parse_args(close_args))
        self.assertEqual(completed["status"], "Complete")

    def test_owner_cannot_release_task_as_complete(self) -> None:
        args = ["--board", str(self.path), "release_task", "--agent", "antigravity",
                "--task-id", "DEMO-001", "--finding", "Attempt completion through release.",
                "--requested-action", "Release task.", "--status", "In Progress",
                "--release-status", "Complete"]
        with self.assertRaisesRegex(board.BoardError, "completion requires"):
            board.execute(board.build_parser().parse_args(args))

    def test_owner_can_release_task_without_marking_it_complete(self) -> None:
        args = ["--board", str(self.path), "release_task", "--agent", "antigravity",
                "--task-id", "DEMO-001", "--finding", "Releasing task to backlog for rescheduling.",
                "--requested-action", "Antigravity reclaims it after dependencies clear.",
                "--status", "Proposed", "--release-status", "Backlog"]
        event = board.execute(board.build_parser().parse_args(args))
        self.assertEqual(event["status"], "Backlog")


if __name__ == "__main__":
    unittest.main()
