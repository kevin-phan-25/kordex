#!/usr/bin/env python3
"""Guarded GKE node-pool upgrade qualification drill.

The default mode is read-only. A real provider operation requires --execute and
KORDEX_GKE_DISPOSABLE_CONFIRM to equal the exact canonical node-pool resource.
This script never creates GCP resources and must only target a disposable pool.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


class DrillError(RuntimeError):
    pass


PAGE_SIZE = 500
MAX_OFFSET = 100_000


def required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise DrillError(f"required environment variable is missing: {name}")
    return value


def run_json(args: list[str]) -> dict:
    try:
        output = subprocess.check_output(args, text=True, stderr=subprocess.STDOUT, timeout=30)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        details = getattr(error, "output", b"") or b""
        if isinstance(details, bytes):
            details = details.decode(errors="replace")
        raise DrillError(f"command failed ({args[0]}): {str(details)[-1500:]}") from error
    try:
        return json.loads(output)
    except json.JSONDecodeError as error:
        raise DrillError(f"command returned invalid JSON ({args[0]})") from error


def parse_time(value: str) -> dt.datetime:
    try:
        result = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as error:
        raise DrillError("management plane returned an invalid observation timestamp") from error
    if result.tzinfo is None:
        raise DrillError("management plane returned a timestamp without a timezone")
    return result.astimezone(dt.timezone.utc)


def version_tuple(value: str) -> tuple[int, int, int, int]:
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)-gke\.(\d+)", value)
    if not match:
        raise DrillError(f"version is not a pinned GKE release: {value!r}")
    return tuple(int(part) for part in match.groups())


class Hub:
    def __init__(self, origin: str, token: str):
        parsed = urllib.parse.urlparse(origin)
        if parsed.scheme != "https" and not (parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"}):
            raise DrillError("KORDEX_API must use HTTPS, except for loopback development")
        if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise DrillError("KORDEX_API must be an origin")
        self.origin = origin.rstrip("/")
        self.token = token

    def request(self, method: str, path: str, body: dict | None = None) -> dict:
        data = None if body is None else json.dumps(body, separators=(",", ":")).encode()
        request = urllib.request.Request(
            self.origin + path,
            method=method,
            data=data,
            headers={
                "Authorization": "Bearer " + self.token,
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                decoded = json.loads(response.read())
        except urllib.error.HTTPError as error:
            detail = error.read(4096).decode(errors="replace")
            raise DrillError(f"Kordex API returned HTTP {error.code}: {detail}") from error
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
            raise DrillError(f"Kordex API request failed: {error}") from error
        if not isinstance(decoded, dict):
            raise DrillError("Kordex API returned an unexpected response")
        return decoded


def api_path(org_id: str, suffix: str) -> str:
    return f"/v1/organizations/{urllib.parse.quote(org_id, safe='')}/{suffix}"


def list_all(hub: Hub, path: str) -> list[dict]:
    """Read every page, rejecting malformed or truncated pagination responses."""
    items: list[dict] = []
    offset = 0
    while True:
        page = hub.request("GET", f"{path}?limit={PAGE_SIZE}&offset={offset}")
        page_items = page.get("items")
        if (not isinstance(page_items, list) or page.get("limit") != PAGE_SIZE
                or page.get("offset") != offset):
            raise DrillError("management plane returned invalid paginated inventory")
        items.extend(page_items)
        if len(page_items) < PAGE_SIZE:
            return items
        offset += len(page_items)
        if offset > MAX_OFFSET:
            raise DrillError("inventory exceeds the API pagination safety limit; refusing a partial preflight")


def get_inventory(hub: Hub, org_id: str, cluster_id: str) -> tuple[dict, list[dict]]:
    clusters = list_all(hub, api_path(org_id, "clusters"))
    cluster = next((item for item in clusters if item.get("id") == cluster_id), None)
    if cluster is None or cluster.get("provider") != "gke" or not cluster.get("connected"):
        raise DrillError("registered cluster is missing, not GKE, or disconnected")
    now = dt.datetime.now(dt.timezone.utc)
    for field in ("observedAt", "lastHeartbeatAt"):
        observed = parse_time(cluster.get(field, ""))
        if (now - observed).total_seconds() > 90 or observed > now + dt.timedelta(minutes=2):
            raise DrillError(f"cluster {field} is stale or from the future")
    nodes = list_all(hub, api_path(org_id, f"clusters/{urllib.parse.quote(cluster_id, safe='')}/nodes"))
    return cluster, nodes


def local_nodes(kubectl: str, pool: str) -> tuple[str, list[dict]]:
    try:
        context = subprocess.check_output(
            [kubectl, "config", "current-context"], text=True, stderr=subprocess.STDOUT, timeout=30
        ).strip()
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        details = getattr(error, "output", b"") or b""
        if isinstance(details, bytes):
            details = details.decode(errors="replace")
        raise DrillError(f"cannot read the active Kubernetes context: {str(details)[-1500:]}") from error
    if not context:
        raise DrillError("kubectl returned an empty active context")
    items = run_json([kubectl, "get", "nodes", "-o", "json"]).get("items", [])
    selected = [node for node in items if node.get("metadata", {}).get("labels", {}).get("cloud.google.com/gke-nodepool") == pool]
    if not selected:
        raise DrillError("no local Kubernetes nodes match the configured GKE node pool")
    for node in selected:
        conditions = {condition["type"]: condition["status"] for condition in node.get("status", {}).get("conditions", [])}
        if conditions.get("Ready") != "True" or node.get("spec", {}).get("unschedulable", False):
            raise DrillError(f"GKE pool node {node['metadata'].get('name')} is not Ready and schedulable")
    return context, selected


def check_pool_identity(nodes: list[dict], project: str, location: str, pool: str) -> None:
    for node in nodes:
        metadata = node.get("metadata", {})
        provider_id = node.get("spec", {}).get("providerID", "")
        zone = metadata.get("labels", {}).get("topology.kubernetes.io/zone", "")
        expected_prefix = f"gce://{project}/{zone}/"
        if not zone or not (zone == location or zone.startswith(location + "-")) or not provider_id.startswith(expected_prefix):
            raise DrillError(f"node {metadata.get('name')} provider identity does not match the configured GKE resource")
        if metadata.get("labels", {}).get("cloud.google.com/gke-nodepool") != pool:
            raise DrillError("node pool membership changed during preflight")


def verify_replacement_nodes(before: list[dict], after: list[dict], target_version: str) -> list[str]:
    if not before or len(after) != len(before):
        raise DrillError("GKE node pool membership did not recover to its pre-upgrade size")
    before_uids = {node.get("metadata", {}).get("uid") for node in before}
    after_uids = [node.get("metadata", {}).get("uid") for node in after]
    if None in before_uids or None in after_uids or len(set(after_uids)) != len(after_uids):
        raise DrillError("GKE node pool contains an unknown or duplicate node identity")
    if before_uids.intersection(after_uids):
        raise DrillError("one or more original node identities remain after the provider operation")
    for node in after:
        version = node.get("status", {}).get("nodeInfo", {}).get("kubeletVersion", "").lstrip("v")
        if version != target_version:
            raise DrillError("replacement node Kubernetes versions do not all match the pinned target")
    return sorted(after_uids)


def check_live_pool(gcloud: str, project: str, location: str, cluster: str, pool: str, target: str, allow_target: bool = False) -> dict:
    description = run_json([
        gcloud, "container", "node-pools", "describe", pool,
        "--project", project, "--location", location, "--cluster", cluster, "--format=json",
    ])
    settings = description.get("upgradeSettings") or {}
    strategy = settings.get("strategy", "")
    if strategy not in ("", "SURGE", "NODE_POOL_UPDATE_STRATEGY_UNSPECIFIED"):
        raise DrillError(f"unsupported live GKE upgrade strategy: {strategy}")
    if settings.get("maxSurge") != 1 or settings.get("maxUnavailable") != 0:
        raise DrillError("live GKE settings must have maxSurge=1 and maxUnavailable=0")
    current = description.get("version", "")
    current_version, target_version = version_tuple(current), version_tuple(target)
    if current_version[:2] != target_version[:2] or target_version < current_version or (target_version == current_version and not allow_target):
        raise DrillError("target must be a higher explicit patch in the current Kubernetes minor version")
    if description.get("status") != "RUNNING":
        raise DrillError(f"GKE node pool is not RUNNING: {description.get('status', 'unknown')}")
    return {"version": current, "status": description.get("status"), "etag": description.get("etag"),
            "upgradeSettings": settings, "imageType": (description.get("config") or {}).get("imageType")}


def check_policy(hub: Hub, org_id: str, cluster_id: str, policy_name: str, resource: str, target: str, digest: str) -> dict:
    catalog = hub.request("GET", api_path(org_id, f"clusters/{urllib.parse.quote(cluster_id, safe='')}/maintenance-policies"))
    capabilities = catalog.get("capabilities") or {}
    observed = parse_time(catalog.get("observedAt", ""))
    if (dt.datetime.now(dt.timezone.utc) - observed).total_seconds() > 45:
        raise DrillError("operator policy catalog is stale")
    if not capabilities.get("gkeNodePoolUpgrade"):
        raise DrillError("local operator does not report GKE upgrades enabled")
    policy = next((item for item in catalog.get("items", []) if item.get("policy", {}).get("name") == policy_name), None)
    if policy is None or policy.get("suspended"):
        raise DrillError("GKE maintenance policy is missing or suspended")
    plan = policy.get("providerUpgrade") or {}
    if plan.get("schemaVersion") != 2 or plan.get("provider") != "gke" or plan.get("resource") != resource or plan.get("targetVersion") != target or plan.get("maxSurge") != 1 or plan.get("maxUnavailable") != 0:
        raise DrillError("policy does not exactly match the approved GKE resource, target and disruption settings")
    if policy.get("providerPlanDigest") != digest or policy.get("providerPlanInvalid"):
        raise DrillError("policy plan digest is invalid or differs from the requested digest")
    return policy["policy"]


def verify_workloads(kubectl: str) -> dict:
    deployments = run_json([kubectl, "get", "deployments", "-A", "-o", "json"]).get("items", [])
    stateful_sets = run_json([kubectl, "get", "statefulsets", "-A", "-o", "json"]).get("items", [])
    daemon_sets = run_json([kubectl, "get", "daemonsets", "-A", "-o", "json"]).get("items", [])
    failures = []
    for item in deployments:
        metadata, spec, status = item.get("metadata", {}), item.get("spec", {}), item.get("status", {})
        desired = spec.get("replicas", 1)
        if status.get("observedGeneration", 0) < metadata.get("generation", 0) or status.get("availableReplicas", 0) < desired:
            failures.append(f"{metadata.get('namespace')}/{metadata.get('name')}")
    for item in stateful_sets:
        metadata, spec, status = item.get("metadata", {}), item.get("spec", {}), item.get("status", {})
        desired = spec.get("replicas", 1)
        if status.get("observedGeneration", 0) < metadata.get("generation", 0) or status.get("readyReplicas", 0) < desired:
            failures.append(f"{metadata.get('namespace')}/{metadata.get('name')}")
    for item in daemon_sets:
        metadata, status = item.get("metadata", {}), item.get("status", {})
        desired = status.get("desiredNumberScheduled", 0)
        if status.get("observedGeneration", 0) < metadata.get("generation", 0) or status.get("numberReady", 0) < desired or status.get("updatedNumberScheduled", 0) < desired:
            failures.append(f"{metadata.get('namespace')}/{metadata.get('name')}")
    if failures:
        raise DrillError("workload recovery is incomplete: " + ", ".join(failures[:20]))
    return {"deploymentsChecked": len(deployments), "statefulSetsChecked": len(stateful_sets),
            "daemonSetsChecked": len(daemon_sets), "unavailableWorkloads": []}


def redacted_operation(operation: dict) -> dict:
    return {key: value for key, value in operation.items() if key not in {"command", "authorization", "signature"}}


def validate_execution_confirmation(resource: str, confirmation: str) -> None:
    if confirmation != resource:
        raise DrillError("--execute requires KORDEX_GKE_DISPOSABLE_CONFIRM to exactly equal the full node-pool resource")


def write_evidence(path: Path, evidence: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    temporary.chmod(0o600)
    temporary.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true", help="submit one signed UpgradeNodePool operation")
    parser.add_argument("--evidence", type=Path, help="write the redacted drill record to this JSON file")
    parser.add_argument("--poll-seconds", type=float, default=10)
    parser.add_argument("--timeout-seconds", type=int, default=14400)
    parser.add_argument("--verification-timeout-seconds", type=int, default=1800,
                        help="maximum time to wait for Kubernetes node and workload recovery after GKE completes")
    args = parser.parse_args()

    evidence: dict = {"drill": "gke-node-pool-upgrade", "startedAt": dt.datetime.now(dt.timezone.utc).isoformat(), "mode": "execute" if args.execute else "preflight"}
    try:
        if args.timeout_seconds < 1 or args.verification_timeout_seconds < 1 or args.poll_seconds <= 0:
            raise DrillError("operation timeout, verification timeout, and polling interval must be positive")
        api = required("KORDEX_API")
        token = required("KORDEX_ADMIN_TOKEN")
        org_id = required("KORDEX_ORG_ID")
        cluster_id = required("KORDEX_CLUSTER_ID")
        project = required("KORDEX_GKE_PROJECT")
        location = required("KORDEX_GKE_LOCATION")
        cluster_name = required("KORDEX_GKE_CLUSTER")
        pool = required("KORDEX_GKE_NODE_POOL")
        policy_name = required("KORDEX_GKE_POLICY")
        target_version = required("KORDEX_GKE_TARGET_VERSION")
        digest = required("KORDEX_GKE_PLAN_DIGEST")
        expected_context = required("KORDEX_GKE_EXPECTED_CONTEXT")
        gcloud, kubectl = os.environ.get("GCLOUD", "gcloud"), os.environ.get("KUBECTL", "kubectl")
        resource = f"projects/{project}/locations/{location}/clusters/{cluster_name}/nodePools/{pool}"
        evidence.update({"resource": resource, "targetVersion": target_version, "policy": policy_name, "planDigest": digest})

        hub = Hub(api, token)
        cluster_record, inventory = get_inventory(hub, org_id, cluster_id)
        if cluster_record.get("name") != cluster_name:
            raise DrillError("registered cluster name does not match the GKE resource")
        kube_uid = run_json([kubectl, "get", "namespace", "kube-system", "-o", "json"]).get("metadata", {}).get("uid")
        if not kube_uid or kube_uid != cluster_record.get("clusterUid"):
            raise DrillError("local Kubernetes cluster identity does not match the registered cluster UID")

        context, nodes = local_nodes(kubectl, pool)
        if context != expected_context:
            raise DrillError(f"kubectl context mismatch: expected {expected_context!r}, got {context!r}")
        check_pool_identity(nodes, project, location, pool)
        local_by_uid = {node.get("metadata", {}).get("uid"): node for node in nodes}
        inventory_pool = [node for node in inventory if node.get("labels", {}).get("cloud.google.com/gke-nodepool") == pool]
        if {node.get("uid") for node in inventory_pool} != set(local_by_uid):
            raise DrillError("central inventory and live Kubernetes pool membership differ")
        if any(not node.get("ready") or node.get("unschedulable") for node in inventory_pool):
            raise DrillError("central inventory reports a pool node unhealthy or unschedulable")

        live_pool = check_live_pool(gcloud, project, location, cluster_name, pool, target_version)
        policy = check_policy(hub, org_id, cluster_id, policy_name, resource, target_version, digest)
        evidence.update({"context": context, "clusterUid": kube_uid, "poolBefore": live_pool,
                         "nodeUidsBefore": sorted(local_by_uid), "nodeCount": len(nodes), "policyIdentity": policy})
        operation_id = str(uuid.uuid4())
        evidence["operationId"] = operation_id
        evidence["preflightPassed"] = True
        evidence["outcome"] = "PreflightPassed"

        if args.execute:
            validate_execution_confirmation(resource, os.environ.get("KORDEX_GKE_DISPOSABLE_CONFIRM", ""))
            request = {
                "operationId": operation_id,
                "nodeName": nodes[0]["metadata"]["name"],
                "nodeUid": nodes[0]["metadata"]["uid"],
                "action": "UpgradeNodePool",
                "planDigest": digest,
                "policy": policy,
            }
            suffix = f"clusters/{urllib.parse.quote(cluster_id, safe='')}/operations"
            created = hub.request("POST", api_path(org_id, suffix), request)
            evidence["operationCreatedAt"] = dt.datetime.now(dt.timezone.utc).isoformat()
            terminal = {"Succeeded", "Failed", "Cancelled", "RecoveryRequired"}
            deadline = time.monotonic() + args.timeout_seconds
            latest = created
            while time.monotonic() < deadline:
                page = hub.request("GET", api_path(org_id, suffix + "?limit=500&offset=0"))
                latest = next((item for item in page.get("items", []) if item.get("id") == operation_id), latest)
                evidence["lastOperation"] = redacted_operation(latest)
                if latest.get("phase") in terminal:
                    break
                time.sleep(max(1.0, min(args.poll_seconds, 60.0)))
            else:
                raise DrillError("operation poll timed out; operation may still be active; inspect Kordex before acting")
            if latest.get("phase") != "Succeeded":
                evidence["outcome"] = latest.get("phase", "Unknown")
                raise DrillError(f"Kordex operation ended in {latest.get('phase')}: {((latest.get('status') or {}).get('reason', 'unknown'))}")

            verification_deadline = time.monotonic() + args.verification_timeout_seconds
            last_verification_error = "post-upgrade evidence is not ready"
            while time.monotonic() < verification_deadline:
                try:
                    after_pool = check_live_pool(gcloud, project, location, cluster_name, pool, target_version, allow_target=True)
                    _, after_nodes = local_nodes(kubectl, pool)
                    check_pool_identity(after_nodes, project, location, pool)
                    after_uids = verify_replacement_nodes(nodes, after_nodes, target_version)
                    workload_evidence = verify_workloads(kubectl)
                    break
                except DrillError as verification_error:
                    last_verification_error = str(verification_error)
                    evidence["lastPostUpgradeVerificationError"] = last_verification_error
                    remaining = verification_deadline - time.monotonic()
                    if remaining > 0:
                        time.sleep(min(max(1.0, min(args.poll_seconds, 60.0)), remaining))
            else:
                raise DrillError("post-upgrade verification timed out; inspect GKE and workload state before acting: " + last_verification_error)
            evidence.update({"poolAfter": after_pool, "nodeUidsAfter": after_uids,
                             "workloadRecovery": workload_evidence, "completedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
                             "outcome": "Succeeded"})
        return_code = 0
    except (DrillError, KeyError, ValueError) as error:
        evidence["outcome"] = "Failed"
        evidence["error"] = str(error)
        return_code = 1
    finally:
        evidence["finishedAt"] = dt.datetime.now(dt.timezone.utc).isoformat()
        if args.evidence:
            write_evidence(args.evidence, evidence)
        print(json.dumps(evidence, indent=2, sort_keys=True))
    return return_code


if __name__ == "__main__":
    sys.exit(main())
