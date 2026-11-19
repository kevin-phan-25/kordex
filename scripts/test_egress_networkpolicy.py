from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
CONTROL_CHART = ROOT / "deployments/helm/kordex-control-plane"
DASHBOARD_CHART = ROOT / "deployments/helm/kordex-dashboard"
AGENT_CHART = ROOT / "deployments/helm/kordex-agent"
OPERATOR_CHART = ROOT / "deployments/helm/kordex-operator"
KUSTOMIZE_OVERLAY = ROOT / "deployments/kustomize/hub/overlays/self-hosted-restricted-egress"
SPOKE_KUSTOMIZE_OVERLAY = ROOT / "deployments/kustomize/overlays/self-managed-restricted-egress"
DIGEST = "sha256:" + "a" * 64


def rule(namespace: str, selector: dict[str, str], protocol: str, port: int) -> dict:
    return {
        "to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": namespace}}, "podSelector": {"matchLabels": selector}}],
        "ports": [{"protocol": protocol, "port": port}],
    }


DNS = rule("kube-system", {"k8s-app": "kube-dns"}, "UDP", 53)
DATABASE = rule("kordex-data", {"app.kubernetes.io/name": "postgres"}, "TCP", 5432)
IDENTITY = rule("identity", {"app.kubernetes.io/name": "oidc-provider"}, "TCP", 443)
API = {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kordex-management"}}, "podSelector": {"matchLabels": {"app.kubernetes.io/component": "api"}}}], "ports": [{"protocol": "TCP", "port": 8080}]}


def documents(rendered: str) -> list[dict]:
    return [item for item in yaml.safe_load_all(rendered) if isinstance(item, dict)]


class EgressNetworkPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.helm = shutil.which(os.environ.get("HELM", "helm"))
        cls.kubectl = shutil.which(os.environ.get("KUBECTL", "kubectl"))
        if not cls.helm:
            raise unittest.SkipTest("helm is required for the egress chart tests")
        if not cls.kubectl:
            raise unittest.SkipTest("kubectl is required for the Kustomize egress test")

    def helm_template(self, chart: Path, values: dict | None = None, dashboard: bool = False) -> subprocess.CompletedProcess[str]:
        args = [self.helm, "template", "test", str(chart), "--namespace", "kordex-management"]
        if dashboard:
            args += [
                "--set", "image.repository=ghcr.io/example/kordex-dashboard",
                "--set", "dashboardURL=https://dashboard.example",
                "--set", "apiURL=https://api.example",
                "--set", "oidc.issuer=https://identity.example",
                "--set", "oidc.clientID=kordex-dashboard",
                "--set", "oidc.secretName=kordex-dashboard-identity",
            ]
        else:
            args += [
                "--set", "credentialsSecretName=kordex-credentials",
                "--set", "oidc.issuer=https://identity.example",
                "--set", "oidc.audience=kordex-api",
            ]
        args += ["--set-string", f"image.digest={DIGEST}"]
        with tempfile.TemporaryDirectory() as temp:
            if values is not None:
                values_path = Path(temp) / "values.yaml"
                values_path.write_text(yaml.safe_dump(values, sort_keys=False), encoding="utf-8")
                args += ["--values", str(values_path)]
            return subprocess.run(args, capture_output=True, text=True)

    def spoke_helm_template(self, chart: Path, values: dict | None = None, operator: bool = False) -> subprocess.CompletedProcess[str]:
        args = [self.helm, "template", "test", str(chart), "--namespace", "kordex-system"]
        if operator:
            args += ["--set", "clusterID=80bd80f9-f097-4474-86f4-b80986fd5423", "--set", "hubPublicKeysConfigMap=hub-trust"]
        else:
            args += [
                "--set", "controlPlaneURL=https://hub.example",
                "--set", "clusterID=80bd80f9-f097-4474-86f4-b80986fd5423",
                "--set", "enrollmentSecretName=enrollment",
            ]
        args += ["--set-string", f"image.digest={DIGEST}"]
        with tempfile.TemporaryDirectory() as temp:
            if values is not None:
                values_path = Path(temp) / "values.yaml"
                values_path.write_text(yaml.safe_dump(values, sort_keys=False), encoding="utf-8")
                args += ["--values", str(values_path)]
            return subprocess.run(args, capture_output=True, text=True)

    def spoke_kustomize_template(self, overlay: str) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as temp:
            target_root = Path(temp) / "kustomize"
            source_root = ROOT / "deployments/kustomize"
            paths = dict.fromkeys((
                "base",
                "components/agent",
                "components/operator",
                "overlays/self-managed",
                f"overlays/{overlay}",
            ))
            for relative in paths:
                source = source_root / relative
                target = target_root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                ignore = (lambda _directory, names: {"keys.json"} & set(names)) if relative == "overlays/self-managed" else None
                shutil.copytree(source, target, ignore=ignore)
            trust_file = target_root / "overlays/self-managed/keys.json"
            trust_file.write_text('{"test-key":"public-test-key-only"}\n', encoding="utf-8")
            return subprocess.run(
                [self.kubectl, "kustomize", str(target_root / "overlays" / overlay)],
                capture_output=True,
                text=True,
            )

    @staticmethod
    def egress_policies(rendered: str) -> dict[str, dict]:
        found = {}
        for item in documents(rendered):
            if item.get("kind") != "NetworkPolicy" or "Egress" not in item.get("spec", {}).get("policyTypes", []):
                continue
            selector = item["spec"]["podSelector"].get("matchLabels", {})
            component = selector.get("app.kubernetes.io/component")
            if component is None:
                component = item["metadata"]["name"].removesuffix("-egress").rsplit("-", 1)[-1]
            found[component] = item
        return found

    def assert_policy_selects_deployed_workload(self, rendered: str, policy: dict) -> None:
        selector = policy["spec"]["podSelector"].get("matchLabels", {})
        self.assertTrue(selector)
        workloads = [item for item in documents(rendered) if item.get("kind") in {"Deployment", "Job"}]
        self.assertTrue(any(
            all(item.get("spec", {}).get("template", {}).get("metadata", {}).get("labels", {}).get(key) == value for key, value in selector.items())
            for item in workloads
        ), f"no rendered Deployment or Job matches egress selector {selector}")

    def assert_bounded_egress_rules(self, policy: dict) -> None:
        for egress in policy["spec"]["egress"]:
            self.assertTrue(egress.get("to"))
            self.assertTrue(egress.get("ports"))
            for destination in egress["to"]:
                self.assertNotIn(destination.get("ipBlock", {}).get("cidr"), {"0.0.0.0/0", "::/0"})
            for port in egress["ports"]:
                self.assertIn(port.get("protocol"), {"TCP", "UDP"})
                self.assertIsInstance(port.get("port"), int)
                self.assertGreaterEqual(port["port"], 1)
                self.assertLessEqual(port["port"], 65535)

    def test_helm_default_leaves_egress_unrestricted(self) -> None:
        results = (
            self.helm_template(CONTROL_CHART),
            self.helm_template(DASHBOARD_CHART, dashboard=True),
            self.spoke_helm_template(AGENT_CHART),
            self.spoke_helm_template(OPERATOR_CHART, operator=True),
        )
        for result in results:
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(self.egress_policies(result.stdout), {})

    def test_spoke_egress_requires_explicit_rules_and_selects_only_its_workload(self) -> None:
        values = {"networkPolicy": {"egress": {"enabled": True}}}
        for chart, operator in ((AGENT_CHART, False), (OPERATOR_CHART, True)):
            missing = self.spoke_helm_template(chart, values, operator)
            self.assertNotEqual(missing.returncode, 0)
            self.assertIn("networkPolicy.egress.rules", missing.stderr)

            enabled = {"networkPolicy": {"egress": {"enabled": True, "rules": [DNS, API]}}}
            result = self.spoke_helm_template(chart, enabled, operator)
            self.assertEqual(result.returncode, 0, result.stderr)
            policies = self.egress_policies(result.stdout)
            self.assertEqual(set(policies), {"agent" if not operator else "operator"})
            policy = next(iter(policies.values()))
            self.assert_policy_selects_deployed_workload(result.stdout, policy)
            self.assertEqual(policy["spec"]["policyTypes"], ["Egress"])
            self.assertEqual(len(policy["spec"]["egress"]), 2)
            self.assert_bounded_egress_rules(policy)

    def test_spoke_egress_schema_rejects_unbounded_or_invalid_rules(self) -> None:
        bad_rules = [
            [{"to": [{"ipBlock": {"cidr": "0.0.0.0/0"}}], "ports": [{"protocol": "TCP", "port": 443}]}],
            [{"to": [{"ipBlock": {"cidr": "::/0"}}], "ports": [{"protocol": "TCP", "port": 443}]}],
            [{"to": [{"ipBlock": {"cidr": "10.0.0.0/8"}}], "ports": []}],
            [{"to": [{"ipBlock": {"cidr": "10.0.0.0/8"}}], "ports": [{"protocol": "SCTP", "port": 443}]}],
            [{"to": [{"ipBlock": {"cidr": "10.0.0.0/8"}}], "ports": [{"protocol": "TCP", "port": 65536}]}],
            [{"to": [{}], "ports": [{"protocol": "TCP", "port": 443}]}],
        ]
        for chart, operator in ((AGENT_CHART, False), (OPERATOR_CHART, True)):
            for rules in bad_rules:
                values = {"networkPolicy": {"egress": {"enabled": True, "rules": rules}}}
                result = self.spoke_helm_template(chart, values, operator)
                self.assertNotEqual(result.returncode, 0, f"accepted invalid rules: {rules}")

    def test_kustomize_default_leaves_egress_unrestricted(self) -> None:
        result = subprocess.run([
            self.kubectl, "kustomize",
            str(ROOT / "deployments/kustomize/hub/overlays/self-hosted"),
        ], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.egress_policies(result.stdout), {})
        spoke = self.spoke_kustomize_template("self-managed")
        self.assertEqual(spoke.returncode, 0, spoke.stderr)
        self.assertEqual(self.egress_policies(spoke.stdout), {})

    def test_spoke_restricted_kustomize_overlay_has_bounded_egress(self) -> None:
        result = self.spoke_kustomize_template("self-managed-restricted-egress")
        self.assertEqual(result.returncode, 0, result.stderr)
        policies = self.egress_policies(result.stdout)
        self.assertEqual(set(policies), {"agent", "operator"})
        for policy in policies.values():
            self.assertEqual(policy["metadata"]["namespace"], "kordex-system")
            self.assert_policy_selects_deployed_workload(result.stdout, policy)
            self.assertEqual(policy["spec"]["policyTypes"], ["Egress"])
            self.assert_bounded_egress_rules(policy)

        agent = policies["agent"]
        operator = policies["operator"]
        agent_cidrs = {
            peer["ipBlock"]["cidr"]
            for entry in agent["spec"]["egress"]
            for peer in entry["to"]
            if "ipBlock" in peer
        }
        operator_cidrs = {
            peer["ipBlock"]["cidr"]
            for entry in operator["spec"]["egress"]
            for peer in entry["to"]
            if "ipBlock" in peer
        }
        self.assertEqual(agent_cidrs, {"192.0.2.10/32", "198.51.100.10/32"})
        self.assertEqual(operator_cidrs, {"192.0.2.10/32"})

    def test_control_plane_egress_requires_explicit_rules_and_renders_scoped_policies(self) -> None:
        missing = self.helm_template(CONTROL_CHART, {"networkPolicy": {"egress": {"enabled": True}}})
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn("networkPolicy.egress.commonTo", missing.stderr)

        values = {"networkPolicy": {"egress": {
            "enabled": True,
            "commonTo": [DNS],
            "apiTo": [DATABASE, IDENTITY],
            "schedulerTo": [DATABASE],
            "migrationTo": [DATABASE],
        }}}
        result = self.helm_template(CONTROL_CHART, values)
        self.assertEqual(result.returncode, 0, result.stderr)
        policies = self.egress_policies(result.stdout)
        self.assertEqual(set(policies), {"api", "scheduler", "migration"})
        for component, expected_rules in (("api", 3), ("scheduler", 2), ("migration", 2)):
            policy = policies[component]
            self.assert_policy_selects_deployed_workload(result.stdout, policy)
            spec = policy["spec"]
            self.assertEqual(spec["policyTypes"], ["Egress"])
            self.assertEqual(len(spec["egress"]), expected_rules)
            self.assert_bounded_egress_rules(policy)

    def test_dashboard_egress_requires_explicit_rules_and_renders_scoped_policy(self) -> None:
        missing = self.helm_template(DASHBOARD_CHART, {"networkPolicy": {"egress": {"enabled": True}}}, dashboard=True)
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn("networkPolicy.egress.commonTo", missing.stderr)

        result = self.helm_template(DASHBOARD_CHART, {"networkPolicy": {"egress": {
            "enabled": True,
            "commonTo": [DNS],
            "dashboardTo": [API, IDENTITY],
        }}}, dashboard=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        policies = self.egress_policies(result.stdout)
        self.assertEqual(set(policies), {"dashboard"})
        self.assert_policy_selects_deployed_workload(result.stdout, policies["dashboard"])
        self.assertEqual(len(policies["dashboard"]["spec"]["egress"]), 3)
        self.assert_bounded_egress_rules(policies["dashboard"])

    def test_helm_schema_rejects_all_addresses_and_invalid_ports(self) -> None:
        bad_rules = [
            {"to": [{"ipBlock": {"cidr": "0.0.0.0/0"}}], "ports": [{"protocol": "TCP", "port": 5432}]},
            {"to": [{"ipBlock": {"cidr": "::/0"}}], "ports": [{"protocol": "TCP", "port": 5432}]},
            {"to": [{"ipBlock": {"cidr": "10.0.0.0/8"}}], "ports": [{"protocol": "TCP", "port": 65536}]},
            {"to": DATABASE["to"], "ports": []},
            {"to": DATABASE["to"], "ports": [{"protocol": "SCTP", "port": 5432}]},
        ]
        for bad_rule in bad_rules:
            values = {"networkPolicy": {"egress": {
                "enabled": True,
                "commonTo": [DNS],
                "apiTo": [bad_rule],
                "schedulerTo": [DATABASE],
                "migrationTo": [DATABASE],
            }}}
            result = self.helm_template(CONTROL_CHART, values)
            self.assertNotEqual(result.returncode, 0)

    def test_kustomize_restricted_overlay_has_bounded_component_egress(self) -> None:
        result = subprocess.run([self.kubectl, "kustomize", str(KUSTOMIZE_OVERLAY)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        migration = subprocess.run([
            self.kubectl, "kustomize",
            str(ROOT / "deployments/kustomize/hub/overlays/self-hosted-migration"),
        ], capture_output=True, text=True)
        self.assertEqual(migration.returncode, 0, migration.stderr)
        rendered = result.stdout + "\n---\n" + migration.stdout
        policies = self.egress_policies(rendered)
        self.assertEqual(set(policies), {"api", "scheduler", "migration", "dashboard"})
        for policy in policies.values():
            self.assert_policy_selects_deployed_workload(rendered, policy)
            self.assert_bounded_egress_rules(policy)


if __name__ == "__main__":
    unittest.main()
