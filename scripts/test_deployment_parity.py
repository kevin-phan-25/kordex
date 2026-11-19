#!/usr/bin/env python3
"""Compare the shared workload contract rendered by Helm and Kustomize."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from copy import deepcopy
from decimal import Decimal
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
CLUSTER_ID = "80bd80f9-f097-4474-86f4-b80986fd5423"


def documents(rendered: str) -> list[dict[str, Any]]:
    return [item for item in yaml.safe_load_all(rendered) if isinstance(item, dict)]


def run(command: list[str]) -> str:
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(f"command failed: {' '.join(command)}\n{result.stderr}")
    return result.stdout


def deployment_components(items: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    found: dict[str, dict[str, Any]] = {}
    for item in items:
        if item.get("kind") != "Deployment":
            continue
        containers = item.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
        if len(containers) != 1:
            continue
        name = containers[0].get("name")
        if name in {"api", "scheduler", "dashboard", "agent", "operator"}:
            if name in found:
                raise ValueError(f"duplicate {name} Deployment")
            found[name] = item
    return found


def cpu_quantity(value: Any) -> Decimal:
    raw = str(value)
    if raw.endswith("m"):
        return Decimal(raw[:-1]) / Decimal(1000)
    return Decimal(raw)


def memory_quantity(value: Any) -> Decimal:
    raw = str(value)
    for suffix, multiplier in (("Ki", 2**10), ("Mi", 2**20), ("Gi", 2**30),
                               ("Ti", 2**40), ("K", 10**3), ("M", 10**6),
                               ("G", 10**9), ("T", 10**12)):
        if raw.endswith(suffix):
            return Decimal(raw[:-len(suffix)]) * multiplier
    return Decimal(raw)


def canonical_resources(resources: dict[str, Any] | None) -> dict[str, dict[str, Decimal]]:
    result: dict[str, dict[str, Decimal]] = {}
    for direction, quantities in (resources or {}).items():
        result[direction] = {}
        for name, value in quantities.items():
            result[direction][name] = cpu_quantity(value) if name == "cpu" else memory_quantity(value)
    return result


def canonical_probe(probe: dict[str, Any] | None) -> tuple[Any, ...] | None:
    if not probe:
        return None
    get = probe.get("httpGet")
    if not get:
        raise ValueError("deployment parity requires HTTP probes")
    return (
        get.get("path"), get.get("port"), get.get("scheme", "HTTP"),
        probe.get("initialDelaySeconds", 0), probe.get("periodSeconds", 10),
        probe.get("timeoutSeconds", 1), probe.get("successThreshold", 1),
        probe.get("failureThreshold", 3),
    )


def canonical_ports(container: dict[str, Any]) -> tuple[tuple[str, int, str], ...]:
    # Metrics exposure is separately configurable in Helm; compare only the
    # shared application and health ports here.
    shared = {"http", "health"}
    ports = [port for port in container.get("ports", []) if port.get("name") in shared]
    return tuple(sorted(
        (port.get("name", ""), int(port["containerPort"]), port.get("protocol", "TCP"))
        for port in ports
    ))


def canonical_affinity(
    pod: dict[str, Any], pod_labels: dict[str, str], component: str
) -> tuple[int, str] | None:
    terms = pod.get("affinity", {}).get("podAntiAffinity", {}).get(
        "preferredDuringSchedulingIgnoredDuringExecution", [])
    if not terms:
        return None
    for term in terms:
        affinity_term = term.get("podAffinityTerm", {})
        selector = affinity_term.get("labelSelector", {}).get("matchLabels", {})
        if (affinity_term.get("topologyKey") == "kubernetes.io/hostname"
                and term.get("weight") == 100
                and selector
                and all(pod_labels.get(key) == value for key, value in selector.items())):
            return (term["weight"], affinity_term["topologyKey"])
    raise AssertionError(f"{component} has no preferred self anti-affinity by hostname")


def selected_component(selector: dict[str, str], workloads: dict[str, dict[str, Any]]) -> str:
    matches = []
    for component, deployment in workloads.items():
        labels = deployment["spec"]["template"].get("metadata", {}).get("labels", {})
        if selector and all(labels.get(key) == value for key, value in selector.items()):
            matches.append(component)
    if len(matches) != 1:
        raise AssertionError(f"selector must identify one deployment, found {matches}: {selector}")
    return matches[0]


def canonical_services(objects: list[dict[str, Any]], workloads: dict[str, dict[str, Any]]) -> dict[str, tuple[Any, ...]]:
    result = {}
    for item in objects:
        if item.get("kind") != "Service":
            continue
        spec = item.get("spec", {})
        component = selected_component(spec.get("selector", {}), workloads)
        ports = tuple(sorted(
            (port.get("name", ""), int(port["port"]), port.get("targetPort", port["port"]),
             port.get("protocol", "TCP"))
            for port in spec.get("ports", [])
        ))
        result[component] = (spec.get("type", "ClusterIP"), ports)
    return result


def canonical_pdbs(objects: list[dict[str, Any]], workloads: dict[str, dict[str, Any]]) -> dict[str, tuple[Any, Any]]:
    result = {}
    for item in objects:
        if item.get("kind") != "PodDisruptionBudget":
            continue
        spec = item.get("spec", {})
        component = selected_component(spec.get("selector", {}).get("matchLabels", {}), workloads)
        result[component] = (spec.get("minAvailable"), spec.get("maxUnavailable"))
    return result


def canonical_workload(deployment: dict[str, Any], component: str) -> dict[str, Any]:
    spec = deployment["spec"]
    pod = spec["template"]["spec"]
    pod_labels = deployment["spec"]["template"].get("metadata", {}).get("labels", {})
    container = next(item for item in pod["containers"] if item.get("name") == component)
    return {
        "replicas": spec.get("replicas", 1),
        "podSecurityContext": pod.get("securityContext", {}),
        "automountServiceAccountToken": pod.get("automountServiceAccountToken", True),
        "terminationGracePeriodSeconds": pod.get("terminationGracePeriodSeconds", 30),
        "containerSecurityContext": container.get("securityContext", {}),
        "resources": canonical_resources(container.get("resources")),
        "imageTag": container.get("image", "").rsplit(":", 1)[-1],
        "ports": canonical_ports(container),
        "imagePullPolicy": container.get("imagePullPolicy", "IfNotPresent"),
        "startupProbe": canonical_probe(container.get("startupProbe")),
        "readinessProbe": canonical_probe(container.get("readinessProbe")),
        "livenessProbe": canonical_probe(container.get("livenessProbe")),
        "affinity": canonical_affinity(pod, pod_labels, component),
    }


def assert_shared_contract_requirements(
    case: unittest.TestCase, component: str, contract: dict[str, Any]
) -> None:
    expected_replicas = 2 if component in {"api", "scheduler", "dashboard"} else 1
    case.assertEqual(contract["replicas"], expected_replicas)
    pod_security = contract["podSecurityContext"]
    case.assertIs(pod_security.get("runAsNonRoot"), True)
    case.assertEqual(pod_security.get("runAsUser"), 65532)
    case.assertEqual(pod_security.get("runAsGroup"), 65532)
    case.assertEqual(pod_security.get("seccompProfile", {}).get("type"), "RuntimeDefault")
    container_security = contract["containerSecurityContext"]
    case.assertIs(container_security.get("readOnlyRootFilesystem"), True)
    case.assertIs(container_security.get("allowPrivilegeEscalation"), False)
    case.assertIn("ALL", container_security.get("capabilities", {}).get("drop", []))
    case.assertIn("cpu", contract["resources"].get("requests", {}))
    case.assertIn("memory", contract["resources"].get("requests", {}))
    case.assertIn("memory", contract["resources"].get("limits", {}))
    expected_image_tags = {
        "api": "0.8.0",
        "scheduler": "0.8.0",
        "dashboard": "0.8.0",
        "agent": "0.4.0",
        "operator": "0.4.0",
    }
    case.assertEqual(contract["imageTag"], expected_image_tags[component])
    expected_ports = {
        "api": (("http", 8080, "TCP"),),
        "scheduler": (("health", 8081, "TCP"),),
        "dashboard": (("http", 3000, "TCP"),),
        "agent": (("health", 8081, "TCP"),),
        "operator": (("health", 8081, "TCP"),),
    }
    case.assertEqual(contract["ports"], expected_ports[component])
    expected_paths = {
        "api": ("/healthz", "/readyz", "/healthz"),
        "scheduler": ("/healthz", "/readyz", "/healthz"),
        "dashboard": ("/login", "/login", "/login"),
        "agent": ("/healthz", "/readyz", "/healthz"),
        "operator": (None, "/readyz", "/healthz"),
    }
    for field, path in zip(("startupProbe", "readinessProbe", "livenessProbe"), expected_paths[component]):
        probe = contract[field]
        if path is None:
            case.assertIsNone(probe)
            continue
        case.assertIsNotNone(probe)
        case.assertEqual(probe[0], path)
        case.assertEqual(probe[1], "health" if component in {"scheduler", "agent", "operator"} else "http")
    if component in {"api", "scheduler", "dashboard"}:
        case.assertEqual(contract["affinity"], (100, "kubernetes.io/hostname"))


def render_spoke_kustomize(kubectl: str) -> str:
    with tempfile.TemporaryDirectory() as temp:
        target_root = Path(temp) / "kustomize"
        source_root = ROOT / "deployments/kustomize"
        for relative in ("base", "components/agent", "components/operator", "overlays/self-managed"):
            source = source_root / relative
            target = target_root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(source, target, ignore=lambda _directory, names: {"keys.json"} & set(names))
        (target_root / "overlays/self-managed/keys.json").write_text(
            '{"test-key":"public-test-key-only"}\n', encoding="utf-8")
        return run([kubectl, "kustomize", str(target_root / "overlays/self-managed")])


class DeploymentParityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.helm = os.environ.get("HELM", "helm")
        cls.kubectl = os.environ.get("KUBECTL", "kubectl")
        try:
            run([cls.helm, "version", "--short"])
            run([cls.kubectl, "version", "--client", "-o", "json"])
        except (FileNotFoundError, RuntimeError) as error:
            raise unittest.SkipTest(f"Helm and kubectl are required for deployment parity: {error}")

        cp = run([
            cls.helm, "template", "kordex-prod", "deployments/helm/kordex-control-plane",
            "--namespace", "kordex-management",
            "--set", "credentialsSecretName=kordex-hub-credentials",
            "--set", "oidc.issuer=https://identity.example",
            "--set", "oidc.audience=kordex",
            "--set", "imagePullSecrets[0].name=kordex-registry",
        ])
        cp_otel = run([
            cls.helm, "template", "kordex-prod", "deployments/helm/kordex-control-plane",
            "--namespace", "kordex-management",
            "--set", "credentialsSecretName=kordex-hub-credentials",
            "--set", "oidc.issuer=https://identity.example",
            "--set", "oidc.audience=kordex",
            "--set", "telemetry.otlpEndpoint=https://otel.example:4318/v1/traces",
        ])
        dashboard = run([
            cls.helm, "template", "kordex-dashboard", "deployments/helm/kordex-dashboard",
            "--namespace", "kordex-management",
            "--set", "image.repository=kordex/dashboard",
            "--set", "imagePullSecrets[0].name=kordex-registry",
            "--set", "dashboardURL=https://dashboard.example",
            "--set", "apiURL=https://api.example",
            "--set", "oidc.issuer=https://identity.example",
            "--set", "oidc.clientID=kordex",
            "--set", "oidc.secretName=kordex-dashboard-identity",
        ])
        agent = run([
            cls.helm, "template", "kordex-agent", "deployments/helm/kordex-agent",
            "--namespace", "kordex-system",
            "--set", "controlPlaneURL=https://hub.example",
            "--set", f"clusterID={CLUSTER_ID}",
            "--set", "enrollmentSecretName=kordex-enrollment",
        ])
        agent_otel = run([
            cls.helm, "template", "kordex-agent", "deployments/helm/kordex-agent",
            "--namespace", "kordex-system",
            "--set", "controlPlaneURL=https://hub.example",
            "--set", f"clusterID={CLUSTER_ID}",
            "--set", "enrollmentSecretName=kordex-enrollment",
            "--set", "telemetry.otlpEndpoint=https://otel.example:4318/v1/traces",
        ])
        operator = run([
            cls.helm, "template", "kordex-operator", "deployments/helm/kordex-operator",
            "--namespace", "kordex-system",
            "--set", f"clusterID={CLUSTER_ID}",
            "--set", "hubPublicKeysConfigMap=kordex-hub-trust",
        ])
        operator_otel = run([
            cls.helm, "template", "kordex-operator", "deployments/helm/kordex-operator",
            "--namespace", "kordex-system",
            "--set", f"clusterID={CLUSTER_ID}",
            "--set", "hubPublicKeysConfigMap=kordex-hub-trust",
            "--set", "telemetry.otlpEndpoint=https://otel.example:4318/v1/traces",
        ])
        cp_objects = documents(cp)
        cls.helm_otel_objects = documents(cp_otel)
        dashboard_objects = documents(dashboard)
        agent_objects = documents(agent)
        cls.helm_agent_otel_objects = documents(agent_otel)
        operator_objects = documents(operator)
        cls.helm_operator_otel_objects = documents(operator_otel)
        cls.helm_objects = {
            "control-plane": cp_objects,
            "dashboard": dashboard_objects,
            "agent": agent_objects,
            "operator": operator_objects,
        }
        cls.helm_workloads = {
            "api": deployment_components(cp_objects)["api"],
            "scheduler": deployment_components(cp_objects)["scheduler"],
            "dashboard": deployment_components(dashboard_objects)["dashboard"],
            "agent": deployment_components(agent_objects)["agent"],
            "operator": deployment_components(operator_objects)["operator"],
        }
        cls.kustom_hub = documents(run([
            cls.kubectl, "kustomize", "deployments/kustomize/hub/overlays/self-hosted"]))
        cls.kustom_spoke = documents(render_spoke_kustomize(cls.kubectl))
        cls.kustom_workloads = {
            **deployment_components(cls.kustom_hub),
            **deployment_components(cls.kustom_spoke),
        }
        cls.helm_hub_objects = cp_objects + dashboard_objects
        cls.helm_hub_workloads = {
            "api": cls.helm_workloads["api"],
            "scheduler": cls.helm_workloads["scheduler"],
            "dashboard": cls.helm_workloads["dashboard"],
        }
        cls.kustom_hub_workloads = {
            component: cls.kustom_workloads[component]
            for component in ("api", "scheduler", "dashboard")
        }

    def test_shared_workload_contract_matches(self) -> None:
        for component in ("api", "scheduler", "dashboard", "agent", "operator"):
            with self.subTest(component=component):
                helm = canonical_workload(self.helm_workloads[component], component)
                kustomize = canonical_workload(self.kustom_workloads[component], component)
                assert_shared_contract_requirements(self, component, helm)
                assert_shared_contract_requirements(self, component, kustomize)
                self.assertEqual(kustomize, helm)

    def test_management_services_and_disruption_budgets_match(self) -> None:
        helm_services = canonical_services(self.helm_hub_objects, self.helm_hub_workloads)
        kustom_services = canonical_services(self.kustom_hub, self.kustom_hub_workloads)
        self.assertEqual(set(helm_services), {"api", "dashboard"})
        self.assertEqual(helm_services, kustom_services)
        helm_pdbs = canonical_pdbs(self.helm_hub_objects, self.helm_hub_workloads)
        kustom_pdbs = canonical_pdbs(self.kustom_hub, self.kustom_hub_workloads)
        self.assertEqual(helm_pdbs, {"api": (1, None), "scheduler": (1, None), "dashboard": (1, None)})
        self.assertEqual(helm_pdbs, kustom_pdbs)

    def test_chart_app_versions_match_rendered_runtime_images(self) -> None:
        chart_components = {
            "api": "control-plane",
            "scheduler": "control-plane",
            "dashboard": "dashboard",
            "agent": "agent",
            "operator": "operator",
        }
        for component, chart in chart_components.items():
            with self.subTest(component=component):
                chart_path = ROOT / "deployments/helm" / f"kordex-{chart}" / "Chart.yaml"
                metadata = yaml.safe_load(chart_path.read_text(encoding="utf-8"))
                image = canonical_workload(self.helm_workloads[component], component)["imageTag"]
                self.assertEqual(metadata["appVersion"], image)

    def test_host_and_provider_upgrade_gates_remain_off(self) -> None:
        def resolved_env(objects: list[dict[str, Any]], component: str) -> dict[str, str]:
            deployment = deployment_components(objects).get(component)
            self.assertIsNotNone(deployment)
            pod = deployment["spec"]["template"]["spec"]
            config_maps = {item["metadata"]["name"]: item.get("data", {})
                           for item in objects if item.get("kind") == "ConfigMap"}
            values: dict[str, str] = {}
            for env in pod["containers"][0].get("env", []):
                if env["name"] not in {"KORDEX_ENABLE_HOST_UPGRADES", "KORDEX_ENABLE_GKE_UPGRADES", "KORDEX_ENABLE_MAINTENANCE"}:
                    continue
                if "value" in env:
                    values[env["name"]] = env["value"]
                else:
                    ref = env["valueFrom"]["configMapKeyRef"]
                    values[env["name"]] = config_maps[ref["name"]][ref["key"]]
            return values

        for objects in (self.helm_objects["operator"], self.kustom_spoke):
            values = resolved_env(objects, "operator")
            self.assertEqual(values, {
                "KORDEX_ENABLE_HOST_UPGRADES": "false",
                "KORDEX_ENABLE_GKE_UPGRADES": "false",
            })
        for objects in (self.helm_objects["agent"], self.kustom_spoke):
            values = resolved_env(objects, "agent")
            self.assertEqual(values.get("KORDEX_ENABLE_MAINTENANCE", "false"), "false")

    def test_otlp_tracing_is_wired_to_api_and_scheduler_but_default_off(self) -> None:
        def endpoint(workload: dict[str, Any], objects: list[dict[str, Any]]) -> str:
            envs = workload["spec"]["template"]["spec"]["containers"][0].get("env", [])
            setting = next((item for item in envs if item.get("name") == "OTEL_EXPORTER_OTLP_ENDPOINT"), None)
            self.assertIsNotNone(setting, "OTLP endpoint must be configurable")
            if "value" in setting:
                return setting["value"]
            reference = setting["valueFrom"]["configMapKeyRef"]
            config_maps = {item["metadata"]["name"]: item.get("data", {})
                           for item in objects if item.get("kind") == "ConfigMap"}
            return config_maps[reference["name"]][reference["key"]]

        for component in ("api", "scheduler"):
            with self.subTest(component=component, deployment="helm"):
                self.assertEqual(endpoint(self.helm_hub_workloads[component], self.helm_hub_objects), "")
            with self.subTest(component=component, deployment="kustomize"):
                self.assertEqual(endpoint(self.kustom_hub_workloads[component], self.kustom_hub), "")
            with self.subTest(component=component, deployment="helm-configured"):
                workload = deployment_components(self.helm_otel_objects)[component]
                self.assertEqual(endpoint(workload, self.helm_otel_objects), "https://otel.example:4318/v1/traces")

        rejected = subprocess.run([
            self.helm, "template", "kordex-prod", "deployments/helm/kordex-control-plane",
            "--namespace", "kordex-management",
            "--set", "credentialsSecretName=kordex-hub-credentials",
            "--set", "oidc.issuer=https://identity.example",
            "--set", "oidc.audience=kordex",
            "--set", "telemetry.otlpEndpoint=https://user:secret@otel.example:4318/v1/traces",
        ], cwd=ROOT, capture_output=True, text=True)
        self.assertNotEqual(rejected.returncode, 0, "OTLP endpoint credentials must be rejected by chart schema")

    def test_operator_otlp_tracing_is_configurable_and_default_off(self) -> None:
        def endpoint(objects: list[dict[str, Any]]) -> str:
            deployment = deployment_components(objects)["operator"]
            envs = deployment["spec"]["template"]["spec"]["containers"][0].get("env", [])
            setting = next((item for item in envs if item.get("name") == "OTEL_EXPORTER_OTLP_ENDPOINT"), None)
            self.assertIsNotNone(setting, "operator OTLP endpoint must be configurable")
            if "value" in setting:
                return setting["value"]
            reference = setting["valueFrom"]["configMapKeyRef"]
            config_maps = {item["metadata"]["name"]: item.get("data", {})
                           for item in objects if item.get("kind") == "ConfigMap"}
            return config_maps[reference["name"]][reference["key"]]

        self.assertEqual(endpoint(self.helm_objects["operator"]), "")
        self.assertEqual(endpoint(self.kustom_spoke), "")
        self.assertEqual(endpoint(self.helm_operator_otel_objects), "https://otel.example:4318/v1/traces")
        configured_kustom = deepcopy(self.kustom_spoke)
        settings = next(item for item in configured_kustom
                        if item.get("kind") == "ConfigMap"
                        and item.get("metadata", {}).get("name") == "kordex-operator-settings")
        settings["data"]["otelExporterOtlpEndpoint"] = "https://otel.example:4318/v1/traces"
        self.assertEqual(endpoint(configured_kustom), "https://otel.example:4318/v1/traces")

        rejected = subprocess.run([
            self.helm, "template", "kordex-operator", "deployments/helm/kordex-operator",
            "--namespace", "kordex-system",
            "--set", f"clusterID={CLUSTER_ID}",
            "--set", "hubPublicKeysConfigMap=kordex-hub-trust",
            "--set", "telemetry.otlpEndpoint=https://user:secret@otel.example:4318/v1/traces",
        ], cwd=ROOT, capture_output=True, text=True)
        self.assertNotEqual(rejected.returncode, 0, "operator OTLP endpoint credentials must be rejected by chart schema")

    def test_agent_otlp_tracing_is_configurable_and_default_off(self) -> None:
        def endpoint(objects: list[dict[str, Any]]) -> str:
            deployment = deployment_components(objects)["agent"]
            envs = deployment["spec"]["template"]["spec"]["containers"][0].get("env", [])
            setting = next((item for item in envs if item.get("name") == "OTEL_EXPORTER_OTLP_ENDPOINT"), None)
            self.assertIsNotNone(setting, "agent OTLP endpoint must be configurable")
            if "value" in setting:
                return setting["value"]
            reference = setting["valueFrom"]["configMapKeyRef"]
            config_maps = {item["metadata"]["name"]: item.get("data", {})
                           for item in objects if item.get("kind") == "ConfigMap"}
            return config_maps[reference["name"]][reference["key"]]

        self.assertEqual(endpoint(self.helm_objects["agent"]), "")
        self.assertEqual(endpoint(self.kustom_spoke), "")
        self.assertEqual(endpoint(self.helm_agent_otel_objects), "https://otel.example:4318/v1/traces")
        configured_kustom = deepcopy(self.kustom_spoke)
        settings = next(item for item in configured_kustom
                        if item.get("kind") == "ConfigMap"
                        and item.get("metadata", {}).get("name") == "kordex-agent-settings")
        settings["data"]["otelExporterOtlpEndpoint"] = "https://otel.example:4318/v1/traces"
        self.assertEqual(endpoint(configured_kustom), "https://otel.example:4318/v1/traces")

        rejected = subprocess.run([
            self.helm, "template", "kordex-agent", "deployments/helm/kordex-agent",
            "--namespace", "kordex-system",
            "--set", "controlPlaneURL=https://hub.example",
            "--set", f"clusterID={CLUSTER_ID}",
            "--set", "enrollmentSecretName=kordex-enrollment",
            "--set", "telemetry.otlpEndpoint=https://user:secret@otel.example:4318/v1/traces",
        ], cwd=ROOT, capture_output=True, text=True)
        self.assertNotEqual(rejected.returncode, 0, "agent OTLP endpoint credentials must be rejected by chart schema")


if __name__ == "__main__":
    unittest.main()
