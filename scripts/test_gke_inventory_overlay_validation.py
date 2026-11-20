#!/usr/bin/env python3
"""Unit tests for the inventory overlay deployment gate."""

from __future__ import annotations
import importlib.util
import socket
import ssl
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

SPEC = importlib.util.spec_from_file_location(
    "gke_inventory_overlay_validation",
    Path(__file__).with_name("validate-gke-inventory-overlay.py"),
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

class OverlayValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = "\n".join((
            "apiVersion: v1",
            "kind: ConfigMap",
            "data:",
            "  clusterID: 123e4567-e89b-12d3-a456-426614174000",
            "  controlPlaneURL: https://kordex.internal.example",
            "---",
            "apiVersion: rbac.authorization.k8s.io/v1",
            "kind: Role",
            "rules:",
            "- apiGroups:",
            "  - \"\"",
            "  resourceNames:",
            "  - kordex-agent-identity",
            "  resources:",
            "  - secrets",
            "  verbs:",
            "  - patch",
            "---",
            "apiVersion: apps/v1",
            "kind: Deployment",
            "spec:",
            "  template:",
            "    spec:",
            "      containers:",
            "      - name: agent",
            "        image: us-east1-docker.pkg.dev/project/repo/agent@sha256:" + "a" * 64,
            "      volumes:",
            "      - name: enrollment",
            "        secret:",
            "          secretName: kordex-enrollment",
            "          items:",
            "          - key: token",
            "            path: token",
            "      - name: identity",
            "        secret:",
            "          secretName: kordex-agent-identity",
            "          items:",
            "          - key: state.json",
            "            path: state.json",
        ))

    def test_accepts_configured_private_https_digest(self) -> None:
        self.assertEqual(MODULE.validation_errors(self.manifest), [])

    def test_rejects_placeholder_digest_and_cluster(self) -> None:
        rendered = self.manifest.replace("sha256:" + "a" * 64, "sha256:REPLACE_WITH_64_LOWERCASE_HEX_DIGEST").replace(
            "123e4567-e89b-12d3-a456-426614174000", "REPLACE_WITH_REGISTERED_CLUSTER_UUID"
        )
        errors = MODULE.validation_errors(rendered)
        self.assertTrue(any("placeholders" in error for error in errors))
        self.assertTrue(any("immutable sha256" in error for error in errors))
        self.assertTrue(any("registered UUID" in error for error in errors))

    def test_rejects_loopback_and_bootstrap_endpoint(self) -> None:
        for endpoint in (
            "http://kordex.internal.example",
            "https://127.0.0.1:8081",
            "https://api.example:8080",
            "https://api.example/v1",
        ):
            with self.subTest(endpoint=endpoint):
                rendered = self.manifest.replace("https://kordex.internal.example", endpoint)
                self.assertTrue(any("controlPlaneURL" in error for error in MODULE.validation_errors(rendered)))

    def test_private_dns_and_hostname_verified_tls_are_required(self) -> None:
        resolver = lambda host, port, type: [(None, None, None, None, ("10.20.30.40", 443))]
        tls_context = MagicMock()
        tls_context.wrap_socket.return_value.__enter__.return_value = object()
        connection = MagicMock()
        connection.__enter__.return_value = object()
        with tempfile.NamedTemporaryFile() as ca_file, patch.object(
            MODULE.ssl, "create_default_context", return_value=tls_context
        ):
            addresses = MODULE.verify_management_tls(
                "https://kordex.internal.example", ca_file.name,
                resolver=resolver, connector=lambda address, timeout: connection,
            )
        self.assertEqual(addresses, ["10.20.30.40"])
        tls_context.wrap_socket.assert_called_once_with(
            connection.__enter__.return_value,
            server_hostname="kordex.internal.example",
        )

    def test_rejects_public_dns_answer(self) -> None:
        resolver = lambda host, port, type: [(None, None, None, None, ("34.23.1.2", 443))]
        with tempfile.NamedTemporaryFile() as ca_file:
            with self.assertRaisesRegex(ValueError, "outside RFC1918/ULA"):
                MODULE.verify_management_tls(
                    "https://kordex.internal.example", ca_file.name,
                    resolver=resolver,
                )

    def test_rejects_untrusted_or_hostname_mismatched_tls(self) -> None:
        resolver = lambda host, port, type: [(None, None, None, None, ("10.20.30.40", 443))]
        with tempfile.NamedTemporaryFile() as ca_file, patch.object(
            MODULE.ssl, "create_default_context", return_value=MagicMock()
        ):
            with self.assertRaisesRegex(ValueError, "TLS connection or hostname verification failed"):
                MODULE.verify_management_tls(
                    "https://kordex.internal.example", ca_file.name,
                    resolver=resolver,
                    connector=lambda address, timeout: (_ for _ in ()).throw(ssl.SSLCertVerificationError()),
                )

    def test_requires_existing_management_ca_file(self) -> None:
        with self.assertRaisesRegex(ValueError, "KORDEX_MANAGEMENT_CA_FILE"):
            MODULE.verify_management_tls("https://kordex.internal.example", "")

    def test_rejects_rendered_enrollment_credential(self) -> None:
        errors = MODULE.validation_errors(self.manifest + "\nenrollment-token: should-not-exist\n")
        self.assertTrue(any("enrollment credentials" in error for error in errors))

    def test_rejects_secret_read_permission(self) -> None:
        rendered = self.manifest.replace("  - patch", "  - get")
        self.assertTrue(
            any("no Secret reads" in error for error in MODULE.validation_errors(rendered))
        )

    def test_helm_agent_uses_projected_state_and_patch_only_secret_permission(self) -> None:
        root = Path(__file__).resolve().parents[1]
        rbac = (root / "deployments/helm/kordex-agent/templates/rbac.yaml").read_text()
        deployment = (root / "deployments/helm/kordex-agent/templates/deployment.yaml").read_text()
        self.assertIn("verbs: [patch]", rbac)
        self.assertNotIn("resourceNames: [{{ include \"kordex-agent.name\" . }}-identity]\n    verbs: [get, update]", rbac)
        self.assertIn("KORDEX_STATE_SECRET_FILE", deployment)
        self.assertIn("mountPath: /var/run/kordex/identity", deployment)

    def test_gke_publisher_image_name_matches_overlay(self) -> None:
        root = Path(__file__).resolve().parents[1]
        publisher = (root / "scripts/publish-gke-inventory-agent.sh").read_text()
        kustomization = (root / "deployments/kustomize/overlays/gke-inventory/kustomization.yaml").read_text()
        self.assertIn("us-east1-docker.pkg.dev/kordex-fleet-platform/kordex-artifacts/agent", publisher)
        self.assertIn("if [[ \"$REPOSITORY\" != 'us-east1-docker.pkg.dev/kordex-fleet-platform/kordex-artifacts/agent' ]]", publisher)
        self.assertIn("us-east1-docker.pkg.dev/kordex-fleet-platform/kordex-artifacts/agent", kustomization)

if __name__ == "__main__":
    unittest.main()
