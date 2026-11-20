#!/usr/bin/env python3
"""Check that the GKE inventory-only overlay cannot install maintenance access."""

from __future__ import annotations

import subprocess
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OVERLAY = ROOT / "deployments/kustomize/overlays/gke-inventory"


def main() -> None:
    rendered = subprocess.run(
        ["kubectl", "kustomize", str(OVERLAY)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    kinds = [line.removeprefix("kind: ") for line in rendered.splitlines() if line.startswith("kind: ")]
    secret_rule = re.search(
        r"resourceNames:\n\s+- kordex-agent-identity\n\s+resources:\n\s+- secrets\n\s+verbs:\n(?P<verbs>(?:\s+- [a-z]+\n)+)",
        rendered,
    )
    secret_verbs = re.findall(r"- ([a-z]+)", secret_rule.group("verbs")) if secret_rule else []
    required = {
        "exactly one agent deployment": kinds.count("Deployment") == 1 and "name: kordex-agent" in rendered,
        "maintenance disabled": 'maintenanceEnabled: "false"' in rendered,
        "no operator or CRDs": "kordex-operator" not in rendered and "kind: CustomResourceDefinition" not in rendered,
        "no maintenance API permissions": "maintenancepolicies" not in rendered and "nodemaintenances" not in rendered,
        "patch-only identity Secret RBAC": secret_verbs == ["patch"],
        "enrollment and identity keys projected read-only": "secretName: kordex-enrollment" in rendered and "key: token" in rendered and "secretName: kordex-agent-identity" in rendered and "key: state.json" in rendered and "KORDEX_STATE_SECRET_FILE" in rendered,
        "image remains an explicit unconfigured placeholder": "@sha256:REPLACE_WITH_64_LOWERCASE_HEX_DIGEST" in rendered,
        "management CA verification configured": "KORDEX_CA_FILE" in rendered and "readOnly: true" in rendered,
        "restricted container security": "runAsNonRoot: true" in rendered and "readOnlyRootFilesystem: true" in rendered,
    }
    for description, passed in required.items():
        print(f"{'PASS' if passed else 'FAIL'}: {description}")
    if not all(required.values()):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
