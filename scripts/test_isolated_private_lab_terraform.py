#!/usr/bin/env python3
"""Guard the isolated lab module against unsafe target and network drift."""
from pathlib import Path
import re

root = Path(__file__).resolve().parents[1]
module = root / "infrastructure/terraform/gcp/isolated-private-management-lab"
variables = (module / "variables.tf").read_text()
main = (module / "main.tf").read_text()
outputs = (module / "outputs.tf").read_text()

assert '"^kordex-pmlab-' in variables
assert 'var.project_id != "kordex-fleet-platform"' in variables
assert 'var.project_id_confirmation == var.project_id' in main
assert 'contains(var.allowed_project_ids, var.project_id)' in main
assert 'labels["kordex-disposable"]' in main
assert '"qualification"' in main
assert 'name_prefix == "kordex-pmlab"' in variables
assert re.search(r'name\s+= "\$\{var\.name_prefix\}-gke"', main)
assert 'network_policy {' not in main
assert re.search(r'datapath_provider\s+= "ADVANCED_DATAPATH"', main)
assert 'enable_private_nodes    = true' in main
assert 'enable_private_endpoint = true' in main
assert 'allow_external_traffic = false' in main
assert 'enable_public_endpoint' not in main  # Provider v6.50 schema lacks this field; private endpoint disables public IP.
assert 'auto_upgrade = false' in main
assert re.search(r'deletion_protection\s+= var\.cluster_deletion_protection', main)
assert 'deletion_protection       = true' in main
assert not re.search(r'^\s*access_config\s*\{', main, re.MULTILINE)
assert 'source_ranges = ["35.235.240.0/20"]' in main
assert 'roles/iam.serviceAccountUser' in main
assert 'roles/artifactregistry.reader' in main
assert '"pd-balanced"' in main
assert 'kordex-fleet-platform' not in outputs
assert not re.search(r'resource\s+"google_project_service"', main)
assert 'terraform.tfstate' in (module / ".gitignore").read_text()

print("isolated private lab Terraform target and network safeguards passed")
