import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "infrastructure/terraform/gcp/self-managed-lab/terraform-deployer-role.json"


class TerraformIdentityContractTests(unittest.TestCase):
    def test_candidate_role_is_resource_scoped_by_capability_and_not_project_admin(self):
        role = json.loads(ROLE.read_text())
        permissions = set(role["includedPermissions"])
        self.assertEqual(len(permissions), len(role["includedPermissions"]))
        for required in (
            "compute.instances.create", "compute.instances.start", "compute.instances.stop",
            "compute.disks.create", "compute.networks.create", "compute.subnetworks.create",
            "compute.firewalls.create", "dns.managedZones.create", "dns.resourceRecordSets.create",
            "secretmanager.secrets.setIamPolicy", "iam.serviceAccounts.create",
            "serviceusage.services.use",
        ):
            self.assertIn(required, permissions)
        for forbidden in (
            "resourcemanager.projects.setIamPolicy", "serviceusage.services.enable",
            "iam.serviceAccounts.setIamPolicy", "compute.projects.setCommonInstanceMetadata",
        ):
            self.assertNotIn(forbidden, permissions)
        self.assertFalse(any(name in {"roles/owner", "roles/editor", "roles/compute.admin"}
                             for name in permissions))

    def test_dedicated_provider_principal_remains_required_by_terraform(self):
        variables = (ROOT / "infrastructure/terraform/gcp/self-managed-lab/variables.tf").read_text()
        versions = (ROOT / "infrastructure/terraform/gcp/self-managed-lab/versions.tf").read_text()
        self.assertIn('variable "terraform_principal_email"', variables)
        self.assertIn("impersonate_service_account", versions)


if __name__ == "__main__":
    unittest.main()
