import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / "infrastructure/terraform/gcp/self-managed-lab"
PROJECT_ROLE = LAB / "terraform-deployer-role.json"
RESOURCE_ROLE = LAB / "terraform-lab-resources-role.json"
LIFECYCLE_ROLE = LAB / "lab-lifecycle-power-role.json"
INVENTORY_ROLE = LAB / "lab-inventory-role.json"


class TerraformIdentityContractTests(unittest.TestCase):
    def test_terraform_roles_separate_project_scope_from_conditionable_lab_resources(self):
        project_role = json.loads(PROJECT_ROLE.read_text())
        resource_role = json.loads(RESOURCE_ROLE.read_text())
        project_permissions = set(project_role["includedPermissions"])
        resource_permissions = set(resource_role["includedPermissions"])
        self.assertEqual(len(project_permissions), len(project_role["includedPermissions"]))
        self.assertEqual(len(resource_permissions), len(resource_role["includedPermissions"]))
        for required in (
            "compute.networks.create", "compute.networks.updatePolicy", "compute.subnetworks.create",
            "dns.managedZones.create", "dns.changes.create", "serviceusage.services.use",
            "compute.snapshots.useReadOnly", "resourcemanager.projects.get", "resourcemanager.projects.list",
        ):
            self.assertIn(required, project_permissions)
        self.assertFalse(any(permission.startswith("cloudresourcemanager.")
                             for permission in project_permissions))
        self.assertFalse(any(permission.startswith("iam.serviceAccounts.") for permission in project_permissions))
        for required in (
            "compute.instances.create",
            "compute.disks.create", "compute.firewalls.create", "dns.resourceRecordSets.create",
            "secretmanager.secrets.getIamPolicy", "secretmanager.secrets.setIamPolicy",
        ):
            self.assertIn(required, resource_permissions)
        for forbidden in (
            "compute.instances.create", "compute.instances.start", "compute.instances.stop",
            "compute.disks.create", "compute.firewalls.create", "dns.resourceRecordSets.create",
            "secretmanager.secrets.setIamPolicy", "iam.serviceAccounts.setIamPolicy",
            "resourcemanager.projects.setIamPolicy", "serviceusage.services.enable",
        ):
            self.assertNotIn(forbidden, project_permissions)
        for forbidden in (
            "resourcemanager.projects.setIamPolicy", "serviceusage.services.enable",
            "iam.serviceAccounts.setIamPolicy", "compute.projects.setCommonInstanceMetadata",
            "compute.instances.start", "compute.instances.stop",
        ):
            self.assertNotIn(forbidden, resource_permissions)

    def test_lifecycle_and_inventory_roles_are_separate_and_least_privilege(self):
        lifecycle = json.loads(LIFECYCLE_ROLE.read_text())
        inventory = json.loads(INVENTORY_ROLE.read_text())
        self.assertEqual(set(lifecycle["includedPermissions"]), {
            "compute.instances.start", "compute.instances.stop",
        })
        self.assertEqual(len(inventory["includedPermissions"]), len(set(inventory["includedPermissions"])))
        self.assertEqual(set(inventory["includedPermissions"]), {
            "resourcemanager.projects.get", "compute.disks.get", "compute.instances.get",
            "compute.instances.list", "compute.projects.get", "compute.zoneOperations.get",
        })
        self.assertFalse(any(permission.startswith("cloudresourcemanager.")
                             for permission in inventory["includedPermissions"]))
        self.assertFalse(any(permission.endswith((".create", ".delete", ".update", ".start", ".stop"))
                             for permission in inventory["includedPermissions"]))

    def test_role_manifests_are_unique_and_terraform_does_not_power_cycle_vms(self):
        for role_path in (PROJECT_ROLE, RESOURCE_ROLE, LIFECYCLE_ROLE, INVENTORY_ROLE):
            permissions = json.loads(role_path.read_text())["includedPermissions"]
            self.assertEqual(len(permissions), len(set(permissions)), str(role_path))
        main = (LAB / "main.tf").read_text()
        self.assertEqual(main.count("allow_stopping_for_update = false"), 2)
        self.assertNotIn("allow_stopping_for_update = true", main)

    def test_lifecycle_runbook_uses_per_vm_iap_grant_path(self):
        runbook = (ROOT / "docs/m3-persistent-lab-lifecycle.md").read_text()
        self.assertIn("--lifecycle-principal-email", runbook)
        self.assertIn("Identity-Aware Proxy → SSH and TCP Resources", runbook)
        self.assertIn("`gcloud compute instances add-iam-policy-binding`", runbook)
        self.assertIn("for the IAP role", runbook)

    def test_lifecycle_uses_a_distinct_principal_from_terraform(self):
        lifecycle = (ROOT / "scripts/m3_lab_lifecycle.py").read_text()
        cli = (ROOT / "scripts/self_managed_lab.py").read_text()
        self.assertIn("lifecycle_principal == terraform_principal", lifecycle)
        self.assertIn("--impersonate-service-account={self.config['lifecyclePrincipalEmail']}", lifecycle)
        self.assertIn('command.add_argument("--lifecycle-principal-email", required=True)', cli)

    def test_dedicated_provider_principal_remains_required_by_terraform(self):
        variables = (ROOT / "infrastructure/terraform/gcp/self-managed-lab/variables.tf").read_text()
        main = (ROOT / "infrastructure/terraform/gcp/self-managed-lab/main.tf").read_text()
        versions = (ROOT / "infrastructure/terraform/gcp/self-managed-lab/versions.tf").read_text()
        self.assertIn('variable "terraform_principal_email"', variables)
        self.assertIn("impersonate_service_account", versions)
        self.assertIn('variable "server_service_account_id"', variables)
        self.assertIn('variable "worker_service_account_id"', variables)
        self.assertIn('var.server_service_account_id == "${var.name_prefix}-server"', main)
        self.assertIn('var.worker_service_account_id == "${var.name_prefix}-worker"', main)
        self.assertNotIn('resource "google_service_account"', main)


if __name__ == "__main__":
    unittest.main()
