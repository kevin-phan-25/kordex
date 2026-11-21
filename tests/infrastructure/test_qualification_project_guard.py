import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
LAB = ROOT / "infrastructure/terraform/gcp/self-managed-lab"


class QualificationProjectGuardTests(unittest.TestCase):
    def test_product_project_is_denied_by_variable_validation(self):
        variables = (LAB / "variables.tf").read_text()
        project_variable = re.search(
            r'variable "project_id"\s*\{(?P<body>.*?)\n\}', variables, re.S
        )
        self.assertIsNotNone(project_variable)
        body = project_variable.group("body")
        self.assertIn('"kordex-fleet-platform"', body)
        self.assertRegex(body, r"!contains\(\[.*?\],\s*var\.project_id\)")

    def test_product_project_has_independent_plan_precondition(self):
        main = (LAB / "main.tf").read_text()
        safety_resource = re.search(
            r'resource "terraform_data" "project_safety"\s*\{(?P<body>.*?)\n\}',
            main,
            re.S,
        )
        self.assertIsNotNone(safety_resource)
        body = safety_resource.group("body")
        self.assertRegex(
            body,
            r"precondition\s*\{\s*condition\s*=\s*var\.project_id\s*!=\s*"
            r'"kordex-fleet-platform"',
        )

    def test_lab_vms_have_no_external_ip_and_no_public_admin_ingress(self):
        main = (LAB / "main.tf").read_text()
        self.assertNotRegex(main, r"(?m)^\s*access_config\s*\{")
        self.assertIn('source_ranges = [local.iap_tcp_cidr]', main)
        self.assertIn('iap_tcp_cidr = "35.235.240.0/20"', main)
        self.assertNotIn('source_ranges = ["0.0.0.0/0"]', main)
        admin = re.search(
            r'resource "google_compute_firewall" "admin"\s*\{(?P<body>.*?)\n\}',
            main,
            re.S,
        )
        self.assertIsNotNone(admin)
        self.assertIn('ports    = ["22"]', admin.group("body"))
        self.assertNotIn("6443", admin.group("body"))

    def test_bootstrap_token_is_runtime_only_and_expires(self):
        variables = (LAB / "variables.tf").read_text()
        main = (LAB / "main.tf").read_text()
        example = (LAB / "terraform.tfvars.example").read_text()
        templates = "\n".join((LAB / name).read_text() for name in (
            "server-startup.sh.tftpl", "worker-startup.sh.tftpl"
        ))
        self.assertNotIn('variable "k3s_token"', variables)
        self.assertNotIn("var.k3s_token", main)
        self.assertNotIn("${k3s_token}", templates)
        self.assertNotIn("k3s_token =", example)
        self.assertRegex(main, r'ttl\s*=\s*"14400s"')
        self.assertIn("--ttl=30m", templates)
        self.assertIn("k3s token delete", templates)
        self.assertIn('roles/secretmanager.secretVersionManager', main)
        self.assertIn('roles/secretmanager.secretAccessor', main)
        self.assertIn('roles/secretmanager.viewer', main)

    def test_private_egress_is_limited_to_lab_protocol_allowlist(self):
        main = (LAB / "main.tf").read_text()
        for resource_name in ("egress_internal", "egress_dns", "egress_web", "egress_deny_other"):
            self.assertIn(f'resource "google_compute_firewall" "{resource_name}"', main)
        self.assertIn('ports    = ["80", "443"]', main)
        self.assertIn('ports    = ["53"]', main)
        self.assertIn('protocol = "all"', main)
        self.assertIn('destination_ranges = ["0.0.0.0/0"]', main)

    def test_terraform_and_helper_target_project_explicitly(self):
        provider = (LAB / "versions.tf").read_text()
        helper = (ROOT / "scripts/self_managed_lab.py").read_text()
        example = (LAB / "terraform.tfvars.example").read_text()
        self.assertIn("project = var.project_id", provider)
        self.assertIn('project_id = "kordex-fleet-platform-515323"', example)
        self.assertIn('f"--project={project_id}"', helper)


if __name__ == "__main__":
    unittest.main()
