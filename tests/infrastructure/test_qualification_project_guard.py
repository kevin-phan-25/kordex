import hashlib
import pathlib
import re
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
LAB = ROOT / "infrastructure/terraform/gcp/self-managed-lab"


class QualificationProjectGuardTests(unittest.TestCase):
    def test_profile_startup_templates_render_to_valid_shell_without_execution(self):
        for template_name in ("server-startup.sh.tftpl", "worker-startup.sh.tftpl"):
            source = (LAB / template_name).read_text()
            # Protect Terraform's escaped shell interpolations while replacing
            # only Terraform template expressions with inert fixture text.
            rendered = source.replace("$${", "\x00{")
            rendered = re.sub(r"\$\{[^{}]*\}", "synthetic", rendered)
            rendered = rendered.replace("\x00{", "${")
            with tempfile.NamedTemporaryFile(mode="w", suffix=".sh") as script:
                script.write(rendered)
                script.flush()
                result = subprocess.run(["bash", "-n", script.name], check=False, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_profile_image_binding_pins_debian13_and_requires_exact_rhel9_image(self):
        main = (LAB / "main.tf").read_text()
        variables = (LAB / "variables.tf").read_text()
        outputs = (LAB / "outputs.tf").read_text()
        self.assertIn('contains(["ubuntu-24.04", "debian-13", "rhel-9"], var.qualification_os_profile)', variables)
        self.assertIn('var.qualification_os_profile == "ubuntu-24.04" ? 1 : 0', main)
        self.assertIn('var.qualification_os_profile == "debian-13" ? 1 : 0', main)
        self.assertIn('var.qualification_os_profile == "debian-13" ? data.google_compute_image.debian_13[0].self_link', main)
        self.assertEqual(main.count("image = local.boot_image"), 2)
        self.assertIn('var.qualification_os_profile == "rhel-9" ? data.google_compute_image.rhel_9[0].self_link', main)
        self.assertIn('tonumber(var.qualification_os_minor) >= 8', main)
        debian_image = re.search(r'data "google_compute_image" "debian_13"\s*\{(?P<body>.*?)\n\}', main, re.S)
        rhel_image = re.search(r'data "google_compute_image" "rhel_9"\s*\{(?P<body>.*?)\n\}', main, re.S)
        self.assertIsNotNone(debian_image)
        self.assertIsNotNone(rhel_image)
        self.assertIn('project = "debian-cloud"', debian_image.group("body"))
        self.assertIn('name    = basename(var.debian_image_self_link)', debian_image.group("body"))
        self.assertNotIn("family", debian_image.group("body"))
        self.assertIn('project = split("/", var.rhel_image_self_link)[6]', rhel_image.group("body"))
        self.assertIn('name    = basename(var.rhel_image_self_link)', rhel_image.group("body"))
        self.assertIn("image_id == var.qualification_image_unique_id", main)
        self.assertNotIn('data "google_compute_image" "rhel"', main)
        self.assertNotIn('data "google_compute_image" "rocky"', main)
        self.assertIn('output "qualification_os_profile"', outputs)
        self.assertIn('output "boot_architecture"', outputs)
        self.assertIn('output "boot_image_id"', outputs)

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
        self.assertRegex(main, r'iap_tcp_cidr\s*=\s*"35\.235\.240\.0/20"')
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

    def test_private_egress_is_limited_to_customer_cidrs_and_restricted_google_apis(self):
        main = (LAB / "main.tf").read_text()
        variables = (LAB / "variables.tf").read_text()
        for resource_name in (
            "egress_internal",
            "egress_dns",
            "egress_private_mirrors",
            "egress_private_relay",
            "egress_restricted_googleapis",
            "egress_deny_other",
        ):
            self.assertIn(f'resource "google_compute_firewall" "{resource_name}"', main)
        private_mirrors = re.search(
            r'resource "google_compute_firewall" "egress_private_mirrors"\s*\{(?P<body>.*?)\n\}',
            main,
            re.S,
        )
        self.assertIsNotNone(private_mirrors)
        self.assertIn('ports    = ["443"]', private_mirrors.group("body"))
        self.assertIn('destination_ranges = tolist(var.approved_private_mirror_cidrs)', private_mirrors.group("body"))
        private_relay = re.search(
            r'resource "google_compute_firewall" "egress_private_relay"\s*\{(?P<body>.*?)\n\}',
            main,
            re.S,
        )
        self.assertIsNotNone(private_relay)
        self.assertIn('ports    = ["18443"]', private_relay.group("body"))
        self.assertIn('destination_ranges = tolist(var.approved_private_relay_cidrs)', private_relay.group("body"))
        googleapis = re.search(
            r'resource "google_compute_firewall" "egress_restricted_googleapis"\s*\{(?P<body>.*?)\n\}',
            main,
            re.S,
        )
        self.assertIsNotNone(googleapis)
        self.assertIn('ports    = ["443"]', googleapis.group("body"))
        self.assertNotIn('ports    = ["443", "18443"]', googleapis.group("body"))
        self.assertNotIn('ports    = ["80", "443"]', main)
        self.assertIn('ports    = ["53"]', main)
        self.assertIn('protocol = "all"', main)
        self.assertIn('destination_ranges = ["0.0.0.0/0"]', main)
        self.assertIn('destination_ranges = [local.restricted_googleapis_cidr]', main)
        self.assertNotIn('resource "google_compute_router_nat"', main)
        self.assertNotIn('resource "google_compute_router"', main)
        self.assertNotIn('resource "google_compute_firewall" "egress_web"', main)
        deny = re.search(
            r'resource "google_compute_firewall" "egress_deny_other"\s*\{(?P<body>.*?)\n\}',
            main,
            re.S,
        )
        self.assertIsNotNone(deny)
        self.assertIn('priority           = 1000', deny.group("body"))
        self.assertIn('destination_ranges = ["0.0.0.0/0"]', deny.group("body"))
        self.assertIn('deny {\n    protocol = "all"', deny.group("body"))
        self.assertNotIn("allow {", deny.group("body"))
        for variable_name in ("approved_private_mirror_cidrs", "approved_private_relay_cidrs"):
            private_ranges = re.search(
                rf'variable "{variable_name}"\s*\{{(?P<body>.*?)\n\}}',
                variables,
                re.S,
            )
            self.assertIsNotNone(private_ranges)
            self.assertIn("RFC1918", private_ranges.group("body"))
            self.assertIn("cidrhost(cidr, 0)", private_ranges.group("body"))
            self.assertIn("tonumber(split(cidr, \"/\")[1]) >= 24", private_ranges.group("body"))
        self.assertIn('199.36.153.4/30', main)
        self.assertIn('(:443)?', variables)
        self.assertIn('resource "google_dns_managed_zone" "restricted_googleapis"', main)
        self.assertIn('name         = "*.googleapis.com."', main)
        safety = re.search(
            r'resource "terraform_data" "project_safety"\s*\{(?P<body>.*?)\n\}',
            main,
            re.S,
        )
        self.assertIsNotNone(safety)
        self.assertIn('var.qualification_os_profile == "ubuntu-24.04"', safety.group("body"))
        self.assertIn('var.qualification_os_profile == "debian-13"', safety.group("body"))
        self.assertIn("var.ubuntu_apt_mirror_url", safety.group("body"))
        self.assertIn("var.debian_archive_mirror_url", safety.group("body"))
        self.assertIn("var.debian_security_mirror_url", safety.group("body"))
        self.assertIn('var.rhel_repository_gpg_fingerprint', safety.group("body"))
        self.assertNotIn('data "google_compute_image" "rocky"', main)
        self.assertIn('project = "debian-cloud"', main)
        self.assertIn('name    = basename(var.debian_image_self_link)', main)
        self.assertNotIn('family  = "debian-13"', main)
        for template_name in ("server-startup.sh.tftpl", "worker-startup.sh.tftpl"):
            template = (LAB / template_name).read_text()
            self.assertIn("UBUNTU_APT_MIRROR_URL='${ubuntu_apt_mirror_url}'", template)
            self.assertIn("DEBIAN_ARCHIVE_MIRROR_URL='${debian_archive_mirror_url}'", template)
            self.assertIn("DEBIAN_SECURITY_MIRROR_URL='${debian_security_mirror_url}'", template)
            self.assertIn("URIs: $${UBUNTU_APT_MIRROR_URL}", template)
            self.assertIn("noble-security", template)
            self.assertIn("ubuntu-archive-keyring.gpg", template)
            self.assertLess(template.index("kordex-ubuntu.sources"), template.index("apt-get update"))
            self.assertIn("trixie trixie-updates", template)
            self.assertIn("trixie-security", template)
            self.assertIn("debian-archive-keyring.gpg", template)
            self.assertLess(template.index("kordex-debian.sources"), template.index("apt-get update"))
            self.assertNotIn("http://archive.ubuntu.com", template)
            self.assertIn("repo_gpgcheck=1", template)
            self.assertIn("gpgcheck=1", template)
            self.assertIn('EXPECTED_OS_ID=debian', template)
            self.assertIn('EXPECTED_OS_VERSION=13', template)
            self.assertIn('EXPECTED_OS_ID=ubuntu', template)
            self.assertIn('EXPECTED_OS_VERSION=24.04', template)
            self.assertIn('dpkg --print-architecture)" != amd64', template)
            self.assertLess(template.index("Host OS identity does not match selected profile"),
                            template.index("kordex-debian.sources"))
            self.assertIn("Host machine identity is unavailable or malformed", template)
            self.assertIn("K3s bootstrap requires systemd and mounted cgroups", template)

    def test_private_egress_inputs_are_explicit_and_no_public_nat_is_configured(self):
        main = (LAB / "main.tf").read_text()
        variables = (LAB / "variables.tf").read_text()
        examples = (LAB / "terraform.tfvars.example").read_text()
        for variable_name in ("approved_private_mirror_cidrs", "approved_private_relay_cidrs"):
            body = re.search(rf'variable "{variable_name}"\s*\{{(?P<body>.*?)\n\}}', variables, re.S).group("body")
            self.assertIn("type        = set(string)", body)
            self.assertNotRegex(body, r'(?m)^\s*default\s*=')
        self.assertIn('variable "ubuntu_apt_mirror_url"', variables)
        self.assertIn("approved_private_mirror_cidrs =", examples)
        self.assertIn("approved_private_relay_cidrs =", examples)
        self.assertIn("ubuntu_apt_mirror_url =", examples)
        self.assertIn('private_ip_google_access = true', main)
        self.assertIn('google_dns_record_set" "restricted_googleapis_a', main)
        self.assertIn('google_dns_record_set" "restricted_googleapis_wildcard', main)
        self.assertNotIn("google_compute_router_nat", main)
        self.assertIn("RFC1918 CIDRs supplied by the customer", (LAB / "README.md").read_text())
        self.assertIn("K3s system images use a separate customer-signed", (LAB / "README.md").read_text())

    def test_lab_topology_has_two_worker_peers_and_exports_all_nodes(self):
        main = (LAB / "main.tf").read_text()
        outputs = (LAB / "outputs.tf").read_text()
        server = (LAB / "server-startup.sh.tftpl").read_text()
        worker_resource = re.search(
            r'resource "google_compute_instance" "worker"\s*\{(?P<body>.*?)\n\}',
            main,
            re.S,
        )
        self.assertIsNotNone(worker_resource)
        self.assertIn("for_each                  = local.worker_vm_names", worker_resource.group("body"))
        self.assertIn('worker-1 = "${var.name_prefix}-worker"', main)
        self.assertIn('worker-2 = "${var.name_prefix}-worker-2"', main)
        self.assertIn('from = google_compute_instance.worker\n  to   = google_compute_instance.worker["worker-1"]', main)
        self.assertRegex(main, r'worker_names\s*=\s*\[local\.worker_vm_names\["worker-1"\], local\.worker_vm_names\["worker-2"\]\]')
        self.assertIn('output "server_name"', outputs)
        self.assertIn('output "worker_names"', outputs)
        self.assertIn('output "worker_internal_ips"', outputs)
        self.assertIn('output "k3s_node_names"', outputs)
        self.assertIn('google_compute_instance.worker["worker-1"].name', outputs)
        self.assertIn('google_compute_instance.worker["worker-2"].name', outputs)
        self.assertIn('WORKER_NAMES=(', server)
        self.assertIn('for worker_name in "$${WORKER_NAMES[@]}"', server)
        self.assertIn('if [[ "$${all_workers_ready}" == true ]]', server)
        self.assertIn('k3s token list', server)
        self.assertIn('^$${BOOTSTRAP_ID}[[:space:]]', server)
        self.assertIn('token remains active after deletion', server)

    def test_k3s_artifact_is_pinned_checked_and_bootstrapped_without_remote_installer(self):
        variables = (LAB / "variables.tf").read_text()
        templates = "\n".join((LAB / name).read_text() for name in (
            "server-startup.sh.tftpl", "worker-startup.sh.tftpl"
        ))
        version = re.search(r'variable "k3s_version"\s*\{(?P<body>.*?)\n\}', variables, re.S)
        digest = re.search(r'variable "k3s_binary_sha256"\s*\{(?P<body>.*?)\n\}', variables, re.S)
        mirror = re.search(r'variable "k3s_binary_mirror_url"\s*\{(?P<body>.*?)\n\}', variables, re.S)
        self.assertIsNotNone(version)
        self.assertIsNotNone(digest)
        self.assertIsNotNone(mirror)
        self.assertRegex(version.group("body"), r'default\s*=\s*"v1\.36\.6\+k3s1"')
        self.assertIn('var.k3s_version == "v1.36.6+k3s1"', version.group("body"))
        self.assertIn("github", mirror.group("body"))
        self.assertNotRegex(digest.group("body"), r'(?m)^\s*default\s*=')
        self.assertIn('regex("^[a-f0-9]{64}$", var.k3s_binary_sha256)', digest.group("body"))
        valid_digest = re.compile(r"^[a-f0-9]{64}$")
        self.assertIsNotNone(valid_digest.fullmatch("a" * 64))
        self.assertIsNone(valid_digest.fullmatch("a" * 63))
        self.assertIsNone(valid_digest.fullmatch("g" * 64))
        self.assertIn("sha256sum --check --status", templates)
        self.assertIn('K3S_BINARY_MIRROR_URL=\'${k3s_binary_mirror_url}\'', templates)
        self.assertIn('"$${K3S_BINARY_MIRROR_URL}"', templates)
        self.assertEqual(templates.count("curl -q --proto '=https' --max-redirs 0"), 4)
        self.assertNotIn("--location", templates)
        self.assertNotIn("--insecure", templates)
        self.assertNotIn("get.k3s.io", templates)
        self.assertEqual(templates.count("K3S_ARCH=amd64"), 2)
        self.assertEqual(templates.count('[[ "$(uname -m)" != x86_64 ]]'), 2)
        self.assertIn("Pinned K3s artifact is linux/$${K3S_ARCH}", templates)
        self.assertIn("internal artifact mirror", mirror.group("body"))
        self.assertNotIn("github.com/k3s-io/k3s/releases", templates)
        self.assertIn("/etc/systemd/system/k3s.service", templates)
        self.assertIn("/etc/systemd/system/k3s-agent.service", templates)

    def test_k3s_system_images_are_signed_bound_staged_and_public_fallback_disabled(self):
        variables = (LAB / "variables.tf").read_text()
        main = (LAB / "main.tf").read_text()
        templates = "\n".join((LAB / name).read_text() for name in (
            "server-startup.sh.tftpl", "worker-startup.sh.tftpl"
        ))
        for variable in (
            "k3s_system_images_manifest_version", "k3s_system_images_k3s_version",
            "k3s_system_images_architecture", "k3s_system_images_bundle_sha256",
            "k3s_system_images_bundle_mirror_url", "k3s_system_images_mirror_host",
        ):
            self.assertIn(f'variable "{variable}"', variables)
            self.assertIn(f"var.{variable}", main)
        self.assertNotRegex(variables, re.compile(r'variable "k3s_system_images_bundle_sha256"\s*\{[^}]*default\s*=', re.S))
        self.assertIn("k3s_system_images_k3s_version == var.k3s_version", main)
        self.assertEqual(templates.count("--disable-default-registry-endpoint"), 2)
        self.assertEqual(templates.count("K3S_SYSTEM_IMAGES_MIRROR_URL='${k3s_system_images_bundle_mirror_url}'"), 2)
        self.assertEqual(templates.count("install_k3s_system_images"), 4)
        self.assertIn("K3s image staging path contains an unexpected cached artifact", templates)
        self.assertIn("Existing K3s image archive is not the customer-approved bundle", templates)
        self.assertIn("registries.yaml", templates)
        self.assertNotIn("docker.io/rancher", templates)
        self.assertNotIn("--insecure", templates)

    def test_checksum_verification_accepts_exact_binary_and_rejects_tampering(self):
        templates = "\n".join((LAB / name).read_text() for name in (
            "server-startup.sh.tftpl", "worker-startup.sh.tftpl"
        ))
        self.assertIn('printf \'%s  %s\\n\' "$${K3S_BINARY_SHA256}" /usr/local/bin/k3s | sha256sum --check --status', templates)
        with tempfile.TemporaryDirectory() as temporary:
            artifact = pathlib.Path(temporary) / "k3s"
            artifact.write_bytes(b"trusted test fixture")
            digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
            check_file = pathlib.Path(temporary) / "k3s.sha256"
            check_file.write_text(f"{digest}  {artifact}\n")
            verified = subprocess.run(["sha256sum", "--check", "--status", str(check_file)], check=False)
            self.assertEqual(verified.returncode, 0)
            artifact.write_bytes(b"tampered test fixture")
            rejected = subprocess.run(["sha256sum", "--check", "--status", str(check_file)], check=False)
            self.assertNotEqual(rejected.returncode, 0)

    def test_worker_bootstrap_token_is_root_only_and_server_revoked(self):
        worker = (LAB / "worker-startup.sh.tftpl").read_text()
        server = (LAB / "server-startup.sh.tftpl").read_text()
        self.assertIn("--ttl=30m", server)
        self.assertIn("--token-file=$${TOKEN_FILE}", worker)
        self.assertIn("TOKEN_FILE=/var/lib/kordex/agent-token", worker)
        self.assertIn("BOOTSTRAP_COMPLETE=/var/lib/kordex-lab/bootstrap-complete", worker)
        self.assertIn("if [[ -f \"$${BOOTSTRAP_COMPLETE}\" ]]; then", worker)
        self.assertIn("BOOTSTRAP_STATE_FILE=", server)
        self.assertIn("if [[ -s \"$${BOOTSTRAP_STATE_FILE}\" ]]; then", server)
        self.assertIn("BOOTSTRAP_COMPLETE=", server)
        self.assertIn("present", worker)

    def test_operator_peer_safety_rule_remains_fail_closed(self):
        checks = (ROOT / "operator/internal/safety/checks.go").read_text()
        self.assertIn('n.Name != target && !ControlPlane(n) && !n.Spec.Unschedulable', checks)
        self.assertIn('Block("NoAvailableWorkerPeer")', checks)

    def test_terraform_and_helper_target_project_explicitly(self):
        provider = (LAB / "versions.tf").read_text()
        helper = (ROOT / "scripts/self_managed_lab.py").read_text()
        example = (LAB / "terraform.tfvars.example").read_text()
        self.assertRegex(provider, r"(?m)^\s*project\s*=\s*var\.project_id$")
        self.assertRegex(provider, r"(?m)^\s*impersonate_service_account\s*=\s*var\.terraform_principal_email$")
        self.assertIn('project_id = "kordex-fleet-platform-515416"', example)
        self.assertIn('f"--project={project_id}"', helper)


if __name__ == "__main__":
    unittest.main()
