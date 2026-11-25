import hashlib
import json
import os
import pathlib
import re
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
LAB = ROOT / "infrastructure/terraform/gcp/self-managed-lab"

APPROVED_GPG_FP = "0123456789ABCDEF0123456789ABCDEF01234567"
OTHER_GPG_FP = "FEDCBA9876543210FEDCBA9876543210FEDCBA98"
PINNED_EVRAS = {
    "k3s-selinux": "1.6-1.el9.noarch",
    "container-selinux": "2:2.229.0-2.el9_4.noarch",
    "policycoreutils-python-utils": "3.6-2.1.el9.noarch",
}

FAKE_K3S_SCRIPT = b"""#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  kubectl)
    if [[ "$*" == *"get --raw=/readyz"* ]]; then
      echo ok
      exit 0
    fi
    if [[ "$*" == *"get node"* ]]; then
      echo True
      exit 0
    fi
    ;;
  token)
    case "${2:-}" in
      create)
        echo "K10abcdef::abc123.0123456789abcdef"
        exit 0
        ;;
      list)
        if [[ -f "${TEST_STATE_DIR}/token-deleted" ]]; then
          echo "TOKEN TTL EXPIRES"
        else
          echo "TOKEN TTL EXPIRES"
          echo "abc123 29m 2026-11-24T12:00:00Z"
        fi
        exit 0
        ;;
      delete)
        : > "${TEST_STATE_DIR}/token-deleted"
        exit 0
        ;;
    esac
    ;;
esac
exit 0
"""

FAKE_AIRGAP_BUNDLE = b"synthetic-k3s-airgap-images-tar-bytes"

FAKE_SECRET_HELPER = r"""#!/usr/bin/env python3
import pathlib, sys
cmd = sys.argv[1]
if cmd == "present":
    # Server checks before publish (absent -> exit 1); worker checks after join (revoked -> exit 1)
    raise SystemExit(1)
if cmd == "publish":
    _ = sys.stdin.read()
    proj = sys.argv[sys.argv.index("--project") + 1]
    sec = sys.argv[sys.argv.index("--secret") + 1]
    print(f"projects/{proj}/secrets/{sec}/versions/1")
    raise SystemExit(0)
if cmd == "fetch":
    out = pathlib.Path(sys.argv[sys.argv.index("--output") + 1])
    out.write_text("K10abcdef::abc123.0123456789abcdef\n", encoding="utf-8")
    raise SystemExit(0)
if cmd == "destroy":
    raise SystemExit(0)
raise SystemExit(2)
"""


def _write_executable(path: pathlib.Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


def _render_template(template_name: str, root: pathlib.Path, overrides: dict[str, str] | None = None) -> pathlib.Path:
    k3s_sha = hashlib.sha256(FAKE_K3S_SCRIPT).hexdigest()
    bundle_sha = hashlib.sha256(FAKE_AIRGAP_BUNDLE).hexdigest()
    values = {
        "os_family": "rhel",
        "qualification_os_profile": "rhel-9",
        "qualification_os_minor": "8",
        "qualification_os_point_release": "9.8",
        "ubuntu_apt_mirror_url": "",
        "debian_archive_mirror_url": "",
        "debian_security_mirror_url": "",
        "rhel_repository_baseurl": "https://rpm.example.internal/rhel/9.8",
        "rhel_repository_gpg_key_path": "/etc/pki/rpm-gpg/RPM-GPG-KEY-customer",
        "rhel_repository_gpg_key_url": "https://rpm.example.internal/keys/RPM-GPG-KEY-customer",
        "rhel_repository_gpg_fingerprint": APPROVED_GPG_FP,
        "rhel_k3s_selinux_evra": PINNED_EVRAS["k3s-selinux"],
        "rhel_container_selinux_evra": PINNED_EVRAS["container-selinux"],
        "rhel_policycoreutils_evra": PINNED_EVRAS["policycoreutils-python-utils"],
        "project_id": "kordex-fleet-platform-515416",
        "secret_id": "kordex-m3-lab-agent-join",
        "server_ip": "10.76.0.10",
        "worker_name": "kordex-m3-lab-worker",
        "worker_names[0]": "kordex-m3-lab-worker",
        "worker_names[1]": "kordex-m3-lab-worker-2",
        "k3s_version": "v1.36.6+k3s1",
        "k3s_binary_sha256": k3s_sha,
        "k3s_binary_mirror_url": "https://mirror.example.internal/k3s/v1.36.6+k3s1/k3s",
        "k3s_system_images_manifest_version": "1",
        "k3s_system_images_k3s_version": "v1.36.6+k3s1",
        "k3s_system_images_architecture": "linux/amd64",
        "k3s_system_images_bundle_sha256": bundle_sha,
        "k3s_system_images_bundle_mirror_url": "https://mirror.example.internal/k3s/v1.36.6+k3s1/images.tar",
        "k3s_system_images_mirror_host": "registry.example.internal",
        "upgrade_ssh_user": "kordex",
        "secret_helper": FAKE_SECRET_HELPER,
    }
    if overrides:
        values.update(overrides)

    source = (LAB / template_name).read_text(encoding="utf-8")
    # Replicate Terraform templatefile() interpolation and escaping semantics.
    protected = source.replace("$${", "\x00{")

    def repl(match: re.Match[str]) -> str:
        key = match.group(1)
        if key not in values:
            raise KeyError(f"Missing template test variable: {key}")
        return values[key]

    rendered = re.sub(r"\$\{([^{}]+)\}", repl, protected)
    rendered = rendered.replace("\x00{", "${").replace("%%{", "%{")

    # Relocate absolute host paths into the isolated temporary root without
    # adding test hooks to the production templates.
    root_str = str(root)
    for prefix in (
        "/etc/",
        "/usr/local/bin/",
        "/usr/local/sbin/",
        "/var/lib/",
        "/proc/1/comm",
        "/sys/fs/cgroup",
    ):
        rendered = rendered.replace(prefix, root_str + prefix)

    script_path = root / f"rendered-{template_name}.sh"
    _write_executable(script_path, rendered)
    return script_path


class FakeRHELHost:
    def __init__(self, tmpdir: pathlib.Path, **config):
        self.root = tmpdir
        self.bin_dir = tmpdir / "bin"
        self.state_dir = tmpdir / "state"
        self.events_file = self.state_dir / "events.log"
        self.rpm_db_file = self.state_dir / "rpm_db.json"
        self.semodules_file = self.state_dir / "semodules.txt"
        self.getenforce_file = self.state_dir / "getenforce.txt"
        self.config_file = self.state_dir / "config.json"

        for rel in (
            "bin",
            "state",
            "etc/pki/rpm-gpg",
            "etc/yum.repos.d",
            "etc/selinux",
            "etc/modules-load.d",
            "etc/sysctl.d",
            "etc/systemd/system",
            "etc/sudoers.d",
            "etc/rancher/k3s",
            "usr/local/bin",
            "usr/local/sbin",
            "var/lib/kordex-lab",
            "var/lib/kordex",
            "var/lib/rancher/k3s",
            "proc/1",
            "sys/fs/cgroup",
        ):
            (tmpdir / rel).mkdir(parents=True, exist_ok=True)

        (tmpdir / "etc/os-release").write_text('ID="rhel"\nVERSION_ID="9.8"\n', encoding="utf-8")
        (tmpdir / "etc/redhat-release").write_text("Red Hat Enterprise Linux release 9.8 (Plow)\n", encoding="utf-8")
        (tmpdir / "etc/yum.repos.d/redhat.repo").write_text("[rhui-baseos]\nenabled=1\n", encoding="utf-8")
        (tmpdir / "etc/selinux/config").write_text(
            config.get("selinux_config", "SELINUX=enforcing\nSELINUXTYPE=targeted\n"),
            encoding="utf-8",
        )
        (tmpdir / "etc/machine-id").write_text("1234567890abcdef1234567890abcdef\n", encoding="utf-8")
        (tmpdir / "proc/1/comm").write_text("systemd\n", encoding="utf-8")
        (tmpdir / "sys/fs/cgroup/cgroup.controllers").write_text("cpu memory pids\n", encoding="utf-8")

        initial_rpms = {
            "redhat-release": "0:9.8-1.el9.x86_64",
            "google-rhui-client-rhel9": "0:20261113-1.el9.noarch",
            "curl": "0:7.76.1-29.el9.x86_64",
            "openssh-server": "0:8.7p1-38.el9.x86_64",
            "python3": "0:3.9.18-3.el9.x86_64",
            "sudo": "0:1.9.5p2-10.el9.x86_64",
            "firewalld": "0:1.3.4-5.el9.noarch",
        }
        if "initial_rpms" in config:
            initial_rpms = dict(config["initial_rpms"])
        self.rpm_db_file.write_text(json.dumps(initial_rpms), encoding="utf-8")

        self.semodules_file.write_text(config.get("initial_semodules", "base\n"), encoding="utf-8")
        self.getenforce_file.write_text(config.get("getenforce", "Enforcing") + "\n", encoding="utf-8")

        shim_cfg = {
            "gpg_lines": config.get(
                "gpg_lines",
                f"pub:-:4096:1:0123456789ABCDEF:1700000000:::-:::scESC::::::23::0:\n"
                f"fpr:::::::::{APPROVED_GPG_FP}:\n"
                f"uid:-::::1700000000::HASH::Customer RPM Key:\n"
                f"sub:-:4096:1:1111222233334444:1700000000::::::e::::::23:\n"
                f"fpr:::::::::{OTHER_GPG_FP}:\n",
            ),
            "gpg_rc": config.get("gpg_rc", 0),
            "curl_fail_gpg_key": config.get("curl_fail_gpg_key", False),
            "dnf_fail_makecache": config.get("dnf_fail_makecache", False),
            "dnf_fail_install": config.get("dnf_fail_install", False),
            "dnf_install_map": config.get(
                "dnf_install_map",
                {
                    f"container-selinux-{PINNED_EVRAS['container-selinux']}": (
                        "container-selinux",
                        PINNED_EVRAS["container-selinux"],
                    ),
                    f"policycoreutils-python-utils-{PINNED_EVRAS['policycoreutils-python-utils']}": (
                        "policycoreutils-python-utils",
                        "0:" + PINNED_EVRAS["policycoreutils-python-utils"],
                    ),
                    f"k3s-selinux-{PINNED_EVRAS['k3s-selinux']}": (
                        "k3s-selinux",
                        "0:" + PINNED_EVRAS["k3s-selinux"],
                    ),
                },
            ),
            "dnf_loads_k3s_module": config.get("dnf_loads_k3s_module", True),
            "firewalld_active": config.get("firewalld_active", True),
            "firewalld_enabled": config.get("firewalld_enabled", True),
            "restorecon_fail": config.get("restorecon_fail", False),
            "flip_getenforce_on_restorecon": config.get("flip_getenforce_on_restorecon", ""),
        }
        self.config_file.write_text(json.dumps(shim_cfg), encoding="utf-8")

        if config.get("prebaked_key"):
            (tmpdir / "etc/pki/rpm-gpg/RPM-GPG-KEY-customer").write_text(
                "-----BEGIN PGP PUBLIC KEY BLOCK-----\n", encoding="utf-8"
            )
        if config.get("symlink_gpg_key"):
            target = tmpdir / "state/other-key"
            target.write_text("key", encoding="utf-8")
            (tmpdir / "etc/pki/rpm-gpg/RPM-GPG-KEY-customer").symlink_to(target)
        if config.get("symlink_k3s_config"):
            target = tmpdir / "state/other-config.yaml"
            target.write_text("selinux: true\n", encoding="utf-8")
            (tmpdir / "etc/rancher/k3s/config.yaml").symlink_to(target)
        if config.get("dir_k3s_config"):
            (tmpdir / "etc/rancher/k3s/config.yaml").mkdir(parents=True, exist_ok=True)
        if config.get("symlink_repo_file"):
            target = tmpdir / "state/should-not-be-overwritten.repo"
            target.write_text("UNTOUCHED\n", encoding="utf-8")
            (tmpdir / "etc/yum.repos.d/kordex-qualification.repo").symlink_to(target)

        (self.state_dir / "k3s.bin").write_bytes(FAKE_K3S_SCRIPT)
        (self.state_dir / "airgap.tar").write_bytes(FAKE_AIRGAP_BUNDLE)

        self._install_shims()

    def _install_shims(self) -> None:
        _write_executable(
            self.bin_dir / "gpg",
            r"""#!/usr/bin/env python3
import json, os, pathlib, sys
state = pathlib.Path(os.environ["TEST_STATE_DIR"])
cfg = json.loads((state / "config.json").read_text())
with (state / "events.log").open("a") as f:
    f.write("gpg_verify\n")
if cfg["gpg_rc"] != 0:
    raise SystemExit(cfg["gpg_rc"])
sys.stdout.write(cfg["gpg_lines"])
""",
        )
        _write_executable(
            self.bin_dir / "curl",
            r"""#!/usr/bin/env python3
import json, os, pathlib, sys
state = pathlib.Path(os.environ["TEST_STATE_DIR"])
cfg = json.loads((state / "config.json").read_text())
args = sys.argv[1:]
url = next(a for a in args if a.startswith("http://") or a.startswith("https://"))
out = args[args.index("--output") + 1] if "--output" in args else None
if "metadata.google.internal" in url:
    sys.stdout.write("10.76.0.10")
    raise SystemExit(0)
if "/keys/" in url:
    with (state / "events.log").open("a") as f:
        f.write(f"curl_gpg_key:{url}\n")
    if cfg["curl_fail_gpg_key"]:
        raise SystemExit(22)
    pathlib.Path(out).write_text("-----BEGIN PGP PUBLIC KEY BLOCK-----\n")
    raise SystemExit(0)
if url.endswith("/k3s"):
    with (state / "events.log").open("a") as f:
        f.write("curl_k3s_bin\n")
    pathlib.Path(out).write_bytes((state / "k3s.bin").read_bytes())
    raise SystemExit(0)
if url.endswith("/images.tar"):
    with (state / "events.log").open("a") as f:
        f.write("curl_k3s_images\n")
    pathlib.Path(out).write_bytes((state / "airgap.tar").read_bytes())
    raise SystemExit(0)
raise SystemExit(22)
""",
        )
        _write_executable(
            self.bin_dir / "rpm",
            r"""#!/usr/bin/env python3
import json, os, pathlib, sys
state = pathlib.Path(os.environ["TEST_STATE_DIR"])
db_path = state / "rpm_db.json"
db = json.loads(db_path.read_text())
args = sys.argv[1:]
if args == ["--eval", "%{_arch}"]:
    print("x86_64")
    raise SystemExit(0)
if args and args[0] == "--import":
    with (state / "events.log").open("a") as f:
        f.write(f"rpm_import:{args[1]}\n")
    raise SystemExit(0)
if args == ["-q", "--qf", "%{VENDOR}", "redhat-release"]:
    sys.stdout.write("Red Hat, Inc.")
    raise SystemExit(0)
if args == ["-qa", "--qf", r"%{NAME}\n"]:
    for name in db:
        print(name)
    raise SystemExit(0)
if len(args) == 4 and args[:2] == ["-q", "--qf"] and "EPOCHNUM" in args[2]:
    pkg = args[3]
    if pkg not in db:
        raise SystemExit(1)
    print(db[pkg])
    raise SystemExit(0)
if args and args[0] == "-q":
    for pkg in args[1:]:
        if pkg not in db:
            raise SystemExit(1)
    raise SystemExit(0)
raise SystemExit(1)
""",
        )
        _write_executable(
            self.bin_dir / "dnf",
            r"""#!/usr/bin/env python3
import json, os, pathlib, sys
state = pathlib.Path(os.environ["TEST_STATE_DIR"])
cfg = json.loads((state / "config.json").read_text())
db_path = state / "rpm_db.json"
db = json.loads(db_path.read_text())
args = sys.argv[1:]
if "--disablerepo=*" not in args or "--enablerepo=kordex-qualification" not in args:
    sys.stderr.write("dnf must lock exclusively to kordex-qualification\n")
    raise SystemExit(1)
for required_opt in (
    "--setopt=gpgcheck=1",
    "--setopt=repo_gpgcheck=1",
    "--setopt=localpkg_gpgcheck=1",
    "--setopt=skip_if_unavailable=0",
):
    if required_opt not in args:
        sys.stderr.write(f"dnf missing required option: {required_opt}\n")
        raise SystemExit(1)
if "makecache" in args:
    with (state / "events.log").open("a") as f:
        f.write("dnf_makecache\n")
    raise SystemExit(1 if cfg["dnf_fail_makecache"] else 0)
if "install" in args:
    if "--" in args:
        specs = args[args.index("--") + 1 :]
    else:
        specs = [a for a in args if not a.startswith("-") and a != "install"]
    with (state / "events.log").open("a") as f:
        f.write("dnf_install:" + ",".join(specs) + "\n")
    if cfg["dnf_fail_install"]:
        raise SystemExit(1)
    install_map = cfg["dnf_install_map"]
    for spec in specs:
        if spec not in install_map:
            sys.stderr.write(f"package not in approved repo: {spec}\n")
            raise SystemExit(1)
        pkg, evra = install_map[spec]
        db[pkg] = evra
        if pkg == "k3s-selinux" and cfg["dnf_loads_k3s_module"]:
            with (state / "semodules.txt").open("a") as sf:
                sf.write("k3s\n")
    db_path.write_text(json.dumps(db))
    raise SystemExit(0)
raise SystemExit(1)
""",
        )
        _write_executable(
            self.bin_dir / "getenforce",
            '#!/usr/bin/env bash\ncat "${TEST_STATE_DIR}/getenforce.txt"\n',
        )
        _write_executable(
            self.bin_dir / "semodule",
            '#!/usr/bin/env bash\necho "semodule_check" >> "${TEST_STATE_DIR}/events.log"\nif [[ "${1:-}" == "-l" ]]; then\n  cat "${TEST_STATE_DIR}/semodules.txt"\n  exit 0\nfi\nexit 1\n',
        )
        _write_executable(
            self.bin_dir / "restorecon",
            r"""#!/usr/bin/env python3
import json, os, pathlib, sys
state = pathlib.Path(os.environ["TEST_STATE_DIR"])
cfg = json.loads((state / "config.json").read_text())
with (state / "events.log").open("a") as f:
    f.write("restorecon:" + " ".join(sys.argv[1:]) + "\n")
if cfg["flip_getenforce_on_restorecon"]:
    (state / "getenforce.txt").write_text(cfg["flip_getenforce_on_restorecon"] + "\n")
raise SystemExit(1 if cfg["restorecon_fail"] else 0)
""",
        )
        _write_executable(
            self.bin_dir / "systemctl",
            r"""#!/usr/bin/env python3
import json, os, pathlib, sys
state = pathlib.Path(os.environ["TEST_STATE_DIR"])
cfg = json.loads((state / "config.json").read_text())
args = sys.argv[1:]
with (state / "events.log").open("a") as f:
    f.write("systemctl:" + " ".join(args) + "\n")
if args[:2] == ["is-active", "--quiet"] and args[-1] == "firewalld":
    raise SystemExit(0 if cfg["firewalld_active"] else 3)
if args[:2] == ["is-enabled", "--quiet"] and args[-1] == "firewalld":
    raise SystemExit(0 if cfg["firewalld_enabled"] else 1)
raise SystemExit(0)
""",
        )
        _write_executable(self.bin_dir / "chown", "#!/usr/bin/env bash\nexit 0\n")
        _write_executable(
            self.bin_dir / "install",
            r"""#!/usr/bin/env python3
import os, sys
cleaned = []
skip = False
for arg in sys.argv[1:]:
    if skip:
        skip = False
        continue
    if arg in ("-o", "-g"):
        skip = True
        continue
    cleaned.append(arg)
os.execv("/usr/bin/install", ["/usr/bin/install", *cleaned])
""",
        )
        for noop in ("firewall-cmd", "modprobe", "ip", "iptables", "useradd", "usermod", "visudo", "sleep"):
            _write_executable(self.bin_dir / noop, "#!/usr/bin/env bash\nexit 0\n")
        _write_executable(self.bin_dir / "id", "#!/usr/bin/env bash\nexit 0\n")
        _write_executable(self.bin_dir / "timeout", "#!/usr/bin/env bash\nexit 0\n")
        _write_executable(self.bin_dir / "uname", "#!/usr/bin/env bash\necho x86_64\n")
        _write_executable(
            self.bin_dir / "sysctl",
            '#!/usr/bin/env bash\nif [[ "${1:-}" == "-n" ]]; then echo 1; fi\nexit 0\n',
        )

    def run_template(self, template_name: str, overrides: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        script = _render_template(template_name, self.root, overrides)
        env = dict(os.environ)
        env["PATH"] = f"{self.bin_dir}:{env.get('PATH', '/usr/bin:/bin')}"
        env["TEST_STATE_DIR"] = str(self.state_dir)
        return subprocess.run(["bash", str(script)], env=env, capture_output=True, text=True, check=False)

    def events(self) -> list[str]:
        if not self.events_file.exists():
            return []
        return self.events_file.read_text(encoding="utf-8").splitlines()


class RHELBootstrapSELinuxTests(unittest.TestCase):
    def test_rhel_server_and_worker_bootstrap_happy_path_and_strict_ordering(self):
        for template_name, unit_name in (
            ("server-startup.sh.tftpl", "k3s.service"),
            ("worker-startup.sh.tftpl", "k3s-agent.service"),
        ):
            with self.subTest(template=template_name), tempfile.TemporaryDirectory() as tmp:
                host = FakeRHELHost(pathlib.Path(tmp))
                result = host.run_template(template_name)
                self.assertEqual(result.returncode, 0, result.stderr)

                # Pre-existing repo files must be purged and private repo locked to GPG verification.
                self.assertFalse((host.root / "etc/yum.repos.d/redhat.repo").exists())
                repo_text = (host.root / "etc/yum.repos.d/kordex-qualification.repo").read_text(encoding="utf-8")
                self.assertIn("gpgcheck=1", repo_text)
                self.assertIn("repo_gpgcheck=1", repo_text)
                self.assertIn("skip_if_unavailable=0", repo_text)
                self.assertIn("baseurl=https://rpm.example.internal/rhel/9.8", repo_text)

                # Explicit K3s SELinux configuration and systemd ExecStart flag.
                k3s_cfg = (host.root / "etc/rancher/k3s/config.yaml").read_text(encoding="utf-8")
                self.assertEqual(k3s_cfg, "selinux: true\n")
                unit_text = (host.root / f"etc/systemd/system/{unit_name}").read_text(encoding="utf-8")
                self.assertIn("--selinux", unit_text)
                self.assertIn("--disable-default-registry-endpoint", unit_text)

                # Prove strict ordering: GPG fetch -> verify -> rpm import -> private dnf ->
                # semodule check -> restorecon -> systemctl daemon-reload -> enable --now.
                events = host.events()
                idx_fetch = next(i for i, e in enumerate(events) if e.startswith("curl_gpg_key:"))
                idx_gpg = events.index("gpg_verify")
                idx_import = next(i for i, e in enumerate(events) if e.startswith("rpm_import:"))
                idx_cache = events.index("dnf_makecache")
                idx_install = next(i for i, e in enumerate(events) if e.startswith("dnf_install:"))
                idx_semodule = events.index("semodule_check")
                idx_restorecon = next(i for i, e in enumerate(events) if e.startswith("restorecon:"))
                idx_reload = events.index("systemctl:daemon-reload")
                idx_start = events.index(f"systemctl:enable --now {unit_name}")
                self.assertLess(idx_fetch, idx_gpg)
                self.assertLess(idx_gpg, idx_import)
                self.assertLess(idx_import, idx_cache)
                self.assertLess(idx_cache, idx_install)
                self.assertLess(idx_install, idx_semodule)
                self.assertLess(idx_semodule, idx_restorecon)
                self.assertLess(idx_restorecon, idx_reload)
                self.assertLess(idx_reload, idx_start)

                restorecon_calls = [e for e in events if e.startswith("restorecon:")]
                self.assertTrue(any("/usr/local/bin/k3s" in c and unit_name in c for c in restorecon_calls))
                self.assertTrue(any("/etc/rancher/k3s" in c and "/var/lib/rancher/k3s" in c for c in restorecon_calls))
                if unit_name == "k3s-agent.service":
                    self.assertTrue(any("/var/lib/kordex" in c for c in restorecon_calls))

                # Subsequent reboot invocation exits early via bootstrap-complete marker.
                before_reboot = len(events)
                reboot_result = host.run_template(template_name)
                self.assertEqual(reboot_result.returncode, 0, reboot_result.stderr)
                self.assertEqual(len(host.events()), before_reboot)

    def test_prebaked_gpg_key_without_url_succeeds(self):
        for template_name in ("server-startup.sh.tftpl", "worker-startup.sh.tftpl"):
            with self.subTest(template=template_name), tempfile.TemporaryDirectory() as tmp:
                host = FakeRHELHost(pathlib.Path(tmp), prebaked_key=True)
                result = host.run_template(template_name, {"rhel_repository_gpg_key_url": ""})
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(any(e.startswith("curl_gpg_key:") for e in host.events()))
                self.assertIn("gpg_verify", host.events())

    def test_invalid_missing_or_multikey_rpm_gpg_fingerprint_fails_closed(self):
        cases = [
            ("missing_fingerprint", {"rhel_repository_gpg_fingerprint": ""}, {}, "fingerprint is missing or malformed"),
            ("malformed_fingerprint", {"rhel_repository_gpg_fingerprint": "not-a-40-hex-fingerprint"}, {}, "fingerprint is missing or malformed"),
            ("mismatched_fingerprint", {"rhel_repository_gpg_fingerprint": OTHER_GPG_FP}, {}, "fingerprint differs from the approved input"),
            (
                "multi_key_keyring",
                {},
                {
                    "gpg_lines": (
                        f"pub:-:4096:1:0123456789ABCDEF:1700000000:::-:::scESC::::::23::0:\n"
                        f"fpr:::::::::{APPROVED_GPG_FP}:\n"
                        f"pub:-:4096:1:FEDCBA9876543210:1700000000:::-:::scESC::::::23::0:\n"
                        f"fpr:::::::::{OTHER_GPG_FP}:\n"
                    )
                },
                "contains multiple keys",
            ),
            (
                "revoked_primary_key",
                {},
                {
                    "gpg_lines": (
                        f"pub:r:4096:1:0123456789ABCDEF:1700000000:::-:::scESC::::::23::0:\n"
                        f"fpr:::::::::{APPROVED_GPG_FP}:\n"
                    )
                },
                "fingerprint differs from the approved input",
            ),
            (
                "expired_primary_key",
                {},
                {
                    "gpg_lines": (
                        f"pub:e:4096:1:0123456789ABCDEF:1700000000:::-:::scESC::::::23::0:\n"
                        f"fpr:::::::::{APPROVED_GPG_FP}:\n"
                    )
                },
                "fingerprint differs from the approved input",
            ),
            (
                "invalid_primary_key",
                {},
                {
                    "gpg_lines": (
                        f"pub:i:4096:1:0123456789ABCDEF:1700000000:::-:::scESC::::::23::0:\n"
                        f"fpr:::::::::{APPROVED_GPG_FP}:\n"
                    )
                },
                "fingerprint differs from the approved input",
            ),
            (
                "secret_key_material_rejected",
                {},
                {
                    "gpg_lines": (
                        f"sec:-:4096:1:0123456789ABCDEF:1700000000:::-:::scESC::::::23::0:\n"
                        f"pub:-:4096:1:0123456789ABCDEF:1700000000:::-:::scESC::::::23::0:\n"
                        f"fpr:::::::::{APPROVED_GPG_FP}:\n"
                    )
                },
                "fingerprint differs from the approved input",
            ),
            ("unparseable_gpg_key", {}, {"gpg_rc": 2}, "could not be parsed"),
            ("dotdot_key_path", {"rhel_repository_gpg_key_path": "/etc/pki/rpm-gpg/.."}, {}, "signing key path is missing or unsafe"),
            ("github_key_url", {"rhel_repository_gpg_key_url": "https://github.com/org/repo/key.asc"}, {}, "signing key URL is malformed"),
            ("traversal_key_url", {"rhel_repository_gpg_key_url": "https://rpm.example.internal/keys/../key.asc"}, {}, "signing key URL is malformed"),
            ("missing_key_without_url", {"rhel_repository_gpg_key_url": ""}, {}, "signing key is absent and no private mirror URL"),
            ("key_download_error", {}, {"curl_fail_gpg_key": True}, "failed download or approved fingerprint verification"),
            ("symlinked_key_path", {}, {"symlink_gpg_key": True}, "signing key is unavailable or unsafe"),
        ]
        for template_name in ("server-startup.sh.tftpl", "worker-startup.sh.tftpl"):
            for case_name, overrides, host_cfg, expected_err in cases:
                with self.subTest(template=template_name, case=case_name), tempfile.TemporaryDirectory() as tmp:
                    host = FakeRHELHost(pathlib.Path(tmp), **host_cfg)
                    result = host.run_template(template_name, overrides)
                    self.assertNotEqual(result.returncode, 0, f"{case_name} unexpectedly succeeded")
                    self.assertIn(expected_err, result.stderr)
                    events = host.events()
                    self.assertFalse(any(e.startswith("rpm_import:") for e in events))
                    self.assertFalse(any(e.startswith("dnf_install:") for e in events))
                    self.assertFalse(any("enable --now" in e for e in events))

    def test_invalid_missing_or_unapproved_package_versions_fail_closed(self):
        cases = [
            ("missing_k3s_selinux_pin", {"rhel_k3s_selinux_evra": ""}, {}, "version pin is missing or malformed: k3s-selinux"),
            ("unpinned_latest", {"rhel_k3s_selinux_evra": "latest"}, {}, "version pin is missing or malformed: k3s-selinux"),
            ("wrong_arch_pin", {"rhel_k3s_selinux_evra": "1.6-1.el9.aarch64"}, {}, "version pin is missing or malformed: k3s-selinux"),
            ("shell_injection_pin", {"rhel_k3s_selinux_evra": "1.6-1.el9.noarch;id"}, {}, "version pin is missing or malformed: k3s-selinux"),
            ("leading_zero_epoch_pin", {"rhel_container_selinux_evra": "02:2.229.0-2.el9_4.noarch"}, {}, "version pin is missing or malformed: container-selinux"),
            ("missing_container_selinux_pin", {"rhel_container_selinux_evra": ""}, {}, "version pin is missing or malformed: container-selinux"),
            ("missing_policycoreutils_pin", {"rhel_policycoreutils_evra": ""}, {}, "version pin is missing or malformed: policycoreutils-python-utils"),
            (
                "repo_installs_unapproved_k3s_selinux_version",
                {},
                {
                    "dnf_install_map": {
                        f"container-selinux-{PINNED_EVRAS['container-selinux']}": (
                            "container-selinux",
                            PINNED_EVRAS["container-selinux"],
                        ),
                        f"policycoreutils-python-utils-{PINNED_EVRAS['policycoreutils-python-utils']}": (
                            "policycoreutils-python-utils",
                            "0:" + PINNED_EVRAS["policycoreutils-python-utils"],
                        ),
                        f"k3s-selinux-{PINNED_EVRAS['k3s-selinux']}": (
                            "k3s-selinux",
                            "0:1.7-1.el9.noarch",
                        ),
                    }
                },
                "does not match approved EVRA: k3s-selinux-",
            ),
        ]
        for template_name in ("server-startup.sh.tftpl", "worker-startup.sh.tftpl"):
            for case_name, overrides, host_cfg, expected_err in cases:
                with self.subTest(template=template_name, case=case_name), tempfile.TemporaryDirectory() as tmp:
                    host = FakeRHELHost(pathlib.Path(tmp), **host_cfg)
                    result = host.run_template(template_name, overrides)
                    self.assertNotEqual(result.returncode, 0, f"{case_name} unexpectedly succeeded")
                    self.assertIn(expected_err, result.stderr)
                    self.assertFalse(any("enable --now" in e for e in host.events()))

    def test_missing_packages_or_repository_access_failure_fails_closed(self):
        cases = [
            ("repo_makecache_failed", {}, {"dnf_fail_makecache": True}, "", "dnf_makecache", "dnf_install:"),
            ("repo_install_failed", {}, {"dnf_fail_install": True}, "", "dnf_install:", "semodule_check"),
            ("missing_k3s_selinux_in_repo", {}, {"dnf_install_map": {}}, "package not in approved repo", "dnf_install:", "semodule_check"),
            ("non_https_repo_url", {"rhel_repository_baseurl": "http://rpm.example.internal/rhel/9.8"}, {}, "private repository URL is missing or malformed", "", "dnf_makecache"),
            ("github_repo_url", {"rhel_repository_baseurl": "https://github.com/org/repo"}, {}, "private repository URL is missing or malformed", "", "dnf_makecache"),
            ("traversal_repo_url", {"rhel_repository_baseurl": "https://rpm.example.internal/rhel/../9.8"}, {}, "private repository URL is missing or malformed", "", "dnf_makecache"),
            (
                "missing_firewalld_rpm",
                {},
                {
                    "initial_rpms": {
                        "redhat-release": "0:9.8-1.el9.x86_64",
                        "google-rhui-client-rhel9": "0:20261113-1.el9.noarch",
                        "curl": "0:7.76.1-29.el9.x86_64",
                        "openssh-server": "0:8.7p1-38.el9.x86_64",
                        "python3": "0:3.9.18-3.el9.x86_64",
                        "sudo": "0:1.9.5p2-10.el9.x86_64",
                    }
                },
                "",
                "dnf_install:",
                "semodule_check",
            ),
        ]
        for template_name in ("server-startup.sh.tftpl", "worker-startup.sh.tftpl"):
            for case_name, overrides, host_cfg, expected_err, must_reach, must_not_reach in cases:
                with self.subTest(template=template_name, case=case_name), tempfile.TemporaryDirectory() as tmp:
                    host = FakeRHELHost(pathlib.Path(tmp), **host_cfg)
                    result = host.run_template(template_name, overrides)
                    self.assertNotEqual(result.returncode, 0, f"{case_name} unexpectedly succeeded")
                    if expected_err:
                        self.assertIn(expected_err, result.stderr)
                    events = host.events()
                    if must_reach:
                        self.assertTrue(any(e.startswith(must_reach) for e in events), f"did not reach {must_reach}: {events}")
                    if must_not_reach:
                        self.assertFalse(any(e.startswith(must_not_reach) for e in events), f"unexpectedly reached {must_not_reach}: {events}")
                    self.assertFalse(any("enable --now" in e for e in events))

    def test_k3s_never_starts_before_selinux_setup_succeeds(self):
        cases = [
            ("selinux_permissive_at_boot", {"getenforce": "Permissive"}, "SELinux must remain Enforcing", "dnf_install:"),
            ("selinux_disabled_in_etc_config", {"selinux_config": "SELINUX=permissive\nSELINUXTYPE=targeted\n"}, "must persist SELINUX=enforcing across reboots", "dnf_install:"),
            ("k3s_selinux_module_not_loaded", {"dnf_loads_k3s_module": False}, "k3s SELinux policy module is not loaded", "semodule_check"),
            ("restorecon_fails", {"restorecon_fail": True}, "", "restorecon:"),
            ("selinux_drops_to_permissive_before_start", {"flip_getenforce_on_restorecon": "Permissive"}, "SELinux is not Enforcing before K3s start", "restorecon:"),
            ("symlinked_k3s_config_yaml", {"symlink_k3s_config": True}, "Refusing symlinked or unsafe K3s configuration path", "semodule_check"),
            ("directory_k3s_config_yaml", {"dir_k3s_config": True}, "Refusing symlinked or unsafe K3s configuration path", "semodule_check"),
            ("firewalld_not_enabled_for_reboot", {"firewalld_enabled": False}, "firewalld must remain enabled across reboots", "semodule_check"),
        ]
        for template_name in ("server-startup.sh.tftpl", "worker-startup.sh.tftpl"):
            for case_name, host_cfg, expected_err, must_reach in cases:
                with self.subTest(template=template_name, case=case_name), tempfile.TemporaryDirectory() as tmp:
                    host = FakeRHELHost(pathlib.Path(tmp), **host_cfg)
                    result = host.run_template(template_name)
                    self.assertNotEqual(result.returncode, 0, f"{case_name} unexpectedly succeeded")
                    if expected_err:
                        self.assertIn(expected_err, result.stderr)
                    events = host.events()
                    self.assertTrue(any(e.startswith(must_reach) for e in events), f"did not reach {must_reach}: {events}")
                    self.assertFalse(any("enable --now" in e for e in events))

    def test_preexisting_repo_symlink_is_purged_without_following_target(self):
        for template_name in ("server-startup.sh.tftpl", "worker-startup.sh.tftpl"):
            with self.subTest(template=template_name), tempfile.TemporaryDirectory() as tmp:
                host = FakeRHELHost(pathlib.Path(tmp), symlink_repo_file=True)
                result = host.run_template(template_name)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(
                    (host.state_dir / "should-not-be-overwritten.repo").read_text(encoding="utf-8"),
                    "UNTOUCHED\n",
                )
                repo_path = host.root / "etc/yum.repos.d/kordex-qualification.repo"
                self.assertFalse(repo_path.is_symlink())
                self.assertIn("repo_gpgcheck=1", repo_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
