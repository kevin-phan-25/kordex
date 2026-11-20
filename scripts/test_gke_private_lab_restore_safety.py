#!/usr/bin/env python3
"""Exercise restore safety gates with stubbed commands and a temporary archive."""
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESTORE = ROOT / "scripts/gke-private-lab-restore-postgres.sh"
CONTEXT = "gke_kordex-fleet-platform_us-east1-b_kordex-gke-test"


def run_case(scenario="success", *, archive_name="backup.dump.age", manifest_name=None, manifest_hash=None,
             archive_bytes=b"encrypted-archive", missing_manifest=False, manifest_text=None, context=CONTEXT,
             schema="14|14", records="1", membership="subject-a"):
    with tempfile.TemporaryDirectory(prefix="kordex-restore-test-") as tmp:
        base = Path(tmp)
        bin_dir = base / "bin"
        bin_dir.mkdir(mode=0o700)
        backup_dir = base / "backup"
        backup_dir.mkdir(mode=0o700)
        archive = backup_dir / archive_name
        archive.write_bytes(archive_bytes)
        digest = manifest_hash or hashlib.sha256(archive_bytes).hexdigest()
        manifest = backup_dir / "backup.sha256"
        if not missing_manifest:
            manifest.write_text(manifest_text if manifest_text is not None else f"{digest}  {manifest_name or archive_name}\n")
            manifest.chmod(0o600)
        archive.chmod(0o600)
        identity = base / "age.identity"
        identity.write_text("AGE-SECRET-KEY-TEST-FIXTURE\n")
        identity.chmod(0o600)
        realm_dir = base / "realm"
        realm_dir.mkdir(mode=0o700)
        (realm_dir / "kordex-realm.json").write_text(json.dumps({"realm": "kordex", "users": [{"id": "subject-a"}]}))
        calls = base / "kubectl-calls.log"

        (bin_dir / "age").write_text("""#!/usr/bin/env python3
import shutil,sys
a=sys.argv[1:]
src=a[-1]
dst=a[a.index('--output')+1]
shutil.copyfile(src,dst)
""")
        (bin_dir / "pg_restore").write_text("""#!/usr/bin/env python3
import sys
sys.exit(0)
""")
        (bin_dir / "kubectl").write_text("""#!/usr/bin/env python3
import os,sys
a=sys.argv[1:]
expected=os.environ['KORDEX_EXPECTED_KUBE_CONTEXT']
log=open(os.environ['KUBECTL_TEST_LOG'],'a')
log.write(' '.join(a)+'\\n'); log.close()
if not a or a[0] != '--context='+expected:
 print('missing or wrong explicit context',file=sys.stderr); sys.exit(90)
a=a[1:]
scenario=os.environ['RESTORE_TEST_SCENARIO']
def out(v): print(v); sys.exit(0)
if a[:3] == ['config','view','--minify']:
 out(expected)
if a[:3] == ['get','namespace','kordex-management']:
 out('namespace/kordex-management')
if 'statefulset' in a: out('statefulset.apps/kordex-postgres')
if 'deployment' in a and ('kordex-api' in a or 'kordex-keycloak' in a):
 out('1' if scenario in ('api_running','keycloak_running') and (('kordex-api' in a and scenario=='api_running') or ('kordex-keycloak' in a and scenario=='keycloak_running')) else '0')
if 'pods' in a and 'app.kubernetes.io/component=api' in a:
 out('kordex-api-123' if scenario=='api_pod_running' else '')
if 'pods' in a and 'app.kubernetes.io/name=kordex-keycloak' in a:
 out('kordex-keycloak-123' if scenario=='keycloak_pod_running' else '')
if 'pod' in a and 'jsonpath=' in ' '.join(a): out('Running|True')
if 'pvc' in a: out('Bound|pvc-kordex-pg')
if 'pv' in a:
 if scenario=='missing_pv': sys.exit(1)
 policy='Delete' if scenario=='delete_policy' else 'Retain'
 out(policy+'|kordex-management|data-kordex-postgres-0')
if 'exec' in a:
 joined=' '.join(a)
 if 'pg_restore' in joined and '--exit-on-error' in joined and scenario=='failed_restore': sys.exit(1)
 if 'SELECT count(*) FROM pg_class' in joined: out('0')
 if 'SHOW server_version_num' in joined: out('170005')
 if 'MAX(version)' in joined: out(os.environ['RESTORE_TEST_SCHEMA'])
 if 'FROM organizations o JOIN fleets' in joined: out(os.environ['RESTORE_TEST_RECORDS'])
 if 'SELECT subject FROM memberships' in joined: out(os.environ['RESTORE_TEST_MEMBERSHIP'])
 sys.exit(0)
print('unexpected mocked kubectl invocation',file=sys.stderr); sys.exit(91)
""")
        for executable in bin_dir.iterdir():
            executable.chmod(0o700)

        env = os.environ.copy()
        env.update({
            "PATH": str(bin_dir) + os.pathsep + env.get("PATH", ""),
            "KORDEX_RESTORE_CONFIRM": "RESTORE KORDEX BACKUP TO EMPTY PRIVATE LAB DATABASE",
            "KORDEX_ENCRYPTED_BACKUP": str(archive),
            "KORDEX_BACKUP_SHA256": str(manifest),
            "AGE_IDENTITY_FILE": str(identity),
            "KORDEX_EXPECTED_KUBE_CONTEXT": context,
            "KORDEX_EXPECTED_SCHEMA_VERSION": "14",
            "KORDEX_EXPECTED_ORGANIZATION_ID": "733ff86d-5dd0-4ad9-8476-0910f9eac046",
            "KORDEX_EXPECTED_FLEET_ID": "1d08cef8-e5a3-443a-a5d1-9c871d9c2617",
            "KORDEX_EXPECTED_SITE_ID": "e8d9d100-aecb-4fb7-a284-55983998a588",
            "KORDEX_EXPECTED_CLUSTER_ID": "103f4d61-4751-4613-8e7c-ed58f0561d3a",
            "KORDEX_EXPECTED_CLUSTER_UID": "ec30d166-c560-49ca-be70-ed55674176c6",
            "KORDEX_REALM_EXPORT_DIR": str(realm_dir),
            "KUBECTL_TEST_LOG": str(calls),
            "RESTORE_TEST_SCENARIO": scenario,
            "RESTORE_TEST_SCHEMA": schema,
            "RESTORE_TEST_RECORDS": records,
            "RESTORE_TEST_MEMBERSHIP": membership,
        })
        result = subprocess.run(["bash", str(RESTORE)], env=env, text=True, capture_output=True)
        call_log = calls.read_text() if calls.exists() else ""
        return result, call_log


result, calls = run_case()
assert result.returncode == 0, result.stderr
assert "restore and schema" in result.stdout.lower()
assert "API has not been started" in result.stdout
assert calls and all(line.startswith("--context=" + CONTEXT + " ") for line in calls.splitlines())

result, calls = run_case(manifest_name="different.dump.age")
assert result.returncode != 0 and "different archive" in result.stderr
assert not calls

result, calls = run_case(manifest_text="not-a-sha256  backup.dump.age\n")
assert result.returncode != 0 and "malformed" in result.stderr
assert not calls

result, calls = run_case(archive_bytes=b"modified archive", manifest_hash=hashlib.sha256(b"original archive").hexdigest())
assert result.returncode != 0 and "does not match" in result.stderr
assert not calls

result, calls = run_case(missing_manifest=True)
assert result.returncode != 0 and "manifest is missing" in result.stderr
assert not calls

result, calls = run_case(context="wrong-context")
assert result.returncode != 0 and "does not match" in result.stderr
assert not calls

result, calls = run_case("missing_pv")
assert result.returncode != 0 and "PersistentVolume is missing or unreadable" in result.stderr
assert "exec" not in calls

result, calls = run_case("delete_policy")
assert result.returncode != 0 and "PV reclaim policy" in result.stderr
assert "exec" not in calls

result, calls = run_case("failed_restore")
assert result.returncode != 0 and "partial data" in result.stderr
assert "API was not started" in result.stderr
assert "MAX(version)" not in calls

result, calls = run_case("api_running")
assert result.returncode != 0 and "kordex-api must remain scaled to zero" in result.stderr
assert "exec" not in calls

result, calls = run_case("keycloak_running")
assert result.returncode != 0 and "kordex-keycloak must remain scaled to zero" in result.stderr
assert "exec" not in calls

result, calls = run_case("api_pod_running")
assert result.returncode != 0 and "kordex-api Pods exist" in result.stderr
assert "exec" not in calls

result, calls = run_case("keycloak_pod_running")
assert result.returncode != 0 and "kordex-keycloak Pods exist" in result.stderr
assert "exec" not in calls

result, _ = run_case(schema="13|13")
assert result.returncode != 0 and "schema version" in result.stderr

result, _ = run_case(records="0")
assert result.returncode != 0 and "organization, fleet, site" in result.stderr

result, _ = run_case(membership="unmatched-subject")
assert result.returncode != 0 and "membership subjects" in result.stderr
assert "unmatched-subject" not in result.stdout + result.stderr

print("private lab PostgreSQL restore safety tests passed")
