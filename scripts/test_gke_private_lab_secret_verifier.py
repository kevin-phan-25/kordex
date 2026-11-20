#!/usr/bin/env python3
"""Ensure Secret validation reports key presence without exposing values."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="kordex-secret-test-") as tmp:
    directory = Path(tmp)
    fake_bin = directory / "bin"
    fake_bin.mkdir()
    kubectl = fake_bin / "kubectl"
    kubectl.write_text("""#!/usr/bin/env python3
import json,sys
a=sys.argv[1:]
name=a[a.index('get')+2]
required={
'kordex-postgres-credentials':['postgresSuperuserPassword','kordexRuntimePassword','kordexMigrationPassword','keycloakDbPassword'],
'kordex-hub-credentials':['databaseURL','migrationDatabaseURL','maintenanceSigningKey','auditSigningKey'],
'kordex-postgres-tls':['tls.crt','tls.key'],'kordex-keycloak-tls':['tls.crt','tls.key'],
'kordex-api-tls':['tls.crt','tls.key'],'kordex-management-ca':['ca.crt'],
'kordex-keycloak-bootstrap':['username','password'],'kordex-keycloak-realm-import':['kordex-realm.json']}
if name == 'kordex-hub-credentials' and __import__('os').environ.get('SECRET_TEST_MISSING') == 'yes':
 required[name]=['databaseURL','missing']
keys=required[name]
if name == 'kordex-hub-credentials' and __import__('os').environ.get('SECRET_TEST_MISSING') == 'yes':
 keys=['databaseURL']
print(json.dumps({'data':{key:'c2VjcmV0LXZhbHVlLXNob3VsZC1ub3QtYmUgcHJpbnRlZA==' for key in keys}}))
""")
    kubectl.chmod(0o700)
    gcloud = fake_bin / "gcloud"
    gcloud.write_text("""#!/usr/bin/env python3
import json,sys
print(json.dumps({'name':'kordex-pmlab-gke','location':'us-east1-b',
 'privateClusterConfig':{'enablePrivateNodes':True,'enablePrivateEndpoint':True},
 'controlPlaneEndpointsConfig':{'ipEndpointsConfig':{'enabled':True,'publicEndpoint':''},'dnsEndpointConfig':{'allowExternalTraffic':False}},
 'networkConfig':{'datapathProvider':'ADVANCED_DATAPATH'}}))
""")
    gcloud.chmod(0o700)
    env = os.environ.copy()
    env.update({
        "PATH": str(fake_bin) + os.pathsep + env.get("PATH", ""),
        "KORDEX_EXPECTED_GCP_PROJECT": "kordex-pmlab-test-2026",
        "KORDEX_EXPECTED_GKE_LOCATION": "us-east1-b",
        "KORDEX_EXPECTED_GKE_CLUSTER": "kordex-pmlab-gke",
        "KORDEX_EXPECTED_KUBE_CONTEXT": "gke_kordex-pmlab-test-2026_us-east1-b_kordex-pmlab-gke",
    })
    good = subprocess.run(["bash", str(root / "scripts/gke-private-lab-verify-secrets.sh")], env=env, text=True, capture_output=True)
    assert good.returncode == 0, (good.stdout, good.stderr)
    assert "required keys present" in good.stdout
    assert "secret-value-should-not" not in good.stdout + good.stderr
    env["SECRET_TEST_MISSING"] = "yes"
    bad = subprocess.run(["bash", str(root / "scripts/gke-private-lab-verify-secrets.sh")], env=env, text=True, capture_output=True)
    assert bad.returncode != 0 and "missing" in bad.stdout
    assert "secret-value-should-not" not in bad.stdout + bad.stderr
print("private lab Secret key verification tests passed without exposing Secret data")
