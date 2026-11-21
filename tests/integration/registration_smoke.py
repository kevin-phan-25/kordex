#!/usr/bin/env python3
"""Real Kubernetes, real agent process, real management API. Disposable DB/cluster only.

Requires KORDEX_BINARY, KORDEX_AGENT_BINARY, KORDEX_TEST_DATABASE_URL and KUBECONFIG.
Creates organization/site/fleet/cluster rows. Never runs node maintenance.
"""
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

base = 'http://127.0.0.1:58082'
admin = secrets.token_hex(32)
control_env = dict(os.environ, DATABASE_URL=os.environ['KORDEX_TEST_DATABASE_URL'],
                   KORDEX_ADMIN_TOKEN=admin, KORDEX_LISTEN_ADDRESS='127.0.0.1:58082',
                   # Keep the host-process smoke isolated from services already on the workstation.
                   KORDEX_METRICS_LISTEN_ADDRESS='127.0.0.1:0',
                   KORDEX_LOCAL_DEVELOPMENT='true')

def local_listener_address():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(('127.0.0.1', 0))
        return f'127.0.0.1:{listener.getsockname()[1]}'

def call(method, path, value=None):
    data = None if value is None else json.dumps(value).encode()
    request = urllib.request.Request(base+path, data=data, method=method,
        headers={'Authorization': 'Bearer '+admin, 'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.load(response)

def wait_for(check, processes, seconds=90):
    deadline = time.monotonic()+seconds
    while time.monotonic() < deadline:
        if any(p.poll() is not None for p in processes):
            raise RuntimeError('test process exited unexpectedly')
        try:
            result = check()
            if result:
                return result
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(0.5)
    raise RuntimeError('timed out waiting for registration/inventory')

def stop(process):
    if process is not None and process.poll() is None:
        process.terminate()
        if process.wait(timeout=80) != 0:
            raise RuntimeError('test process failed graceful shutdown')

subprocess.run([os.environ['KORDEX_BINARY'], '-migrate'], env=control_env,
               check=True, stdout=subprocess.DEVNULL)
control = subprocess.Popen([os.environ['KORDEX_BINARY']], env=control_env,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
agent = None
try:
    wait_for(lambda: call('GET', '/readyz'), [control])
    org = call('POST', '/v1/organizations', {'name': 'kind-'+secrets.token_hex(8)})
    root = '/v1/organizations/'+org['id']
    site = call('POST', root+'/sites', {'name': 'local', 'region': 'lab'})
    fleet = call('POST', root+'/fleets', {'name': 'lab'})
    cluster = call('POST', root+'/clusters', {'name': 'kind', 'siteId': site['id'],
                    'fleetId': fleet['id'], 'provider': 'self-managed'})
    enrollment = call('POST', root+'/clusters/'+cluster['id']+'/enrollment-tokens')
    with tempfile.TemporaryDirectory(prefix='kordex-agent-smoke-') as directory:
        token_file = Path(directory)/'enrollment'
        token_file.write_text(enrollment['token'])
        token_file.chmod(0o600)
        agent_env = dict(os.environ, KORDEX_CONTROL_PLANE_URL=base,
                        KORDEX_CLUSTER_ID=cluster['id'], KORDEX_LOCAL_DEVELOPMENT='true',
                        KORDEX_HEALTH_ADDR=local_listener_address(),
                        KORDEX_ENROLLMENT_TOKEN_FILE=str(token_file),
                        KORDEX_STATE_FILE=str(Path(directory)/'identity.json'))
        def start_agent():
            return subprocess.Popen([os.environ['KORDEX_AGENT_BINARY']], env=agent_env,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        def inventory_after(version):
            current = next(c for c in call('GET', root+'/clusters')['items'] if c['id']==cluster['id'])
            return current if current['snapshotVersion'] > version else None
        agent = start_agent()
        first = wait_for(lambda: inventory_after(0), [control, agent])
        nodes = call('GET', root+'/clusters/'+cluster['id']+'/nodes')['items']
        assert nodes and first['connected'], 'missing real Kubernetes inventory'
        stop(agent)
        agent_env['KORDEX_ENROLLMENT_TOKEN_FILE'] = ''
        agent = start_agent()
        second = wait_for(lambda: inventory_after(first['snapshotVersion']), [control, agent])
        assert second['clusterUid'] == first['clusterUid'], 'identity changed on restart'
        call('POST', root+'/clusters/'+cluster['id']+'/revoke')
        stop(agent)
        agent = None
        print('Real Kubernetes smoke passed: enrollment, node inventory, connectivity, restart without enrollment token, revocation.')
finally:
    stop(agent)
    stop(control)
