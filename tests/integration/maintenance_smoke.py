#!/usr/bin/env python3
"""Real stateless-worker drain drill. DISPOSABLE Kubernetes cluster and PostgreSQL only.

Requires KORDEX_BINARY, KORDEX_AGENT_BINARY, KORDEX_OPERATOR_BINARY,
KORDEX_KEYGEN_BINARY, KORDEX_TEST_DATABASE_URL, KUBECONFIG, KUBECTL and HELM.
The chart RBAC is exercised through Kubernetes service-account impersonation.
No package update, kernel update, host command or reboot is performed.
"""
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid

root = Path(__file__).resolve().parents[2]
kubectl = os.environ['KUBECTL']
helm = os.environ['HELM']
base = 'http://127.0.0.1:58083'
admin = secrets.token_hex(32)
namespace = 'kordex-drill-'+secrets.token_hex(4)
workloads = namespace+'-apps'
processes = []
logs = []

def command(args, data=None):
    try:
        return subprocess.check_output(args, input=data, text=True, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as error:
        detail = 'configuration command failed' if '--raw' in args else error.output[-4000:]
        raise RuntimeError('test command failed: '+detail) from error

def k(*args, value=None):
    return command([kubectl, *args], None if value is None else json.dumps(value))

def apply(value):
    return k('apply', '-f', '-', value=value)

def call(method, path, value=None):
    request = urllib.request.Request(base+path, method=method,
        data=None if value is None else json.dumps(value).encode(),
        headers={'Authorization': 'Bearer '+admin, 'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.load(response)

def wait_for(check, timeout=180):
    deadline = time.monotonic()+timeout
    while time.monotonic() < deadline:
        if any(p.poll() is not None for p in processes):
            raise RuntimeError('a test service exited unexpectedly')
        try:
            result = check()
            if result:
                return result
        except (urllib.error.URLError, ConnectionError):
            pass
        time.sleep(0.3)
    raise RuntimeError('timed out waiting for maintenance checkpoint')

def start(binary, env, name, directory):
    log = open(Path(directory)/(name+'.log'), 'w+')
    logs.append(log)
    process = subprocess.Popen([binary], env=env, stdout=log, stderr=log)
    processes.append(process)
    return process

def stop(process):
    if process in processes:
        processes.remove(process)
    if process.poll() is None:
        process.terminate()
        if process.wait(timeout=80) != 0:
            raise RuntimeError('service failed graceful shutdown')

def chart(chart_name, template, cluster, extra):
    args = [helm, 'template', 'smoke', str(root/'deployments/helm'/chart_name),
            '--namespace', namespace, '--show-only', template,
            '--set', 'clusterID='+cluster]
    for item in extra:
        args += ['--set', item]
    manifest = command(args)
    command([kubectl, 'apply', '-f', '-'], manifest)

def impersonation_config(path, service_account):
    config = json.loads(k('config', 'view', '--raw', '-o', 'json'))
    for user in config['users']:
        user['user']['as'] = 'system:serviceaccount:'+namespace+':'+service_account
    path.write_text(json.dumps(config))
    path.chmod(0o600)

with tempfile.TemporaryDirectory(prefix='kordex-maintenance-') as directory:
    directory = Path(directory)
    try:
        # Set a default namespace in a private kubeconfig copy, without overriding explicit ledger namespaces.
        config = json.loads(k('config', 'view', '--raw', '-o', 'json'))
        for entry in config['contexts']:
            entry['context']['namespace'] = namespace
        admin_config = directory/'admin.kubeconfig'
        admin_config.write_text(json.dumps(config))
        admin_config.chmod(0o600)
        os.environ['KUBECONFIG'] = str(admin_config)
        private, public = directory/'signing-key', directory/'keys.json'
        command([os.environ['KORDEX_KEYGEN_BINARY'], '-private-file', str(private), '-public-file', str(public)])
        env = dict(os.environ, DATABASE_URL=os.environ['KORDEX_TEST_DATABASE_URL'],
            KORDEX_ADMIN_TOKEN=admin, KORDEX_LOCAL_DEVELOPMENT='true',
            KORDEX_LISTEN_ADDRESS='127.0.0.1:58083', KORDEX_OIDC_ISSUER='',
            KORDEX_OIDC_AUDIENCE='', KORDEX_MAINTENANCE_SIGNING_KEY_FILE=str(private))
        subprocess.run([os.environ['KORDEX_BINARY'], '-migrate'], env=env,
                       check=True, stdout=subprocess.DEVNULL)
        start(os.environ['KORDEX_BINARY'], env, 'control', directory)
        wait_for(lambda: call('GET', '/readyz'))
        k('apply', '-f', str(root/'operator/config/crd'))
        for kind in ['nodemaintenances', 'maintenancepolicies', 'maintenancecampaigns']:
            k('wait', '--for=condition=Established', 'crd/'+kind+'.operations.kordex.local', '--timeout=60s')
        for name in [namespace, workloads]:
            apply({'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': name}})
        org = call('POST', '/v1/organizations', {'name': namespace})
        prefix = '/v1/organizations/'+org['id']
        site = call('POST', prefix+'/sites', {'name': 'lab', 'region': 'local'})
        fleet = call('POST', prefix+'/fleets', {'name': 'lab'})
        cluster = call('POST', prefix+'/clusters', {'name': 'kind', 'siteId': site['id'],
                         'fleetId': fleet['id'], 'provider': 'self-managed'})
        cluster_id = cluster['id']
        enrollment = call('POST', prefix+'/clusters/'+cluster_id+'/enrollment-tokens')
        token_file = directory/'enrollment'
        token_file.write_text(enrollment['token'])
        token_file.chmod(0o600)
        for template in ['templates/ledger.yaml', 'templates/rbac.yaml']:
            chart('kordex-operator', template, cluster_id, ['hubPublicKeysConfigMap=hub-trust'])
        for template in ['templates/identity.yaml', 'templates/rbac.yaml']:
            chart('kordex-agent', template, cluster_id, ['controlPlaneURL=https://hub.example',
                  'enrollmentSecretName=enrollment', 'maintenance.enabled=true'])
        agent_config, operator_config = directory/'agent.kubeconfig', directory/'operator.kubeconfig'
        impersonation_config(agent_config, 'smoke-agent')
        impersonation_config(operator_config, 'smoke-operator')
        agent_env = dict(os.environ, KUBECONFIG=str(agent_config), KORDEX_NAMESPACE=namespace,
            KORDEX_CONTROL_PLANE_URL=base, KORDEX_CLUSTER_ID=cluster_id,
            KORDEX_LOCAL_DEVELOPMENT='true', KORDEX_STATE_FILE='',
            KORDEX_STATE_SECRET='smoke-agent-identity', KORDEX_LEASE_NAME='smoke-agent',
            KORDEX_ENROLLMENT_TOKEN_FILE=str(token_file), KORDEX_ENABLE_MAINTENANCE='true',
            POD_UID='smoke-agent-process')
        start(os.environ['KORDEX_AGENT_BINARY'], agent_env, 'agent', directory)
        operator_env = dict(os.environ, KUBECONFIG=str(operator_config),
            KORDEX_NAMESPACE=namespace, KORDEX_CLUSTER_ID=cluster_id,
            KORDEX_HUB_PUBLIC_KEYS_FILE=str(public))
        operator = start(os.environ['KORDEX_OPERATOR_BINARY'], operator_env, 'operator', directory)
        inventory_path = prefix+'/clusters/'+cluster_id+'/nodes'
        nodes = wait_for(lambda: call('GET', inventory_path)['items'])
        workers = [n for n in nodes if not n['controlPlane'] and n['ready']]
        assert len(workers) >= 2, 'two ready worker nodes are required'
        target = workers[0]
        k('label', 'node', target['name'], 'operations.kordex.local/maintenance=stateless', '--overwrite')
        apply({'apiVersion': 'operations.kordex.local/v1alpha1', 'kind': 'MaintenancePolicy',
            'metadata': {'name': 'safe-workers', 'namespace': namespace},
            'spec': {'nodeSelector': {'matchLabels': {'operations.kordex.local/maintenance': 'stateless'}},
                     'recoverySeconds': 10, 'gracePeriodSeconds': 30}})
        policy = json.loads(k('-n', namespace, 'get', 'maintenancepolicy', 'safe-workers', '-o', 'json'))
        labels = {'app': namespace}
        apply({'apiVersion': 'apps/v1', 'kind': 'Deployment', 'metadata': {'name': 'web', 'namespace': workloads},
            'spec': {'replicas': 2, 'selector': {'matchLabels': labels}, 'template': {
                'metadata': {'labels': labels}, 'spec': {
                    'affinity': {'nodeAffinity': {'preferredDuringSchedulingIgnoredDuringExecution': [
                        {'weight': 100, 'preference': {'matchExpressions': [
                            {'key': 'kubernetes.io/hostname', 'operator': 'In', 'values': [target['name']]}]}}]}},
                    'containers': [{'name': 'web', 'image': 'registry.k8s.io/pause:3.10.1',
                                    'resources': {'requests': {'cpu': '10m', 'memory': '16Mi'}}}]}}}})
        k('-n', workloads, 'rollout', 'status', 'deployment/web', '--timeout=120s')
        original = json.loads(k('-n', workloads, 'get', 'pods', '-o', 'json'))['items']
        target_uids = {p['metadata']['uid'] for p in original if p['spec']['nodeName'] == target['name']}
        assert target_uids, 'fixture has no workload on the maintenance node'
        apply({'apiVersion': 'policy/v1', 'kind': 'PodDisruptionBudget',
            'metadata': {'namespace': workloads, 'name': 'web'},
            'spec': {'minAvailable': 2, 'selector': {'matchLabels': labels}}})
        request = {'operationId': str(uuid.uuid4()), 'nodeName': target['name'],
                   'nodeUid': target['uid'], 'action': 'DrainAndVerify',
                   'policy': {'name': policy['metadata']['name'], 'uid': policy['metadata']['uid'],
                              'generation': policy['metadata']['generation']}}
        operations_path = prefix+'/clusters/'+cluster_id+'/operations'
        issued = call('POST', operations_path, request)
        name = 'op-'+request['operationId']
        def observed():
            return next((op for op in call('GET', operations_path)['items'] if op['id']==request['operationId']), None)
        blocked = wait_for(lambda: (op if (op := observed()) and op['phase']=='Blocked' else None))
        assert blocked['status']['reason'] == 'PDBBlocked', blocked['status']
        node = json.loads(k('get', 'node', target['name'], '-o', 'json'))
        assert not node['spec'].get('unschedulable', False), 'PDB-blocked operation cordoned the node'
        k('-n', workloads, 'patch', 'pdb', 'web', '--type=merge', '-p', '{"spec":{"minAvailable":1}}')
        wait_for(lambda: json.loads(k('get', 'node', target['name'], '-o', 'json'))['spec'].get('unschedulable', False))
        stop(operator)
        operator = start(os.environ['KORDEX_OPERATOR_BINARY'], operator_env, 'operator-restarted', directory)
        completed = wait_for(lambda: (op if (op := observed()) and op['phase']=='Succeeded' else None))
        k('-n', workloads, 'rollout', 'status', 'deployment/web', '--timeout=60s')
        node = json.loads(k('get', 'node', target['name'], '-o', 'json'))
        assert not node['spec'].get('unschedulable', False)
        assert 'operations.kordex.local/cordon-owner' not in node['metadata'].get('annotations', {})
        remaining = json.loads(k('-n', workloads, 'get', 'pods', '-o', 'json'))['items']
        assert not target_uids.intersection(p['metadata']['uid'] for p in remaining), 'workload was not evicted'
        events = completed['status']['events']
        assert completed['sequence'] == len(events)
        assert {'Cordoning', 'Draining', 'VerifyingNode', 'VerifyingWorkloads', 'Uncordoning', 'Succeeded'} <= {e['phase'] for e in events}
        again = call('POST', operations_path, request)
        assert again['phase']=='Succeeded' and again['command']==issued['command'], 'retry reissued an operation'
        original_cr = json.loads(k('-n', namespace, 'get', 'nodemaintenance', name, '-o', 'json'))
        wait_for(lambda: not json.loads(k('-n', namespace, 'get', 'nodemaintenance', name, '-o', 'json'))['metadata'].get('finalizers'))
        k('-n', namespace, 'delete', 'nodemaintenance', name, '--wait=true')
        apply({'apiVersion': 'operations.kordex.local/v1alpha1', 'kind': 'NodeMaintenance',
               'metadata': {'name': name, 'namespace': namespace}, 'spec': original_cr['spec']})
        rejected = wait_for(lambda: (m if (m := json.loads(k('-n', namespace, 'get', 'nodemaintenance', name, '-o', 'json'))).get('status', {}).get('reason')=='DuplicateOperation' else None))
        assert rejected['status']['phase']=='Failed'
        print('Maintenance smoke passed: real chart RBAC, PDB block, signed delivery, eviction, operator restart, workload recovery, uncordon, durable replay rejection.')
    except Exception:
        for log in logs:
            log.flush()
            log.seek(0)
            print('\n'.join(log.read().splitlines()[-12:]))
        raise
    finally:
        for process in list(reversed(processes)):
            stop(process)
        for log in logs:
            log.close()
