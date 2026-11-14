#!/usr/bin/env python3
"""Real process restart and HTTP persistence smoke test. Disposable DB only."""
import json
import os
import secrets
import subprocess
import time
import urllib.error
import urllib.request

binary = os.environ['KORDEX_BINARY']
env = dict(os.environ, DATABASE_URL=os.environ['KORDEX_TEST_DATABASE_URL'],
           KORDEX_ADMIN_TOKEN=secrets.token_hex(32), KORDEX_LOCAL_DEVELOPMENT='true',
           KORDEX_LISTEN_ADDRESS='127.0.0.1:58080')
base = 'http://127.0.0.1:58080'

def call(method, path, body=None, auth=True):
    headers = {'Content-Type': 'application/json'}
    if auth:
        headers['Authorization'] = 'Bearer ' + env['KORDEX_ADMIN_TOKEN']
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=3) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, json.load(error)

def start():
    process = subprocess.Popen([binary], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(100):
        if process.poll() is not None:
            raise RuntimeError('control plane exited before readiness')
        try:
            if call('GET', '/readyz', auth=False)[0] == 200:
                return process
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(0.1)
    process.terminate()
    process.wait(timeout=25)
    raise RuntimeError('control plane did not become ready')

def stop(process):
    process.terminate()
    assert process.wait(timeout=25) == 0, 'graceful shutdown failed'

subprocess.run([binary, '-migrate'], env=env, check=True, stdout=subprocess.DEVNULL)
process = start()
try:
    assert call('GET', '/v1/organizations', auth=False)[0] == 401
    name = 'smoke-' + secrets.token_hex(8)
    status, org = call('POST', '/v1/organizations', {'name': name})
    assert status == 201
    assert call('POST', '/v1/organizations', {'name': name})[0] == 409
    path = '/v1/organizations/' + org['id'] + '/sites'
    status, site = call('POST', path, {'name': 'dc1', 'region': 'us-east'})
    assert status == 201
finally:
    stop(process)
process = start()
try:
    status, page = call('GET', path)
    assert status == 200 and page['items'][0]['id'] == site['id']
finally:
    stop(process)
print('Process smoke passed: auth, creates, conflict, graceful shutdown, restart persistence.')
