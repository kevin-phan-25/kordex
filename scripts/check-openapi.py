#!/usr/bin/env python3
"""Dependency-free sanity check; not a complete OpenAPI validator."""
import json
from pathlib import Path
spec = json.loads(Path('api/openapi/v1.json').read_text())
assert spec['openapi'] == '3.0.3'
identifiers = set()
def visit(value):
    if isinstance(value, dict):
        if '$ref' in value:
            target = spec
            assert value['$ref'].startswith('#/')
            for part in value['$ref'][2:].split('/'):
                target = target[part]
        for child in value.values():
            visit(child)
    elif isinstance(value, list):
        for child in value:
            visit(child)
visit(spec)
for path, item in spec['paths'].items():
    for method, operation in item.items():
        if method == 'parameters':
            continue
        assert operation['operationId'] not in identifiers
        identifiers.add(operation['operationId'])
        assert operation['responses']
        if path.startswith('/v1/organizations'):
            assert operation['security'] == [{'bootstrapBearer': []}, {'oidcBearer': []}]
            assert '401' in operation['responses']
        if path == '/v1/session/revoke':
            assert method == 'post'
            assert operation['security'] == [{'oidcBearer': []}]
            assert {'204', '401', '503'} <= set(operation['responses'])
        if path == '/v1/organizations/{organizationID}/operations':
            assert method == 'get'
            phase = next(parameter for parameter in operation['parameters'] if parameter['name'] == 'phase')
            assert phase['required'] is True
            assert set(phase['schema']['enum']) == {'Blocked', 'RecoveryRequired', 'Failed'}
assert len(identifiers) == 53
operation_schema = spec['components']['schemas']['NodeOperation']
assert operation_schema['properties']['evidence']['$ref'] == '#/components/schemas/OperationEvidence'
status_schema = operation_schema['properties']['status']
assert status_schema['properties']['upgradeCheckpoint']['$ref'] == '#/components/schemas/UpgradeCheckpoint'
assert status_schema['properties']['providerUpgradeCheckpoint']['$ref'] == '#/components/schemas/ProviderUpgradeCheckpoint'
assert {'Preflighting', 'Executing', 'Rebooting'} <= set(operation_schema['properties']['phase']['enum'])
assert spec['components']['schemas']['Report']['properties']['clusterCapabilities']['allOf'][0]['$ref'] == '#/components/schemas/ClusterCapabilities'
assert spec['components']['schemas']['Cluster']['properties']['capabilities']['allOf'][0]['$ref'] == '#/components/schemas/ClusterCapabilities'
assert spec['components']['schemas']['Cluster']['properties']['compatibility']['allOf'][0]['$ref'] == '#/components/schemas/ClusterCompatibility'
assert set(spec['components']['schemas']['ClusterCapabilities']['required']) == {'observedAt', 'cniHints', 'csiDrivers', 'storageProvisioners', 'admissionAPIs', 'podSecurityNamespaceLabels'}
assert set(spec['components']['schemas']['ClusterCompatibility']['properties']['status']['enum']) == {'Unknown', 'MixedSignals', 'Unqualified'}
assert set(spec['components']['schemas']['ClusterCompatibility']['required']) == {'status', 'distributionHints', 'nodeCount', 'distinctOSImages', 'distinctArchitectures', 'reasonCodes'}
catalog_capabilities = spec['paths']['/v1/organizations/{organizationID}/clusters/{clusterID}/maintenance-policies']['get']['responses']['200']['content']['application/json']['schema']['properties']['operatorCapabilities']
assert set(catalog_capabilities['required']) == {'observedAt', 'nodeMaintenance', 'hostUpgrades', 'gkeNodePoolUpgrade'}
policy_items = spec['paths']['/v1/organizations/{organizationID}/clusters/{clusterID}/maintenance-policies']['get']['responses']['200']['content']['application/json']['schema']['properties']['items']['items']
assert set(policy_items['properties']['allowedActions']['items']['enum']) == {'ValidateOnly', 'DrainAndVerify', 'UpgradePackages', 'UpgradeNodePool'}
assert policy_items['properties']['allowedActions']['minItems'] == 1 and policy_items['properties']['allowedActions']['uniqueItems'] is True
inventory_filters = {parameter['name'] for parameter in spec['paths']['/v1/organizations/{organizationID}/nodes']['get']['parameters']}
assert 'nodeUid' in inventory_filters and 'clusterId' in inventory_filters
print('Contract sanity checks passed (53 operations, local refs, auth declarations).')
