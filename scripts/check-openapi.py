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
assert len(identifiers) == 48
operation_schema = spec['components']['schemas']['NodeOperation']
assert operation_schema['properties']['evidence']['$ref'] == '#/components/schemas/OperationEvidence'
status_schema = operation_schema['properties']['status']
assert status_schema['properties']['upgradeCheckpoint']['$ref'] == '#/components/schemas/UpgradeCheckpoint'
assert status_schema['properties']['providerUpgradeCheckpoint']['$ref'] == '#/components/schemas/ProviderUpgradeCheckpoint'
assert {'Preflighting', 'Executing', 'Rebooting'} <= set(operation_schema['properties']['phase']['enum'])
print('Contract sanity checks passed (48 operations, local refs, auth declarations).')
