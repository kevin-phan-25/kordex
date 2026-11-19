import test from 'node:test'
import assert from 'node:assert/strict'
import { pkceAuthorizationParameters, resolveApiTokenContract, selectApiBearerToken } from '../src/lib/oidc-contract.ts'

test('authorization requests explicitly require S256 PKCE', () => {
  assert.deepEqual(pkceAuthorizationParameters('challenge'), {
    code_challenge: 'challenge', code_challenge_method: 'S256',
  })
})

test('ID-token mode stays compatible and rejects access-only settings', () => {
  assert.deepEqual(resolveApiTokenContract(), { mode: 'id_token', scopes: [] })
  assert.deepEqual(resolveApiTokenContract('id_token', ''), { mode: 'id_token', scopes: [] })
  assert.throws(() => resolveApiTokenContract('id_token', 'kordex.read'), /requires access-token mode/)
})

test('access-token mode requires unique valid scopes', () => {
  assert.deepEqual(resolveApiTokenContract('access_token', 'kordex.read kordex.operate'), {
    mode: 'access_token', scopes: ['kordex.read', 'kordex.operate'],
  })
  assert.throws(() => resolveApiTokenContract('access_token', ''), /is required/)
  assert.throws(() => resolveApiTokenContract('access_token', 'kordex.read kordex.read'), /unique/)
  assert.throws(() => resolveApiTokenContract('access_token', 'bad"scope'), /valid OAuth scope/)
  assert.throws(() => resolveApiTokenContract('jwt', 'kordex.read'), /must be id_token or access_token/)
})

test('API bearer selection uses access token while retaining ID token for claims', () => {
  assert.deepEqual(selectApiBearerToken('access_token', {
    id_token: 'signed-id-token', access_token: 'signed-api-token', token_type: 'bearer',
  }), { token: 'signed-api-token', identityToken: 'signed-id-token' })
  assert.deepEqual(selectApiBearerToken('id_token', {
    id_token: 'signed-id-token', access_token: 'unused-token', token_type: 'bearer',
  }), { token: 'signed-id-token', identityToken: 'signed-id-token' })
  assert.throws(() => selectApiBearerToken('access_token', {
    id_token: 'signed-id-token', access_token: 'signed-api-token', token_type: 'dpop',
  }), /bearer access token/)
  assert.throws(() => selectApiBearerToken('access_token', { id_token: 'signed-id-token' }), /bearer access token/)
})
