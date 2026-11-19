import test from 'node:test'
import assert from 'node:assert/strict'
import { callbackAuthorizationOptions, pkceAuthorizationParameters, resolveApiTokenContract, safeOidcErrorDetails, selectApiBearerToken, sessionCookieOptions } from '../src/lib/oidc-contract.ts'

test('authorization requests explicitly require S256 PKCE', () => {
  assert.deepEqual(pkceAuthorizationParameters('challenge'), {
    code_challenge: 'challenge', code_challenge_method: 'S256',
  })
})

test('callback grant requires stored state, nonce, and PKCE verifier', () => {
  assert.deepEqual(callbackAuthorizationOptions('state', 'nonce', 'verifier'), {
    expectedState: 'state', expectedNonce: 'nonce', idTokenExpected: true, pkceCodeVerifier: 'verifier',
  })
  for (const values of [[undefined, 'nonce', 'verifier'], ['state', undefined, 'verifier'], ['state', 'nonce', '']]) {
    assert.throws(() => callbackAuthorizationOptions(...values), /Sign in expired/)
  }
})

test('OIDC callback diagnostics expose only allowlisted error category fields', () => {
  assert.deepEqual(safeOidcErrorDetails({name: 'ResponseBodyError', status: 400, error: 'invalid_grant', error_description: 'secret payload'}), {
    type: 'ResponseBodyError', status: 400, oauthCode: 'invalid_grant',
  })
  assert.deepEqual(safeOidcErrorDetails({name: 'Error', status: 503, error: 'sensitive provider text'}), {
    type: 'OtherError', status: 503, oauthCode: 'none',
  })
})

test('session cookies are encrypted by the caller and HTTP-only with local HTTP policy', () => {
  assert.deepEqual(sessionCookieOptions('http://127.0.0.1:3000', 'development', 120), {
    httpOnly: true, secure: false, sameSite: 'lax', path: '/', maxAge: 120,
  })
  assert.equal(sessionCookieOptions('https://dashboard.example', 'production', 120).secure, true)
  assert.throws(() => sessionCookieOptions('http://dashboard.example', 'production', 120), /must use HTTPS/)
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
