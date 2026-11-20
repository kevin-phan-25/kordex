import assert from 'node:assert/strict'
import {test} from 'node:test'
import * as oidc from 'openid-client'
import {exportJWK, generateKeyPair, SignJWT} from 'jose'
import {callbackAuthorizationOptions, canonicalCallbackURL, pkceAuthorizationParameters} from '../src/lib/oidc-contract.ts'
import {discoverOIDC} from '../src/lib/oidc-provider.ts'

const issuer = 'https://local-idp.example.test/realms/kordex'
const clientId = 'kordex-dashboard'
const callback = 'http://127.0.0.1:3000/api/auth/callback'
const verifier = 'a'.repeat(43)
const nonce = 'nonce-fixture'
const state = 'state-fixture'
const [signing, wrongSigning] = await Promise.all([generateKeyPair('RS256'), generateKeyPair('RS256')])
const publicJWK = await exportJWK(signing.publicKey)
Object.assign(publicJWK, {kid: 'local-test-key', use: 'sig', alg: 'RS256'})

async function signedIDToken({iss = issuer, aud = clientId, tokenNonce = nonce, exp = Math.floor(Date.now() / 1000) + 300, key = signing.privateKey} = {}) {
  return new SignJWT({nonce: tokenNonce})
    .setProtectedHeader({alg: 'RS256', kid: 'local-test-key'})
    .setIssuer(iss).setSubject('keycloak-user-id').setAudience(aud)
    .setIssuedAt().setExpirationTime(exp).sign(key)
}

async function grantFixture(claims = {}) {
  const idToken = await signedIDToken(claims)
  let tokenRequests = 0
  let tokenForm
  const metadata = {
    issuer,
    authorization_endpoint: `${issuer}/protocol/openid-connect/auth`,
    token_endpoint: `${issuer}/protocol/openid-connect/token`,
    jwks_uri: `${issuer}/protocol/openid-connect/certs`,
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    token_endpoint_auth_methods_supported: ['none'],
  }
  const fetcher = async (url, options) => {
    const path = new URL(url).pathname
    if (path.endsWith('/.well-known/openid-configuration')) return Response.json(metadata)
    if (path.endsWith('/protocol/openid-connect/certs')) return Response.json({keys: [publicJWK]})
    if (path.endsWith('/protocol/openid-connect/token')) {
      tokenRequests += 1
      tokenForm = new URLSearchParams(String(options.body))
      return Response.json({access_token: 'fixture-access-token', token_type: 'Bearer', expires_in: 300, id_token: idToken})
    }
    return new Response(null, {status: 404})
  }
  const config = await discoverOIDC(issuer, clientId, fetcher)
  async function complete(callbackState = state, options = callbackAuthorizationOptions(state, nonce, verifier)) {
    const incoming = new URL(`http://localhost:3000/api/auth/callback?code=one-time-code&state=${callbackState}`)
    return oidc.authorizationCodeGrant(config, canonicalCallbackURL(incoming, 'http://127.0.0.1:3000'), options)
  }
  return {complete, get tokenRequests() { return tokenRequests }, get tokenForm() { return tokenForm }}
}

test('authorization request uses a derived S256 challenge', async () => {
  const challenge = await oidc.calculatePKCECodeChallenge(verifier)
  const parameters = pkceAuthorizationParameters(challenge)
  assert.equal(parameters.code_challenge_method, 'S256')
  assert.equal(parameters.code_challenge, challenge)
  assert.notEqual(parameters.code_challenge, verifier)
})

test('authorization-code callback validates state, nonce, signature, issuer, audience, expiry, and PKCE verifier', async () => {
  const fixture = await grantFixture()
  const tokens = await fixture.complete()
  assert.ok(tokens.id_token)
  assert.equal(fixture.tokenRequests, 1)
  assert.equal(fixture.tokenForm.get('code_verifier'), verifier)
  assert.equal(fixture.tokenForm.get('redirect_uri'), callback)
})

test('callback rejects mismatched state before exchanging the code', async () => {
  const fixture = await grantFixture()
  await assert.rejects(fixture.complete('attacker-state'))
  assert.equal(fixture.tokenRequests, 0)
})

test('callback rejects wrong nonce, issuer, audience, expiry, and signing key', async (t) => {
  for (const [name, claims] of [
    ['nonce', {tokenNonce: 'wrong-nonce'}],
    ['issuer', {iss: `${issuer}/wrong`}],
    ['audience', {aud: 'another-client'}],
    ['expiry', {exp: Math.floor(Date.now() / 1000) - 30}],
    ['signature', {key: wrongSigning.privateKey}],
  ]) {
    await t.test(name, async () => {
      const fixture = await grantFixture(claims)
      await assert.rejects(fixture.complete())
    })
  }
})

test('callback fails closed when stored state, nonce, or verifier is missing', () => {
  for (const args of [[undefined, nonce, verifier], [state, undefined, verifier], [state, nonce, '']]) {
    assert.throws(() => callbackAuthorizationOptions(...args), /Sign in expired/)
  }
})
