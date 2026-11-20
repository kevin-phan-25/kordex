import assert from 'node:assert/strict'
import {test} from 'node:test'
import {fetchManagementNoRedirect,proxyManagementRequest, readLimitedBody, scopedProxyTarget} from '../src/lib/proxy.ts'
import {tokenRevocationConfirmed} from '../src/lib/oidc-contract.ts'

const org = '80bd80f9-f097-4474-86f4-b80986fd5423'
const id = '90bd80f9-f097-4474-86f4-b80986fd5423'
const origin = 'https://dashboard.example'
function dependencies(status = 200) {
  const calls = []
  return {calls, appURL: () => origin, apiURL: () => 'https://hub.example',
    getSession: async () => ({token: 'private-token', organizationID: org}),
    fetch: async (url, options) => { calls.push({url, options}); return Response.json({ok: true}, {status}) },
  }
}
function request(method = 'GET', body, headers = {}) {
  return new Request(`${origin}/api/kordex/campaigns`, {method, body,
    headers: {origin, 'content-type': 'application/json', ...headers},
    ...(body instanceof ReadableStream ? {duplex: 'half'} : {}),
  })
}
test('decoded and multiply encoded path escapes never reach the upstream', async () => {
  for (const path of [['../../agent', 'report'], ['..'], ['%2e%2e'], ['%252e%252e'],
    ['campaigns%2f..'], ['campaigns\\..'], ['campaigns/../memberships'], ['campaigns?x=y'],
    ['campaigns#x'], ['campaigns', ''], ['campaigns', '\0'], ['organizations', id, 'nodes']]) {
    const deps = dependencies()
    const result = await proxyManagementRequest(request(), path, deps)
    assert.ok([400, 404].includes(result.status), JSON.stringify(path))
    assert.equal(deps.calls.length, 0)
  }
})
test('allowlist constrains method and organization while preserving queries', async () => {
  const deps = dependencies()
  const result = await proxyManagementRequest(request('POST', '{"revision":1}'), ['campaigns', id, 'approve'], deps)
  assert.equal(result.status, 200)
  assert.equal(deps.calls[0].url.pathname, `/v1/organizations/${org}/campaigns/${id}/approve`)
  assert.equal(deps.calls[0].options.headers.get('authorization'), 'Bearer private-token')
  assert.equal(deps.calls[0].options.redirect, 'manual')
  assert.equal(scopedProxyTarget('https://hub.example', org, ['nodes'], 'GET', '?search=a%2Fb').search, '?search=a%2Fb')
  assert.equal(scopedProxyTarget('https://hub.example', org, ['operations'], 'GET', '?phase=RecoveryRequired').pathname,
    `/v1/organizations/${org}/operations`)
  assert.equal(scopedProxyTarget('https://hub.example', org, ['kubernetes-compatibility'], 'GET', '').pathname,
    `/v1/organizations/${org}/kubernetes-compatibility`)
  const attention = dependencies()
  assert.equal((await proxyManagementRequest(new Request(`${origin}/api/kordex/operations?phase=RecoveryRequired`), ['operations'], attention)).status, 200)
  assert.equal(attention.calls[0].url.search, '?phase=RecoveryRequired')
  assert.equal(scopedProxyTarget('https://hub.example', org, ['audit', 'export'], 'GET', '').pathname,
    `/v1/organizations/${org}/audit/export`)
  assert.equal((await proxyManagementRequest(request('POST', '{}'), ['audit'], deps)).status, 405)
})
test('concurrency policy reads and revision-checked updates stay under the active organization', async () => {
  const deps = dependencies()
  const target = scopedProxyTarget('https://hub.example', org, ['concurrency-policy'], 'PUT', '')
  assert.equal(target.pathname, `/v1/organizations/${org}/concurrency-policy`)
  assert.equal((await proxyManagementRequest(request('PUT', JSON.stringify({revision:4,limits:{organization:2}}), {'x-kordex-expected-organization':org}), ['concurrency-policy'], deps)).status, 200)
  assert.equal(deps.calls[0].url.pathname, `/v1/organizations/${org}/concurrency-policy`)
  assert.equal(deps.calls[0].options.method, 'PUT')
  for (const method of ['POST', 'DELETE']) assert.throws(() => scopedProxyTarget('https://hub.example', org, ['concurrency-policy'], method, ''))

  const stale = dependencies()
  const changedOrganization = 'a0bd80f9-f097-4474-86f4-b80986fd5423'
  const staleResponse = await proxyManagementRequest(request('PUT', JSON.stringify({revision:4,limits:{organization:2}}), {'x-kordex-expected-organization':changedOrganization}), ['concurrency-policy'], stale)
  assert.equal(staleResponse.status, 409)
  assert.equal((await staleResponse.json()).error, 'organization_changed')
  assert.equal(stale.calls.length, 0)
})
test('mutations require same origin and a session; API authorization errors propagate', async () => {
  const deps = dependencies(403)
  assert.equal((await proxyManagementRequest(request('POST', '{}', {origin: 'https://other.example'}), ['campaigns'], deps)).status, 403)
  assert.equal(deps.calls.length, 0)
  deps.getSession = async () => null
  assert.equal((await proxyManagementRequest(request(), ['campaigns'], deps)).status, 401)
  assert.equal(deps.calls.length, 0)
  const denied = dependencies(403)
  assert.equal((await proxyManagementRequest(request('POST', '{}'), ['campaigns'], denied)).status, 403)
})
test('chunked input is cancelled as soon as its byte limit is exceeded', async () => {
  for (const headers of [{}, {'content-length': '1'}]) {
    let cancelled = false
    const body = new ReadableStream({start(c) { c.enqueue(new Uint8Array((256 << 10) + 1)) },
      cancel() { cancelled = true }})
    const deps = dependencies()
    assert.equal((await proxyManagementRequest(request('POST', body, headers), ['campaigns'], deps)).status, 413)
    assert.equal(cancelled, true)
    assert.equal(deps.calls.length, 0)
  }
})
test('declared oversized and multibyte input fail before upstream access', async () => {
  for (const [body, headers] of [['{}', {'content-length': '999999999'}], ['💥'.repeat(70000), {}]]) {
    const deps = dependencies()
    assert.equal((await proxyManagementRequest(request('POST', body, headers), ['campaigns'], deps)).status, 413)
    assert.equal(deps.calls.length, 0)
  }
  await assert.rejects(readLimitedBody(request('POST', '💥'.repeat(600)), 2048), {status: 413})
})
test('invalid UTF-8 and non-JSON content types are refused', async () => {
  const deps = dependencies()
  assert.equal((await proxyManagementRequest(request('POST', new Uint8Array([0xff])), ['campaigns'], deps)).status, 400)
  assert.equal((await proxyManagementRequest(request('POST', '{}', {'content-type': 'text/plain'}), ['campaigns'], deps)).status, 415)
  assert.equal(deps.calls.length, 0)
})
test('redirects are refused instead of changing the authorized target', async () => {
  const deps = dependencies()
  deps.fetch = async () => new Response(null, {status: 307, headers: {location: `/v1/organizations/${id}/nodes`}})
  assert.equal((await proxyManagementRequest(request(), ['nodes'], deps)).status, 502)
})
test('all management API fetches disable automatic redirects', async () => {
  let options
  const response=await fetchManagementNoRedirect('https://hub.example/v1/organizations',{},async(_url,init)=>{
    options=init
    return new Response(null,{status:302,headers:{location:'https://attacker.example/collect'}})
  })
  assert.equal(options.redirect,'manual')
  assert.equal(response.status,302)
})
test('logout accepts completed or already-invalid API token revocation only', () => {
  assert.equal(tokenRevocationConfirmed(204), true)
  assert.equal(tokenRevocationConfirmed(401), true)
  for (const status of [200, 302, 403, 500, 503]) assert.equal(tokenRevocationConfirmed(status), false)
})
