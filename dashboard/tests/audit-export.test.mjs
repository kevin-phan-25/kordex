import assert from 'node:assert/strict'
import {test} from 'node:test'
import {exportAuditSnapshot} from '../src/lib/audit-export.ts'

const organizationId = '80bd80f9-f097-4474-86f4-b80986fd5423'
const signature = Buffer.alloc(64, 7).toString('base64').replace(/=+$/, '')
async function bundle(overrides = {}) {
  const value = {
    format: 'kordex-audit-export-v1', recordsFormat: 'ndjson-v1', organizationId,
    throughEventId: 3, recordCount: 2, recordsSha256: 'a'.repeat(64),
    createdAt: '2026-11-18T12:34:56Z', recordsNdjson: '{"id":1}\n{"id":3}\n',
    signingKeyId: 'b'.repeat(64), signature, ...overrides,
  }
  if (!Object.hasOwn(overrides, 'recordsSha256')) {
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value.recordsNdjson))
    value.recordsSha256 = Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('')
  }
  return value
}

test('downloads the API signed high-water snapshot without rebuilding it in the browser', async () => {
  let requested
  const value = await bundle()
  const result = await exportAuditSnapshot(organizationId, async (url, init) => {
    requested = {url, init}
    return Response.json(value)
  })
  assert.equal(requested.url, '/api/kordex/audit/export')
  assert.equal(requested.init.cache, 'no-store')
  assert.equal(requested.init.credentials, 'same-origin')
  assert.deepEqual(result, value)
})

test('rejects cross-tenant and malformed or unsigned bundles', async t => {
  await t.test('tenant mismatch', async () => {
    await assert.rejects(exportAuditSnapshot(organizationId, async () => Response.json(await bundle({organizationId: '90bd80f9-f097-4474-86f4-b80986fd5423'}))), {message: 'audit_export_tenant_mismatch'})
  })
  await t.test('unsigned', async () => {
    await assert.rejects(exportAuditSnapshot(organizationId, async () => Response.json(await bundle({signature: ''}))), {message: 'audit_export_response_invalid'})
  })
  await t.test('tampered records', async () => {
    const value = await bundle()
    value.recordsNdjson = value.recordsNdjson.replace('id":1', 'id":2')
    await assert.rejects(exportAuditSnapshot(organizationId, async () => Response.json(value)), {message: 'audit_export_digest_mismatch'})
  })
  await t.test('malformed JSON', async () => {
    await assert.rejects(exportAuditSnapshot(organizationId, async () => new Response('{')), {message: 'audit_export_response_invalid'})
  })
  await t.test('server error', async () => {
    await assert.rejects(exportAuditSnapshot(organizationId, async () => Response.json({error: 'audit_export_signing_unavailable'}, {status: 503})), {message: 'audit_export_signing_unavailable'})
  })
  await t.test('oversized response', async () => {
    const response = new Response(null, {headers: {'content-length': String(16 * 1024 * 1024 + 1)}})
    await assert.rejects(exportAuditSnapshot(organizationId, async () => response), {message: 'audit_export_response_too_large'})
  })
})
