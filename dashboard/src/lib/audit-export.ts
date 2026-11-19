const MAX_BUNDLE_BYTES = 16 * 1024 * 1024

export type AuditExportBundle = {
  format: 'kordex-audit-export-v1'
  recordsFormat: 'ndjson-v1'
  organizationId: string
  throughEventId: number
  recordCount: number
  recordsSha256: string
  createdAt: string
  recordsNdjson: string
  signingKeyId: string
  signature: string
}

async function readBounded(response: Response): Promise<string> {
  const declared = response.headers.get('content-length')
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > MAX_BUNDLE_BYTES)) {
    await response.body?.cancel().catch(() => {})
    throw new Error('audit_export_response_too_large')
  }
  if (!response.body) throw new Error('audit_export_response_invalid')
  const reader = response.body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  try {
    for (;;) {
      const {done, value} = await reader.read()
      if (done) break
      total += value.byteLength
      if (total > MAX_BUNDLE_BYTES) {
        await reader.cancel().catch(() => {})
        throw new Error('audit_export_response_too_large')
      }
      chunks.push(value)
    }
  } finally { reader.releaseLock() }
  const bytes = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength }
  try { return new TextDecoder('utf-8', {fatal: true}).decode(bytes) }
  catch { throw new Error('audit_export_response_invalid') }
}

async function validateBundle(value: unknown, organizationId: string): Promise<AuditExportBundle> {
  if (!value || typeof value !== 'object') throw new Error('audit_export_response_invalid')
  const bundle = value as Partial<AuditExportBundle>
  if (bundle.format !== 'kordex-audit-export-v1' || bundle.recordsFormat !== 'ndjson-v1' ||
      bundle.organizationId !== organizationId || !Number.isSafeInteger(bundle.throughEventId) ||
      (bundle.throughEventId ?? 0) < 1 || !Number.isSafeInteger(bundle.recordCount) ||
      (bundle.recordCount ?? 0) < 1 || typeof bundle.recordsSha256 !== 'string' ||
      !/^[0-9a-f]{64}$/.test(bundle.recordsSha256) || typeof bundle.createdAt !== 'string' ||
      typeof bundle.recordsNdjson !== 'string' || !bundle.recordsNdjson.endsWith('\n') ||
      typeof bundle.signingKeyId !== 'string' || !/^[0-9a-f]{64}$/.test(bundle.signingKeyId) ||
      typeof bundle.signature !== 'string' || !/^[A-Za-z0-9+/]{86}$/.test(bundle.signature)) {
    throw new Error(bundle.organizationId !== organizationId ? 'audit_export_tenant_mismatch' : 'audit_export_response_invalid')
  }
  const lines = bundle.recordsNdjson.split('\n')
  if (lines.length - 1 !== bundle.recordCount || lines.slice(0, -1).some(line => line.length === 0)) {
    throw new Error('audit_export_response_invalid')
  }
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(bundle.recordsNdjson))
  const actualDigest = Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('')
  if (actualDigest !== bundle.recordsSha256) throw new Error('audit_export_digest_mismatch')
  return bundle as AuditExportBundle
}

// The API fixes the high-water mark, checks the records and signs the exact
// snapshot. The browser only transports the signed bundle to the download.
export async function exportAuditSnapshot(
  organizationId: string,
  fetcher: typeof fetch = fetch,
): Promise<AuditExportBundle> {
  const response = await fetcher('/api/kordex/audit/export', {
    cache: 'no-store', credentials: 'same-origin',
  })
  const text = await readBounded(response)
  let value: unknown
  try { value = JSON.parse(text) } catch { throw new Error('audit_export_response_invalid') }
  if (!response.ok) {
    if (value && typeof value === 'object' && typeof (value as {error?: unknown}).error === 'string') {
      throw new Error((value as {error: string}).error)
    }
    throw new Error('audit_export_request_failed')
  }
  return validateBundle(value, organizationId)
}
