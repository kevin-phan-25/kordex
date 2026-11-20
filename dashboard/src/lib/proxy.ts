// HTTP boundary helpers shared by Next routes and security regression tests.
export class ProxyError extends Error {
  status: number
  constructor(status: number, message: string) { super(message); this.status = status }
}
export function fetchManagementNoRedirect(input: RequestInfo | URL, init: RequestInit = {}, fetcher: typeof fetch = fetch): Promise<Response> {
  return fetcher(input, {...init, redirect: 'manual'})
}
const uuid = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}'
const organizationID = new RegExp(`^${uuid}$`)
const routes: Array<[RegExp, string[]]> = [
  [/^(summary|identity|nodes|audit|lifecycle-drivers|kubernetes-compatibility|operations)$/, ['GET']],
  [/^audit\/export$/, ['GET']],
  [/^(sites|fleets|clusters|campaigns)$/, ['GET', 'POST']],
  [/^dashboard\/(sites|fleets|clusters)$/, ['GET']],
  [/^(memberships|concurrency-policy)$/, ['PUT']],
  [/^concurrency-policy$/, ['GET']],
  [/^campaigns\/preview$/, ['POST']],
  [new RegExp(`^campaigns/${uuid}$`), ['GET', 'PUT']],
  [new RegExp(`^campaigns/${uuid}/(targets|operations|events|approvals)$`), ['GET']],
  [new RegExp(`^campaigns/${uuid}/(start|approve|reject|pause|resume|cancel)$`), ['POST']],
  [new RegExp(`^clusters/${uuid}/(nodes|maintenance-policies)$`), ['GET']],
  [new RegExp(`^clusters/${uuid}/operations$`), ['GET', 'POST']],
  [new RegExp(`^clusters/${uuid}/(enrollment-tokens|revoke)$`), ['POST']],
  [new RegExp(`^clusters/${uuid}/operations/${uuid}/cancel$`), ['POST']],
]
export function scopedProxyTarget(origin: string, org: string, path: string[], method: string, search: string): URL {
  if (!organizationID.test(org)) throw new ProxyError(401, 'invalid_session')
  // Next has decoded parameters. Reject separators, escapes (including double
  // encoding), dots, controls and URL delimiters before URL normalization.
  if (!path.length || path.some(segment => !/^[A-Za-z0-9_-]+$/.test(segment))) throw new ProxyError(400, 'invalid_path')
  const relative = path.join('/')
  const matches = routes.filter(([pattern]) => pattern.test(relative))
  if (!matches.length) throw new ProxyError(404, 'route_not_allowed')
  if (!matches.some(([, methods]) => methods.includes(method))) throw new ProxyError(405, 'method_not_allowed')
  const base = new URL(origin)
  if (base.pathname !== '/' || base.search || base.hash || base.username || base.password ||
      !['http:', 'https:'].includes(base.protocol)) throw new Error('Management API must be an HTTP(S) origin')
  const target = new URL(`/v1/organizations/${org}/${relative}`, base)
  target.search = search
  return target
}
export async function readLimitedBody(request: Request, limit: number): Promise<string> {
  const declared = request.headers.get('content-length')
  if (declared !== null && !/^\d+$/.test(declared)) throw new ProxyError(400, 'invalid_content_length')
  if (declared !== null && Number(declared) > limit) {
    await request.body?.cancel().catch(() => {})
    throw new ProxyError(413, 'request_too_large')
  }
  if (!request.body) return ''
  const reader = request.body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  try {
    for (;;) {
      const {done, value} = await reader.read()
      if (done) break
      total += value.byteLength
      if (total > limit) {
        await reader.cancel().catch(() => {})
        throw new ProxyError(413, 'request_too_large')
      }
      chunks.push(value)
    }
  } finally { reader.releaseLock() }
  const bytes = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength }
  try { return new TextDecoder('utf-8', {fatal: true}).decode(bytes) }
  catch { throw new ProxyError(400, 'invalid_utf8') }
}
type Dependencies = {
  appURL: () => string
  apiURL: () => string
  getSession: () => Promise<{token: string; organizationID: string} | null>
  fetch?: typeof fetch
}
export async function proxyManagementRequest(request: Request, path: string[], deps: Dependencies): Promise<Response> {
  const failure = (status: number, error: string) => Response.json({error}, {
    status, headers: {'cache-control': 'no-store', 'x-content-type-options': 'nosniff'},
  })
  if (!['GET', 'POST', 'PUT'].includes(request.method)) return failure(405, 'method_not_allowed')
  if (request.method !== 'GET' && request.headers.get('origin') !== deps.appURL()) return failure(403, 'invalid_origin')
  const session = await deps.getSession()
  if (!session) return failure(401, 'unauthorized')
  const expectedOrganization = request.headers.get('x-kordex-expected-organization')
  if (request.method !== 'GET' && expectedOrganization !== null && expectedOrganization !== session.organizationID) {
    return failure(409, 'organization_changed')
  }
  try {
    const target = scopedProxyTarget(deps.apiURL(), session.organizationID, path, request.method, new URL(request.url).search)
    const headers = new Headers({authorization: `Bearer ${session.token}`})
    let body: string | undefined
    if (request.method !== 'GET') {
      if (request.headers.get('content-type')?.split(';')[0].trim().toLowerCase() !== 'application/json') return failure(415, 'json_required')
      headers.set('content-type', 'application/json')
      body = await readLimitedBody(request, 256 << 10)
    }
    const upstream = await fetchManagementNoRedirect(target, {
      method: request.method, headers, body, cache: 'no-store', signal: AbortSignal.timeout(12000),
    }, deps.fetch ?? fetch)
    if (upstream.status >= 300 && upstream.status < 400) return failure(502, 'upstream_redirect_refused')
    return new Response(upstream.body, {status: upstream.status, headers: {
      'content-type': upstream.headers.get('content-type') ?? 'application/json',
      'cache-control': 'no-store', 'x-content-type-options': 'nosniff',
    }})
  } catch (error) {
    return error instanceof ProxyError ? failure(error.status, error.message) : failure(503, 'control_plane_unavailable')
  }
}
