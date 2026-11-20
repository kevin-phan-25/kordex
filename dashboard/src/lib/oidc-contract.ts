export type ApiTokenMode = 'id_token' | 'access_token'
export type ApiTokenContract = { mode: ApiTokenMode; scopes: string[] }

export function callbackAuthorizationOptions(state?: string, nonce?: string, verifier?: string) {
  if (!state || !nonce || !verifier) throw new Error('Sign in expired. Please try again.')
  return { expectedState: state, expectedNonce: nonce, idTokenExpected: true as const, pkceCodeVerifier: verifier }
}

// The authorization request and the authorization-code exchange must use the
// exact same redirect_uri. NextRequest.url may reflect a request made using a
// different loopback alias (localhost vs 127.0.0.1), so the callback URL sent
// to openid-client is rebuilt from the configured dashboard origin.
export function canonicalCallbackURL(requestURL: string | URL, configuredAppURL: string): URL {
  const request = new URL(requestURL)
  if (request.pathname !== '/api/auth/callback') throw new Error('Invalid OIDC callback path')
  const callback = new URL('/api/auth/callback', configuredAppURL)
  callback.search = request.search
  return callback
}

// Avoid setting transaction cookies on a host different from the configured
// callback host. Cookies are host-only and would otherwise be absent when
// Keycloak returns the browser to the canonical callback origin.
export function canonicalLoginRedirect(requestURL: string | URL, configuredAppURL: string, observedHost?: string | null): URL | null {
  const request = new URL(requestURL)
  const app = new URL(configuredAppURL)
  // Next's development server or a trusted reverse proxy may reconstruct
  // request.url with an internal hostname. The browser-facing Host header is
  // the cookie origin; the redirect destination remains fixed by app config.
  const host = observedHost?.trim() || request.host
  let observedOrigin: string
  try { observedOrigin = new URL(`${request.protocol}//${host}`).origin }
  catch { return new URL('/api/auth/login', app) }
  if (observedOrigin === app.origin) return null
  return new URL('/api/auth/login', app)
}

const oidcErrorTypes = new Set(['TypeError','ClientError','OperationProcessingError','AuthorizationResponseError','ResponseBodyError','WWWAuthenticateChallengeError'])
const oauthErrorCodes = new Set(['access_denied','invalid_client','invalid_grant','invalid_request','invalid_scope','server_error','temporarily_unavailable','unauthorized_client','unsupported_grant_type'])
export function safeOidcErrorDetails(error: unknown) {
  if (!error || typeof error !== 'object') return { type: 'OtherError', status: 0, oauthCode: 'none' }
  const value = error as { name?: unknown; status?: unknown; error?: unknown }
  const type = typeof value.name === 'string' && oidcErrorTypes.has(value.name) ? value.name : 'OtherError'
  const status = typeof value.status === 'number' && Number.isInteger(value.status) && value.status >= 400 && value.status <= 599 ? value.status : 0
  const oauthCode = typeof value.error === 'string' && oauthErrorCodes.has(value.error) ? value.error : 'none'
  return { type, status, oauthCode }
}

export function sessionCookieOptions(appUrl: string, nodeEnv: string | undefined, maxAge: number) {
  const url = new URL(appUrl)
  const secure = url.protocol === 'https:'
  if (!secure && (nodeEnv === 'production' || !['localhost', '127.0.0.1', '::1'].includes(url.hostname))) {
    throw new Error('The dashboard URL must use HTTPS except on localhost during development.')
  }
  return { httpOnly: true, secure, sameSite: 'lax' as const, path: '/', maxAge }
}

export type AuthCookieKind='session'|'state'|'pkce'|'nonce'
type AuthCookieStore={set:(name:string,value:string,options:ReturnType<typeof sessionCookieOptions>&{expires:Date})=>unknown}

export function expireAuthCookies(store:AuthCookieStore,appUrl:string,nodeEnv:string|undefined,nameFor:(kind:AuthCookieKind)=>string){
  const options={...sessionCookieOptions(appUrl,nodeEnv,0),expires:new Date(0)}
  for(const kind of ['session','state','pkce','nonce'] as const)store.set(nameFor(kind),'',options)
}

export function pkceAuthorizationParameters(codeChallenge: string): { code_challenge: string; code_challenge_method: 'S256' } {
  return { code_challenge: codeChallenge, code_challenge_method: 'S256' }
}

export function resolveApiTokenContract(modeValue?: string, scopeValue?: string): ApiTokenContract {
  const mode=modeValue||'id_token',scopeText=scopeValue?.trim()||''
  if(mode!=='id_token'&&mode!=='access_token')throw new Error('KORDEX_OIDC_API_TOKEN_MODE must be id_token or access_token')
  if(mode==='access_token'&&!scopeText)throw new Error('KORDEX_OIDC_API_SCOPES is required for access-token mode')
  if(mode==='id_token'&&scopeText)throw new Error('KORDEX_OIDC_API_SCOPES requires access-token mode')
  const scopes=scopeText?scopeText.split(/\s+/):[]
  if(scopes.some(scope=>!/^[\x21-\x7e]+$/.test(scope)||/["\\]/.test(scope))||new Set(scopes).size!==scopes.length)throw new Error('KORDEX_OIDC_API_SCOPES must contain unique valid OAuth scope names')
  return {mode,scopes}
}

export function selectApiBearerToken(mode: ApiTokenMode, tokens: { id_token?: string; access_token?: string; token_type?: string }): { token: string; identityToken: string } {
  const identityToken=tokens.id_token
  if(!identityToken)throw new Error('Identity provider did not return an ID token.')
  if(mode==='access_token'&&(tokens.token_type!=='bearer'||!tokens.access_token))throw new Error('Identity provider did not return a bearer access token.')
  const token=mode==='access_token'?tokens.access_token:identityToken
  if(!token)throw new Error('Identity provider did not return the configured API token.')
  return {token,identityToken}
}

export function tokenRevocationConfirmed(status:number):boolean {
  return status===204||status===401
}
