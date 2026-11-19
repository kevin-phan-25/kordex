export type ApiTokenMode = 'id_token' | 'access_token'
export type ApiTokenContract = { mode: ApiTokenMode; scopes: string[] }

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
