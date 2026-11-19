import {customFetch, discovery, enableNonRepudiationChecks, type Configuration, type CustomFetch} from 'openid-client'

export async function discoverOIDC(issuer: string, clientId: string, fetcher?: CustomFetch): Promise<Configuration> {
  const options = fetcher ? {[customFetch]: fetcher} : undefined
  const config = await discovery(new URL(issuer), clientId, undefined, undefined, options)
  // openid-client validates ID-token claims by default but exposes signature
  // verification as an explicit opt-in. Always verify against the discovered JWKS.
  enableNonRepudiationChecks(config)
  return config
}
