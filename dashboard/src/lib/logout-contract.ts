export function postLogoutRedirect(appURL:string,redirectURI:string){
  const base=new URL(appURL)
  const candidate=new URL(redirectURI)
  if(candidate.origin!==base.origin||candidate.pathname!=='/login'||candidate.hash||
    (candidate.search&&candidate.search!=='?error=session_revocation_failed')){
    throw new Error('Invalid post-logout redirect URI')
  }
  return candidate.toString()
}

export function logoutCompletionRedirect(appURL:string,hasSession:boolean,apiTokenRevoked:boolean){
  const path=hasSession&&!apiTokenRevoked?'/login?error=session_revocation_failed':'/login'
  return postLogoutRedirect(appURL,new URL(path,appURL).toString())
}

export function validateEndSessionMetadata(issuer:string,metadata:unknown):string{
  if(!metadata||typeof metadata!=='object')throw new Error('Invalid OIDC discovery metadata')
  const value=metadata as Record<string,unknown>
  if(value.issuer!==issuer||typeof value.end_session_endpoint!=='string')throw new Error('Invalid OIDC end-session metadata')
  return value.end_session_endpoint
}

export function buildKeycloakLogoutURL(input:{
  appURL:string
  issuer:string
  endSessionEndpoint:string
  clientId:string
  postLogoutRedirectURI:string
}){
  const issuer=new URL(input.issuer),endpoint=new URL(input.endSessionEndpoint)
  const expectedPath=`${issuer.pathname.replace(/\/$/,'')}/protocol/openid-connect/logout`
  if(issuer.protocol!=='https:'||endpoint.protocol!=='https:'||endpoint.origin!==issuer.origin||
    endpoint.pathname!==expectedPath||endpoint.search||endpoint.hash){
    throw new Error('Invalid OIDC end-session endpoint')
  }
  if(!input.clientId)throw new Error('Incomplete OIDC logout request')
  const redirect=postLogoutRedirect(input.appURL,input.postLogoutRedirectURI)
  endpoint.searchParams.set('client_id',input.clientId)
  endpoint.searchParams.set('post_logout_redirect_uri',redirect)
  return endpoint.toString()
}
