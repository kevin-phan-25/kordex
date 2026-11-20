import {NextResponse} from 'next/server'
import {apiURL,appURL,clearSession,endSessionEndpoint,getSession} from '../../../../lib/auth'
import {fetchManagementNoRedirect} from '../../../../lib/proxy'
import {tokenRevocationConfirmed} from '../../../../lib/oidc-contract'
import {buildKeycloakLogoutURL,logoutCompletionRedirect} from '../../../../lib/logout-contract'
export async function POST(request:Request){
  const origin=appURL()
  if(request.headers.get('origin')!==origin)return new NextResponse(null,{status:403})
  const session=await getSession()
  let revoked=!session
  if(session){
    try{
      const response=await fetchManagementNoRedirect(`${apiURL()}/v1/session/revoke`,{method:'POST',headers:{authorization:`Bearer ${session.token}`},cache:'no-store',signal:AbortSignal.timeout(5000)})
      revoked=tokenRevocationConfirmed(response.status)
    }catch{revoked=false}
  }
  await clearSession()
  let providerLogoutStage='configuration'
  try{
    const issuer=process.env.KORDEX_OIDC_ISSUER
    const clientId=process.env.KORDEX_OIDC_CLIENT_ID
    if(!issuer||!clientId)throw new Error('OIDC logout configuration is incomplete')
    providerLogoutStage='discovery'
    const endpoint=await endSessionEndpoint()
    providerLogoutStage='discovery_metadata'
    if(!endpoint)throw new Error('Provider does not advertise an end-session endpoint')
    const redirectURI=logoutCompletionRedirect(origin,Boolean(session),revoked)
    providerLogoutStage='redirect_validation'
    const logoutURL=buildKeycloakLogoutURL({appURL:origin,issuer,endSessionEndpoint:endpoint,clientId,postLogoutRedirectURI:redirectURI})
    providerLogoutStage='redirect'
    console.info(`[auth] logout local_session_cleared=true api_token_revoked=${revoked} provider_logout=redirected`)
    const response=NextResponse.redirect(logoutURL,303)
    response.headers.set('cache-control','no-store')
    response.headers.set('referrer-policy','no-referrer')
    return response
  }catch(error){
    const failureType=error instanceof Error?error.name:'unknown'
    const message=error instanceof Error?error.message:''
    const failureReason=/^fetch failed$/i.test(message)?'discovery_fetch_failed':
      /invalid url/i.test(message)?'invalid_discovery_url':
      /cannot read properties/i.test(message)?'discovery_metadata_invalid':'unclassified'
    const chain=[failureType]
    let current=error
    for(let depth=0;depth<3&&current&&typeof current==='object';depth++){
      const cause=Reflect.get(current,'cause')
      if(!cause||typeof cause!=='object')break
      const name=Reflect.get(cause,'name')
      const code=Reflect.get(cause,'code')
      chain.push(typeof name==='string'&&/^[A-Za-z0-9_]+$/.test(name)?name:'unknown')
      if(typeof code==='string'&&/^[A-Z0-9_]+$/.test(code))chain.push(code)
      current=cause
    }
    console.error(`[auth] logout local_session_cleared=true api_token_revoked=${revoked} provider_logout=unavailable stage=${providerLogoutStage} failure_chain=${chain.join('>')} failure_reason=${failureReason}`)
    const response=NextResponse.redirect(new URL('/login?error=provider_logout_unavailable',origin),303)
    response.headers.set('cache-control','no-store')
    response.headers.set('referrer-policy','no-referrer')
    return response
  }
}
