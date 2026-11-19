import {NextResponse} from 'next/server'
import {apiURL,appURL,clearSession,getSession} from '../../../../lib/auth'
import {fetchManagementNoRedirect} from '../../../../lib/proxy'
import {tokenRevocationConfirmed} from '../../../../lib/oidc-contract'
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
  const destination=new URL(revoked?'/login':'/login?error=session_revocation_failed',origin)
  const response=NextResponse.redirect(destination,303)
  response.headers.set('cache-control','no-store')
  return response
}
