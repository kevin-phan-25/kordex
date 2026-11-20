import {NextRequest,NextResponse} from 'next/server'
import {appURL,loginURL} from '../../../../lib/auth'
import {canonicalLoginRedirect,safeOidcErrorDetails} from '../../../../lib/oidc-contract'
export async function GET(request:NextRequest){
  try {
    const canonical=canonicalLoginRedirect(request.url,appURL(),request.headers.get('host'))
    if(canonical)return NextResponse.redirect(canonical)
    return NextResponse.redirect(await loginURL())
  } catch(error) {
    const details=safeOidcErrorDetails(error)
    console.error(`[auth] oidc_login_start_failed type=${details.type} status=${details.status} oauth_code=${details.oauthCode}`)
    return NextResponse.redirect(new URL('/login?error=oidc_unavailable',appURL()))
  }
}
