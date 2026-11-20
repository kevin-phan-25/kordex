import {NextRequest,NextResponse} from 'next/server'
import {appURL,callbackURL,OidcFlowFailure,setSession} from '../../../../lib/auth'
export async function GET(request:NextRequest){
  try {
    const session=await callbackURL(new URL(request.url))
    try { await setSession(session) }
    catch { throw new OidcFlowFailure('session_creation_failed') }
    console.info('[auth] oidc_callback_succeeded session_created=true organization_authorized=true')
    return NextResponse.redirect(new URL('/overview',appURL()))
  } catch(error) {
    const category=error instanceof OidcFlowFailure?error.category:'session_creation_failed'
    console.error(`[auth] oidc_callback_failed category=${category}`)
    return NextResponse.redirect(new URL(`/login?error=${encodeURIComponent(category)}`,appURL()))
  }
}
