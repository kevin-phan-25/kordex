import {NextRequest,NextResponse} from 'next/server'
import {appURL,callbackURL,setSession} from '../../../../lib/auth'
export async function GET(request:NextRequest){try{const session=await callbackURL(new URL(request.url));await setSession(session);return NextResponse.redirect(new URL('/overview',appURL()))}catch{return NextResponse.redirect(new URL('/login?error=signin_failed',appURL()))}}
