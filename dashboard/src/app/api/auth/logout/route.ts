import {NextResponse} from 'next/server'
import {appURL,clearSession} from '../../../../lib/auth'
export async function POST(request:Request){if(request.headers.get('origin')!==appURL())return new NextResponse(null,{status:403});await clearSession();return NextResponse.redirect(new URL('/login',appURL()),303)}
