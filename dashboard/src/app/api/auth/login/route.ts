import {NextResponse} from 'next/server'
import {appURL,loginURL} from '../../../../lib/auth'
export async function GET(){try{const url=await loginURL();return NextResponse.redirect(url)}catch{return NextResponse.redirect(new URL('/login?error=configuration',appURL()))}}
