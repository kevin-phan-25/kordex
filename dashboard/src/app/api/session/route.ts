import {NextResponse} from 'next/server'
import {getSession} from '../../../lib/auth'
export async function GET(){const s=await getSession();if(!s)return NextResponse.json({error:'unauthorized'},{status:401});return NextResponse.json({subject:s.sub,name:s.name,email:s.email,role:s.role,organizationID:s.organizationID,organizationName:s.organizationName,expiresAt:s.expiresAt})}
