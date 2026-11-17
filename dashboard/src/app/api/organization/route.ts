import {NextRequest,NextResponse} from 'next/server'
import {apiURL,appURL,getSession,setSession} from '../../../lib/auth'

const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const roles=new Set(['viewer','operator','approver','administrator'])

export async function POST(request:NextRequest){
  if(request.headers.get('origin')!==appURL())return NextResponse.json({error:'invalid_origin'},{status:403})
  const session=await getSession()
  if(!session)return NextResponse.json({error:'unauthorized'},{status:401})
  if(session.expiresAt<=Date.now())return NextResponse.json({error:'unauthorized'},{status:401})
  const raw=await request.text()
  if(raw.length>2048)return NextResponse.json({error:'request_too_large'},{status:413})
  let input:{organizationID?:unknown}
  try{input=JSON.parse(raw) as {organizationID?:unknown}}catch{return NextResponse.json({error:'invalid_request'},{status:400})}
  if(typeof input.organizationID!=='string'||!uuid.test(input.organizationID))return NextResponse.json({error:'invalid_organization_id'},{status:400})
  try{
    const organizationID=input.organizationID
    const [identityResponse,organizationResponse]=await Promise.all([
      fetch(`${apiURL()}/v1/organizations/${organizationID}/identity`,{headers:{authorization:`Bearer ${session.token}`},cache:'no-store',signal:AbortSignal.timeout(8000)}),
      fetch(`${apiURL()}/v1/organizations/${organizationID}`,{headers:{authorization:`Bearer ${session.token}`},cache:'no-store',signal:AbortSignal.timeout(8000)}),
    ])
    if(identityResponse.status===401||organizationResponse.status===401)return NextResponse.json({error:'unauthorized'},{status:401})
    if(identityResponse.status===403||identityResponse.status===404||organizationResponse.status===403||organizationResponse.status===404)return NextResponse.json({error:'organization_access_denied'},{status:403})
    if(!identityResponse.ok||!organizationResponse.ok)return NextResponse.json({error:'control_plane_unavailable'},{status:503})
    const identity=await identityResponse.json() as {subject?:unknown;role?:unknown}
    const organization=await organizationResponse.json() as {id?:unknown;name?:unknown}
    if(identity.subject!==session.sub||typeof identity.role!=='string'||!roles.has(identity.role)||organization.id!==organizationID||typeof organization.name!=='string')return NextResponse.json({error:'invalid_membership_response'},{status:502})
    await setSession({...session,organizationID,organizationName:organization.name,role:identity.role})
    return NextResponse.json({ok:true},{headers:{'cache-control':'no-store','x-content-type-options':'nosniff'}})
  }catch{
    return NextResponse.json({error:'control_plane_unavailable'},{status:503})
  }
}
