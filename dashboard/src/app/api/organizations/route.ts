import {NextResponse} from 'next/server'
import {apiURL,getSession} from '../../../lib/auth'
import {fetchManagementNoRedirect} from '../../../lib/proxy'

export async function GET(){
  const session=await getSession()
  if(!session)return NextResponse.json({error:'unauthorized'},{status:401,headers:{'cache-control':'no-store'}})
  try{
    const response=await fetchManagementNoRedirect(`${apiURL()}/v1/organizations?limit=500`,{headers:{authorization:`Bearer ${session.token}`},cache:'no-store',signal:AbortSignal.timeout(8000)})
    if(!response.ok)return NextResponse.json({error:response.status===401?'unauthorized':'organizations_unavailable'},{status:response.status===401?401:503,headers:{'cache-control':'no-store'}})
    const value=await response.json() as {items?:unknown}
    if(!Array.isArray(value.items))return NextResponse.json({error:'invalid_organization_response'},{status:502,headers:{'cache-control':'no-store'}})
    const items=value.items.filter((item):item is {id:string;name:string}=>typeof item==='object'&&item!==null&&typeof (item as {id?:unknown}).id==='string'&&typeof (item as {name?:unknown}).name==='string')
    return NextResponse.json({items},{headers:{'cache-control':'no-store','x-content-type-options':'nosniff'}})
  }catch{
    return NextResponse.json({error:'control_plane_unavailable'},{status:503,headers:{'cache-control':'no-store'}})
  }
}
