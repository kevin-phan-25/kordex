import 'server-only'
import { apiURL, requireSession, type Session } from './auth'
import { fetchManagementNoRedirect } from './proxy'
export class APIError extends Error { constructor(public status:number,public code:string){super(code)} }
export async function api<T>(session:Session,path:string,init:RequestInit={}):Promise<T>{
  const response=await fetchManagementNoRedirect(`${apiURL()}/v1/organizations/${session.organizationID}${path}`,{...init,headers:{authorization:`Bearer ${session.token}`,'content-type':'application/json',...init.headers},cache:'no-store',signal:init.signal??AbortSignal.timeout(10000)})
  if(!response.ok){let code='api_error';try{code=(await response.json()).error??code}catch{};throw new APIError(response.status,code)}
  if(response.status===204)return undefined as T
  return response.json() as Promise<T>
}
export async function currentAPI<T>(path:string,init?:RequestInit){return api<T>(await requireSession(),path,init)}
export type Page<T>={items:T[];limit:number;offset:number}
