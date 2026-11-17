'use client'
import {useEffect,useState} from 'react'
import {useRouter} from 'next/navigation'
import {ChevronDown,LoaderCircle} from 'lucide-react'

type Organization={id:string;name:string}
export function OrganizationSwitcher({activeID,activeName}:{activeID:string;activeName:string}){
  const router=useRouter()
  const [organizations,setOrganizations]=useState<Organization[]>([{id:activeID,name:activeName}])
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')
  useEffect(()=>{let active=true;fetch('/api/organizations',{cache:'no-store'}).then(async response=>{if(!response.ok)throw new Error('Could not load organizations');const value=await response.json() as {items?:Organization[]};if(active&&Array.isArray(value.items))setOrganizations(value.items.some(org=>org.id===activeID)?value.items:[...value.items,{id:activeID,name:activeName}])}).catch(()=>{if(active)setError('Organization list unavailable')});return()=>{active=false}},[activeID,activeName])
  async function switchOrganization(organizationID:string){
    if(organizationID===activeID||busy)return
    setBusy(true);setError('')
    try{
      const response=await fetch('/api/organization',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({organizationID})})
      if(!response.ok)throw new Error(response.status===403?'Access to this organization is no longer available.':'Could not switch organization.')
      router.replace('/overview')
    }catch(cause){setError(cause instanceof Error?cause.message:'Could not switch organization.');setBusy(false)}
  }
  if(organizations.length<2)return <div><div className="org-select" title={activeName}><span><span className="dot"/>{activeName||'Organization'}</span><span>{activeID.slice(0,8)}</span></div>{error&&<span className="org-switcher-error" role="status">{error}</span>}</div>
  return <div className="org-switcher"><label className="sr-only" htmlFor="organization-switcher">Organization</label><select id="organization-switcher" value={activeID} disabled={busy} onChange={event=>void switchOrganization(event.target.value)}>{organizations.map(org=><option key={org.id} value={org.id}>{org.name}</option>)}</select>{busy?<LoaderCircle className="org-switcher-progress" size={13}/>:<ChevronDown className="org-switcher-chevron" size={13} />}{error&&<span className="org-switcher-error" role="alert">{error}</span>}</div>
}
