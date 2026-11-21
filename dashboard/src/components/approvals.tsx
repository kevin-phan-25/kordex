'use client'
import {useState} from 'react'
import {useRouter} from 'next/navigation'
import {Check,LoaderCircle,ShieldX,Undo2} from 'lucide-react'

export function ApprovalActions({id,revision}:{id:string;revision:number}) {
  const router=useRouter(),[busy,setBusy]=useState(false),[error,setError]=useState('')
  async function act(action:string) {
    setBusy(true);setError('')
    try {
      const r=await fetch(`/api/kordex/campaigns/${id}/${action}`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({revision})})
      if(!r.ok){const v=await r.json().catch(()=>({error:'request_failed'}));throw new Error(r.status===409?'Campaign changed during review. Refresh and review the current plan.':v.error??'request_failed')}
      router.refresh()
    } catch(e) {setError(e instanceof Error?e.message:'Request failed')}
    finally {setBusy(false)}
  }
  return <div style={{display:'flex',gap:7}}><button className="button primary small" onClick={()=>act('approve')} disabled={busy}>{busy?<LoaderCircle size={12}/>:<Check size={12}/>}Approve</button><button className="button danger small" onClick={()=>act('reject')} disabled={busy}><ShieldX size={12}/>Reject</button>{error&&<span role="alert" className="secondary-cell">{error}</span>}</div>
}

export function ApprovalRevocation({campaignID,approvalID,revision}:{campaignID:string;approvalID:string;revision:number}) {
  const router=useRouter(),[reason,setReason]=useState(''),[busy,setBusy]=useState(false),[error,setError]=useState('')
  async function revoke() {
    setBusy(true);setError('')
    try {
      const response=await fetch(`/api/kordex/campaigns/${campaignID}/approvals/${approvalID}/revoke`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({revision,reason})})
      if(!response.ok){const body=await response.json().catch(()=>({error:'request_failed'}));throw new Error(response.status===409?'Campaign or approval changed. Refresh and review the current state.':body.error??'request_failed')}
      setReason('');router.refresh()
    } catch(e) {setError(e instanceof Error?e.message:'Request failed')}
    finally {setBusy(false)}
  }
  return <form onSubmit={event=>{event.preventDefault();void revoke()}} style={{display:'flex',gap:6,marginTop:7,flexWrap:'wrap'}}>
    <input aria-label="Approval revocation reason" value={reason} onChange={event=>setReason(event.target.value)} maxLength={512} required placeholder="Reason for revocation" className="search" style={{minWidth:220}}/>
    <button className="button danger small" type="submit" disabled={busy||reason.trim().length===0}>{busy?<LoaderCircle size={12}/>:<Undo2 size={12}/>}Revoke</button>
    {error&&<span role="alert" className="secondary-cell">{error}</span>}
  </form>
}
