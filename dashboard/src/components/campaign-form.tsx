'use client'
import {FormEvent, useEffect, useState} from 'react'
import {useRouter} from 'next/navigation'
import {ArrowLeft, ArrowRight, LoaderCircle, ShieldCheck, Workflow} from 'lucide-react'
import type {CampaignPreview,Cluster,Fleet,PolicyCatalog,PolicyCatalogEntry,Site} from '../lib/types'
import {concurrencyLimitFields,draftFromLimits,validateConcurrencyLimitDraft,type ConcurrencyLimitDraft,type ConcurrencyLimits} from '../lib/concurrency-policy'

type PolicyInput={name:string;uid:string;generation:string}
const MAX_CAMPAIGN_CLUSTERS=500
const DEFAULT_CAMPAIGN_LIMITS:ConcurrencyLimits={organization:1,fleet:1,site:1,zone:1,cluster:1,node:1,maxUnavailablePerSite:1}
const newID=()=>crypto.randomUUID()
const emptyPolicy=():PolicyInput=>({name:'',uid:'',generation:''})
const durationLabel=(nanoseconds:number)=>`${Math.ceil(nanoseconds/60_000_000_000)} min`
const hostUpgrade=(item:PolicyCatalogEntry)=>item.upgrade?.executionBackend==='ansible-ee'&&((item.upgrade.osFamily==='debian'&&item.upgrade.playbookCatalogId==='kordex.os-upgrade.debian.v2')||(item.upgrade.osFamily==='rhel'&&item.upgrade.playbookCatalogId==='kordex.os-upgrade.rhel.v1'))&&!item.upgradePlanInvalid&&Boolean(item.upgradePlanDigest)
const fleetExecutor=(item:PolicyCatalogEntry,catalog:PolicyCatalog|undefined):'UpgradePackages'|'UpgradeNodePool'|''=>{
  const caps=catalog?.operatorCapabilities
  const host=hostUpgrade(item)&&caps?.hostUpgrades
  const gke=item.providerUpgrade?.provider==='gke'&&!item.providerPlanInvalid&&Boolean(item.providerPlanDigest)&&caps?.gkeNodePoolUpgrade
  return host?'UpgradePackages':gke?'UpgradeNodePool':''
}
const policiesForAction=(catalog:PolicyCatalog|undefined,action:string):PolicyCatalogEntry[]=>{
  if(!catalog?.fresh)return []
  return catalog.items.filter(item=>!item.suspended&&(
    action==='UpgradePackages'?hostUpgrade(item):
    action==='UpgradeNodePool'?(item.providerUpgrade?.provider==='gke'&&!item.providerPlanInvalid&&Boolean(item.providerPlanDigest)):
    action==='UpgradeFleet'?Boolean(fleetExecutor(item,catalog)):true
  ))
}
function zonedInstant(value:string,zone:string):string {
  const match=/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})$/.exec(value)
  if(!match)throw new Error('Choose a valid maintenance window.')
  const wanted=match.slice(1).map(Number),target=Date.UTC(wanted[0],wanted[1]-1,wanted[2],wanted[3],wanted[4])
  const formatter=new Intl.DateTimeFormat('en-CA',{timeZone:zone,year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',hourCycle:'h23'})
  let candidate=target
  for(let i=0;i<4;i++) {
    const parts=formatter.formatToParts(new Date(candidate)),get=(key:string)=>Number(parts.find(part=>part.type===key)?.value)
    const shown=[get('year'),get('month'),get('day'),get('hour'),get('minute')]
    const represented=Date.UTC(shown[0],shown[1]-1,shown[2],shown[3],shown[4])
    const delta=target-represented
    if(delta===0)return new Date(candidate).toISOString()
    candidate+=delta
  }
  throw new Error('The selected local time does not exist in this time zone. Choose another time.')
}

type ClusterPolicyProps={cluster:Cluster;catalog:PolicyCatalog|undefined;action:string;value:PolicyInput|undefined;onChoose:(entry:PolicyCatalogEntry)=>void;onEdit:(key:keyof PolicyInput,value:string)=>void}
function UpgradePlanDetails({entry}:{entry:PolicyCatalogEntry}) {
  const plan=entry.upgrade
  if(!plan)return null
  return <details style={{marginTop:6}}><summary>Review exact package and executor plan</summary><div style={{marginTop:6,overflowWrap:'anywhere'}}><div>Packages</div><ul style={{margin:'4px 0 8px',paddingLeft:18}}>{plan.packages.map(pkg=><li key={pkg.name}>{pkg.name}={pkg.version}</li>)}</ul>{plan.expectedKernelVersion&&<div>Required running kernel after reboot: {plan.expectedKernelVersion}</div>}<div>Execution environment: {plan.executionEnvironment}</div><div>Catalog: {plan.playbookCatalogId} · channel {plan.channel}</div><div>Playbook SHA-256: {plan.playbookDigest}</div><div>Collections SHA-256: {plan.collectionsDigest}</div><div>Timeouts: execution {durationLabel(plan.executionTimeout)}, reboot {durationLabel(plan.rebootTimeout)}, verification {durationLabel(plan.verificationTimeout)}</div><div>Plan SHA-256: {entry.upgradePlanDigest}</div></div></details>
}
function ProviderUpgradePlanDetails({entry}:{entry:PolicyCatalogEntry}) {
  const plan=entry.providerUpgrade
  if(!plan)return null
  return <details style={{marginTop:6}}><summary>Review exact GKE node-pool upgrade</summary><div style={{marginTop:6,overflowWrap:'anywhere'}}><div>Resource: {plan.resource}</div><div>Kubernetes version: {plan.targetVersion}</div><div>Upgrade strategy: SURGE · max surge {plan.maxSurge} per zone · max unavailable {plan.maxUnavailable}</div><div>Maximum observation time: {durationLabel(plan.timeout)}</div><div>Plan SHA-256: {entry.providerPlanDigest}</div></div></details>
}
function ClusterPolicy({cluster,catalog,action,value,onChoose,onEdit}:ClusterPolicyProps) {
  const available=policiesForAction(catalog,action)
  const chosen=available.find(item=>item.policy.name===value?.name&&item.policy.uid===value?.uid&&item.policy.generation===Number(value?.generation))
  return <fieldset style={{border:'1px solid #e5eaf0',borderRadius:7,padding:12,margin:'0 0 8px'}}>
    <legend style={{fontSize:12,fontWeight:650,padding:'0 5px'}}>{cluster.name}</legend>
    {available.length>0?<>
      <select className="form-select" aria-label={`${cluster.name} maintenance policy`} required value={chosen?.policy.name??''} onChange={event=>{const entry=available.find(item=>item.policy.name===event.target.value);if(entry)onChoose(entry)}}>
        <option value="">Select a discovered policy</option>
        {available.map(item=><option key={item.policy.name} value={item.policy.name}>{item.policy.name} · generation {item.policy.generation}{item.upgrade?` · ${item.upgrade.osFamily} host upgrade plan`:''}{item.providerUpgrade?' · GKE node-pool plan':''}</option>)}
      </select>
      {chosen&&<div className="form-note" style={{marginTop:6}}>UID {chosen.policy.uid} · generation {chosen.policy.generation}{chosen.upgrade&&<><div>{chosen.upgrade.osFamily} / {chosen.upgrade.id} · reboot {chosen.upgrade.reboot} · attempts {chosen.upgrade.maxAttempts}</div><UpgradePlanDetails entry={chosen}/></>}{chosen.providerUpgrade&&<ProviderUpgradePlanDetails entry={chosen}/>}</div>}
      {(action==='UpgradePackages'||action==='UpgradeNodePool'||action==='UpgradeFleet')&&<div className="form-note" role="status">{!catalog?.operatorCapabilities?'Local operator capability has not been reported recently; campaign preview will block until the operator publishes a fresh status.':action==='UpgradePackages'&&!catalog.operatorCapabilities.hostUpgrades?'The local Ansible EE host-upgrade executor is disabled. Enable and verify it on this cluster before starting an upgrade campaign.':action==='UpgradeNodePool'&&!catalog.operatorCapabilities.gkeNodePoolUpgrade?'The local GKE node-pool adapter is disabled. Enable it with Workload Identity before starting an upgrade campaign.':action==='UpgradeFleet'?'The fleet campaign selects the provider-neutral host executor when its signed plan and gate are available, then falls back to an enabled provider adapter.':'Local operator reports this executor enabled. The operator still validates configuration and safety when the operation arrives.'}</div>}
    </>:action==='UpgradePackages'||action==='UpgradeNodePool'||action==='UpgradeFleet'?<div className="form-note" role="status">{catalog?.fresh?`No valid ${action==='UpgradeNodePool'?'GKE node-pool':action==='UpgradeFleet'?'self-managed or provider-native':'Ansible EE host'} upgrade plan was reported by this cluster.`:'Fresh local policy discovery is required. Manual policy IDs cannot authorize upgrades.'}</div>:<>
      <div className="form-note" style={{marginBottom:8}}>{catalog?.fresh?'No active local policies were reported.':'Policy catalog is stale or unavailable; exact references can be entered for existing validation/drain workflows.'}</div>
      <div className="form-grid">
        <input className="text-input" aria-label={`${cluster.name} policy name`} placeholder="Policy name" required value={value?.name??''} onChange={event=>onEdit('name',event.target.value)}/>
        <input className="text-input" aria-label={`${cluster.name} policy UID`} placeholder="Kubernetes UID" required value={value?.uid??''} onChange={event=>onEdit('uid',event.target.value)}/>
        <input className="text-input" aria-label={`${cluster.name} policy generation`} placeholder="Generation" type="number" min={1} required value={value?.generation??''} onChange={event=>onEdit('generation',event.target.value)}/>
      </div>
    </>}
  </fieldset>
}

function CampaignPreviewPanel({preview,clusters,action}:{preview:CampaignPreview;clusters:Cluster[];action:string}) {
  const stageNames=['Canary','Small batch','Expanded','Remaining']
  const blockerHelp=(reason:string)=>reason==='LocalOperatorRBACIncomplete'||reason==='LocalOperatorRBACIncompleteAtAdmission'?'The operator denied a required node, eviction, PDB, NodeMaintenance status, or durable reservation permission review. Install the current operator-default RBAC profile and wait for a fresh capability report.':reason==='OperatorCapabilitiesStale'?'The operator capability report is missing or expired. Restore agent/operator reporting and refresh the preview.':''
  return <section className="card" style={{marginTop:14}}><div className="card-head"><div><h3 className="card-title">Fleet preflight preview</h3><div className="card-description">Read-only assessment from central inventory and reported local policy catalogs</div></div><span className={`status ${preview.startAllowed?'green':'amber'}`}>{preview.targets.length} eligible · {preview.blockedCount} blocked</span></div><div className="card-body"><div className="detail-stats">{stageNames.map((name,index)=><div key={name}><div className="detail-stat-label">{name}</div><div className="detail-stat-value">{preview.stageCounts[index]??0}</div></div>)}</div><div className="detail-id" style={{marginTop:12}}>Campaign start: {preview.startAllowed?'preflight clear':'blocked until findings are resolved'}{preview.snapshotDigest?` · snapshot sha256:${preview.snapshotDigest}`:''} · observed {new Date(preview.observedAt).toLocaleString()}</div><div className="table-wrap" style={{maxHeight:360,overflow:'auto',marginTop:12}}><table><thead><tr><th>Node</th><th>Cluster</th><th>Assessment</th><th>Action</th><th>Stage</th></tr></thead><tbody>{preview.nodes.map((finding,index)=><tr key={`${finding.clusterId}/${finding.node?.uid??'none'}/${index}`}><td className="primary-cell">{finding.node?.name??'No node inventory'}{finding.node&&<div className="secondary-cell">{finding.node.uid}</div>}</td><td>{finding.clusterName||clusters.find(cluster=>cluster.id===finding.clusterId)?.name||finding.clusterId}</td><td><span className={`status ${finding.blocking?'red':finding.selected?'green':'gray'}`}>{finding.blocking?'Blocked':finding.selected?'Eligible':'Excluded'}</span><div className="secondary-cell"><strong>{finding.reason}</strong>{blockerHelp(finding.reason)&&<> · {blockerHelp(finding.reason)}</>}</div></td><td>{finding.action==='UpgradePackages'?'Ansible EE host':finding.action==='UpgradeNodePool'?'GKE node pool':finding.selected&&action==='UpgradeFleet'&&!finding.blocking?'No action resolved':'—'}</td><td>{finding.stage===undefined?'—':stageNames[finding.stage]??`Stage ${finding.stage+1}`}</td></tr>)}</tbody></table>{preview.nodes.length===0&&<div className="empty"><strong>No clusters matched</strong>Adjust the selected clusters or scope.</div>}</div><div className={`banner ${preview.startAllowed?'warning':'error'}`} style={{marginTop:12}}>{preview.startAllowed?'Stored inventory preflight is clear.':'Campaign start is blocked by the findings above; resolve them and refresh the preview.'} This preview does not run live workload, PDB, storage, quorum, capacity, or node safety checks. Each local operator repeats those checks before execution.</div></div></section>
}

export function CampaignForm({clusters,sites,fleets}:{clusters:Cluster[];sites:Site[];fleets:Fleet[]}) {
  const router=useRouter()
  const [busy,setBusy]=useState(false),[error,setError]=useState(''),[step,setStep]=useState(1)
  const [selectionError,setSelectionError]=useState('')
  const [name,setName]=useState(''),[action,setAction]=useState('ValidateOnly'),[selected,setSelected]=useState<string[]>([])
  const [policies,setPolicies]=useState<Record<string,PolicyInput>>({}),[selector,setSelector]=useState(''),[approval,setApproval]=useState('AllStages')
  const [campaignLimitDraft,setCampaignLimitDraft]=useState<ConcurrencyLimitDraft>(()=>draftFromLimits(DEFAULT_CAMPAIGN_LIMITS))
  const [canaryTopologyKey,setCanaryTopologyKey]=useState('')
  const [catalogs,setCatalogs]=useState<Record<string,PolicyCatalog>>({})
  const [preview,setPreview]=useState<CampaignPreview>()
  const [zone,setZone]=useState(Intl.DateTimeFormat().resolvedOptions().timeZone||'UTC'),[start,setStart]=useState(''),[end,setEnd]=useState('')
  const toggle=(id:string)=>{const next=selected.includes(id)?selected.filter(x=>x!==id):[...selected,id];if(next.length>MAX_CAMPAIGN_CLUSTERS){setSelectionError(`Campaigns support at most ${MAX_CAMPAIGN_CLUSTERS} clusters. Narrow the site or fleet selection.`);return}setSelectionError('');setSelected(next)}
  const toggleGroup=(ids:string[])=>{const allSelected=ids.length>0&&ids.every(id=>selected.includes(id));const next=allSelected?selected.filter(id=>!ids.includes(id)):[...new Set([...selected,...ids])];if(next.length>MAX_CAMPAIGN_CLUSTERS){setSelectionError(`This group would exceed the ${MAX_CAMPAIGN_CLUSTERS}-cluster campaign limit. Select a smaller scope.`);return}setSelectionError('');setSelected(next)}
  const setPolicy=(id:string,key:keyof PolicyInput,value:string)=>setPolicies(current=>({...current,[id]:{...(current[id]??emptyPolicy()),[key]:value}}))
  useEffect(()=>{let active=true;Promise.all(selected.map(async id=>{try{const response=await fetch(`/api/kordex/clusters/${id}/maintenance-policies`,{cache:'no-store'});if(!response.ok)throw new Error('catalog_unavailable');return [id,await response.json() as PolicyCatalog] as const}catch{return [id,{observedAt:null,fresh:false,items:[]}] as const}})).then(entries=>{if(active)setCatalogs(Object.fromEntries(entries))});return()=>{active=false}},[selected])
  const chooseCatalogPolicy=(clusterID:string,entry:PolicyCatalogEntry)=>setPolicies(current=>({...current,[clusterID]:{name:entry.policy.name,uid:entry.policy.uid,generation:String(entry.policy.generation)}}))
  const campaignLimits=validateConcurrencyLimitDraft(campaignLimitDraft)
  const editCampaignLimit=(key:keyof ConcurrencyLimits,value:string)=>setCampaignLimitDraft(current=>({...current,[key]:value}))
  const buildCampaignSpec=(startInstant:string,endInstant:string)=>{
    if(!selected.length)throw new Error('Select at least one cluster.')
    if(!campaignLimits.limits)throw new Error(`Invalid campaign concurrency limit: ${campaignLimits.error??'check each value.'}`)
    if(action==='UpgradeNodePool'&&canaryTopologyKey)throw new Error('GKE node-pool operations can span multiple zones; use a node-pool canary instead of a node topology canary.')
    const missing=selected.find(id=>{const p=policies[id];return !p?.name.trim()||!p.uid.trim()||!Number.isSafeInteger(Number(p.generation))||Number(p.generation)<1})
    if(missing)throw new Error('Enter the MaintenancePolicy name, Kubernetes UID and generation for every selected cluster.')
    if(action==='UpgradePackages'||action==='UpgradeNodePool'||action==='UpgradeFleet'){
      const unsupported=selected.find(id=>!policiesForAction(catalogs[id],action).some(item=>item.policy.name===policies[id]?.name&&item.policy.uid===policies[id]?.uid&&item.policy.generation===Number(policies[id]?.generation)))
      if(unsupported)throw new Error(`${action==='UpgradeNodePool'?'GKE node-pool':action==='UpgradeFleet'?'fleet':'Package'} upgrades require a fresh agent-reported compatible plan and executor capability for every selected cluster. Manual policy references are not accepted.`)
    }
    const bindings=selected.map(clusterId=>{
      const policy={name:policies[clusterId].name.trim(),uid:policies[clusterId].uid.trim(),generation:Number(policies[clusterId].generation)}
      if(action==='UpgradeFleet')return {clusterId,policy}
      if(action!=='UpgradePackages'&&action!=='UpgradeNodePool')return {clusterId,policy}
      const entry=policiesForAction(catalogs[clusterId],action).find(item=>item.policy.name===policy.name&&item.policy.uid===policy.uid&&item.policy.generation===policy.generation)
      const selectedAction=action
      const planDigest=selectedAction==='UpgradeNodePool'?entry?.providerPlanDigest:entry?.upgradePlanDigest
      if(!planDigest)throw new Error('Fresh upgrade plan digest is missing; refresh the cluster policy catalog.')
      return {clusterId,policy,planDigest}
    })
    return {name,action,selection:{clusterIds:selected,fleetIds:[],siteIds:[],nodeSelector:selector,canaries:[],...(canaryTopologyKey?{canaryTopologyKey}:{})},policies:bindings,windows:[{start:startInstant,end:endInstant,timeZone:zone}],limits:campaignLimits.limits,approvalMode:approval}
  }
  async function review() {
    setBusy(true);setError('')
    try {
      const startInstant=zonedInstant(start,zone),endInstant=zonedInstant(end,zone)
      if(new Date(endInstant)<=new Date(startInstant))throw new Error('The maintenance window end must be after its start.')
      const response=await fetch('/api/kordex/campaigns/preview',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(buildCampaignSpec(startInstant,endInstant))})
      const data=await response.json()
      if(!response.ok)throw new Error(data.error==='stale_report'?'Target preview is blocked because inventory or a policy catalog is stale. Refresh agent reports, then preview again.':data.error==='invalid_campaign'?'Campaign validation failed. Check cluster policies, selector, and maintenance window.':data.error??'preview_failed')
      setPreview(data as CampaignPreview);setStep(2)
    } catch(err) {setError(err instanceof Error?err.message:'Could not preview campaign targets')} finally {setBusy(false)}
  }
  async function create(e:FormEvent) {
    e.preventDefault();setBusy(true);setError('')
    try {
      const startInstant=zonedInstant(start,zone),endInstant=zonedInstant(end,zone)
      if(new Date(endInstant)<=new Date(startInstant))throw new Error('The maintenance window end must be after its start.')
      const spec=buildCampaignSpec(startInstant,endInstant)
      const response=await fetch('/api/kordex/campaigns',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({id:newID(),spec})})
      const data=await response.json()
      if(!response.ok)throw new Error(data.error==='invalid_campaign'?'Campaign validation failed. Check the policy references, selector, and maintenance window.':data.error??'request_failed')
      router.push(`/campaigns/${data.id}`);router.refresh()
    } catch(err) {setError(err instanceof Error?err.message:'Could not create campaign')} finally {setBusy(false)}
  }
  return <form onSubmit={create}><div className="grid-two"><section className="card"><div className="card-head"><div><h2 className="card-title">Campaign details</h2><div className="card-description">Build an approved validation, worker maintenance, self-managed host, or GKE node-pool upgrade campaign.</div></div><span className="status blue">Step {step} of 2</span></div><div className="card-body">{step===1?<>
    <div className="form-field"><label className="form-label" htmlFor="campaign-name">Campaign name</label><input id="campaign-name" className="text-input" required maxLength={128} value={name} onChange={e=>setName(e.target.value)} placeholder="Example: November worker maintenance"/></div>
    <div className="form-grid"><div className="form-field"><label className="form-label">Action</label><select className="form-select" value={action} onChange={e=>{setAction(e.target.value);if(e.target.value==='UpgradeNodePool')setCanaryTopologyKey('');if(e.target.value!=='ValidateOnly'&&approval==='None')setApproval('AllStages')}}><option value="ValidateOnly">Validate only</option><option value="DrainAndVerify">Drain and verify</option><option value="UpgradePackages">Upgrade pinned host packages</option><option value="UpgradeNodePool">Upgrade GKE node-pool Kubernetes version</option><option value="UpgradeFleet">Fleet upgrade (select executor per cluster)</option></select><div className="form-note">{action==='UpgradePackages'?'Uses a pinned Debian/Ubuntu or RHEL-family Ansible EE plan and requires the local host-upgrade gate. Not production qualified.':action==='UpgradeNodePool'?'Uses a GKE-native node-pool update with attached Workload Identity. It can replace every node in a pool and is only qualified for disposable-cluster drills.':action==='UpgradeFleet'?'One staged campaign can span self-managed and managed clusters. Each target is bound to a local host plan or optional provider plan; local safety remains authoritative.': 'Worker drain/recovery only; local safety and recovery checks remain authoritative.'}</div></div><div className="form-field"><label className="form-label">Approval gate</label><select className="form-select" value={approval} onChange={e=>setApproval(e.target.value)}><option value="AllStages">Approval at every stage</option><option value="BeforeStart">Approval before rollout</option>{action==='ValidateOnly'&&<option value="None">No approval (validation only)</option>}</select></div></div>
    <div className="form-field"><label className="form-label" htmlFor="node-selector">Node selector</label><input id="node-selector" className="text-input" value={selector} onChange={e=>setSelector(e.target.value)} placeholder="environment=production, maintenance=approved"/><div className="form-note">Kubernetes label selector. Control plane nodes are excluded. Local safety remains authoritative.</div></div>
    <div className="form-field"><div className="form-label">Quick select by site or fleet</div><div className="grid-two">
      <div style={{maxHeight:190,overflow:'auto',border:'1px solid #e5eaf0',borderRadius:7,padding:'4px 10px'}}><div className="secondary-cell" style={{padding:'6px 0',fontWeight:650}}>Sites</div>{sites.map(site=>{const ids=clusters.filter(cluster=>cluster.siteId===site.id).map(cluster=>cluster.id);const count=ids.filter(id=>selected.includes(id)).length;return <label key={site.id} style={{display:'grid',gridTemplateColumns:'20px 1fr auto',gap:8,alignItems:'center',padding:'7px 0',borderBottom:'1px solid #f0f2f5',cursor:ids.length?'pointer':'default'}}><input type="checkbox" disabled={!ids.length} checked={ids.length>0&&count===ids.length} onChange={()=>toggleGroup(ids)}/><span>{site.name}<span className="secondary-cell" style={{display:'block'}}>{site.region||'Region unspecified'}</span></span><span className="secondary-cell">{count}/{ids.length}</span></label>})}{sites.length===0&&<div className="form-note">No sites are registered.</div>}</div>
      <div style={{maxHeight:190,overflow:'auto',border:'1px solid #e5eaf0',borderRadius:7,padding:'4px 10px'}}><div className="secondary-cell" style={{padding:'6px 0',fontWeight:650}}>Fleets</div>{fleets.map(fleet=>{const ids=clusters.filter(cluster=>cluster.fleetId===fleet.id).map(cluster=>cluster.id);const count=ids.filter(id=>selected.includes(id)).length;return <label key={fleet.id} style={{display:'grid',gridTemplateColumns:'20px 1fr auto',gap:8,alignItems:'center',padding:'7px 0',borderBottom:'1px solid #f0f2f5',cursor:ids.length?'pointer':'default'}}><input type="checkbox" disabled={!ids.length} checked={ids.length>0&&count===ids.length} onChange={()=>toggleGroup(ids)}/><span>{fleet.name}</span><span className="secondary-cell">{count}/{ids.length}</span></label>})}{fleets.length===0&&<div className="form-note">No fleets are registered.</div>}</div>
    </div><div className="form-note">Group selection expands to explicit cluster IDs. Review the cluster list below; later site or fleet changes will not silently add targets. A campaign can include up to {MAX_CAMPAIGN_CLUSTERS} clusters.</div>{selectionError&&<div className="banner error" role="alert">{selectionError}</div>}</div>
    <div className="form-field"><div className="form-label">Clusters ({selected.length} selected / {MAX_CAMPAIGN_CLUSTERS} maximum)</div><div style={{maxHeight:230,overflow:'auto',border:'1px solid #e5eaf0',borderRadius:7}}>{clusters.map(c=><label key={c.id} style={{display:'grid',gridTemplateColumns:'20px 1fr auto',gap:8,alignItems:'center',padding:'10px 12px',borderBottom:'1px solid #f0f2f5',cursor:'pointer'}}><input type="checkbox" checked={selected.includes(c.id)} onChange={()=>toggle(c.id)}/><span><strong style={{fontSize:12}}>{c.name}</strong><span className="secondary-cell" style={{display:'block'}}>{c.provider} · {fleets.find(fleet=>fleet.id===c.fleetId)?.name??'No fleet'} · {sites.find(site=>site.id===c.siteId)?.name??'No site'} · {c.kubernetesVersion||'version unknown'}</span></span><span className="status gray">{c.connected?'Connected':'Stale'}</span></label>)}</div></div>
    {selected.length > 0 && <div className="form-field">
      <div className="form-label">Policy for each cluster</div>
      <div className="form-note" style={{marginBottom: 9}}>Policies are read from each cluster when its agent has maintenance catalog access. Campaign start verifies the exact local policy identity and plan digest.</div>
      {clusters.filter(cluster => selected.includes(cluster.id)).map(cluster => (
        <ClusterPolicy
          key={cluster.id}
          cluster={cluster}
          catalog={catalogs[cluster.id]}
          action={action}
          value={policies[cluster.id]}
          onChoose={entry => chooseCatalogPolicy(cluster.id, entry)}
          onEdit={(key, value) => setPolicy(cluster.id, key, value)}
        />
      ))}
    </div>}
    <div className="form-field"><div className="form-label">Maintenance window and time zone</div><div className="form-grid"><input aria-label="Window starts" className="text-input" type="datetime-local" required value={start} onChange={e=>setStart(e.target.value)}/><input aria-label="Window ends" className="text-input" type="datetime-local" required value={end} onChange={e=>setEnd(e.target.value)}/></div><input aria-label="IANA time zone" className="text-input" style={{marginTop:8}} required value={zone} onChange={e=>setZone(e.target.value)} placeholder="America/New_York"/><div className="form-note">The API validates the IANA zone and UTC offsets at both ends of the window.</div></div>
    <div className="form-field">
      <div className="form-label">Campaign concurrency ceilings</div>
      <div className="form-note" style={{marginBottom:9}}>These limits apply within this campaign. Organization-wide limits can be lower and are enforced separately. Unknown zone inventory conservatively overlaps every zone; one operation per cluster and node remains fixed.</div>
      <div className="form-grid">
        {concurrencyLimitFields.map(field=><div className="form-field" key={field.key}>
          <label className="form-label" htmlFor={`campaign-limit-${field.key}`}>{field.label}</label>
          <input id={`campaign-limit-${field.key}`} aria-label={`Campaign ${field.label.toLowerCase()} limit`} className="text-input" type="number" inputMode="numeric" min={1} max={field.fixed?1:1000} step={1} required disabled={field.fixed} value={campaignLimitDraft[field.key]} onChange={event=>editCampaignLimit(field.key,event.target.value)}/>
          <div className="form-note">{field.campaignDescription}{field.fixed?' Fixed at 1.':' Allowed range: 1–1000.'}</div>
        </div>)}
      </div>
      {!campaignLimits.limits&&<div className="banner error" role="alert">{campaignLimits.error}</div>}
    </div>
    <div className="form-field"><label className="form-label" htmlFor="canary-topology">Automatic canary topology (optional)</label><input id="canary-topology" className="text-input" value={canaryTopologyKey} disabled={action==='UpgradeNodePool'} onChange={e=>setCanaryTopologyKey(e.target.value)} placeholder="topology.kubernetes.io/zone"/><div className="form-note">When set, Kordex selects at least one canary per site, cluster, and observed label value. Every target must report that topology label. The canary stage size is derived from the domain count. GKE node-pool operations are pool-wide and use pool-level canaries instead.</div></div>
    <div className="form-field"><div className="form-label">Rollout stages</div>{[['1','Canary','1 target · batch 1'],['2','Small batch','5 targets · batch 2'],['3','Expanded','20 targets · batch 5'],['4','Remaining','All remaining · batch 10']].map(([n,title,detail])=><div className="rollout-item" key={n}><span className="rollout-step">{n}</span><span><b className="rollout-name">{title}</b><span className="rollout-meta" style={{display:'block'}}>{detail}</span></span></div>)}</div>
    <div className="banner warning"><ShieldCheck size={14}/>{action==='UpgradePackages'?'Package upgrades require a fresh local capability report, an enabled fixed-catalog Ansible EE executor, and a compatible policy on every cluster. The path is not production qualified and does not support GKE Container-Optimized OS.':action==='UpgradeNodePool'?'Every selected cluster must report a matching GKE node-pool plan and a fresh local adapter capability. The adapter also requires Workload Identity. Not production qualified.':action==='UpgradeFleet'?'Each selected cluster must have a fresh, enabled executor and one unambiguous signed plan. Kordex prefers the provider-neutral host executor, with managed node-pool updates as optional fallbacks. Provider node-pool targets cannot use node-level topology canaries.':'Local operators enforce workload disruption budgets, cluster safety, and verified recovery.'}</div>{error&&<div className="banner error" role="alert">{error}</div>}<div style={{display:'flex',justifyContent:'space-between'}}><button className="button" type="button" disabled={step===1} onClick={()=>setStep(1)}><ArrowLeft size={13}/>Back</button><button className="button primary" type="button" disabled={busy||!name||!selected.length||!start||!end} onClick={review}>{busy?<LoaderCircle size={13}/>:null}Preview exact targets <ArrowRight size={13}/></button></div>
  </>:<><h3>Review your campaign</h3><p className="page-subtitle">Review every node assessment. Starting resolves targets again and freezes a fresh immutable snapshot.</p><div className="detail-stats" style={{margin:'22px 0'}}>{[['Name',name],['Action',action],['Clusters',selected.length],['Approvals',approval]].map(([a,b])=><div key={a}><div className="detail-stat-label">{a}</div><div className="detail-stat-value">{b}</div></div>)}</div><div className="form-field"><div className="form-label">Campaign concurrency limits</div><div className="table-wrap"><table><thead><tr><th>Scope</th><th>Campaign limit</th></tr></thead><tbody>{concurrencyLimitFields.map(field=><tr key={field.key}><td>{field.label}</td><td className="primary-cell">{campaignLimitDraft[field.key]}</td></tr>)}</tbody></table></div><div className="form-note">Organization-wide limits still apply. The scheduler uses the stricter value at each scope.</div></div><div className="form-field"><div className="form-label">Selected clusters and policies</div>{clusters.filter(c=>selected.includes(c.id)).map(c=>{const entry=action==='UpgradePackages'||action==='UpgradeNodePool'||action==='UpgradeFleet'?policiesForAction(catalogs[c.id],action).find(item=>item.policy.name===policies[c.id]?.name&&item.policy.uid===policies[c.id]?.uid&&item.policy.generation===Number(policies[c.id]?.generation)):undefined;const selectedAction=action==='UpgradeFleet'&&entry?fleetExecutor(entry,catalogs[c.id]):action;const digest=selectedAction==='UpgradeNodePool'?entry?.providerPlanDigest:selectedAction==='UpgradePackages'?entry?.upgradePlanDigest:undefined;return <div className="rollout-item" key={c.id}><span className="rollout-step">✓</span><span className="rollout-name">{c.name}</span><span className="rollout-meta">{policies[c.id]?.name} · {action==='UpgradeFleet'?'executor resolved per node in preview':selectedAction==='UpgradePackages'?'Ansible EE host':selectedAction==='UpgradeNodePool'?'GKE node-pool adapter':'policy'} · generation {policies[c.id]?.generation}{action!=='UpgradeFleet'&&digest?` · plan sha256:${digest}`:''}</span>{entry?.upgrade&&<UpgradePlanDetails entry={entry}/>}{entry?.providerUpgrade&&<ProviderUpgradePlanDetails entry={entry}/>}</div>})}</div>{preview&&<CampaignPreviewPanel preview={preview} clusters={clusters} action={action}/>}<div className="form-field"><div className="form-label">Window</div>{new Intl.DateTimeFormat(undefined,{timeZone:zone,dateStyle:'medium',timeStyle:'short'}).format(new Date(zonedInstant(start,zone)))} – {new Intl.DateTimeFormat(undefined,{timeZone:zone,dateStyle:'medium',timeStyle:'short'}).format(new Date(zonedInstant(end,zone)))} · {zone}</div><div className="banner info">This creates a draft with exact local policy references. The campaign does not start until an authorized operator starts it and configured approval gates are satisfied. A blocked preview can be saved as a draft, but campaign start will rerun the fail-closed resolver.</div>{error&&<div className="banner error" role="alert">{error}</div>}<div style={{display:'flex',justifyContent:'space-between'}}><button className="button" type="button" onClick={()=>setStep(1)}><ArrowLeft size={13}/>Edit plan</button><button className="button primary" type="submit" disabled={busy||!preview}>{busy?<LoaderCircle size={14}/>:<Workflow size={14}/>}Create draft</button></div></>}</div></section><aside className="card"><div className="card-head"><h2 className="card-title">Safety and rollout</h2></div><div className="card-body">{[['Targets are snapshotted','Only fresh, ready worker nodes match the immutable plan.'],['Independent approvals','Approvers cannot approve plans they created or changed.'],['Local operators decide','PDB and workload recovery checks run in each cluster.'],['Uncertain work retains capacity','Disconnected agents do not release an issued operation.']].map(([title,description])=><div className="event" key={title}><span className="event-marker"/><div><div className="event-title">{title}</div><div className="event-meta">{description}</div></div></div>)}</div></aside></div></form>
}
