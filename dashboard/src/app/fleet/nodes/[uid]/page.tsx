import Link from 'next/link'
import {ArrowLeft} from 'lucide-react'
import {Shell} from '../../../../components/shell'
import {Status} from '../../../../components/status'
import {api} from '../../../../lib/api'
import {publicBrand,requireSession} from '../../../../lib/auth'
import type {InventoryNode,Page} from '../../../../lib/types'
import {date} from '../../../../lib/format'

export const dynamic='force-dynamic'
export const metadata={title:'Node detail'}

function value(input:string|undefined|null){return input||'Not reported'}

export default async function NodeDetailPage({params,searchParams}:{params:Promise<{uid:string}>;searchParams:Promise<{clusterId?:string}>}){
  const [session,{uid},{clusterId}]=await Promise.all([requireSession(),params,searchParams])
  let item:InventoryNode|undefined
  let unavailable=false
  if(clusterId){
    const query=new URLSearchParams({clusterId,nodeUid:uid,limit:'1'})
    try{
      const result=await api<Page<InventoryNode>>(session,`/nodes?${query}`)
      item=result.items.length===1&&result.items[0].node.uid===uid?result.items[0]:undefined
    }catch{unavailable=true}
  }
  const node=item?.node
  const health=item?(item.fresh?(node?.ready?'Healthy':'Unhealthy'):'Unknown'):'Unknown'
  return <Shell brand={publicBrand()} identity={{name:session.name,email:session.email,role:session.role,subject:session.sub}} organization={session.organizationID} organizationName={session.organizationName}>
    <div className="eyebrow">INVENTORY / NODE DETAIL</div>
    <div className="page-title-row"><div><div className="detail-heading"><h1 className="page-title">{node?.name??'Node detail'}</h1>{item&&<Status value={health}/>}</div><p className="page-subtitle">Read-only node inventory. Reported metadata is not a compatibility or maintenance approval.</p><div className="detail-id">UID {uid}</div></div><Link className="button" href={clusterId?`/fleet?tab=nodes&clusterId=${encodeURIComponent(clusterId)}`:'/fleet'}><ArrowLeft size={14}/>Back to inventory</Link></div>
    {!clusterId&&<div className="banner warning">A cluster must be selected to look up a node identity.</div>}
    {unavailable&&<div className="banner warning">Node inventory is temporarily unavailable. Check organization access and API health.</div>}
    {clusterId&&!item&&!unavailable&&<div className="banner info">No node with this UID exists in the selected cluster, or its inventory has not been reported.</div>}
    {item&&node&&<>
      <div className="metrics-grid">
        <div className="card metric"><div className="metric-top">Readiness</div><div className="metric-value"><Status value={item.present?health:'Absent'}/></div><div className="metric-foot">{item.present?(item.fresh?'Based on fresh agent inventory':'Inventory or agent identity is stale'):'Missing from the latest successful inventory report'}</div></div>
        <div className="card metric"><div className="metric-top">Operating system</div><div className="metric-value" style={{fontSize:16}}>{value(node.osImage)}</div><div className="metric-foot">Display metadata only</div></div>
        <div className="card metric"><div className="metric-top">Kernel</div><div className="metric-value" style={{fontSize:16}}>{value(node.kernelVersion)}</div><div className="metric-foot">Last reported kernel</div></div>
        <div className="card metric"><div className="metric-top">Last inventory</div><div className="metric-value" style={{fontSize:16}}>{date(item.observedAt)}</div><div className="metric-foot">Agent and inventory freshness are evaluated separately</div></div>
      </div>
      <section className="card" style={{marginBottom:16}}><div className="card-head"><div><h2 className="card-title">Node attributes</h2><div className="card-description">Current agent-reported Kubernetes Node metadata</div></div><Link className="table-link" href={`/fleet?tab=nodes&clusterId=${encodeURIComponent(item.clusterId)}`}>Cluster {item.clusterName}</Link></div><div className="table-wrap"><table><tbody>
        <tr><th scope="row">Cluster</th><td>{item.clusterName}</td><th scope="row">Kubernetes version</th><td>{value(node.lifecycle?.kubernetes.version)}</td></tr>
        <tr><th scope="row">OS identity</th><td>{value(node.osId)}</td><th scope="row">OS version</th><td>{value(node.osVersion)}</td></tr>
        <tr><th scope="row">Operating system</th><td>{value(node.operatingSystem)}</td><th scope="row">Internal IP</th><td>{value(node.internalIp)}</td></tr>
        <tr><th scope="row">External IP</th><td>{value(node.externalIp)}</td><th scope="row">Created</th><td>{date(node.createdAt)}</td></tr>
        <tr><th scope="row">Distribution hint</th><td>{value(node.lifecycle?.kubernetes.distribution)}</td><th scope="row">Node role</th><td>{value(node.lifecycle?.kubernetes.role)}</td></tr>
        <tr><th scope="row">Architecture</th><td>{value(node.architecture)}</td><th scope="row">Kubelet</th><td>{value(node.kubeletVersion)}</td></tr>
        <tr><th scope="row">Container runtime</th><td>{value(node.containerRuntime)}</td><th scope="row">Zone</th><td>{value(node.zone)}</td></tr>
        <tr><th scope="row">Provider ID</th><td>{value(node.providerId)}</td><th scope="row">Node pool</th><td>{value(node.lifecycle?.kubernetes.nodePool)}</td></tr>
        <tr><th scope="row">Scheduling</th><td>{node.unschedulable?'Cordoned':'Schedulable'}</td><th scope="row">Control plane</th><td>{node.controlPlane?'Yes':'No'}</td></tr>
      </tbody></table></div></section>
      <section className="card" style={{marginBottom:16}}><div className="card-head"><div><h2 className="card-title">Conditions</h2><div className="card-description">Node conditions observed through the Kubernetes API</div></div></div><div className="table-wrap"><table><thead><tr><th>Type</th><th>Status</th><th>Reason</th><th>Last transition</th></tr></thead><tbody>{(node.conditions??[]).map((condition,index)=><tr key={`${condition.type}-${index}`}><td className="primary-cell">{condition.type}</td><td>{condition.status}</td><td>{value(condition.reason)}</td><td>{date(condition.lastTransitionTime)}</td></tr>)}</tbody></table>{!node.conditions?.length&&<div className="empty"><strong>No conditions reported</strong>The agent did not observe node conditions.</div>}</div></section>
      <section className="grid-two" style={{marginBottom:16}}><div className="card"><div className="card-head"><div><h2 className="card-title">Taints</h2><div className="card-description">Scheduling restrictions reported for this node</div></div></div><div className="table-wrap"><table><thead><tr><th>Key</th><th>Value</th><th>Effect</th></tr></thead><tbody>{(node.taints??[]).map((taint,index)=><tr key={`${taint.key}-${index}`}><td className="primary-cell">{taint.key}</td><td>{taint.value||'—'}</td><td>{taint.effect}</td></tr>)}</tbody></table>{!node.taints?.length&&<div className="empty"><strong>No taints reported</strong>This node has no observed scheduling taints.</div>}</div></div><div className="card"><div className="card-head"><div><h2 className="card-title">Resources</h2><div className="card-description">Capacity and allocatable quantities from Node status</div></div></div><div className="table-wrap"><table><thead><tr><th>Resource</th><th>Capacity</th><th>Allocatable</th></tr></thead><tbody>{Array.from(new Set([...Object.keys(node.capacity??{}),...Object.keys(node.allocatable??{})])).sort().map(name=><tr key={name}><td className="primary-cell">{name}</td><td>{node.capacity?.[name]??'—'}</td><td>{node.allocatable?.[name]??'—'}</td></tr>)}</tbody></table>{!Object.keys(node.capacity??{}).length&&!Object.keys(node.allocatable??{}).length&&<div className="empty"><strong>No resource quantities reported</strong>Capacity and allocatable values were unavailable.</div>}</div></div></section>
      <section className="card"><div className="card-head"><div><h2 className="card-title">Node labels</h2><div className="card-description">Labels are displayed as inventory and do not grant authorization.</div></div><span className="secondary-cell">{Object.keys(node.labels??{}).length} labels</span></div><div className="table-wrap"><table><thead><tr><th>Key</th><th>Value</th></tr></thead><tbody>{Object.entries(node.labels??{}).sort(([a],[b])=>a.localeCompare(b)).map(([key,label])=><tr key={key}><td className="primary-cell">{key}</td><td>{label}</td></tr>)}</tbody></table>{!Object.keys(node.labels??{}).length&&<div className="empty"><strong>No labels reported</strong>Label inventory is empty for this node.</div>}</div></section>
    </>}
  </Shell>
}
