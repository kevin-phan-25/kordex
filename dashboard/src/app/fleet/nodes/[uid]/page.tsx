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
        <div className="card metric"><div className="metric-top">Readiness</div><div className="metric-value"><Status value={health}/></div><div className="metric-foot">{item.fresh?'Based on fresh agent inventory':'Inventory or agent identity is stale'}</div></div>
        <div className="card metric"><div className="metric-top">Operating system</div><div className="metric-value" style={{fontSize:16}}>{value(node.osImage)}</div><div className="metric-foot">Display metadata only</div></div>
        <div className="card metric"><div className="metric-top">Kernel</div><div className="metric-value" style={{fontSize:16}}>{value(node.kernelVersion)}</div><div className="metric-foot">Last reported kernel</div></div>
        <div className="card metric"><div className="metric-top">Last inventory</div><div className="metric-value" style={{fontSize:16}}>{date(item.observedAt)}</div><div className="metric-foot">Agent and inventory freshness are evaluated separately</div></div>
      </div>
      <section className="card" style={{marginBottom:16}}><div className="card-head"><div><h2 className="card-title">Node attributes</h2><div className="card-description">Current agent-reported Kubernetes Node metadata</div></div><Link className="table-link" href={`/fleet?tab=nodes&clusterId=${encodeURIComponent(item.clusterId)}`}>Cluster {item.clusterName}</Link></div><div className="table-wrap"><table><tbody>
        <tr><th scope="row">Cluster</th><td>{item.clusterName}</td><th scope="row">Kubernetes version</th><td>{value(node.lifecycle?.kubernetes.version)}</td></tr>
        <tr><th scope="row">Distribution hint</th><td>{value(node.lifecycle?.kubernetes.distribution)}</td><th scope="row">Node role</th><td>{value(node.lifecycle?.kubernetes.role)}</td></tr>
        <tr><th scope="row">Architecture</th><td>{value(node.architecture)}</td><th scope="row">Kubelet</th><td>{value(node.kubeletVersion)}</td></tr>
        <tr><th scope="row">Container runtime</th><td>{value(node.containerRuntime)}</td><th scope="row">Zone</th><td>{value(node.zone)}</td></tr>
        <tr><th scope="row">Provider ID</th><td>{value(node.providerId)}</td><th scope="row">Node pool</th><td>{value(node.lifecycle?.kubernetes.nodePool)}</td></tr>
        <tr><th scope="row">Scheduling</th><td>{node.unschedulable?'Cordoned':'Schedulable'}</td><th scope="row">Control plane</th><td>{node.controlPlane?'Yes':'No'}</td></tr>
      </tbody></table></div></section>
      <section className="card"><div className="card-head"><div><h2 className="card-title">Node labels</h2><div className="card-description">Labels are displayed as inventory and do not grant authorization.</div></div><span className="secondary-cell">{Object.keys(node.labels??{}).length} labels</span></div><div className="table-wrap"><table><thead><tr><th>Key</th><th>Value</th></tr></thead><tbody>{Object.entries(node.labels??{}).sort(([a],[b])=>a.localeCompare(b)).map(([key,label])=><tr key={key}><td className="primary-cell">{key}</td><td>{label}</td></tr>)}</tbody></table>{!Object.keys(node.labels??{}).length&&<div className="empty"><strong>No labels reported</strong>Label inventory is empty for this node.</div>}</div></section>
    </>}
  </Shell>
}
