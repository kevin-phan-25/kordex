import Link from 'next/link'
import {notFound} from 'next/navigation'
import {ArrowLeft} from 'lucide-react'
import {Shell} from '../../../../components/shell'
import {Status} from '../../../../components/status'
import {api} from '../../../../lib/api'
import {publicBrand,requireSession} from '../../../../lib/auth'
import {date,shortID} from '../../../../lib/format'
import type {Cluster,InventoryNode,Page} from '../../../../lib/types'

export const dynamic='force-dynamic'
export const metadata={title:'Cluster detail'}

const idPattern=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const value=(input:string|undefined|null)=>input||'Not reported'

export default async function ClusterDetailPage({params}:{params:Promise<{id:string}>}){
  const [session,{id}]=await Promise.all([requireSession(),params])
  if(!idPattern.test(id))notFound()
  let cluster:Cluster|undefined
  let clusterUnavailable=false
  try{
    const result=await api<Page<Cluster>>(session,'/dashboard/clusters?limit=500')
    cluster=result.items.find(item=>item.id===id)
  }catch{clusterUnavailable=true}
  if(!cluster&& !clusterUnavailable)notFound()

  let nodes:InventoryNode[]=[]
  let nodesUnavailable=false
  if(cluster){
    try{
      const result=await api<Page<InventoryNode>>(session,`/nodes?clusterId=${encodeURIComponent(id)}&limit=500`)
      nodes=result.items
    }catch{nodesUnavailable=true}
  }
  const nodeCount=nodes.filter(item=>item.present).length
  const readyCount=nodes.filter(item=>item.present&&item.fresh&&item.node.ready).length
  const notReadyCount=nodes.filter(item=>item.present&&item.fresh&&!item.node.ready).length
  const staleCount=nodes.filter(item=>item.present&&!item.fresh).length
  const absentCount=nodes.filter(item=>!item.present).length

  return <Shell brand={publicBrand()} identity={{name:session.name,email:session.email,role:session.role,subject:session.sub}} organization={session.organizationID} organizationName={session.organizationName}>
    <div className="eyebrow">INVENTORY / CLUSTER DETAIL</div>
    <div className="page-title-row">
      <div>
        <h1 className="page-title">{cluster?.name??'Cluster detail'}</h1>
        {cluster&&<div className="detail-id">{cluster.provider} · {shortID(cluster.id)}</div>}
        <p className="page-subtitle">Organization-scoped cluster and agent-reported node inventory.</p>
      </div>
      <Link className="button" href="/fleet?tab=clusters"><ArrowLeft size={14}/>Back to fleet</Link>
    </div>
    {clusterUnavailable&&<div className="banner warning">Cluster inventory is temporarily unavailable. Check organization access and API health.</div>}
    {cluster&&<>
      <div className="metrics-grid">
        <div className="card metric"><div className="metric-top">Agent</div><div className="metric-value"><Status value={cluster.connected?'Connected':'Stale'}/></div><div className="metric-foot">Last heartbeat {date(cluster.lastHeartbeatAt)}</div></div>
        <div className="card metric"><div className="metric-top">Current nodes</div><div className="metric-value">{nodesUnavailable?'—':nodeCount}</div><div className="metric-foot">{nodesUnavailable?'Inventory unavailable':`${readyCount} ready · ${notReadyCount} not ready · ${staleCount} stale · ${absentCount} absent`}</div></div>
        <div className="card metric"><div className="metric-top">Kubernetes</div><div className="metric-value" style={{fontSize:16}}>{value(cluster.kubernetesVersion)}</div><div className="metric-foot">Last inventory {date(cluster.observedAt)}</div></div>
        <div className="card metric"><div className="metric-top">Location</div><div className="metric-value" style={{fontSize:16}}>{value(cluster.providerMetadata?.location)}</div><div className="metric-foot">Project {value(cluster.providerMetadata?.gcpProjectId)}</div></div>
      </div>
      <section className="card" style={{marginBottom:16}}>
        <div className="card-head"><div><h2 className="card-title">Cluster metadata</h2><div className="card-description">Registration and latest successful inventory</div></div></div>
        <div className="table-wrap"><table><tbody>
          <tr><th scope="row">Provider</th><td>{cluster.provider}</td><th scope="row">Kubernetes version</th><td>{value(cluster.kubernetesVersion)}</td></tr>
          <tr><th scope="row">GCP project</th><td>{value(cluster.providerMetadata?.gcpProjectId)}</td><th scope="row">Location</th><td>{value(cluster.providerMetadata?.location)}</td></tr>
          <tr><th scope="row">Cluster UID</th><td>{value(cluster.clusterUid)}</td><th scope="row">Registered</th><td>{date(cluster.createdAt)}</td></tr>
          <tr><th scope="row">Last inventory</th><td>{date(cluster.observedAt)}</td><th scope="row">Last agent heartbeat</th><td>{date(cluster.lastHeartbeatAt)}</td></tr>
        </tbody></table></div>
      </section>
      <section className="card">
        <div className="card-head"><div><h2 className="card-title">Node inventory</h2><div className="card-description">Actual node records reported by the cluster agent</div></div><span className="secondary-cell">{nodesUnavailable?'Inventory unavailable':`${nodeCount} current · ${absentCount} absent retained`}</span></div>
        {nodesUnavailable&&<div className="banner warning">Node inventory is temporarily unavailable. Check API health and organization membership.</div>}
        {!nodesUnavailable&&<div className="table-wrap"><table>
          <thead><tr><th>Node</th><th>Operating system</th><th>Kernel</th><th>Architecture</th><th>Container runtime</th><th>Provider ID / IP</th><th>Node pool</th><th>Ready</th><th>Scheduling</th><th>Last report</th></tr></thead>
          <tbody>{nodes.map(item=>{const node=item.node;const health=!item.present?'Absent':!item.fresh?'Stale':node.ready?'Healthy':'Unhealthy';const pool=node.lifecycle?.kubernetes.nodePool||node.labels?.['cloud.google.com/gke-nodepool'];return <tr key={node.uid}>
            <td className="primary-cell"><Link className="table-link" href={`/fleet/nodes/${encodeURIComponent(node.uid)}?clusterId=${encodeURIComponent(id)}`}>{node.name}</Link><div className="secondary-cell">{shortID(node.uid)}</div></td>
            <td>{value(node.osImage)}<div className="secondary-cell">{node.osId||'unknown'} {node.osVersion||''}</div></td>
            <td>{value(node.kernelVersion)}<div className="secondary-cell">Kubernetes {value(node.lifecycle?.kubernetes.version||cluster.kubernetesVersion)}</div></td>
            <td>{value(node.architecture)}</td>
            <td>{value(node.containerRuntime)}</td>
            <td>{value(node.providerId)}<div className="secondary-cell">{value(node.internalIp)}</div></td>
            <td>{pool||'Not reported'}</td>
            <td><Status value={health}/></td>
            <td>{node.unschedulable?'Unschedulable':'Schedulable'}</td>
            <td>{date(item.observedAt)}</td>
          </tr>})}</tbody>
        </table>{nodes.length===0&&<div className="empty"><strong>No node inventory</strong>Nodes appear here after the agent reports a successful cluster inventory.</div>}</div>}
      </section>
    </>}
  </Shell>
}
