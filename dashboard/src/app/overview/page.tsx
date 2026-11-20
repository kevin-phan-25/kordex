import Link from 'next/link'
import {AlertTriangle,ArrowRight,Boxes,Layers,Server,ShieldAlert,Workflow} from 'lucide-react'
import {Shell} from '../../components/shell'
import {Status} from '../../components/status'
import {api} from '../../lib/api'
import {publicBrand,requireSession} from '../../lib/auth'
import type {Campaign,Cluster,InventoryNode,Page,Summary} from '../../lib/types'
import {relative,shortID} from '../../lib/format'

export const dynamic='force-dynamic'
export const metadata={title:'Fleet overview'}

type LoadResult<T>={value:T|null;failed:boolean}
async function load<T>(session:Awaited<ReturnType<typeof requireSession>>,path:string):Promise<LoadResult<T>>{
  try{return {value:await api<T>(session,path),failed:false}}
  catch{return {value:null,failed:true}}
}
const terminal=['Succeeded','Failed','Cancelled','CompletedWithFailures']

export default async function Overview(){
  const session=await requireSession()
  const [summaryLoad,campaignLoad,clusterLoad,nodeLoad]=await Promise.all([
    load<Summary>(session,'/summary'),
    load<Page<Campaign>>(session,'/campaigns?limit=6'),
    load<Page<Cluster>>(session,'/dashboard/clusters?limit=5'),
    load<Page<InventoryNode>>(session,'/nodes?limit=5'),
  ])
  const summary=summaryLoad.value
  const campaigns=campaignLoad.value??{items:[],limit:6,offset:0}
  const clusters=clusterLoad.value??{items:[],limit:5,offset:0}
  const nodes=nodeLoad.value??{items:[],limit:5,offset:0}
  const activeCampaigns=campaigns.items.filter(c=>!terminal.includes(c.phase))
  const metrics=[
    ['Fleets',summary?.fleets??'—','Organization inventory',Layers,'teal'],
    ['Sites',summary?.sites??'—','Geographic locations',Layers,'teal'],
    ['Clusters',summary?.clusters??'—',summary?`${summary.disconnectedClusters} with stale agent evidence`:'Summary unavailable',Server,'orange'],
    ['Nodes',summary?.nodes??'—',summary?`${summary.healthyNodes} healthy with fresh reports`:'Summary unavailable',Boxes,''],
    ['Active campaigns',summary?.activeCampaigns??'—','Across all rollout stages',Workflow,'orange'],
    ['Unhealthy / unknown',summary?summary.unhealthyNodes+summary.unknownNodes:'—',summary?`${summary.unknownNodes} unknown`:'Summary unavailable',ShieldAlert,'red'],
    ['Blocked operations',summary?.blockedOperations??'—',summary?`${summary.retainedReservations} reservations retained`:'Summary unavailable',AlertTriangle,'red'],
    ['Failed operations',summary?.failedOperations??'—',summary?`${summary.pendingOperations} pending delivery`:'Summary unavailable',AlertTriangle,'orange'],
  ] as const

  return <Shell brand={publicBrand()} identity={{name:session.name,email:session.email,role:session.role,subject:session.sub}} organization={session.organizationID} organizationName={session.organizationName}>
    <div className="eyebrow">FLEET OPERATIONS / OVERVIEW</div>
    <div className="page-title-row"><div><h1 className="page-title">Fleet overview</h1><p className="page-subtitle">A live view of infrastructure health and maintenance activity.</p></div><div style={{display:'flex',alignItems:'center',gap:10}}><span className="secondary-cell">Updated {summary?relative(summary.observedAt):'—'}</span><Link className="button primary" href="/campaigns/new"><Workflow size={14}/>Plan maintenance</Link></div></div>
    {(summaryLoad.failed||campaignLoad.failed||clusterLoad.failed||nodeLoad.failed)&&<div className="banner warning"><AlertTriangle size={16}/><span>Some dashboard data could not be loaded. The affected sections are marked unavailable; empty results are not treated as zero inventory.</span></div>}
    {summary&&(summary.disconnectedClusters>0||summary.blockedOperations>0||summary.retainedReservations>0)&&<div className="banner warning"><AlertTriangle size={16}/><span>{summary.disconnectedClusters>0&&`${summary.disconnectedClusters} clusters have stale agent or inventory evidence. `}{summary.blockedOperations>0&&`${summary.blockedOperations} operations are blocked and need review. `}{summary.retainedReservations>0&&`${summary.retainedReservations} reservations remain held until terminal status is verified.`}</span></div>}

    <div className="metrics-grid">{metrics.slice(0,4).map(([label,value,foot,Icon,tone])=><div className="card metric" key={label}><div className="metric-top"><span>{label}</span><span className={`metric-icon ${tone}`}><Icon size={15}/></span></div><div className="metric-value">{typeof value==='number'?value.toLocaleString():value}</div><div className="metric-foot">{foot}</div></div>)}</div>
    <div className="metrics-grid">{metrics.slice(4).map(([label,value,foot,Icon,tone])=><div className="card metric" key={label}><div className="metric-top"><span>{label}</span><span className={`metric-icon ${tone}`}><Icon size={15}/></span></div><div className="metric-value">{typeof value==='number'?value.toLocaleString():value}</div><div className="metric-foot">{foot}</div></div>)}</div>

    <div className="grid-two">
      <section className="card"><div className="card-head"><div><h2 className="card-title">Fleet health</h2><div className="card-description">Node readiness using current agent evidence</div></div><Link className="table-link" href="/fleet">View nodes <ArrowRight size={12}/></Link></div><div className="card-body">
        {summary&&[['Healthy','healthyNodes','#2c9b75'],['Unhealthy','unhealthyNodes','#d05a5d'],['Unknown / stale','unknownNodes','#a3adbb']].map(([name,key,color])=>{const count=Number(summary[key as keyof Summary]??0),total=summary.nodes;return <div className="health-row" key={name}><div className="health-label">{name}</div><div className="track"><div className="track-fill" style={{background:color,width:`${total?Math.max(count?2:0,count/total*100):0}%`}}/></div><div className="health-number">{count.toLocaleString()}</div></div>})}
        {!summary&&<div className="banner warning">Fleet health summary unavailable.</div>}{summary?.nodes===0&&<div className="empty"><strong>No node inventory yet</strong>Nodes appear after an outbound agent reports.</div>}
        {summary&&<div className="legend"><span><i style={{background:'#2c9b75'}}/>Ready</span><span><i style={{background:'#d05a5d'}}/>Unhealthy</span><span><i style={{background:'#a3adbb'}}/>Evidence stale</span></div>}
      </div></section>
      <section className="card"><div className="card-head"><div><h2 className="card-title">Campaign progress</h2><div className="card-description">Approval gates and rollout stages</div></div><Link className="table-link" href="/campaigns">All campaigns <ArrowRight size={12}/></Link></div><div className="card-body">
        {!campaignLoad.failed&&activeCampaigns.slice(0,4).map((campaign,index)=><Link className="rollout-item" href={`/campaigns/${campaign.id}`} key={campaign.id}><span className={`rollout-step ${campaign.progress.succeeded?'done':''}`}>{index+1}</span><span><span className="rollout-name" style={{display:'block'}}>{campaign.spec.name}</span><span className="rollout-meta">Stage {campaign.stage+1} · {campaign.progress.succeeded}/{campaign.progress.total} complete</span></span><Status value={campaign.phase}/></Link>)}
        {campaignLoad.failed?<div className="banner warning">Campaign data unavailable.</div>:activeCampaigns.length===0&&<div className="empty"><strong>No active campaigns</strong>Plan a validation or maintenance campaign.</div>}
        <Link className="button" href="/campaigns/new" style={{width:'100%',marginTop:11}}><Workflow size={14}/>Create campaign</Link>
      </div></section>
    </div>

    <div className="grid-equal">
      <section className="card"><div className="card-head"><div><h2 className="card-title">Clusters</h2><div className="card-description">Agent connectivity and Kubernetes version</div></div><Link className="table-link" href="/fleet?tab=clusters">Inventory <ArrowRight size={12}/></Link></div><div className="table-wrap"><table><thead><tr><th>Cluster</th><th>Provider</th><th>Version</th><th>Agent</th></tr></thead><tbody>{clusters.items.map(cluster=><tr key={cluster.id}><td><Link className="primary-cell row-link" href={`/fleet/clusters/${cluster.id}`}>{cluster.name}</Link><div className="secondary-cell">{shortID(cluster.id)}</div></td><td>{cluster.provider}</td><td>{cluster.kubernetesVersion||'—'}</td><td><Status value={cluster.connected?'Connected':'Stale'}/></td></tr>)}</tbody></table>{clusterLoad.failed?<div className="banner warning">Cluster inventory unavailable.</div>:clusters.items.length===0&&<div className="empty"><strong>No clusters registered</strong>Connect a cluster with the outbound agent.</div>}</div></section>
      <section className="card"><div className="card-head"><div><h2 className="card-title">Recently reported nodes</h2><div className="card-description">Latest observed node inventory</div></div><Link className="table-link" href="/fleet">All nodes <ArrowRight size={12}/></Link></div><div className="table-wrap"><table><thead><tr><th>Node</th><th>Cluster</th><th>Operating system</th><th>Health</th></tr></thead><tbody>{nodes.items.map(item=><tr key={`${item.clusterId}/${item.node.uid}`}><td className="primary-cell"><Link className="table-link" href={`/fleet/nodes/${encodeURIComponent(item.node.uid)}?clusterId=${item.clusterId}`}>{item.node.name}</Link><div className="secondary-cell">{item.node.architecture||'—'}</div></td><td>{item.clusterName}</td><td>{item.node.osImage||'—'}</td><td><Status value={item.fresh?(item.node.ready?'Healthy':'Unhealthy'):'Unknown'}/></td></tr>)}</tbody></table>{nodeLoad.failed?<div className="banner warning">Node inventory unavailable.</div>:nodes.items.length===0&&<div className="empty"><strong>No node inventory</strong>Inventory is reported by connected agents.</div>}</div></section>
    </div>
  </Shell>
}
