import Link from 'next/link'
import {ArrowLeft,ArrowRight,ShieldAlert} from 'lucide-react'
import {Shell} from '../../components/shell'
import {Status} from '../../components/status'
import {api} from '../../lib/api'
import {publicBrand,requireSession} from '../../lib/auth'
import type {Cluster,Operation,Page} from '../../lib/types'
import {date,relative,shortID} from '../../lib/format'

export const dynamic='force-dynamic'
export const metadata={title:'Recovery and failures'}

const pageSize=100
const phases=['RecoveryRequired','Blocked','Failed'] as const
type AttentionPhase=typeof phases[number]

export default async function RecoveryPage({searchParams}:{searchParams:Promise<{phase?:string;offset?:string}>}){
  const[session,query]=await Promise.all([requireSession(),searchParams])
  const phase=(phases as readonly string[]).includes(query.phase??'')?query.phase as AttentionPhase:'RecoveryRequired'
  const parsedOffset=Number.parseInt(query.offset??'0',10)
  const offset=Number.isInteger(parsedOffset)&&parsedOffset>=0&&parsedOffset<=100000?parsedOffset:0
  const[operations,clusters]=await Promise.all([
    api<Page<Operation>>(session,`/operations?phase=${phase}&limit=${pageSize}&offset=${offset}`),
    api<Page<Cluster>>(session,'/dashboard/clusters?limit=500'),
  ])
  const clusterNames=new Map(clusters.items.map(cluster=>[cluster.id,cluster.name]))
  const hasPrevious=offset>0
  const hasNext=operations.items.length===pageSize
  const previousOffset=Math.max(0,offset-pageSize)
  const nextOffset=offset+pageSize
  return <Shell brand={publicBrand()} identity={{name:session.name,email:session.email,role:session.role,subject:session.sub}} organization={session.organizationID} organizationName={session.organizationName}>
    <div className="eyebrow">OPERATIONS / RECOVERY REVIEW</div>
    <div className="page-title-row">
      <div><h1 className="page-title">Recovery and failures</h1><p className="page-subtitle">Review blocked, failed, and recovery-required operations across this organization.</p></div>
      <span className="status red"><ShieldAlert size={13}/>{operations.items.length} shown</span>
    </div>
    <div className="toolbar">
      {phases.map(value=><Link key={value} className={`button small ${phase===value?'primary':''}`} href={`/recovery?phase=${value}`}>{value}</Link>)}
    </div>
    <div className="banner warning">This page is read-only. Reported inventory and agent connectivity are point-in-time context. They do not authorize retrying host work, uncordoning a node, or releasing a reservation; the cluster-local operator must verify recovery.</div>
    <section className="card">
      <div className="table-wrap"><table><thead><tr><th>Operation and node</th><th>Cluster</th><th>Phase and reason</th><th>Last evidence</th><th>Review</th></tr></thead><tbody>
        {operations.items.map(operation=>{
          const event=operation.status?.events.at(-1)
          const checkpoint=operation.status?.upgradeCheckpoint
          const provider=operation.status?.providerUpgradeCheckpoint
          return <tr key={operation.id}>
            <td><div className="primary-cell">{operation.request.nodeName}</div><div className="secondary-cell monospace">{shortID(operation.request.nodeUid)} · {operation.request.action}</div><div className="secondary-cell monospace">Operation {shortID(operation.id)}</div></td>
            <td>{clusterNames.get(operation.clusterId)??shortID(operation.clusterId)}<div className="secondary-cell">{shortID(operation.clusterId)}</div></td>
            <td><Status value={operation.phase}/><div className="operation-block-reason">{operation.status?.reason??'No phase reason reported'}</div><div className="secondary-cell">Sequence {operation.sequence} · created {date(operation.createdAt)}</div></td>
            <td>
              <div>{event?`${event.phase} · ${event.reason}`:'No phase event reported'}</div>
              <div className="secondary-cell">{event?`${relative(event.time)} · ${date(event.time)}`:'Phase time unavailable'}</div>
              <div className="secondary-cell">Inventory {operation.evidence?.inventoryFresh?'fresh':'stale or unknown'} · agent {operation.evidence?.agentConnected?'connected':'stale or unknown'}</div>
              {checkpoint&&<details><summary>Host checkpoint · {checkpoint.phase}</summary><div className="secondary-cell">Sequence {checkpoint.sequence} · {checkpoint.reason??'No checkpoint detail'}</div>{checkpoint.receipts?.map(receipt=><div className="secondary-cell" key={receipt.reference}>{receipt.phase} · sha256:{receipt.digest} · machine {receipt.machineId} · boot {receipt.bootIdBefore} → {receipt.bootIdAfter}</div>)}</details>}
              {provider&&<details><summary>Provider checkpoint · {provider.phase}</summary><div className="secondary-cell">{provider.resource} · {provider.initialVersion??'unknown'} → {provider.targetVersion}</div>{provider.reason&&<div className="secondary-cell">{provider.reason}</div>}</details>}
            </td>
            <td>{operation.campaignId?<Link className="table-link" href={`/campaigns/${operation.campaignId}/operations`}>Campaign operations <ArrowRight size={12}/></Link>:<span className="secondary-cell">Manual operation · inspect cluster-local status</span>}
              <div className="secondary-cell">Authorization expires {date(operation.expiresAt)}</div>
            </td>
          </tr>
        })}
      </tbody></table>{!operations.items.length&&<div className="empty"><strong>No {phase} operations</strong>Operations appear here when the control plane has a matching durable report.</div>}</div>
      <div className="card-body" style={{display:'flex',justifyContent:'space-between',alignItems:'center'}}><span className="secondary-cell">Newest first · page size {pageSize}</span><div style={{display:'flex',gap:8}}>{hasPrevious&&<Link className="button" href={`/recovery?phase=${phase}&offset=${previousOffset}`}><ArrowLeft size={13}/>Previous</Link>}{hasNext&&<Link className="button" href={`/recovery?phase=${phase}&offset=${nextOffset}`}>Next<ArrowRight size={13}/></Link>}</div></div>
    </section>
  </Shell>
}
