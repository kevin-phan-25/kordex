import Link from 'next/link'
import {ArrowLeft, ArrowRight} from 'lucide-react'
import {Shell} from '../../../../components/shell'
import {Status} from '../../../../components/status'
import {LiveRefresh} from '../../../../components/live-refresh'
import {api} from '../../../../lib/api'
import {publicBrand,requireSession} from '../../../../lib/auth'
import type {Campaign,Operation,Page} from '../../../../lib/types'
import {date,relative,shortID} from '../../../../lib/format'

export const dynamic='force-dynamic'

const pageSize=100

function ReceiptDetails({operation}:{operation:Operation}) {
  const checkpoint=operation.status?.upgradeCheckpoint
  const provider=operation.status?.providerUpgradeCheckpoint
  if (!checkpoint&&!provider) return null
  if (provider) return <div className="secondary-cell">
    GKE pool {provider.phase} · {provider.initialVersion??'unknown'} → {provider.targetVersion} · checkpoint {provider.sequence} · {date(provider.updatedAt)}
    <div className="monospace">{provider.resource}</div>
    {provider.operationName&&<div className="monospace">GKE operation: {provider.operationName}</div>}
    {provider.cancelRequested&&<div>Cancellation requested; observing the accepted GKE operation to a verified outcome.</div>}
    {provider.reason&&<div>{provider.reason}</div>}
  </div>
  if (!checkpoint) return null
  return <div className="secondary-cell">
    Upgrade {checkpoint.phase} · checkpoint {checkpoint.sequence} · {date(checkpoint.updatedAt)}
    {checkpoint.executionReference?` · ${checkpoint.executionReference}`:''}
    {checkpoint.interruptedPhase?` · interrupted ${checkpoint.interruptedPhase}`:''}
    {checkpoint.recoveryReference?` · inspection ${checkpoint.recoveryReference}`:''}
    {(checkpoint.receipts?.length??0)>0&&<details>
      <summary>{checkpoint.receipts?.length} verified execution receipts</summary>
      {checkpoint.receipts?.map(receipt=><div className="secondary-cell" key={receipt.reference}>
        <strong>{receipt.phase}</strong> · sha256:{receipt.digest} · machine {receipt.machineId} · boot {receipt.bootIdBefore} → {receipt.bootIdAfter}
        {receipt.rebooted?' · rebooted':''}{receipt.rebootRequired?' · reboot required':''}
        {receipt.packages&&Object.entries(receipt.packages).map(([name,version])=><div key={name}>{name}={version}</div>)}
        <div>{date(receipt.completedAt)}</div>
      </div>)}
    </details>}
  </div>
}

function RecentTransitions({operation}:{operation:Operation}) {
  const events=operation.status?.events??[]
  if(!events.length)return null
  return <details className="operation-transitions">
    <summary>Recent transitions · {events.length} recorded</summary>
    <ol>
      {[...events].slice(-8).reverse().map(event=><li key={event.sequence}>
        <span><Status value={event.phase}/><strong>{event.reason}</strong></span>
        <time dateTime={event.time}>{date(event.time)}</time>
      </li>)}
    </ol>
  </details>
}

export default async function Operations({params,searchParams}:{params:Promise<{id:string}>;searchParams:Promise<{offset?:string}>}) {
  const session=await requireSession()
  const [{id},{offset:offsetValue}]=await Promise.all([params,searchParams])
  const parsedOffset=Number.parseInt(offsetValue??'0',10)
  const offset=Number.isInteger(parsedOffset)&&parsedOffset>=0&&parsedOffset<=100000?parsedOffset:0
  const [campaign,result]=await Promise.all([
    api<Campaign>(session,`/campaigns/${id}`),
    api<Page<Operation>>(session,`/campaigns/${id}/operations?limit=${pageSize}&offset=${offset}`),
  ])
  const clusters=await api<Page<{id:string;name:string}>>(session,'/dashboard/clusters?limit=500')
  const clusterNames=new Map(clusters.items.map(cluster=>[cluster.id,cluster.name]))
  const hasPrevious=offset>0
  const hasNext=result.items.length===pageSize
  const previousOffset=Math.max(0,offset-pageSize)
  const nextOffset=offset+pageSize

  return <Shell brand={publicBrand()} identity={{name:session.name,email:session.email,role:session.role,subject:session.sub}} organization={session.organizationID} organizationName={session.organizationName}>
    <div className="eyebrow">OPERATIONS / CAMPAIGNS / HISTORY</div>
    <div className="page-title-row">
      <div>
        <Link href={`/campaigns/${id}`} className="breadcrumbs" style={{display:'inline-flex',marginBottom:12}}><ArrowLeft size={13}/>Campaign</Link>
        <h1 className="page-title">Execution history</h1>
        <p className="page-subtitle">Signed operations and status transitions for {campaign.spec.name}, across every cluster in the immutable target snapshot.</p>
      </div>
        <div style={{display:'flex',gap:8,alignItems:'center'}}>
          <LiveRefresh enabled={campaign.progress.active>0||campaign.progress.pending>0||campaign.progress.retryWaiting>0||['Scheduled','Running','Cancelling'].includes(campaign.phase)}/>
          <span className="status blue">{result.items.length?`${offset+1}–${offset+result.items.length}`:'0'} shown</span>
        </div>
    </div>
    <section className="card">
      <div className="table-wrap">
        <table><thead><tr><th>Operation</th><th>Node</th><th>Cluster</th><th>Phase</th><th>Detail</th><th>Authorized until</th></tr></thead>
          <tbody>{result.items.map(operation=><tr key={operation.id}>
            <td className="monospace">{shortID(operation.id)}</td>
            <td>{operation.request.nodeName}<div className="secondary-cell">{shortID(operation.request.nodeUid)}</div></td>
            <td>{clusterNames.get(operation.clusterId)??shortID(operation.clusterId)}</td>
            <td><Status value={operation.phase}/><div className={`status ${operation.evidence?.agentConnected?'green':'amber'}`} style={{marginTop:6}}>{operation.evidence?.agentConnected?'Agent connected':'Agent evidence stale'}</div></td>
            <td>
              {['Blocked','RecoveryRequired'].includes(operation.phase)?<div className="operation-block-reason">{operation.status?.reason??'Waiting for operator recovery evidence'}</div>:operation.status?.reason??'Waiting for agent report'}
              <div className="secondary-cell">
                {operation.status?.events.length?<>Last phase evidence {relative(operation.status.events.at(-1)?.time)} · {date(operation.status.events.at(-1)?.time)}</>:'No phase evidence reported'}
                <div>Inventory {operation.evidence?.inventoryFresh?'fresh':'stale'} · observed {relative(operation.evidence?.inventoryObservedAt)}</div>
                <div>Agent last seen {relative(operation.evidence?.agentLastSeenAt)}</div>
              </div>
              <ReceiptDetails operation={operation}/>
              <RecentTransitions operation={operation}/>
            </td>
            <td>{date(operation.expiresAt)}</td>
          </tr>)}</tbody>
        </table>
        {!result.items.length&&<div className="empty"><strong>No operation records found</strong>Operations appear here when the campaign scheduler issues work.</div>}
      </div>
      <div className="card-body" style={{display:'flex',justifyContent:'space-between',alignItems:'center'}}>
        <span className="secondary-cell">Newest operations appear first · page size {pageSize}</span>
        <div style={{display:'flex',gap:8}}>
          {hasPrevious&&<Link className="button" href={`/campaigns/${id}/operations?offset=${previousOffset}`}><ArrowLeft size={13}/>Previous</Link>}
          {hasNext&&<Link className="button" href={`/campaigns/${id}/operations?offset=${nextOffset}`}>Next<ArrowRight size={13}/></Link>}
        </div>
      </div>
    </section>
  </Shell>
}
