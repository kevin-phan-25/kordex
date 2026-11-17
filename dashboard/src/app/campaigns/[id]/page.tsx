import Link from 'next/link'
import {ArrowLeft,Clock3,FileCheck2,Layers,Shield} from 'lucide-react'
import {ApprovalActions} from '../../../components/approvals'
import {CampaignControls} from '../../../components/actions'
import {LiveRefresh} from '../../../components/live-refresh'
import {Shell} from '../../../components/shell'
import {Status} from '../../../components/status'
import {api} from '../../../lib/api'
import {publicBrand,requireSession} from '../../../lib/auth'
import type {Approval,Campaign,Page,Target} from '../../../lib/types'
import {date,shortID} from '../../../lib/format'

export const dynamic='force-dynamic'

export default async function CampaignDetail({params}:{params:Promise<{id:string}>}) {
  const session=await requireSession()
  const {id}=await params
  const [campaign,targets,approvals]=await Promise.all([
    api<Campaign>(session,`/campaigns/${id}`),
    api<Page<Target>>(session,`/campaigns/${id}/targets?limit=200`),
    api<{items:Approval[];limit:number;offset:number}>(session,`/campaigns/${id}/approvals?limit=100`),
  ])
  const refreshing=campaign.progress.active>0||campaign.progress.pending>0||campaign.progress.retryWaiting>0||['Scheduled','Running','Cancelling'].includes(campaign.phase)

  return <Shell brand={publicBrand()} identity={{name:session.name,email:session.email,role:session.role,subject:session.sub}} organization={session.organizationID} organizationName={session.organizationName}>
    <div className="eyebrow">OPERATIONS / CAMPAIGNS / DETAIL</div>
    <div className="page-title-row">
      <div>
        <Link href="/campaigns" className="breadcrumbs" style={{display:'inline-flex',marginBottom:12}}><ArrowLeft size={13}/>Campaigns</Link>
        <div className="detail-heading"><h1 className="page-title">{campaign.spec.name}</h1><Status value={campaign.phase} className="lg"/></div>
        <div className="page-subtitle">{campaign.spec.action} · {campaign.reason} · updated {date(campaign.updatedAt)}</div>
        <div className="detail-id">Campaign {campaign.id} · Plan {campaign.planGeneration} · Stage approval epoch {campaign.approvalEpoch}</div>
      </div>
      <div style={{display:'grid',gap:9,justifyItems:'end'}}>
        <LiveRefresh enabled={refreshing}/>
        <CampaignControls campaign={campaign} role={session.role}/>
        {campaign.phase==='Draft'&&['operator','administrator'].includes(session.role)&&<Link className="button primary" href={`/campaigns/${id}/start`}>Resolve targets and start</Link>}
        {campaign.phase==='AwaitingApproval'&&['approver','administrator'].includes(session.role)&&<ApprovalActions id={campaign.id} revision={campaign.revision}/>}
      </div>
    </div>

    <div className="metrics-grid">
      {[
        ['Target nodes',campaign.progress.total,`${campaign.progress.pending} pending · ${campaign.progress.retryWaiting} retry waiting`],
        ['Succeeded',campaign.progress.succeeded,'Verified operation status'],
        ['Active',campaign.progress.active,'Operations currently in progress'],
        ['Failed attempts',campaign.progress.failedAttempts,`${campaign.progress.consecutiveFailures} consecutive failures`],
      ].map(([label,value,foot])=><div className="card metric" key={label}>
        <div className="metric-top">{label}</div><div className="metric-value">{Number(value).toLocaleString()}</div><div className="metric-foot">{foot}</div>
      </div>)}
    </div>

    <div className="grid-two">
      <section className="card">
        <div className="card-head"><div><h2 className="card-title">Target snapshot</h2><div className="card-description">Immutable nodes selected when the campaign started</div></div><span className="status blue">{targets.items.length} shown</span></div>
        <div className="card-body">
          <div className="detail-stats">
            <div><div className="detail-stat-label">Selector</div><div className="detail-stat-value monospace">{campaign.spec.selection.nodeSelector||'All eligible workers'}</div></div>
            <div><div className="detail-stat-label">Approval</div><div className="detail-stat-value">{campaign.spec.approvalMode}</div></div>
            <div><div className="detail-stat-label">Action</div><div className="detail-stat-value">{campaign.spec.action}</div></div>
          </div>
          <div className="table-wrap" style={{marginTop:18}}>
            <table><thead><tr><th>Node</th><th>Cluster</th><th>Executor</th><th>Stage</th><th>Attempts</th><th>State</th></tr></thead><tbody>
              {targets.items.map(target=><tr key={target.id}>
                <td className="primary-cell">{target.snapshot.node.name}<div className="secondary-cell">{shortID(target.snapshot.node.uid)}</div></td>
                <td>{shortID(target.snapshot.clusterId)}</td><td>{target.snapshot.action??campaign.spec.action}</td><td>{['Canary','Small batch','Expanded','Remaining'][target.snapshot.stage]}</td>
                <td>{target.attempts} <span className="secondary-cell">({target.failures} failed)</span></td>
                <td><Status value={target.state}/><div className="secondary-cell">{target.reason}</div></td>
              </tr>)}
            </tbody></table>
            {targets.items.length===0&&<div className="empty"><strong>Draft has no target snapshot</strong>Start the campaign to resolve and freeze eligible nodes.</div>}
          </div>
        </div>
      </section>
      <section className="card">
        <div className="card-head"><div><h2 className="card-title">Maintenance window</h2><div className="card-description">Explicit window and time zone</div></div><Clock3 size={15} color="#718198"/></div>
        <div className="card-body">
          {campaign.spec.windows.map((window,index)=><div className="rollout-item" key={index}>
            <span className="rollout-step">{index+1}</span><span><span className="rollout-name" style={{display:'block'}}>{date(window.start)}</span><span className="rollout-meta">Until {date(window.end)} · {window.timeZone}</span></span>
            <Status value={new Date(window.end)>new Date()?'Scheduled':'Expired'}/>
          </div>)}
          <div className="banner info" style={{marginTop:15}}><Shield size={14}/>The cluster operator independently checks health, workload disruption budgets, node identity and local policy before any disruptive step.</div>
          <Link className="table-link" href={`/campaigns/${id}/operations`}>View signed operation history →</Link>
          <div className="detail-id">Snapshot digest: {campaign.snapshotDigest||'Not resolved yet'}</div>
        </div>
      </section>
    </div>

    <div className="grid-two">
      <section className="card">
        <div className="card-head"><div><h2 className="card-title">Target progress by stage</h2><div className="card-description">Stages advance only after prior targets reach terminal state and safety thresholds pass</div></div><Layers size={15} color="#718198"/></div>
        <div className="card-body">
          {['Canary','Small batch','Expanded','Remaining'].map((name,index)=>{
            const group=targets.items.filter(target=>target.snapshot.stage===index)
            const done=group.filter(target=>['Succeeded','Failed','Cancelled'].includes(target.state)).length
            const active=group.filter(target=>target.state==='Active').length
            return <div className="rollout-item" key={name}>
              <span className={`rollout-step ${group.length&&done===group.length?'done':''}`}>{index+1}</span>
              <span><span className="rollout-name" style={{display:'block'}}>{name}</span><span className="rollout-meta">{done}/{group.length} terminal · {active} active</span></span>
              <div className="phase-track">{group.slice(0,14).map(target=><i key={target.id} className={`phase-segment ${target.state==='Succeeded'?'complete':target.state==='Active'?'current':''}`}/>)}</div>
            </div>
          })}
        </div>
      </section>
      <section className="card">
        <div className="card-head"><div><h2 className="card-title">Approvals</h2><div className="card-description">Decisions bound to this plan revision and snapshot digest</div></div><FileCheck2 size={15} color="#718198"/></div>
        <div className="card-body">
          {approvals.items.map(approval=><div className="event" key={approval.id}><span className="event-marker"/><div>
            <div className="event-title">{approval.decision} · {['Canary','Small batch','Expanded','Remaining'][approval.stage]??'Stage'} <Status value={approval.decision}/></div>
            <div className="event-meta">{approval.actor} · {date(approval.createdAt)}</div>
          </div></div>)}
          {approvals.items.length===0&&<div className="empty"><strong>No approvals recorded</strong>Awaiting independent review or approval is disabled.</div>}
        </div>
      </section>
    </div>
  </Shell>
}
