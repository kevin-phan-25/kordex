import {SlidersHorizontal} from 'lucide-react'
import {ConcurrencyPolicyForm} from '../../../components/concurrency-policy-form'
import {Shell} from '../../../components/shell'
import {api} from '../../../lib/api'
import {publicBrand, requireSession} from '../../../lib/auth'
import type {ConcurrencyLimits} from '../../../lib/concurrency-policy'

export const metadata = {title: 'Concurrency policy'}

type ConcurrencyPolicy = {limits: ConcurrencyLimits; revision: number}

export default async function ConcurrencyPolicyPage() {
  const session = await requireSession()
  const policy = await api<ConcurrencyPolicy>(session, '/concurrency-policy')
  const canEdit = session.role === 'administrator'

  return <Shell brand={publicBrand()} identity={{name:session.name,email:session.email,role:session.role,subject:session.sub}} organization={session.organizationID} organizationName={session.organizationName}>
    <div className="eyebrow">GOVERNANCE / CONCURRENCY POLICY</div>
    <div className="page-title-row">
      <div>
        <h1 className="page-title">Organization concurrency policy</h1>
        <p className="page-subtitle">Set the upper bounds for operations admitted by the fleet scheduler.</p>
      </div>
      <span className="status blue"><SlidersHorizontal size={12}/>Organization scoped</span>
    </div>
    {!canEdit && <div className="banner info">You can inspect the current organization limits. Only an organization administrator can change them.</div>}
    <ConcurrencyPolicyForm initial={policy} canEdit={canEdit} organizationID={session.organizationID}/>
  </Shell>
}
