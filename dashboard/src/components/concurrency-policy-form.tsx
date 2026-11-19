'use client'
import {useState, type FormEvent} from 'react'
import {Check, LoaderCircle, Pencil, ShieldAlert} from 'lucide-react'
import {
  concurrencyLimitFields,
  draftFromLimits,
  validateConcurrencyLimitDraft,
  type ConcurrencyLimitDraft,
  type ConcurrencyLimits,
} from '../lib/concurrency-policy'

type Policy = {limits: ConcurrencyLimits; revision: number}
const updateErrors = new Set([
  'The policy or active organization changed since you opened this page. Reload it and review the current limits.',
  'Only an organization administrator can update concurrency limits.',
  'The policy update was rejected. Check the values and try again.',
  'The server returned an invalid policy revision. Reload the page before making another change.',
])

export function ConcurrencyPolicyForm({initial, canEdit, organizationID}: {initial: Policy; canEdit: boolean; organizationID: string}) {
  const [policy, setPolicy] = useState(initial)
  const [draft, setDraft] = useState<ConcurrencyLimitDraft>(() => draftFromLimits(initial.limits))
  const [review, setReview] = useState<ConcurrencyLimits | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [saved, setSaved] = useState(false)

  function update(key: keyof ConcurrencyLimits, value: string) {
    setDraft(current => ({...current, [key]: value}))
    setReview(null)
    setError('')
    setSaved(false)
  }

  function prepareReview(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const result = validateConcurrencyLimitDraft(draft)
    if (!result.limits) {
      setError(result.error ?? 'The concurrency policy is invalid.')
      return
    }
    setError('')
    setReview(result.limits)
  }

  async function save() {
    if (!review || !canEdit) return
    setBusy(true)
    setError('')
    setSaved(false)
    try {
      const response = await fetch('/api/kordex/concurrency-policy', {
        method: 'PUT',
        headers: {'content-type': 'application/json', 'x-kordex-expected-organization': organizationID},
        body: JSON.stringify({revision: policy.revision, limits: review}),
        cache: 'no-store',
      })
      if (!response.ok) {
        if (response.status === 409) throw new Error('The policy or active organization changed since you opened this page. Reload it and review the current limits.')
        throw new Error(response.status === 403 ? 'Only an organization administrator can update concurrency limits.' : 'The policy update was rejected. Check the values and try again.')
      }
      const body = await response.json().catch(() => undefined) as Partial<Policy> | undefined
      if (!body || !body.limits || typeof body.limits !== 'object') {
        throw new Error('The server returned an invalid policy revision. Reload the page before making another change.')
      }
      const updated = body as Policy
      const valid = validateConcurrencyLimitDraft(draftFromLimits(updated.limits))
      if (!valid.limits || !Number.isSafeInteger(updated.revision) || updated.revision <= policy.revision) throw new Error('The server returned an invalid policy revision. Reload the page before making another change.')
      setPolicy(updated)
      setDraft(draftFromLimits(updated.limits))
      setReview(null)
      setSaved(true)
    } catch (cause) {
      setError(cause instanceof Error && updateErrors.has(cause.message) ? cause.message : 'The policy update could not be confirmed. Reload before retrying.')
    } finally {
      setBusy(false)
    }
  }

  const shownLimits = review ?? policy.limits
  return <>
    <form className="card" onSubmit={prepareReview}>
      <div className="card-head">
        <div><h2 className="card-title">Organization concurrency limits</h2><div className="card-description">Revision {policy.revision} · changes are audited and take effect on the next scheduler cycle.</div></div>
        <span className="status blue">Revision {policy.revision}</span>
      </div>
      <div className="card-body">
        <div className="banner info"><ShieldAlert size={14}/>These limits control new campaign admissions. Lowering a limit does not release existing reservations; raising it never bypasses fresh inventory, campaign approvals, or local operator safety checks.</div>
        <div className="form-grid">
          {concurrencyLimitFields.map(field => <div className="form-field" key={field.key}>
            <label className="form-label" htmlFor={`limit-${field.key}`}>{field.label}</label>
            <input
              id={`limit-${field.key}`}
              aria-describedby={`limit-note-${field.key}`}
              className="text-input"
              type="number"
              inputMode="numeric"
              min={1}
              max={field.fixed ? 1 : 1000}
              step={1}
              required
              disabled={!canEdit || busy || Boolean(review) || field.fixed}
              value={draft[field.key]}
              onChange={event => update(field.key, event.target.value)}
            />
            <div id={`limit-note-${field.key}`} className="form-note">{field.organizationDescription}{field.fixed ? ' This invariant is enforced by the API.' : ' Allowed range: 1–1000.'}</div>
          </div>)}
        </div>
        {!canEdit && <div className="banner warning">This policy is read-only for your role. Ask an organization administrator to change it.</div>}
        {error && <div className="banner error" role="alert">{error}{error.startsWith('The policy or active organization changed') && <button className="button small" type="button" onClick={() => window.location.reload()}>Reload policy</button>}</div>}
        {saved && <div className="banner success" role="status"><Check size={14}/>Concurrency limits saved as revision {policy.revision}.</div>}
        {canEdit && !review && <button className="button primary" type="submit" disabled={busy}><Pencil size={13}/>Review policy change</button>}
      </div>
    </form>
    {review && <section className="card" style={{marginTop:16}} aria-labelledby="review-policy-title">
      <div className="card-head"><div><h2 id="review-policy-title" className="card-title">Review concurrency policy update</h2><div className="card-description">The API will compare revision {policy.revision} before saving.</div></div><span className="status amber">Confirmation required</span></div>
      <div className="card-body">
        <div className="table-wrap"><table><thead><tr><th>Limit</th><th>Current</th><th>Proposed</th></tr></thead><tbody>{concurrencyLimitFields.map(field=><tr key={field.key}><td>{field.label}</td><td>{policy.limits[field.key]}</td><td className="primary-cell">{shownLimits[field.key]}</td></tr>)}</tbody></table></div>
        <p className="form-note">Confirming records an organization audit event and schedules another admission pass. Existing operations keep their reservations.</p>
        {error && <div className="banner error" role="alert">{error}</div>}
        <div style={{display:'flex',gap:8}}>
          <button className="button" type="button" disabled={busy} onClick={() => setReview(null)}>Edit limits</button>
          <button className="button primary" type="button" disabled={busy} onClick={save}>{busy?<LoaderCircle size={13}/>:<Check size={13}/>}Confirm and save</button>
        </div>
      </div>
    </section>}
  </>
}
