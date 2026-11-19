import type {Campaign} from '../lib/types'
import {concurrencyLimitFields} from '../lib/concurrency-policy'

export function CampaignConcurrencyLimits({limits}:{limits:Campaign['spec']['limits']}) {
  return <div className="form-field" style={{marginTop:18}}>
    <div className="form-label">Campaign concurrency ceilings</div>
    {limits?<div className="table-wrap"><table><thead><tr><th>Scope</th><th>Limit</th></tr></thead><tbody>{concurrencyLimitFields.map(field=><tr key={field.key}><td>{field.label}</td><td className="primary-cell">{limits[field.key]}</td></tr>)}</tbody></table></div>:<div className="banner warning">This campaign record does not include explicit concurrency ceilings. The server applies its normalized campaign defaults and organization limits.</div>}
    <div className="form-note">Organization-wide limits are enforced separately; admission uses the stricter limit at each scope.</div>
  </div>
}
