import assert from 'node:assert/strict'
import {test} from 'node:test'
import {concurrencyLimitFields,draftFromLimits, validateConcurrencyLimitDraft} from '../src/lib/concurrency-policy.ts'

const defaults = {organization:1,fleet:1,site:1,zone:1,cluster:1,node:1,maxUnavailablePerSite:1}

test('accepts valid integer concurrency limits and preserves cluster/node safety caps', () => {
  const result = validateConcurrencyLimitDraft(draftFromLimits({...defaults,organization:20,fleet:4,site:2,zone:3,maxUnavailablePerSite:3}))
  assert.deepEqual(result.limits, {...defaults,organization:20,fleet:4,site:2,zone:3,maxUnavailablePerSite:3})
})

test('distinguishes organization-wide ceilings from campaign-local ceilings', () => {
  const zone = concurrencyLimitFields.find(field=>field.key==='zone')
  assert.match(zone.organizationDescription,/across the organization/)
  assert.match(zone.campaignDescription,/for this campaign/)
  assert.doesNotMatch(zone.campaignDescription,/across the organization/)
})

test('rejects malformed, out-of-range, and mutable per-cluster/per-node limits', () => {
  for (const value of ['', '0', '1001', '1.5', '1e2', '-1', 'NaN']) {
    const result = validateConcurrencyLimitDraft({...draftFromLimits(defaults),organization:value})
    assert.equal(result.limits, undefined, `accepted organization=${value}`)
    assert.match(result.error, /Organization/)
  }
  for (const key of ['cluster','node']) {
    const result = validateConcurrencyLimitDraft({...draftFromLimits(defaults),[key]:'2'})
    assert.equal(result.limits, undefined, `accepted ${key}=2`)
    assert.match(result.error, /must remain fixed at 1/)
  }
  for (const value of ['0', '1001']) {
    const result = validateConcurrencyLimitDraft({...draftFromLimits(defaults),zone:value})
    assert.equal(result.limits, undefined, `accepted zone=${value}`)
    assert.match(result.error, /Zone/)
  }
})
