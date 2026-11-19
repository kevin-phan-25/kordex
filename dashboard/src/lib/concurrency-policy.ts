export type ConcurrencyLimits = {
  organization: number
  fleet: number
  site: number
  zone: number
  cluster: number
  node: number
  maxUnavailablePerSite: number
}

export type ConcurrencyLimitDraft = Record<keyof ConcurrencyLimits, string>

export const concurrencyLimitFields: Array<{
  key: keyof ConcurrencyLimits
  label: string
  organizationDescription: string
  campaignDescription: string
  fixed?: boolean
}> = [
  {key: 'organization', label: 'Organization', organizationDescription: 'Maximum active operations across this organization.', campaignDescription: 'Maximum active operations across the organization for this campaign.'},
  {key: 'fleet', label: 'Fleet', organizationDescription: 'Maximum active operations within one fleet.', campaignDescription: 'Maximum active operations within one fleet for this campaign.'},
  {key: 'site', label: 'Site', organizationDescription: 'Maximum active operations within one site.', campaignDescription: 'Maximum active operations within one site for this campaign.'},
  {key: 'zone', label: 'Zone', organizationDescription: 'Maximum active operations in one reported topology zone across the organization. Unknown zones conservatively overlap all zones.', campaignDescription: 'Maximum active operations in one reported topology zone for this campaign. Unknown zones conservatively overlap all zones.'},
  {key: 'cluster', label: 'Cluster', organizationDescription: 'One operation at a time per cluster.', campaignDescription: 'One operation at a time per cluster in this campaign.', fixed: true},
  {key: 'node', label: 'Node', organizationDescription: 'One operation at a time per node.', campaignDescription: 'One operation at a time per node in this campaign.', fixed: true},
  {key: 'maxUnavailablePerSite', label: 'Unavailable nodes per site', organizationDescription: 'Maximum not-ready or reserved worker nodes allowed at one site.', campaignDescription: 'Maximum not-ready or reserved worker nodes allowed at one site for this campaign.'},
]

export function draftFromLimits(limits: ConcurrencyLimits): ConcurrencyLimitDraft {
  return {
    organization: String(limits.organization),
    fleet: String(limits.fleet),
    site: String(limits.site),
    zone: String(limits.zone),
    cluster: String(limits.cluster),
    node: String(limits.node),
    maxUnavailablePerSite: String(limits.maxUnavailablePerSite),
  }
}

export function validateConcurrencyLimitDraft(draft: ConcurrencyLimitDraft): {limits?: ConcurrencyLimits; error?: string} {
  const limits = {} as ConcurrencyLimits
  for (const {key, label, fixed} of concurrencyLimitFields) {
    const raw = draft[key]
    if (!/^\d+$/.test(raw)) return {error: `${label} must be a whole number.`}
    const value = Number(raw)
    if (!Number.isSafeInteger(value)) return {error: `${label} must be a whole number.`}
    if (fixed && value !== 1) return {error: `${label} concurrency must remain fixed at 1.`}
    if (!fixed && (value < 1 || value > 1000)) return {error: `${label} must be between 1 and 1000.`}
    limits[key] = value
  }
  return {limits}
}
