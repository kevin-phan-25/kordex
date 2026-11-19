import {Shell} from '../../components/shell'
import {api} from '../../lib/api'
import {publicBrand, requireSession} from '../../lib/auth'

type Driver = {
  name: string; version: string; kind: string; mechanism: string; offline: string
  compatibility: Array<{osId: string; versions: string[] | null; architectures: string[]}> | null
  operations: Record<string, string>
}
type PermissionRule = {
  scope: string; apiGroup: string; resources: string[]; verbs: string[]
  resourceNames: string[]; nonResourceURLs: string[]
}
type PermissionProfile = {
  id: string; description: string; rules: PermissionRule[]; providerActions: string[]
}
type KubernetesDistribution = {
  id: string; displayName: string; qualification: string; identification: string
  qualifiedKubernetesVersions: string[]; qualifiedNodeOperatingSystems: string[]
  qualifiedArchitectures: string[]; requiredPermissionProfiles: string[]
  optionalPermissionProfiles: string[]; requiredCRDs: string[]
  networkRequirements: string[]; optionalNetworkRequirements: string[]
  operations: Record<string, string>; automatedTestCoverage: string[]
  knownLimitations: string[]
}

export const dynamic = 'force-dynamic'
export const metadata = {title: 'Compatibility'}

function listOrNone(values: string[]) {
  return values.length ? values.join(', ') : 'None qualified'
}

export default async function CompatibilityPage() {
  const session = await requireSession()
  const [drivers, compatibility] = await Promise.all([
    api<{items: Driver[]}>(session, '/lifecycle-drivers'),
    api<{items: KubernetesDistribution[]; permissionProfiles: PermissionProfile[]}>(session, '/kubernetes-compatibility'),
  ])

  return <Shell brand={publicBrand()} identity={{name: session.name, email: session.email, role: session.role, subject: session.sub}}
    organization={session.organizationID} organizationName={session.organizationName}>
    <h1 className="page-title">Compatibility registry</h1>
    <p className="page-subtitle">A listed integration is not qualified by its presence in this registry. Empty version, operating system, and architecture fields mean no combination has passed Kordex qualification.</p>

    <section className="card">
      <div className="card-head"><div><h2 className="card-title">Kubernetes distributions</h2><p className="card-description">Unknown and conflicting distribution evidence remains unqualified. Provider integrations are separate from Kubernetes API compatibility.</p></div></div>
      <div className="table-wrap"><table>
        <thead><tr><th>Distribution</th><th>Qualification</th><th>Qualified versions</th><th>Node OS</th><th>Architecture</th><th>Operations</th><th>Identification and limits</th></tr></thead>
        <tbody>{compatibility.items.map(item => <tr key={item.id}>
          <td className="primary-cell">{item.displayName}<div className="secondary-cell">{item.id}</div></td>
          <td><span className="status gray">{item.qualification}</span></td>
          <td>{listOrNone(item.qualifiedKubernetesVersions)}</td>
          <td>{listOrNone(item.qualifiedNodeOperatingSystems)}</td>
          <td>{listOrNone(item.qualifiedArchitectures)}</td>
          <td>{Object.entries(item.operations).map(([operation, state]) => <div key={operation}>{operation}: {state}</div>)}</td>
          <td><div>{item.identification}</div><ul>{item.knownLimitations.map(limit => <li key={limit}>{limit}</li>)}</ul>{item.automatedTestCoverage.length > 0 && <div className="secondary-cell">Test coverage: {item.automatedTestCoverage.join(' ')}</div>}</td>
        </tr>)}</tbody>
      </table></div>
    </section>

    <section className="card" style={{marginTop: 20}}>
      <div className="card-head"><div><h2 className="card-title">Kubernetes requirements</h2><p className="card-description">RBAC profiles describe the checked-in agent and operator manifests. Optional execution profiles are separate from default permissions.</p></div></div>
      <div className="grid-two card-body">{compatibility.permissionProfiles.map(profile => <article className="event" key={profile.id}>
        <span className="event-marker"/><div><div className="event-title">{profile.id}</div><div className="event-meta">{profile.description}</div>
          {profile.providerActions.length > 0 && <div className="event-meta">Provider API actions: {profile.providerActions.join(', ')}</div>}
          <ul>{profile.rules.map((rule, index) => <li key={`${rule.scope}-${rule.apiGroup}-${index}`}>
            {rule.scope} · {rule.apiGroup || 'core'} · {rule.resources.join(', ')} · {rule.verbs.join(', ')}
            {rule.resourceNames.length > 0 && ` · names: ${rule.resourceNames.join(', ')}`}
            {rule.nonResourceURLs.length > 0 && ` · URLs: ${rule.nonResourceURLs.join(', ')}`}
          </li>)}</ul>
        </div>
      </article>)}</div>
      <div className="card-body"><h3>Common requirements</h3>
        <ul>{compatibility.items[0]?.requiredCRDs.map(crd => <li key={crd}>{crd}</li>)}</ul>
        <ul>{compatibility.items[0]?.networkRequirements.map(requirement => <li key={requirement}>{requirement}</li>)}</ul>
      </div>
    </section>

    <section className="card" style={{marginTop: 20}}>
      <div className="card-head"><div><h2 className="card-title">OS and provider drivers</h2><p className="card-description">Driver metadata describes implementation contracts. Registration does not grant execution or qualification.</p></div></div>
      <div className="table-wrap"><table>
        <thead><tr><th>Driver</th><th>Model</th><th>Compatibility profiles</th><th>Operations</th><th>Offline</th><th>Mechanism</th></tr></thead>
        <tbody>{drivers.items.map(driver => <tr key={driver.name}>
          <td className="primary-cell">{driver.name}<div className="secondary-cell">Adapter metadata v{driver.version}</div></td>
          <td>{driver.kind}</td>
          <td>{driver.compatibility?.length ? driver.compatibility.map(profile => <div key={profile.osId}>
            {profile.osId}: {profile.versions?.length ? profile.versions.join(', ') : 'no reviewed version profile'}
            <div className="secondary-cell">{profile.architectures.join(', ')}</div>
          </div>) : 'Native discovery and version validation required'}</td>
          <td>{Object.entries(driver.operations).map(([operation, status]) => <div key={operation}>{operation}: {status}</div>)}</td>
          <td>{driver.offline}</td><td>{driver.mechanism}</td>
        </tr>)}</tbody>
      </table></div>
    </section>
  </Shell>
}
