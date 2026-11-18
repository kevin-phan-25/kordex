import {Shell} from '../../components/shell'
import {api} from '../../lib/api'
import {publicBrand, requireSession} from '../../lib/auth'

type Driver = {
  name: string; version: string; kind: string; mechanism: string; offline: string
  compatibility: Array<{osId: string; versions: string[] | null; architectures: string[]}> | null
  operations: Record<string, string>
}
export const dynamic = 'force-dynamic'
export const metadata = {title: 'Driver compatibility'}
export default async function CompatibilityPage() {
  const session = await requireSession()
  const catalog = await api<{items: Driver[]}>(session, '/lifecycle-drivers')
  return <Shell brand={publicBrand()} identity={{name: session.name, email: session.email, role: session.role, subject: session.sub}}
    organization={session.organizationID} organizationName={session.organizationName}>
    <h1 className="page-title">Driver compatibility</h1>
    <p className="page-subtitle">No upgrade executor is lab-qualified or production-qualified. Unverified entries require qualification; unsupported entries require implementation. Catalog registration never enables execution.</p>
    <section className="card"><div className="table-wrap"><table>
      <thead><tr><th>Driver</th><th>Model</th><th>Compatibility profiles</th><th>Operations</th><th>Offline</th><th>Mechanism</th></tr></thead>
      <tbody>{catalog.items.map(driver => <tr key={driver.name}>
        <td className="primary-cell">{driver.name}<div className="secondary-cell">Adapter metadata v{driver.version}</div></td>
        <td>{driver.kind}</td>
        <td>{driver.compatibility?.length ? driver.compatibility.map(profile => <div key={profile.osId}>
          {profile.osId}: {profile.versions?.length ? profile.versions.join(', ') : 'no reviewed version profile'}
          <div className="secondary-cell">{profile.architectures.join(', ')}</div>
        </div>) : 'Native discovery and version validation required'}</td>
        <td>{Object.entries(driver.operations).map(([operation, status]) => <div key={operation}>{operation}: {status}</div>)}</td>
        <td>{driver.offline}</td><td>{driver.mechanism}</td>
      </tr>)}</tbody>
    </table></div></section>
  </Shell>
}
