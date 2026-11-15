import {redirect} from 'next/navigation'
import {CampaignForm} from '../../../components/campaign-form'
import {Shell} from '../../../components/shell'
import {publicBrand,requireSession} from '../../../lib/auth'
import {api} from '../../../lib/api'
import type {Cluster,Page} from '../../../lib/types'
export const metadata={title:'Plan maintenance'}
export default async function NewCampaign(){const s=await requireSession();if(!['administrator','operator'].includes(s.role))redirect('/campaigns');const clusters=await api<Page<Cluster>>(s,'/clusters?limit=500');return <Shell brand={publicBrand()} identity={{name:s.name,email:s.email,role:s.role,subject:s.sub}} organization={s.organizationID} organizationName={s.organizationName}><div className="eyebrow">OPERATIONS / CAMPAIGNS / NEW</div><div className="page-title-row"><div><h1 className="page-title">Plan a maintenance campaign</h1><p className="page-subtitle">Select clusters, local policies and a bounded schedule. Targets are resolved and snapshotted on start.</p></div></div>{!clusters.items.length?<div className="banner warning">Register a cluster and install its outbound agent before creating a campaign.</div>:<CampaignForm clusters={clusters.items}/>}</Shell>}
