'use client'

import {useState} from 'react'
import {Download} from 'lucide-react'
import {exportAuditSnapshot} from '../lib/audit-export'

export function AuditExport({organizationId}: {organizationId: string}) {
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')

  async function download() {
    setBusy(true)
    setMessage('Requesting a signed audit snapshot…')
    try {
      const bundle = await exportAuditSnapshot(organizationId)
      const blob = new Blob([`${JSON.stringify(bundle, null, 2)}\n`], {type: 'application/json'})
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = `kordex-audit-${organizationId}-through-${bundle.throughEventId}.json`
      document.body.appendChild(link)
      link.click()
      link.remove()
      setTimeout(() => URL.revokeObjectURL(url), 1000)
      setMessage(`Downloaded ${bundle.recordCount} events through ${bundle.throughEventId}. Bundle digest checked; signature needs verification with key ${bundle.signingKeyId}.`)
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'audit_export_failed')
    } finally {
      setBusy(false)
    }
  }

  return <div className="audit-export"><button className="button" type="button" onClick={download} disabled={busy}>
    <Download size={14}/>{busy ? 'Exporting…' : 'Export audit snapshot'}
  </button><span className="secondary-cell" role="status" aria-live="polite">{message}</span></div>
}
