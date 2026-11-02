// Command Center: only the four severity cards (Critical, High, Medium, Low). A card opens that severity's risks
// (pages/RiskList.tsx). The old Approvals, Incidents and Review addresses still land here (?tab=...) and show that
// full list under the cards, so old links and bookmarks keep working.
import { lazy, Suspense, useCallback, useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { X } from 'lucide-react'
import { api, ApiError } from '../lib/api'
import { SeverityBubbles, type Risks } from '../lib/Risks'

const TABS = [
  { key: 'approvals', label: 'Approve Many at Once', Page: lazy(() => import('./Approvals')) },
  { key: 'incidents', label: 'All Incidents', Page: lazy(() => import('./Incidents')) },
  { key: 'review', label: 'Risk Review', Page: lazy(() => import('./Review')) },
] as const

export default function Command() {
  const [risks, setRisks] = useState<Risks | null>(null)
  const [error, setError] = useState('')
  const [params, setParams] = useSearchParams()
  const tab = TABS.find((t) => t.key === params.get('tab'))
  const load = useCallback(async () => {
    try { setRisks(await api<Risks>('/ui/risks')); setError('') }
    catch (e) { setError(e instanceof ApiError ? e.message : 'Could not reach SentrAI.') }
  }, [])
  useEffect(() => { void load(); const t = setInterval(() => void load(), 10000); return () => clearInterval(t) }, [load])

  return (
    <section className="space-y-8">
      <h1>Command Center</h1>
      {error && <p role="alert" className="rounded-md border border-line bg-surface p-3 text-bad">{error}</p>}
      <SeverityBubbles data={risks} />
      {!!risks?.handled_count && (
        <p className="text-sm text-soft">SentrAI already blocked {risks.handled_count} risk{risks.handled_count === 1 ? '' : 's'} on its own, so {risks.handled_count === 1 ? 'it is' : 'they are'} not counted above. Each list shows them under "Already handled", where you can undo one if it was a false alarm.</p>)}
      {tab && (
        <div role="region" aria-label={tab.label} className="min-w-0 space-y-3 rounded-2xl border border-line bg-surface p-4">
          <div className="flex items-start justify-between gap-2">
            <h2 className="font-semibold">{tab.label}</h2>
            <button className="text-muted hover:text-ink" aria-label="Close this list" onClick={() => setParams({}, { replace: true })}><X size={16} aria-hidden /></button>
          </div>
          <Suspense fallback={<p className="text-muted" role="status">Loading…</p>}><tab.Page embedded /></Suspense>
        </div>)}
    </section>
  )
}
