// Command Center: the four severity cards (Critical, High, Medium, Low) and, under them, the same risks as a table by
// type or by computer (RiskTable). A card opens that severity's risks (pages/RiskList.tsx). The old Approvals, Incidents and Review addresses still land here (?tab=...) and show that
// full list under the cards, so old links and bookmarks keep working.
import { lazy, Suspense, useCallback, useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { CheckCircle2, CircleAlert, X } from 'lucide-react'
import { api, ApiError } from '../lib/api'
import { onDemoChange } from '../lib/demo'
import { RiskTable, SeverityBubbles, type Risks } from '../lib/Risks'

const TABS = [
  { key: 'approvals', label: 'Approve Many at Once', Page: lazy(() => import('./Approvals')) },
  { key: 'incidents', label: 'All Incidents', Page: lazy(() => import('./Incidents')) },
  { key: 'review', label: 'Risk Review', Page: lazy(() => import('./Review')) },
] as const

type Readiness = { ready: boolean; missing: number; headline: string; checks: { key: string; ok: boolean; title: string; detail: string; fix: string }[] }

/** What is still missing before SentrAI fully protects this business (ui_readiness.py). Hidden once all is ready,
 *  and on a panel too old to answer, so it never gets in the way of the risks. */
function ReadinessCard() {
  const [r, setR] = useState<Readiness | null>(null)
  const [open, setOpen] = useState(true)
  useEffect(() => {
    let live = true
    const load = () => api<Readiness>('/ui/readiness').then((x) => { if (live) setR(x) }).catch(() => { if (live) setR(null) })
    void load(); const t = setInterval(load, 60000); return () => { live = false; clearInterval(t) }
  }, [])
  if (!r || r.ready) return null
  return (
    <section aria-label="Protection readiness" className="rounded-2xl border border-warn bg-surface p-4">
      <button className="flex w-full items-start justify-between gap-3 text-left" aria-expanded={open} onClick={() => setOpen(!open)}>
        <span className="flex items-center gap-2 font-semibold"><CircleAlert size={18} className="text-warn" aria-hidden /> {r.headline}</span>
        <span className="text-sm text-soft">{open ? 'Hide' : 'Show'}</span>
      </button>
      {open && (
        <ul className="mt-3 space-y-2">
          {r.checks.map((c) => (
            <li key={c.key} className="flex items-start gap-2 text-sm">
              {c.ok ? <CheckCircle2 size={16} className="mt-0.5 shrink-0 text-ok" aria-label="Ready" /> : <CircleAlert size={16} className="mt-0.5 shrink-0 text-warn" aria-label="Not ready" />}
              <span><span className="font-medium">{c.title}.</span> <span className="text-soft">{c.detail}{c.fix ? ` ${c.fix}` : ''}</span></span>
            </li>))}
        </ul>)}
    </section>
  )
}

export default function Command() {
  const [risks, setRisks] = useState<Risks | null>(null)
  const [error, setError] = useState('')
  const [params, setParams] = useSearchParams()
  const tab = TABS.find((t) => t.key === params.get('tab'))
  const load = useCallback(async () => {
    try { setRisks(await api<Risks>('/ui/risks')); setError('') }
    catch (e) { setError(e instanceof ApiError ? e.message : 'Could not reach SentrAI.') }
  }, [])
  useEffect(() => { void load(); const t = setInterval(() => void load(), 10000); const off = onDemoChange(() => void load()); return () => { clearInterval(t); off() } }, [load])

  return (
    <section className="space-y-8">
      <h1>Command Center</h1>
      {error && <p role="alert" className="rounded-md border border-line bg-surface p-3 text-bad">{error}</p>}
      <ReadinessCard />
      <SeverityBubbles data={risks} />
      {!!risks?.handled_count && (
        <p className="text-sm text-soft">SentrAI already blocked {risks.handled_count} risk{risks.handled_count === 1 ? '' : 's'} on its own, so {risks.handled_count === 1 ? 'it is' : 'they are'} not counted above. Each list shows them under "Already handled", where you can undo one if it was a false alarm.</p>)}
      <RiskTable data={risks} />
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
