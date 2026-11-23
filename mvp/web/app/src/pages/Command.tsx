// Command Center: the four severity cards (Critical, High, Medium, Low) and, under them, the same risks as a table by
// type or by computer (RiskTable). A card opens that severity's risks (pages/RiskList.tsx). The old Approvals, Incidents and Review addresses still land here (?tab=...) and show that
// full list under the cards, so old links and bookmarks keep working.
import { lazy, Suspense, useCallback, useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { CheckCircle2, CircleAlert, CircleHelp, Lightbulb, X } from 'lucide-react'
import { btn } from '../lib/ui'
import { useSession } from '../lib/session'
import { api, ApiError } from '../lib/api'
import { onDemoChange } from '../lib/demo'
import { allQuiet, RiskTable, SeverityBubbles, type Risks } from '../lib/Risks'

const TABS = [
  { key: 'approvals', label: 'Approve Many at Once', Page: lazy(() => import('./Approvals')) },
  { key: 'incidents', label: 'All Incidents', Page: lazy(() => import('./Incidents')) },
  { key: 'review', label: 'Risk Review', Page: lazy(() => import('./Review')) },
] as const

type Readiness = { ready: boolean; missing: number; headline: string; checks: { key: string; ok: boolean; state?: 'ok' | 'missing' | 'not_checked'; title: string; detail: string; fix: string }[] }

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
              {c.ok ? <CheckCircle2 size={16} className="mt-0.5 shrink-0 text-ok" aria-label="Ready" />
                : c.state === 'not_checked' ? <CircleHelp size={16} className="mt-0.5 shrink-0 text-muted" aria-label="Not checked" />
                : <CircleAlert size={16} className="mt-0.5 shrink-0 text-warn" aria-label="Not ready" />}
              <span><span className="font-medium">{c.title}.</span> <span className="text-soft">{c.detail}{c.fix ? ` ${c.fix}` : ''}</span></span>
            </li>))}
        </ul>)}
    </section>
  )
}

type Lesson = { key: string; state: string; words: string; kind_words: string; network: string; evidence: string[] }

/** What SentrAI noticed from how your team closed alerts (lessons.py), waiting for a yes or no. Hidden when none
 *  waits, and on a panel too old to answer. A yes silences nothing: those alerts still come, labelled. */
function LessonsCard() {
  const { can } = useSession()
  const [rows, setRows] = useState<Lesson[]>([])
  const [note, setNote] = useState('')
  const load = useCallback(() => api<{ lessons: Lesson[] }>('/ui/lessons')
    .then((x) => setRows(x.lessons.filter((l) => l.state === 'suggested'))).catch(() => setRows([])), [])
  useEffect(() => { void load(); const t = setInterval(() => void load(), 60000); return () => clearInterval(t) }, [load])
  const answer = async (key: string, yes: boolean) => {
    try { setNote((await api<{ message: string }>('/ui/lessons/decide', { body: { key, yes } })).message); await load() }
    catch (e) { setNote(e instanceof ApiError ? e.message : 'That did not go through.') }
  }
  if (!rows.length && !note) return null
  return (
    <section aria-label="SentrAI noticed" className="space-y-3 rounded-2xl border border-line bg-surface p-4">
      <h2 className="flex items-center gap-2 font-semibold"><Lightbulb size={18} className="text-accent" aria-hidden /> SentrAI noticed</h2>
      {note && <p role="status" className="text-sm text-soft">{note}</p>}
      <ul className="space-y-3">
        {rows.map((l) => (
          <li key={l.key} className="space-y-2 text-sm">
            <p>{l.words} Is this normal for you?</p>
            <div className="flex flex-wrap gap-2">
              <button className={btn} disabled={!can('act')} onClick={() => void answer(l.key, true)}>Yes, this is normal for us</button>
              <button className={btn} disabled={!can('act')} onClick={() => void answer(l.key, false)}>No, keep treating it as an attack</button>
            </div>
          </li>))}
      </ul>
      <p className="text-xs text-muted">A yes turns nothing off: these alerts still come, marked as seen before.</p>
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
      <LessonsCard />
      <SeverityBubbles data={risks} />
      {risks && !allQuiet(risks.watching) && (
        <p role="status" className="flex items-start gap-2 rounded-md border border-warn bg-surface p-3 text-sm">
          <CircleAlert size={16} className="mt-0.5 shrink-0 text-warn" aria-hidden /> {risks.watching?.words} Empty cards here do not mean you are safe.</p>)}
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
