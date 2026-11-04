// Risk bubbles (GET /ui/risks): what needs a person, grouped Critical / High / Medium / Low. The Command center
// shows one bubble per severity; the severity page shows one bubble per risk, and opening one explains it in plain
// words and suggests a fix with its quick actions.
import { useEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { useGo, vtName, VLink } from './motion'
import { Bell, ChevronRight, Clock, MessageSquare, ShieldAlert, ShieldCheck, TriangleAlert, X, type LucideIcon } from 'lucide-react'
import { api, ApiError } from './api'
import { btn, btnPrimary } from './ui'
import { useSession } from './session'
import { ask } from './notice'
import { DEMO, isLiveRisk } from './demo'
import { DEMO_FIXES } from './demoFixes'

export type Level = 'critical' | 'high' | 'medium' | 'low'
export type LevelCount = { severity: Level; count: number; bubbles: number; overdue: number; oldest: string }
export type RiskAction = { verb: string; label: string; hint: string }
export type Risk = {
  id: string; ids: string[]; wave: string; incident: string; title: string; category: string; severity: Level
  host: string; source: string; owner: string; open_for: string; hours: number; overdue: boolean; status: string
  needs: string[]; what_happened: string; meaning: string; fix: string; steps: string[]; unsure: boolean
  actions: RiskAction[]; inc: { id: string; status: string; category: string; acked: boolean; actions: { status?: string }[] }
}
// handled: what SentrAI already blocked on its own at that level (off the active list, still undoable).
// groups: the same risks counted by type and by computer (the table under the cards); done = % SentrAI blocked.
export type RiskGroup = { name: string; open: number; overdue: number; handled: number; done: number; worst: Level | '' }
export type Risks = { levels: LevelCount[]; headline: string; protection_on: boolean; rows?: Risk[]; handled?: Risk[]; handled_count?: number
  groups?: { type: RiskGroup[]; machine: RiskGroup[] } }

export const LEVEL_TEXT: Record<Level, { name: string; color: string; tint: string; blurb: string }> = {
  critical: { name: 'Critical', color: 'var(--critical)', tint: 'color-mix(in oklab, var(--critical) 12%, transparent)', blurb: 'act now' },
  high: { name: 'High', color: 'var(--red)', tint: 'color-mix(in oklab, var(--red) 11%, transparent)', blurb: 'today' },
  medium: { name: 'Medium', color: 'var(--amber)', tint: 'color-mix(in oklab, var(--amber) 11%, transparent)', blurb: 'soon' },
  low: { name: 'Low', color: 'var(--green)', tint: 'color-mix(in oklab, var(--green) 10%, transparent)', blurb: 'for the record' },
}

// The cards' own colours, from Erick's reference picture (the rest of the console keeps the theme colours).
// Per theme in index.css (--card-*), taken from the reference console.
const CARD_COLOR: Record<Level, string> = { critical: 'var(--card-critical)', high: 'var(--card-high)', medium: 'var(--card-medium)', low: 'var(--card-low)' }

const LEVEL_ICON: Record<Level, LucideIcon> = { critical: ShieldAlert, high: TriangleAlert, medium: Bell, low: ShieldCheck }

// One row of four on a wide page, two by two on a medium one, one per row on a phone (by the page's own width).
// In the row of four (and on a phone) the icon sits in the top corner, so the words have the whole card.
const SEV_GRID = 'grid gap-6 @2xl:grid-cols-2 @5xl:grid-cols-4'

/** The Command center's grouped buttons: a glowing card per severity (Critical, High, Medium, Low) with its count. */
export function SeverityBubbles({ data }: { data: Risks | null }) {
  if (!data) return (
    <div className="@container"><ul role="status" aria-label="Loading" className={SEV_GRID}>
      {[0, 1, 2, 3].map((i) => <li key={i} className="skeleton h-[10.75rem] rounded-[1.25rem]" />)}
    </ul></div>)
  return (
    <div className="@container"><ul className={SEV_GRID}>
      {data.levels.map((l) => {
        const t = LEVEL_TEXT[l.severity]
        const Icon = LEVEL_ICON[l.severity]
        return (
          <li key={l.severity}>
            <VLink to={`/risks/${l.severity}`} aria-label={`${t.name}: ${l.count} risk${l.count === 1 ? '' : 's'}. Open the list.`}
              className={'sev-card flex h-full min-h-[10.75rem] items-center gap-8 px-5 py-6 @2xl:gap-10 @2xl:px-9 @5xl:px-7' + (l.count ? '' : ' sev-zero')} style={{ '--c': CARD_COLOR[l.severity], viewTransitionName: `sev-${l.severity}` } as React.CSSProperties}>
              <Icon className="sev-icon absolute right-5 top-5 size-10 shrink-0 @2xl:static @2xl:size-[4.5rem] @5xl:absolute @5xl:right-6 @5xl:top-6 @5xl:size-12" size={72} strokeWidth={1.6} aria-hidden />
              <span className="min-w-0 space-y-1">
                <span className="sev-name block pr-12 text-[1.375rem] font-bold uppercase @2xl:pr-0 @5xl:pr-12">{t.name}</span>
                <span className="block text-[2.75rem] font-bold tabular-nums leading-none text-ink">{l.count.toLocaleString()}</span>
                <span className="flex items-center gap-1 pt-1.5 text-[1.0625rem] text-soft @5xl:text-base">
                  {l.count === 0 ? 'Nothing needs you here' : `${l.count === 1 ? 'Risk requires' : 'Risks require'} your attention`}
                  <ChevronRight size={16} aria-hidden />
                </span>
                {l.count > 0 && <span className="block text-xs text-muted">{l.overdue ? `${l.overdue} overdue · oldest` : 'Oldest'} {l.oldest}</span>}
              </span>
            </VLink>
          </li>)
      })}
    </ul></div>
  )
}

const GROUP_TABS = [{ key: 'type', label: 'By Type of Risk', col: 'Risk' }, { key: 'machine', label: 'By Computer', col: 'Computer' }] as const

/** Under the cards: the same risks as a table, by type or by computer, with how much SentrAI already blocked. */
export function RiskTable({ data }: { data: Risks | null }) {
  const [tab, setTab] = useState<'type' | 'machine'>('type')
  if (!data?.groups) return null
  const t = GROUP_TABS.find((g) => g.key === tab)!
  const rows = data.groups[tab]
  return (
    <section aria-labelledby="risk-table-title" className="risk-table rounded-[1.25rem] border border-line">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line px-5 pt-4 pb-3">
        <h2 id="risk-table-title" className="text-lg font-semibold">Where Your Risks Are</h2>
        <div role="tablist" aria-label="Group the risks" className="flex flex-wrap gap-1">
          {GROUP_TABS.map((g) => (
            <button key={g.key} role="tab" aria-selected={tab === g.key} onClick={() => setTab(g.key)}
              className={'rounded-md px-3 py-1.5 text-sm ' + (tab === g.key ? 'bg-surface-3 text-ink' : 'text-soft hover:bg-surface-2')}>{g.label}</button>))}
        </div>
      </div>
      {rows.length === 0
        ? <p className="px-5 py-6 text-soft">Nothing to show yet. Risks appear here once SentrAI sees one.</p>
        : (
          <div role="tabpanel" className="overflow-x-auto">
            <table className="w-full min-w-[36rem] text-left text-sm">
              <thead className="text-xs uppercase tracking-wide text-muted">
                <tr>
                  <th scope="col" className="px-5 py-2.5 font-semibold">{t.col}</th>
                  <th scope="col" className="px-3 py-2.5 text-right font-semibold">Waiting for You</th>
                  <th scope="col" className="px-3 py-2.5 text-right font-semibold">Overdue</th>
                  <th scope="col" className="px-3 py-2.5 text-right font-semibold">Blocked by SentrAI</th>
                  <th scope="col" className="w-[30%] px-5 py-2.5 font-semibold">Taken Care Of</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.name} className="border-t border-line-soft">
                    <th scope="row" className="px-5 py-3 font-medium">
                      <span className="flex items-center gap-2">
                        <span className="stat-dot" style={{ background: r.worst ? CARD_COLOR[r.worst] : 'var(--green)' }}
                          title={r.worst ? `Worst open risk: ${LEVEL_TEXT[r.worst].name}` : 'Nothing open'} aria-hidden />
                        {tab === 'machine' && r.name !== 'Unknown computer' && r.name !== '-'
                          ? <VLink to={`/machines/${encodeURIComponent(r.name)}`} className="hover:underline">{r.name}</VLink> : r.name}
                        {r.worst && <span className="sr-only"> (worst open risk: {LEVEL_TEXT[r.worst].name})</span>}
                      </span>
                    </th>
                    <td className="px-3 py-3 text-right tabular-nums">{r.open ? r.open.toLocaleString() : <span className="text-muted">0</span>}</td>
                    <td className="px-3 py-3 text-right tabular-nums">{r.overdue ? <span className="font-medium text-bad">{r.overdue}</span> : <span className="text-muted">0</span>}</td>
                    <td className="px-3 py-3 text-right tabular-nums">{r.handled ? r.handled.toLocaleString() : <span className="text-muted">0</span>}</td>
                    <td className="px-5 py-3">
                      <span className="flex items-center gap-3">
                        <span className="risk-bar" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={r.done}
                          aria-label={`${r.done}% taken care of`}><span style={{ width: `${r.done}%` }} /></span>
                        <span className="w-10 text-right tabular-nums text-soft">{r.done}%</span>
                      </span>
                    </td>
                  </tr>))}
              </tbody>
            </table>
          </div>)}
      <p className="border-t border-line px-5 py-3 text-xs text-muted">"Taken care of" is the share SentrAI already blocked on its own. A full bar means nothing there is waiting for you.</p>
    </section>
  )
}

/** One risk on the severity page: its title and how long it has been open. */
export function RiskBubble({ r, onOpen, named = false, handled = false }: { r: Risk; onOpen: () => void; named?: boolean; handled?: boolean }) {
  const t = LEVEL_TEXT[r.severity]
  return (
    // The bubble and its dialog share a transition name, so the bubble grows into the dialog and back.
    <button onClick={onOpen} aria-haspopup="dialog" style={{ borderColor: t.color, viewTransitionName: named ? vtName('risk', r.id) : undefined }}
      className="flex h-full min-h-40 w-full flex-col items-start gap-2 rounded-[2rem] border-2 bg-surface p-5 text-left transition hover:-translate-y-0.5 hover:bg-surface-2">
      <span className="text-lg font-semibold leading-snug">{r.title}{r.ids.length > 1 && <span className="ml-1 text-sm font-normal text-muted">×{r.ids.length}</span>}</span>
      {handled
        ? <span className="flex items-center gap-1.5 text-sm text-ok"><ShieldCheck size={14} aria-hidden />Blocked by SentrAI {r.open_for} ago</span>
        : <span className="flex items-center gap-1.5 text-sm text-soft"><Clock size={14} aria-hidden />open for {r.open_for}</span>}
      <span className="mt-auto flex flex-wrap gap-1.5 text-xs text-muted">
        {r.overdue && <span className="rounded-full px-2 py-0.5 font-medium" style={{ background: t.tint, color: t.color }}>Overdue</span>}
      </span>
    </button>
  )
}

/** The opened risk, kept short: what happened, what it means and the suggested fix with its quick actions. */
export function RiskDetail({ r, protectionOn, onClose, onDone }: { r: Risk; protectionOn: boolean; onClose: () => void; onDone: (note: string) => void }) {
  const { can, me } = useSession()
  const [busy, setBusy] = useState('')
  const [err, setErr] = useState('')
  const go = useGo()  // Talk to Sentry opens the Sentry page with this risk as the subject
  const box = useRef<HTMLDivElement>(null)
  const t = LEVEL_TEXT[r.severity]
  const off = !can('act')
  const many = r.ids.length > 1
  // The demo copy shows a fixed answer the team has checked; the real console shows the core's fix.
  const vetted = DEMO && !isLiveRisk(r.id) ? DEMO_FIXES[r.category] : undefined
  const fix = vetted ?? (r.fix ? (r.status === 'contained' ? `SentrAI already did this for you. ${r.fix} Keep it, or undo it if it was a false alarm.` : r.fix) : '')

  useEffect(() => {
    box.current?.focus()
    const esc = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', esc)
    return () => window.removeEventListener('keydown', esc)
  }, [onClose])

  // No safe automatic step: hand it to the SentrAI team (the Contact Us inbox, emailed to them when set up).
  const escalate = async () => {
    setBusy('escalate'); setErr('')
    try {
      const out = await api<{ message: string }>('/ui/feedback', { body: {
        name: me?.name || me?.email || 'Panel user', contact: me?.email || 'signed-in user', incident: r.incident,
        message: `Please look into ${r.incident}: ${r.title} on ${r.host}.\n\n${r.what_happened}${many ? `\n\nIncidents: ${r.ids.join(', ')}` : ''}` } })
      onDone(out.message)
    } catch (e) { setErr(e instanceof ApiError ? e.message : 'That did not go through.') }
    setBusy('')
  }

  const act = async (a: RiskAction) => {
    if (a.verb === 'escalate') return void escalate()
    let justification = ''
    if (a.verb === 'reject') {
      justification = (await ask({ title: `${a.label}?`, confirm: a.label, danger: true,
        input: { label: 'Why? (written to the audit log)', required: true } })) ?? ''
      if (!justification.trim()) return
    }
    setBusy(a.verb); setErr('')
    try {
      const out = await api<{ message: string; done: string[] }>('/ui/approvals/bulk', { body: { verb: a.verb, ids: r.ids, justification } })
      if (out.done.length) onDone(out.message); else setErr(out.message)
    } catch (e) { setErr(e instanceof ApiError ? e.message : 'That did not go through.') }
    setBusy('')
  }

  // On <body>, so no transformed or transition-named parent can trap the backdrop or put the top bar over it.
  return createPortal(
    <div className="risk-backdrop fixed inset-0 z-40 flex items-start justify-center overflow-y-auto bg-black/50 p-4 sm:items-center" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose() }}>
      <div ref={box} role="dialog" aria-modal="true" aria-labelledby="risk-title" tabIndex={-1}
        className="relative w-full max-w-xl space-y-4 rounded-[2rem] border-2 bg-surface p-6 shadow-2xl outline-none" style={{ borderColor: t.color, viewTransitionName: vtName('risk', r.id) }}>
        <button className="absolute right-4 top-4 text-muted hover:text-ink" aria-label="Close" onClick={onClose}><X size={18} aria-hidden /></button>
        <header className="space-y-1 pr-8">
          <p className="text-xs font-semibold uppercase tracking-wide" style={{ color: t.color }}>{t.name}{r.overdue ? ' · overdue' : ''}</p>
          <h2 id="risk-title" className="text-2xl font-semibold">{r.title}</h2>
        </header>
        <section className="space-y-1">
          <h3 className="text-sm font-semibold uppercase tracking-wide text-muted">What happened</h3>
          <p>{r.what_happened}</p>
        </section>
        <section className="space-y-1">
          <h3 className="text-sm font-semibold uppercase tracking-wide text-muted">What it means</h3>
          <p className="text-soft">{r.meaning}</p>
        </section>
        <section className="space-y-3 rounded-2xl bg-surface-2 p-4">
          <h3 className="text-sm font-semibold uppercase tracking-wide text-muted">Suggested fix</h3>
          {fix && <p>{fix}</p>}
          {r.actions.length > 0 && (
            <div className="flex flex-wrap gap-2">
              {r.actions.map((a) => (
                <button key={a.verb} className={a.verb === 'approve' || a.verb === 'keep' || a.verb === 'escalate' ? btnPrimary : btn}
                  disabled={!!busy || off || (a.verb === 'approve' && !protectionOn)}
                  title={off ? 'Your role can read everything but change nothing.' : a.verb === 'approve' && !protectionOn ? 'Protection is off: turn it on to apply anything.' : a.hint}
                  onClick={() => void act(a)}>{busy === a.verb ? 'Working…' : a.label}{many && a.verb !== 'escalate' ? ` (all ${r.ids.length})` : ''}</button>))}
            </div>)}
        </section>
        <button className={btn} onClick={() => { go(`/manager?about=${encodeURIComponent(r.incident)}&title=${encodeURIComponent(r.title)}`) }}>
          <MessageSquare size={14} aria-hidden /> Talk to Sentry about this</button>
        {err && <p role="alert" className="text-sm text-bad">{err}</p>}
      </div>
    </div>,
    document.body,
  )
}
