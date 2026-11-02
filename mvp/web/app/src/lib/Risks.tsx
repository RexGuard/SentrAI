// Risk bubbles (GET /ui/risks): what needs a person, grouped Critical / High / Medium / Low. The Command center
// shows one bubble per severity; the severity page shows one bubble per risk, and opening one explains it in plain
// words and suggests a fix with its quick actions.
import { useEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { vtName, VLink } from './motion'
import { Bell, ChevronRight, Clock, MessageSquare, Send, ShieldAlert, ShieldCheck, TriangleAlert, X, type LucideIcon } from 'lucide-react'
import { api, ApiError } from './api'
import { btn, btnPrimary } from './ui'
import { useSession } from './session'
import { ask } from './notice'
import { DEMO } from './demo'
import { Text } from './Rich'
import { backToQuestion } from './turns'
import { SuggestionCard, type Message } from '../pages/Chat'
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
export type Risks = { levels: LevelCount[]; headline: string; protection_on: boolean; rows?: Risk[] }

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

/** The Command center's grouped buttons: a glowing card per severity (Critical, High, Medium, Low) with its count. */
export function SeverityBubbles({ data }: { data: Risks | null }) {
  if (!data) return (
    <ul role="status" aria-label="Loading" className="grid max-w-[64rem] gap-8 sm:grid-cols-2">
      {[0, 1, 2, 3].map((i) => <li key={i} className="skeleton h-[10.75rem] rounded-[1.25rem]" />)}
    </ul>)
  return (
    <ul className="grid max-w-[64rem] gap-8 sm:grid-cols-2">
      {data.levels.map((l) => {
        const t = LEVEL_TEXT[l.severity]
        const Icon = LEVEL_ICON[l.severity]
        return (
          <li key={l.severity}>
            <VLink to={`/risks/${l.severity}`} aria-label={`${t.name}: ${l.count} risk${l.count === 1 ? '' : 's'}. Open the list.`}
              className={'sev-card flex min-h-[10.75rem] items-center gap-12 px-8 py-6 sm:px-11' + (l.count ? '' : ' sev-zero')} style={{ '--c': CARD_COLOR[l.severity], viewTransitionName: `sev-${l.severity}` } as React.CSSProperties}>
              <Icon className="sev-icon shrink-0" size={72} strokeWidth={1.6} aria-hidden />
              <span className="min-w-0 space-y-1">
                <span className="sev-name block text-[1.375rem] font-bold uppercase">{t.name}</span>
                <span className="block text-[2.75rem] font-bold tabular-nums leading-none text-ink">{l.count.toLocaleString()}</span>
                <span className="flex items-center gap-1 pt-1.5 text-[1.0625rem] text-soft">
                  {l.count === 0 ? 'Nothing needs you here' : `${l.count === 1 ? 'Risk requires' : 'Risks require'} your attention`}
                  <ChevronRight size={16} aria-hidden />
                </span>
                {l.count > 0 && <span className="block text-xs text-muted">{l.overdue ? `${l.overdue} overdue · oldest` : 'Oldest'} {l.oldest}</span>}
              </span>
            </VLink>
          </li>)
      })}
    </ul>
  )
}

/** One risk on the severity page: its title and how long it has been open. */
export function RiskBubble({ r, onOpen, named = false }: { r: Risk; onOpen: () => void; named?: boolean }) {
  const t = LEVEL_TEXT[r.severity]
  return (
    // The bubble and its dialog share a transition name, so the bubble grows into the dialog and back.
    <button onClick={onOpen} aria-haspopup="dialog" style={{ borderColor: t.color, viewTransitionName: named ? vtName('risk', r.id) : undefined }}
      className="flex h-full min-h-40 w-full flex-col items-start gap-2 rounded-[2rem] border-2 bg-surface p-5 text-left transition hover:-translate-y-0.5 hover:bg-surface-2">
      <span className="text-lg font-semibold leading-snug">{r.title}{r.ids.length > 1 && <span className="ml-1 text-sm font-normal text-muted">×{r.ids.length}</span>}</span>
      <span className="flex items-center gap-1.5 text-sm text-soft"><Clock size={14} aria-hidden />open for {r.open_for}</span>
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
  const [talking, setTalking] = useState(false)  // Talk to Sentry: folded until asked for, so the card stays short
  const [idea, setIdea] = useState('')
  const [asking, setAsking] = useState(false)
  const [reply, setReply] = useState<Message | null>(null)
  const [asked, setAsked] = useState('')
  const box = useRef<HTMLDivElement>(null)
  const t = LEVEL_TEXT[r.severity]
  const off = !can('act')
  const many = r.ids.length > 1
  // The demo copy shows a fixed answer the team has checked; the real console shows the core's fix.
  const vetted = DEMO ? DEMO_FIXES[r.category] : undefined
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

  const talk = async () => {
    const text = idea.trim()
    if (!text || asking) return
    setAsking(true); setErr('')
    try {
      setReply(await api<Message>('/chat', { body: { operator: me?.email ?? 'dashboard', message: `My fix for ${r.incident}: ${text}`, incident: r.incident } }))
      setAsked(text); setIdea('')
    } catch (e) { setErr(e instanceof ApiError ? `Sentry could not answer: ${e.message}` : 'Sentry could not answer.') }
    setAsking(false)
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
        {!talking ? (
          <button className={btn} onClick={() => setTalking(true)}><MessageSquare size={14} aria-hidden /> Talk to Sentry</button>
        ) : (
          <section className="space-y-2">
            <h3 className="text-sm font-semibold uppercase tracking-wide text-muted">Talk to Sentry</h3>
            <form onSubmit={(e) => { e.preventDefault(); void talk() }}>
              <label className="sr-only" htmlFor="risk-idea">Ask Sentry about {r.title}</label>
              <div className="prompt">
                <textarea id="risk-idea" rows={1} autoFocus value={idea} disabled={asking} placeholder="e.g. block that address for good, or: this is our own backup job"
                  onChange={(e) => setIdea(e.target.value)}
                  onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); void talk() } }} />
                <button className="prompt-send" disabled={asking || !idea.trim()} aria-label="Send to Sentry"><Send size={16} aria-hidden /></button>
              </div>
            </form>
            {asking && <p className="text-sm text-muted" role="status">Sentry is thinking…</p>}
            {reply && (
              <div className="space-y-1 rounded-2xl bg-surface-2 p-4" aria-live="polite" data-turn>
                {asked && <div className="chat-stick" style={{ '--stick-bg': 'var(--surface-2)' } as React.CSSProperties} title="Back to your question" onClick={backToQuestion}>
                  <p className="ml-auto w-fit max-w-[90%] whitespace-pre-wrap rounded-2xl bg-surface-3 px-3 py-2 text-sm">{asked}</p></div>}
                <p className="text-xs text-muted">Sentry</p>
                <Text md={reply.text} />
                {(reply.suggestions ?? []).map((sg, k) => <SuggestionCard key={k} s={sg} inc={r.inc} onDone={onDone} />)}
              </div>)}
          </section>
        )}
        {err && <p role="alert" className="text-sm text-bad">{err}</p>}
      </div>
    </div>,
    document.body,
  )
}
