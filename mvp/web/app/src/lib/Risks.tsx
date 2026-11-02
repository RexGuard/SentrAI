// Risk bubbles (GET /ui/risks): what needs a person, grouped Critical / High / Medium / Low. The Command center
// shows one bubble per severity; the severity page shows one bubble per risk, and opening one explains it in plain
// words, suggests a fix, offers the quick actions and lets the person talk their own fix through with Cyanide.
import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { AlertTriangle, Clock, Send, User, X } from 'lucide-react'
import { api, ApiError } from './api'
import { btn, btnPrimary } from './ui'
import { useSession } from './session'
import { ask } from './notice'
import { Text } from './Rich'
import { SuggestionCard, type Message } from '../pages/Chat'

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

/** The Command center's grouped buttons: one round bubble per severity with its count. Low only shows when it has some. */
export function SeverityBubbles({ data }: { data: Risks | null }) {
  if (!data) return <p className="text-muted" role="status">Loading…</p>
  const levels = data.levels.filter((l) => l.severity !== 'low' || l.count > 0)
  return (
    <ul className={'grid gap-4 ' + (levels.length > 3 ? 'grid-cols-2 lg:grid-cols-4' : 'grid-cols-1 sm:grid-cols-3')}>
      {levels.map((l) => {
        const t = LEVEL_TEXT[l.severity]
        return (
          <li key={l.severity}>
            <Link to={`/risks/${l.severity}`} aria-label={`${t.name}: ${l.count} risk${l.count === 1 ? '' : 's'}. Open the list.`}
              className="sev-bubble group flex aspect-[5/3] w-full flex-col items-center justify-center gap-1 rounded-[999px] border-2 p-4 text-center transition hover:-translate-y-0.5"
              style={{ borderColor: l.count ? t.color : 'var(--line)', background: l.count ? t.tint : undefined }}>
              <span className="text-sm font-semibold uppercase tracking-wide" style={{ color: l.count ? t.color : undefined }}>{t.name}</span>
              <span className="text-4xl font-semibold tabular-nums">{l.count}</span>
              <span className="text-xs text-muted">
                {l.count === 0 ? 'nothing here' : l.overdue ? `${l.overdue} overdue · oldest ${l.oldest}` : `${t.blurb} · oldest ${l.oldest}`}
              </span>
            </Link>
          </li>)
      })}
    </ul>
  )
}

/** One risk on the severity page: title, who has it and how long it has been open, as in Erick's sketch. */
export function RiskBubble({ r, onOpen }: { r: Risk; onOpen: () => void }) {
  const t = LEVEL_TEXT[r.severity]
  return (
    <button onClick={onOpen} aria-haspopup="dialog"
      className="flex h-full min-h-40 w-full flex-col items-start gap-2 rounded-[2rem] border-2 bg-surface p-5 text-left transition hover:-translate-y-0.5 hover:bg-surface-2"
      style={{ borderColor: t.color }}>
      <span className="text-lg font-semibold leading-snug">{r.title}{r.ids.length > 1 && <span className="ml-1 text-sm font-normal text-muted">×{r.ids.length}</span>}</span>
      <span className="flex items-center gap-1.5 text-sm text-soft"><User size={14} aria-hidden />{r.owner}</span>
      <span className="flex items-center gap-1.5 text-sm text-soft"><Clock size={14} aria-hidden />open for {r.open_for}</span>
      <span className="mt-auto flex flex-wrap gap-1.5 text-xs text-muted">
        <span>{r.host}</span>
        {r.overdue && <span className="rounded-full px-2 py-0.5 font-medium" style={{ background: t.tint, color: t.color }}>Overdue</span>}
        {r.unsure && <span className="rounded-full bg-surface-3 px-2 py-0.5">AI unsure</span>}
      </span>
    </button>
  )
}

/** The opened risk: what happened, what it means, the suggested fix, quick actions, and the person's own fix with Cyanide. */
export function RiskDetail({ r, protectionOn, onClose, onDone }: { r: Risk; protectionOn: boolean; onClose: () => void; onDone: (note: string) => void }) {
  const { me, can } = useSession()
  const [busy, setBusy] = useState('')
  const [err, setErr] = useState('')
  const [idea, setIdea] = useState('')
  const [closing, setClosing] = useState('')
  const [asking, setAsking] = useState(false)
  const [reply, setReply] = useState<Message | null>(null)
  const box = useRef<HTMLDivElement>(null)
  const t = LEVEL_TEXT[r.severity]
  const off = !can('act')
  const many = r.ids.length > 1

  useEffect(() => {
    box.current?.focus()
    const esc = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', esc)
    return () => window.removeEventListener('keydown', esc)
  }, [onClose])

  const act = async (a: RiskAction) => {
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

  const resolve = async () => {
    const note = closing.trim()
    if (!note) return
    setBusy('resolve'); setErr('')
    const failed: string[] = []
    for (const id of r.ids) {
      try { await api(`/incidents/${encodeURIComponent(id)}/resolve`, { body: { operator: me?.email ?? 'dashboard', note } }) }
      catch { failed.push(id) }
    }
    setBusy('')
    if (failed.length < r.ids.length) onDone(`Closed ${r.ids.length - failed.length} of ${r.ids.length}${failed.length ? `. Not closed: ${failed.join(', ')}` : ''}`)
    else setErr('That did not go through.')
  }

  const talk = async () => {
    const text = idea.trim()
    if (!text || asking) return
    setAsking(true); setErr('')
    try {
      setReply(await api<Message>('/chat', { body: { operator: me?.email ?? 'dashboard', message: `My fix for ${r.incident}: ${text}`, incident: r.incident } }))
      setIdea('')
    } catch (e) { setErr(e instanceof ApiError ? `Cyanide could not answer: ${e.message}` : 'Cyanide could not answer.') }
    setAsking(false)
  }

  return (
    <div className="fixed inset-0 z-40 flex items-start justify-center overflow-y-auto bg-black/50 p-4 sm:items-center" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose() }}>
      <div ref={box} role="dialog" aria-modal="true" aria-labelledby="risk-title" tabIndex={-1}
        className="relative w-full max-w-2xl space-y-4 rounded-[2rem] border-2 bg-surface p-6 shadow-2xl outline-none" style={{ borderColor: t.color }}>
        <button className="absolute right-4 top-4 text-muted hover:text-ink" aria-label="Close" onClick={onClose}><X size={18} aria-hidden /></button>
        <header className="space-y-1 pr-8">
          <p className="text-xs font-semibold uppercase tracking-wide" style={{ color: t.color }}>{t.name}{r.overdue ? ' · overdue' : ''}</p>
          <h2 id="risk-title" className="text-2xl font-semibold">{r.title}</h2>
          <p className="text-sm text-muted">{r.owner} · open for {r.open_for} · {r.host}{r.source ? ` · from ${r.source}` : ''}</p>
        </header>

        <section className="space-y-1">
          <h3 className="text-sm font-semibold uppercase tracking-wide text-muted">What happened</h3>
          <p>{r.what_happened}</p>
        </section>
        <section className="space-y-1">
          <h3 className="text-sm font-semibold uppercase tracking-wide text-muted">What it means</h3>
          <p className="text-soft">{r.meaning}</p>
          {r.unsure && <p className="flex items-center gap-1.5 text-sm text-warn"><AlertTriangle size={14} aria-hidden />SentrAI is not sure this is an attack, so it waited for a person.</p>}
        </section>
        <section className="space-y-2 rounded-2xl bg-surface-2 p-4">
          <h3 className="text-sm font-semibold uppercase tracking-wide text-muted">Suggested fix</h3>
          {r.fix && (r.status === 'contained'
            ? <p><span className="font-medium">SentrAI already did this:</span> {r.fix}. Keep it, or undo it if it was a false alarm.</p>
            : <p className="font-medium">{r.fix}.</p>)}
          {r.steps.length > 0 && <ul className="list-disc space-y-0.5 pl-5 text-sm text-soft">{r.steps.map((s, i) => <li key={i}>{s}</li>)}</ul>}
          {r.actions.length > 0 ? (
            <div className="flex flex-wrap gap-2 pt-1">
              {r.actions.map((a) => (
                <button key={a.verb} className={a.verb === 'approve' || a.verb === 'keep' ? btnPrimary : btn}
                  disabled={!!busy || off || (a.verb === 'approve' && !protectionOn)}
                  title={off ? 'Your role can read everything but change nothing.' : a.verb === 'approve' && !protectionOn ? 'Protection is off: turn it on to apply anything.' : a.hint}
                  onClick={() => void act(a)}>{busy === a.verb ? 'Working…' : a.label}{many ? ` (all ${r.ids.length})` : ''}</button>))}
            </div>
          ) : <p className="text-sm text-muted">No one-click step fits this one: follow the steps above, then close it below.</p>}
          <form className="flex flex-wrap items-end gap-2 border-t border-line-soft pt-3" onSubmit={(e) => { e.preventDefault(); void resolve() }}>
            <label className="min-w-0 flex-1 text-sm text-soft">Done by hand? Close it with a note
              <input value={closing} onChange={(e) => setClosing(e.target.value)} placeholder="e.g. reset j.tan's password and checked the export"
                className="mt-1 block w-full rounded-md border border-line bg-surface px-3 py-1.5 text-ink" /></label>
            <button className={btn} disabled={!!busy || off || !closing.trim()} title={off ? 'Your role can read everything but change nothing.' : 'Resolves it; the note goes in the audit log'}>
              {busy === 'resolve' ? 'Closing…' : many ? `Close all ${r.ids.length}` : 'Close it'}</button>
          </form>
        </section>

        <section className="space-y-2">
          <h3 className="text-sm font-semibold uppercase tracking-wide text-muted">Your own fix? Talk to Cyanide</h3>
          <form onSubmit={(e) => { e.preventDefault(); void talk() }}>
            <label className="sr-only" htmlFor="risk-idea">Your idea for {r.title}</label>
            <div className="prompt">
              <textarea id="risk-idea" rows={1} value={idea} disabled={asking} placeholder="e.g. block that address for good, or: this is our own backup job"
                onChange={(e) => setIdea(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); void talk() } }} />
              <button className="prompt-send" disabled={asking || !idea.trim()} aria-label="Send to Cyanide"><Send size={16} aria-hidden /></button>
            </div>
          </form>
          {asking && <p className="text-sm text-muted" role="status">Cyanide is weighing your idea…</p>}
          {reply && (
            <div className="space-y-1 rounded-2xl bg-surface-2 p-4" aria-live="polite">
              <p className="text-xs text-muted">Cyanide{reply.source === 'fallback' ? ' · core explanation (no AI)' : ''}</p>
              <Text md={reply.text} />
              {(reply.suggestions ?? []).map((s, k) => <SuggestionCard key={k} s={s} inc={r.inc} onDone={onDone} />)}
              {many && (reply.suggestions ?? []).length > 0 && <p className="text-xs text-muted">That button acts on {r.incident} only. The buttons under Suggested fix act on all {r.ids.length}.</p>}
            </div>)}
        </section>
        {err && <p role="alert" className="text-sm text-bad">{err}</p>}
        <p className="text-xs text-muted">{many ? `${r.ids.length} incidents: ${r.ids.slice(0, 4).join(', ')}${r.ids.length > 4 ? ' …' : ''}` : r.incident} · every step is written to the audit log</p>
      </div>
    </div>
  )
}
