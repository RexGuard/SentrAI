import { useCallback, useEffect, useId, useRef, useState, type FormEvent } from 'react'
import { Lightbulb, Send, Trash2 } from 'lucide-react'
import { api, ApiError } from '../lib/api'
import { btn, btnPrimary } from '../lib/ui'
import { useSession } from '../lib/session'
import { SetupBanner, SetupConversation, type Setup } from './SetupChat'

export type Suggestion = {
  kind?: string; incident?: string; decision?: string; label?: string; reason?: string; file_id?: string; finding_id?: string
}
export type Message = {
  id: string | number; role: string; text: string; ts?: string; operator?: string; incident?: string; source?: string
  looked_at?: string[]; suggestions?: Suggestion[]
}
type History = { assistant?: string; model?: string; messages: Message[] }
export type Incident = { id: string; status: string; category?: string; acked?: boolean; actions?: { status?: string }[] }

const STARTERS = ['What is happening right now?', 'Which incident should I deal with first?', 'Why did you block the last IP address?']
const FOLLOW_UPS = [...STARTERS, 'Is anything waiting for my approval?', 'What changed in the last hour?', 'Is any machine offline?']
const NEEDS: Record<string, 'decide' | 'ack' | 'mine' | 'contain'> = { approve: 'decide', reject: 'decide', ack: 'ack', mine: 'mine', rollback: 'contain', keep: 'contain', permanent: 'contain' }

function canDo(inc: Incident | undefined, decision: string): [boolean, string] {
  if (!inc) return [false, 'incident not found']
  const need = NEEDS[decision]
  if (!need) return [false, `unknown decision ${decision}`]
  const active = inc.status === 'open' || inc.status === 'acknowledged'
  const ok = need === 'decide' ? active : need === 'ack' ? inc.status === 'open' && !inc.acked
    : need === 'mine' ? active && inc.category === 'unauthorised_admin'
    : inc.status === 'contained' || !!inc.actions?.some((a) => a.status === 'active')
  return ok ? [true, ''] : [false, `no longer possible: incident is ${inc.status}`]
}

const time = (ts?: string) => (ts ? new Date(ts).toLocaleTimeString() : '')

export function SuggestionCard({ s, inc, onDone }: { s: Suggestion; inc?: Incident; onDone: (note: string) => void }) {
  const { me, can } = useSession()
  const op = me?.email ?? 'dashboard'
  const label = s.label || `${s.decision} ${s.incident}`
  const [why, setWhy] = useState(s.reason ?? '')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const decision = s.decision ?? ''
  const isIncident = !s.kind || !['watch_log', 'quarantine_file', 'backup_now'].includes(s.kind)
  const [ok, whyNot] = isIncident ? canDo(inc, decision) : [true, '']
  if (!ok) return <p className="text-sm text-muted"><Lightbulb size={14} className="mr-1 inline" aria-hidden />Suggested: {label} · {whyNot}</p>

  const run = async () => {
    if (decision === 'reject' && !why.trim()) return setErr('Rejecting requires a written justification.')
    setBusy(true); setErr('')
    const id = encodeURIComponent(s.incident ?? '')
    try {
      if (s.kind === 'watch_log') await api('/log-sources', { body: { file_id: s.file_id, operator: op } })
      else if (s.kind === 'quarantine_file') await api(`/threats/${encodeURIComponent(s.finding_id ?? '')}/quarantine`, { body: { operator: op, reason: s.reason ?? '' } })
      else if (s.kind === 'backup_now') await api('/backups', { body: { operator: op } })
      else if (decision === 'approve' || decision === 'reject') {
        if (inc?.status === 'open' && !inc.acked) await api(`/incidents/${id}/ack`, { body: { operator: op } }).catch(() => {})
        await api(`/incidents/${id}/decision`, { body: { operator: op, decision, justification: why.trim() } })
      } else if (decision === 'ack') await api(`/incidents/${id}/ack`, { body: { operator: op } })
      else if (decision === 'mine') await api(`/incidents/${id}/mine`, { body: { operator: op } })
      else if (decision === 'rollback') await api(`/incidents/${id}/rollback`, { body: { operator: op, justification: why.trim() || 'Rolled back by operator after chat' } })
      else await api(`/incidents/${id}/permanent`, { body: { operator: op, justification: why.trim() || 'Made permanent by operator after chat' } })
      onDone(`Done: ${label}`)
    } catch (e) { setErr(e instanceof ApiError ? e.message : 'That did not go through.') }
    setBusy(false)
  }
  return (
    <form className="mt-2 space-y-2 rounded-lg border border-line bg-surface-2 p-3" onSubmit={(e: FormEvent) => { e.preventDefault(); void run() }}>
      <p className="font-medium"><Lightbulb size={14} className="mr-1 inline" aria-hidden />Suggested: {label}</p>
      {isIncident
        ? <label className="block text-sm text-soft">Justification (written to the audit log)
            <input value={why} onChange={(e) => setWhy(e.target.value)} className="mt-1 block w-full rounded-md border border-line bg-surface px-3 py-1.5 text-ink" /></label>
        : s.reason && <p className="text-sm text-soft">{s.reason}</p>}
      {err && <p role="alert" className="text-sm text-bad">{err}</p>}
      <button className={decision === 'reject' ? btn : btnPrimary} disabled={busy || !can('act')} title={can('act') ? undefined : 'Your role can read everything but change nothing.'}>
        Confirm: {label}
      </button>
    </form>
  )
}

/** The conversation with Cyanide. `compact` fits it into the side panel the ? button opens. */
export default function Chat({ compact = false }: { compact?: boolean }) {
  const inputId = useId()
  const { me, can } = useSession()
  const [hist, setHist] = useState<History | null>(null)
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [error, setError] = useState('')
  const [note, setNote] = useState('')
  const [about, setAbout] = useState('')
  const [text, setText] = useState('')
  const [asking, setAsking] = useState(false)
  const [setup, setSetup] = useState<Setup | null>(null)
  const [later, setLater] = useState(false)
  const end = useRef<HTMLDivElement>(null)

  const load = useCallback(async () => {
    try {
      const [h, i] = await Promise.all([api<History>('/chat'), api<Incident[]>('/incidents')])
      setHist(Array.isArray(h) ? { messages: h } : h); setIncidents(i); setError('')
    } catch (e) { setError(e instanceof ApiError ? `Chat is not available on this core: ${e.message}` : 'Could not load chat.') }
  }, [])
  useEffect(() => { void load() }, [load])
  useEffect(() => { api<Setup>('/ui/setup').then(setSetup).catch(() => setSetup(null)) }, [])
  useEffect(() => { end.current?.scrollIntoView({ block: 'end' }) }, [hist?.messages.length, asking])

  const ask = async (message: string) => {
    if (!message.trim() || asking) return
    setAsking(true); setNote(''); setText('')
    try { await api('/chat', { body: { operator: me?.email ?? 'dashboard', message, incident: about || null } }) }
    catch (e) { setNote(e instanceof ApiError ? `Chat failed: ${e.message}` : 'Chat failed.') }
    await load(); setAsking(false)
  }
  const clear = async () => { await api('/chat/clear', { body: {} }); await load() }

  const assistant = hist?.assistant || 'Cyanide'
  const messages = hist?.messages ?? []
  const byId = Object.fromEntries(incidents.map((i) => [i.id, i]))
  const asked = new Set(messages.filter((m) => m.role === 'operator').map((m) => m.text.trim().toLowerCase()))
  const followUps = FOLLOW_UPS.filter((q) => !asked.has(q.toLowerCase())).slice(0, 3)
  const lastReply = messages.map((m, n) => (m.role !== 'operator' ? n : -1)).reduce((a, b) => Math.max(a, b), -1)
  const chip = 'rounded-full border border-line px-3 py-1 text-sm text-soft hover:bg-surface-2 disabled:opacity-50'

  return (
    <section className={compact ? 'flex h-full min-h-0 flex-col gap-3' : 'space-y-4'}>
      {!compact && <header>
        <h1 className="text-2xl font-semibold">Chat</h1>
        <p className="text-sm text-muted">ask the orchestrator what it sees and why it acted · it suggests, you decide</p>
      </header>}
      {error && <p role="alert" className="rounded-md border border-line bg-surface p-3 text-bad">{error}</p>}
      {note && <p role="status" className="rounded-md border border-line bg-surface p-3">{note}</p>}
      {setup?.active ? <SetupConversation setup={setup} onChange={setSetup} onLeave={() => { setSetup({ ...setup, active: false }); setLater(true) }} /> : (
      <>
      {setup && !compact && <SetupBanner setup={setup} onChange={setSetup} later={later} onLater={() => setLater(true)} />}
      {hist && (
        <>
          <div className="flex flex-wrap items-end gap-3">
            <label className="text-sm text-soft">Talk about
              <select value={about} onChange={(e) => setAbout(e.target.value)} className="mt-1 block rounded-md border border-line bg-surface-2 px-2 py-1.5 text-ink">
                <option value="">The whole operation</option>
                {[...incidents].sort((a, b) => b.id.localeCompare(a.id)).map((i) => <option key={i.id} value={i.id}>{i.id} · {(i.category ?? '').replace(/_/g, ' ')}</option>)}
              </select>
            </label>
            <p className="min-w-0 flex-1 text-xs text-muted">{compact ? 'It suggests, you decide' : `${assistant} · ${hist.model || 'model unknown'} · read-only: every action still needs your click and goes through the normal approval checks`}</p>
            <button className={btn} disabled={!messages.length || !can('act')} onClick={() => void clear()} aria-label="Clear chat"><Trash2 size={14} aria-hidden />{compact ? '' : ' Clear chat'}</button>
          </div>
          <div className={(compact ? 'min-h-0 flex-1 ' : 'h-[28rem] ') + 'space-y-4 overflow-y-auto rounded-lg border border-line bg-surface p-4'} role="log" aria-live="polite" aria-label="Conversation" tabIndex={0}>
            {!messages.length && (
              <div className="space-y-2">
                <p>Hi, I'm {assistant}. Ask me about incidents, why I acted, or what to do next. Or pick one of these to start:</p>
                <div className="flex flex-wrap gap-2">{STARTERS.map((q) => <button key={q} className={chip} onClick={() => void ask(q)}>{q}</button>)}</div>
              </div>
            )}
            {messages.map((m, n) => {
              const mine = m.role === 'operator'
              return (
                <div key={m.id} className={(compact ? 'max-w-[92%]' : 'max-w-[85%]') + ' space-y-1 rounded-lg p-3 ' + (mine ? 'ml-auto bg-surface-3' : 'bg-surface-2')}>
                  <p className="text-xs text-muted">{mine ? m.operator || me?.email : assistant} · {time(m.ts)}{m.incident ? ` · about ${m.incident}` : ''}{!mine && m.source === 'fallback' ? ' · core explanation (no AI)' : ''}</p>
                  <p className="whitespace-pre-wrap">{m.text}</p>
                  {m.looked_at?.length ? <p className="text-xs text-muted">Looked at: {[...new Set(m.looked_at)].join(', ')}</p> : null}
                  {(m.suggestions ?? []).map((s, k) => <SuggestionCard key={k} s={s} inc={byId[String(s.incident)]} onDone={(t) => { setNote(t); void load() }} />)}
                  {n === lastReply && followUps.length > 0 && (
                    <div className="flex flex-wrap gap-2 pt-1">{followUps.map((q) => <button key={q} className={chip} disabled={asking} onClick={() => void ask(q)}>{q}</button>)}</div>
                  )}
                </div>
              )
            })}
            {asking && <p className="text-muted" role="status">{assistant} is looking into it…</p>}
            <div ref={end} />
          </div>
          <form onSubmit={(e) => { e.preventDefault(); void ask(text) }}>
            <label className="sr-only" htmlFor={inputId}>Ask {assistant}</label>
            <div className="prompt">
              <textarea id={inputId} rows={1} value={text} disabled={asking} placeholder={`Ask ${assistant}…`}
                onChange={(e) => setText(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); void ask(text) } }} />
              <button className="prompt-send" disabled={asking || !text.trim()} aria-label="Send"><Send size={16} aria-hidden /></button>
            </div>
            <p className="mt-1 px-1 text-xs text-muted">Enter to send · Shift+Enter for a new line</p>
          </form>
        </>
      )}
      <div className={compact ? 'hidden' : 'flex'}><button className={btn} onClick={() => void api<Setup>('/ui/setup/start', { body: {} }).then(setSetup).catch(() => {})}>Setup</button></div>
      </>
      )}
    </section>
  )
}
