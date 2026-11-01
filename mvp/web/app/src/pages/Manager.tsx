// Manager view: one page and nothing else. A greeting, one big box to ask Cyanide, a few suggested questions, and
// the answers in a single column under a soft glow. No sidebar and no other pages: a manager asks in plain words
// ("are we safe?") and Cyanide answers from the same live data the dashboard uses. Auto mode, the full dashboard
// and sign out stay in the top corner. Any action Cyanide suggests still needs a click and the usual checks.
import { useCallback, useEffect, useId, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ArrowUp, BarChart3, ChevronDown, LayoutDashboard, ListChecks, LogOut, Plus, ShieldQuestion } from 'lucide-react'
import { api, ApiError } from '../lib/api'
import { useSession } from '../lib/session'
import { useSimple } from '../lib/simple'
import AutoMode from './AutoMode'
import { SuggestionCard, type Incident, type Message } from './Chat'

type History = { assistant?: string; model?: string; messages: Message[] }

const STARTERS = [
  { q: 'Are we safe right now?', icon: ShieldQuestion },
  { q: 'What needs my attention today?', icon: ListChecks },
  { q: 'Summarise this week for me in plain words', icon: BarChart3 },
]
const greeting = () => { const h = new Date().getHours(); return h < 12 ? 'Good morning' : h < 18 ? 'Good afternoon' : 'Good evening' }

export default function Manager() {
  const inputId = useId()
  const nav = useNavigate()
  const { me, signOut } = useSession()
  const { simple, toggle } = useSimple()
  const [hist, setHist] = useState<History | null>(null)
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [since, setSince] = useState<number | null>(null) // messages before this visit's first question stay hidden
  const [about, setAbout] = useState('')
  const [text, setText] = useState('')
  const [asking, setAsking] = useState(false)
  const [note, setNote] = useState('')
  const end = useRef<HTMLDivElement>(null)

  const load = useCallback(async () => {
    try {
      const [h, i] = await Promise.all([api<History>('/chat'), api<Incident[]>('/incidents')])
      setHist(Array.isArray(h) ? { messages: h } : h); setIncidents(i)
    } catch (e) { setNote(e instanceof ApiError ? `Cyanide is not available: ${e.message}` : 'Could not reach SentrAI.') }
  }, [])
  useEffect(() => { void load() }, [load])
  useEffect(() => { end.current?.scrollIntoView({ block: 'end', behavior: 'smooth' }) }, [hist?.messages.length, asking])

  const ask = async (message: string) => {
    if (!message.trim() || asking) return
    if (since === null) setSince(hist?.messages.length ?? 0)
    setAsking(true); setNote(''); setText('')
    try { await api('/chat', { body: { operator: me?.email ?? 'dashboard', message, incident: about || null } }) }
    catch (e) { setNote(e instanceof ApiError ? `That did not go through: ${e.message}` : 'That did not go through.') }
    await load(); setAsking(false)
  }

  const assistant = hist?.assistant || 'Cyanide'
  const shown = since === null ? [] : (hist?.messages ?? []).slice(since)
  const chatting = shown.length > 0 || asking
  const byId = Object.fromEntries(incidents.map((i) => [i.id, i]))
  const first = (me?.name || '').split(' ')[0]
  const openIncidents = incidents.filter((i) => i.status === 'open' || i.status === 'acknowledged').sort((a, b) => b.id.localeCompare(a.id))
  const full = () => { if (simple) toggle(); nav('/command') }

  const box = (
    <form onSubmit={(e) => { e.preventDefault(); void ask(text) }} className="w-full">
      <label className="sr-only" htmlFor={inputId}>Ask {assistant}</label>
      <div className="mgr-box">
        <button type="button" className="mgr-icon" title="Start a new conversation" aria-label="New conversation"
          onClick={() => { setSince(hist?.messages.length ?? 0); setNote('') }}><Plus size={18} aria-hidden /></button>
        <textarea id={inputId} rows={1} value={text} disabled={asking} placeholder={`Ask ${assistant} anything about your security`}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); void ask(text) } }} />
        <label className="mgr-pick">
          <span className="sr-only">Talk about</span>
          <select value={about} onChange={(e) => setAbout(e.target.value)}>
            <option value="">{assistant} · everything</option>
            {openIncidents.map((i) => <option key={i.id} value={i.id}>{assistant} · {i.id}</option>)}
          </select>
          <ChevronDown size={14} aria-hidden />
        </label>
        <button className="mgr-send" disabled={asking || !text.trim()} aria-label="Send"><ArrowUp size={18} aria-hidden /></button>
      </div>
    </form>
  )

  return (
    <div className="mgr">
      <div className="mgr-glow" aria-hidden />
      <header className="relative z-10 flex flex-wrap items-center justify-end gap-2 p-4 text-sm">
        <AutoMode />
        <button onClick={full} className="mgr-top" title="Every page, for IT staff"><LayoutDashboard size={14} aria-hidden /> Full dashboard</button>
        <button onClick={() => void signOut()} className="mgr-top"><LogOut size={14} aria-hidden /> Sign out</button>
      </header>

      {!chatting ? (
        <main className="relative z-10 mx-auto flex min-h-[calc(100vh-9rem)] w-full max-w-3xl flex-col items-center justify-center gap-6 px-4">
          <h1 className="text-center text-3xl font-light tracking-tight sm:text-[2.25rem]">{greeting()}{first ? `, ${first}` : ''}. Where should we start?</h1>
          <div className="w-full max-w-2xl">{box}</div>
          {note && <p role="alert" className="text-sm text-bad">{note}</p>}
          <ul className="w-full max-w-2xl space-y-1 px-2">
            {STARTERS.map(({ q, icon: Icon }) => (
              <li key={q}><button className="mgr-starter" disabled={asking} onClick={() => void ask(q)}><Icon size={15} aria-hidden /> {q}</button></li>))}
          </ul>
        </main>
      ) : (
        <main className="relative z-10 mx-auto flex min-h-[calc(100vh-4.5rem)] w-full max-w-3xl flex-col px-4">
          <div className="flex-1 space-y-6 py-6" role="log" aria-live="polite" aria-label="Conversation">
            {shown.map((m) => m.role === 'operator' ? (
              <p key={m.id} className="ml-auto w-fit max-w-[85%] whitespace-pre-wrap rounded-2xl bg-surface-3 px-4 py-2.5">{m.text}</p>
            ) : (
              <div key={m.id} className="space-y-2">
                <p className="text-xs text-muted">{assistant}{m.incident ? ` · about ${m.incident}` : ''}</p>
                <p className="whitespace-pre-wrap leading-relaxed">{m.text}</p>
                {(m.suggestions ?? []).map((s, k) => <SuggestionCard key={k} s={s} inc={byId[String(s.incident)]} onDone={(t) => { setNote(t); void load() }} />)}
              </div>))}
            {asking && <p className="text-muted" role="status">{assistant} is looking into it…</p>}
            {note && <p role="status" className="text-sm text-soft">{note}</p>}
            <div ref={end} />
          </div>
          <div className="sticky bottom-0 pb-5 pt-2" style={{ background: 'linear-gradient(transparent, var(--bg) 30%)' }}>
            {box}
            <p className="mt-2 text-center text-xs text-muted">{assistant} suggests; nothing happens until you click and the usual checks pass.</p>
          </div>
        </main>
      )}
    </div>
  )
}
