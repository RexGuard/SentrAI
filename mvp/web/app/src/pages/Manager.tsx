// Manager view: one page and nothing else. A greeting, one big box to ask Cyanide, a few suggested questions, and
// the answers in a single column under a soft glow. No other pages: a manager asks in plain words
// ("are we safe?") and Cyanide answers from the same live data the dashboard uses. Auto mode, the full dashboard
// and sign out stay in the top corner. Past conversations sit on the left, kept in this browser; the glow
// drifts slowly and turns warmer as the safety status worsens. Any action Cyanide suggests still needs a click and the usual checks.
import type React from 'react'
import { useCallback, useEffect, useId, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ArrowUp, BarChart3, ChevronDown, LayoutDashboard, ListChecks, LogOut, MessageSquare, PanelLeftClose, PanelLeftOpen, Pencil, Pin, PinOff, Search, Plus, ShieldQuestion, SquarePen, X } from 'lucide-react'
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
// Past conversations, kept in this browser: the core keeps one running chat log, and each conversation here is the
// list of its message ids in that log. A conversation whose messages the core has since dropped says so.
type Convo = { id: string; title: string; at: string; ids: string[]; pinned?: boolean }
const KEY = 'sentrai.manager.chats'
const loadConvos = (): Convo[] => { try { const v = JSON.parse(localStorage.getItem(KEY) ?? '[]'); return Array.isArray(v) ? v : [] } catch { return [] } }
const saveConvos = (c: Convo[]) => { try { localStorage.setItem(KEY, JSON.stringify(c.slice(0, 50))) } catch { /* private window */ } }
// A message's key: the core numbers messages from 1 again after a restart, so the time tells them apart.
const key = (m: Message) => `${m.id}|${m.ts}`
const when = (iso: string) => {
  const d = new Date(iso), days = Math.floor((Date.now() - d.getTime()) / 86400000)
  return days === 0 ? d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : days === 1 ? 'Yesterday' : d.toLocaleDateString([], { day: 'numeric', month: 'short' })
}
// The glow follows how safe things are right now.
const GLOW: Record<string, [string, string]> = {
  green: ['rgba(37, 99, 235, .45)', 'rgba(20, 184, 166, .28)'], amber: ['rgba(37, 82, 210, .40)', 'rgba(245, 158, 11, .30)'],
  red: ['rgba(79, 70, 229, .38)', 'rgba(239, 68, 68, .32)'], critical: ['rgba(124, 58, 237, .38)', 'rgba(220, 38, 38, .40)'],
}

const greeting = () => { const h = new Date().getHours(); return h < 12 ? 'Good morning' : h < 18 ? 'Good afternoon' : 'Good evening' }

export default function Manager() {
  const inputId = useId()
  const nav = useNavigate()
  const { me, signOut } = useSession()
  const { simple, toggle } = useSimple()
  const [hist, setHist] = useState<History | null>(null)
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [convos, setConvos] = useState<Convo[]>(loadConvos)
  const [current, setCurrent] = useState<string | null>(null)
  const [side, setSide] = useState(true)
  const [band, setBand] = useState('green')
  const [find, setFind] = useState('')
  const [renaming, setRenaming] = useState<string | null>(null)
  const [about, setAbout] = useState('')
  const [text, setText] = useState('')
  const [asking, setAsking] = useState(false)
  const [note, setNote] = useState('')
  const end = useRef<HTMLDivElement>(null)

  const load = useCallback(async () => {
    try {
      const [h, i] = await Promise.all([api<History>('/chat?limit=200'), api<Incident[]>('/incidents')])
      const next = Array.isArray(h) ? { messages: h } : h
      setHist(next); setIncidents(i)
      return next
    } catch (e) { setNote(e instanceof ApiError ? `Cyanide is not available: ${e.message}` : 'Could not reach SentrAI.') }
  }, [])
  useEffect(() => { void load() }, [load])
  useEffect(() => { saveConvos(convos) }, [convos])
  useEffect(() => {
    const risk = () => api<{ band?: string }>('/risk').then((r) => r.band && setBand(r.band)).catch(() => {})
    void risk(); const t = setInterval(risk, 20000); return () => clearInterval(t)
  }, [])
  useEffect(() => { end.current?.scrollIntoView({ block: 'end', behavior: 'smooth' }) }, [hist?.messages.length, asking])

  const ask = async (message: string) => {
    if (!message.trim() || asking) return
    const before = new Set((hist?.messages ?? []).map(key))
    let id = current
    if (!id) {
      id = `c${Date.now()}`
      const c: Convo = { id, title: message.trim().slice(0, 80), at: new Date().toISOString(), ids: [] }
      setConvos((cs) => [c, ...cs]); setCurrent(id)
    }
    setAsking(true); setNote(''); setText('')
    try { await api('/chat', { body: { operator: me?.email ?? 'dashboard', message, incident: about || null } }) }
    catch (e) { setNote(e instanceof ApiError ? `That did not go through: ${e.message}` : 'That did not go through.') }
    const next = await load()
    const added = (next?.messages ?? []).map(key).filter((x) => !before.has(x))
    const cid = id
    setConvos((cs) => cs.map((c) => (c.id === cid ? { ...c, ids: [...c.ids, ...added], at: new Date().toISOString() } : c)))
    setAsking(false)
  }

  const assistant = hist?.assistant || 'Cyanide'
  const convo = convos.find((c) => c.id === current)
  const ids = new Set(convo?.ids ?? [])
  const shown = convo ? (hist?.messages ?? []).filter((m) => ids.has(key(m))) : []
  const gone = !!convo && convo.ids.length > 0 && shown.length === 0
  const newChat = () => { setCurrent(null); setNote(''); setText('') }
  const patch = (cid: string, p: Partial<Convo>) => setConvos((cs) => cs.map((c) => (c.id === cid ? { ...c, ...p } : c)))
  const listed = convos.filter((c) => !find.trim() || c.title.toLowerCase().includes(find.trim().toLowerCase()))
    .sort((a, b) => Number(!!b.pinned) - Number(!!a.pinned) || b.at.localeCompare(a.at))
  const forget = (cid: string) => { setConvos((cs) => cs.filter((c) => c.id !== cid)); if (cid === current) newChat() }
  const chatting = shown.length > 0 || asking || gone
  const byId = Object.fromEntries(incidents.map((i) => [i.id, i]))
  const first = (me?.name || '').split(' ')[0]
  const openIncidents = incidents.filter((i) => i.status === 'open' || i.status === 'acknowledged').sort((a, b) => b.id.localeCompare(a.id))
  const full = () => { if (simple) toggle(); nav('/command') }

  const box = (
    <form onSubmit={(e) => { e.preventDefault(); void ask(text) }} className="w-full">
      <label className="sr-only" htmlFor={inputId}>Ask {assistant}</label>
      <div className="mgr-box">
        <button type="button" className="mgr-icon" title="Start a new conversation" aria-label="New conversation"
          onClick={newChat}><Plus size={18} aria-hidden /></button>
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

  const [g1, g2] = GLOW[band] ?? GLOW.green
  return (
    <div className="mgr" style={{ '--glow-a': g1, '--glow-b': g2 } as React.CSSProperties}>
      <div className="mgr-glow" aria-hidden />
      <div className="relative z-10 flex min-h-screen">
        {side && (
          <aside className="mgr-side" aria-label="Past conversations">
            <div className="flex items-center justify-between gap-2 p-3">
              <button className="mgr-top flex-1 justify-start" onClick={newChat}><SquarePen size={14} aria-hidden /> New chat</button>
              <button className="mgr-icon" onClick={() => setSide(false)} title="Hide past conversations" aria-label="Hide past conversations"><PanelLeftClose size={16} aria-hidden /></button>
            </div>
            <label className="relative mx-3 mb-1 block">
              <span className="sr-only">Search past conversations</span>
              <Search size={13} className="pointer-events-none absolute left-2 top-1/2 -translate-y-1/2 text-muted" aria-hidden />
              <input className="mgr-search mgr-search-i" value={find} onChange={(e) => setFind(e.target.value)} placeholder="Search chats" />
            </label>
            <p className="px-4 pb-1 pt-2 text-xs text-muted">Recent</p>
            <ul className="flex-1 space-y-0.5 overflow-y-auto px-2 pb-4">
              {listed.length === 0 && <li className="px-2 py-1.5 text-sm text-muted">{find ? 'No chat matches.' : 'Your conversations appear here.'}</li>}
              {listed.map((c) => (
                <li key={c.id} className={'mgr-convo' + (c.id === current ? ' is-on' : '')}>
                  {renaming === c.id ? (
                    <form className="flex-1" onSubmit={(e) => { e.preventDefault(); setRenaming(null) }}>
                      <input autoFocus className="mgr-search" aria-label="Chat name" value={c.title} maxLength={80}
                        onChange={(e) => patch(c.id, { title: e.target.value })} onBlur={() => { if (!c.title.trim()) patch(c.id, { title: 'Untitled chat' }); setRenaming(null) }}
                        onKeyDown={(e) => { if (e.key === 'Escape') setRenaming(null) }} />
                    </form>
                  ) : (
                    <button className="min-w-0 flex-1 text-left" onClick={() => { setCurrent(c.id); setNote('') }} onDoubleClick={() => setRenaming(c.id)}
                      aria-current={c.id === current ? 'true' : undefined}>
                      <span className="flex items-center gap-2">{c.pinned ? <Pin size={13} className="shrink-0 text-muted" aria-label="Pinned" /> : <MessageSquare size={13} className="shrink-0 text-muted" aria-hidden />}<span className="truncate">{c.title}</span></span>
                      <span className="block pl-5 text-[11px] text-muted">{when(c.at)}</span>
                    </button>)}
                  <button className="mgr-x" onClick={() => patch(c.id, { pinned: !c.pinned })} title={c.pinned ? 'Unpin' : 'Pin to the top'} aria-label={(c.pinned ? 'Unpin ' : 'Pin ') + c.title}>{c.pinned ? <PinOff size={13} aria-hidden /> : <Pin size={13} aria-hidden />}</button>
                  <button className="mgr-x" onClick={() => setRenaming(c.id)} title="Rename" aria-label={`Rename ${c.title}`}><Pencil size={13} aria-hidden /></button>
                  <button className="mgr-x" onClick={() => forget(c.id)} title="Delete from this list" aria-label={`Delete ${c.title} from the list`}><X size={13} aria-hidden /></button>
                </li>))}
            </ul>
            <p className="px-4 pb-3 text-[11px] text-muted">Kept in this browser only.</p>
          </aside>)}
        <div className="flex min-w-0 flex-1 flex-col">
      <header className="flex flex-wrap items-center justify-end gap-2 p-4 text-sm">
        {!side && <button className="mgr-icon mr-auto" onClick={() => setSide(true)} title="Show past conversations" aria-label="Show past conversations"><PanelLeftOpen size={16} aria-hidden /></button>}
        <AutoMode />
        <button onClick={full} className="mgr-top" title="Every page, for IT staff"><LayoutDashboard size={14} aria-hidden /> Full dashboard</button>
        <button onClick={() => void signOut()} className="mgr-top"><LogOut size={14} aria-hidden /> Sign out</button>
      </header>

      {!chatting ? (
        <main className="mx-auto flex min-h-[calc(100vh-9rem)] w-full max-w-3xl flex-col items-center justify-center gap-6 px-4">
          <h1 className="text-center text-3xl font-light tracking-tight sm:text-[2.25rem]">{greeting()}{first ? `, ${first}` : ''}. Where should we start?</h1>
          <div className="w-full max-w-2xl">{box}</div>
          {note && <p role="alert" className="text-sm text-bad">{note}</p>}
          <ul className="w-full max-w-2xl space-y-1 px-2">
            {STARTERS.map(({ q, icon: Icon }) => (
              <li key={q}><button className="mgr-starter" disabled={asking} onClick={() => void ask(q)}><Icon size={15} aria-hidden /> {q}</button></li>))}
          </ul>
        </main>
      ) : (
        <main className="mx-auto flex flex-1 w-full max-w-3xl flex-col px-4">
          <div className="flex-1 space-y-6 py-6" role="log" aria-live="polite" aria-label="Conversation">
            {shown.map((m) => m.role === 'operator' ? (
              <p key={m.id} className="ml-auto w-fit max-w-[85%] whitespace-pre-wrap rounded-2xl bg-surface-3 px-4 py-2.5">{m.text}</p>
            ) : (
              <div key={m.id} className="space-y-2">
                <p className="text-xs text-muted">{assistant}{m.incident ? ` · about ${m.incident}` : ''}</p>
                <p className="whitespace-pre-wrap leading-relaxed">{m.text}</p>
                {(m.suggestions ?? []).map((s, k) => <SuggestionCard key={k} s={s} inc={byId[String(s.incident)]} onDone={(t) => { setNote(t); void load() }} />)}
              </div>))}
            {gone && <p className="text-sm text-muted">These messages are no longer on the server (the chat was cleared or is older than it keeps). Ask again to continue.</p>}
            {asking && <p className="text-muted" role="status">{assistant} is looking into it…</p>}
            {note && <p role="status" className="text-sm text-soft">{note}</p>}
            <div ref={end} />
          </div>
          <div className="mgr-dock sticky bottom-0 pb-5 pt-8">
            {box}
            <p className="mt-2 text-center text-xs text-muted">{assistant} suggests; nothing happens until you click and the usual checks pass.</p>
          </div>
        </main>
      )}
        </div>
      </div>
    </div>
  )
}
