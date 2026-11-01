// Manager view: one page and nothing else. A greeting, one big box to ask Cyanide, a few suggested questions, and
// the answers in a single column under a soft glow. No other pages: a manager asks in plain words
// ("are we safe?") and Cyanide answers from the same live data the dashboard uses. Auto mode, the full dashboard
// and sign out stay in the top corner. Past conversations sit on the left, kept in this browser; the glow
// drifts slowly and turns warmer as the safety status worsens. Any action Cyanide suggests still needs a click and the usual checks.
import type React from 'react'
import { useCallback, useEffect, useId, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ArrowUp, BarChart3, Brain, Share2, Users, Check, FileText, Image as ImageIcon, Mic, MicOff, Square, FileDown, RotateCcw, ThumbsDown, ThumbsUp, Zap, ChevronDown, LayoutDashboard, ListChecks, LogOut, MessageSquare, PanelLeftClose, PanelLeftOpen, Pencil, Pin, PinOff, Search, Plus, ShieldQuestion, SquarePen, X } from 'lucide-react'
import { api, ApiError, stream } from '../lib/api'
import { ACCEPT, MAX_FILES, read as readFile, sizeLabel, type Attachment } from '../lib/attach'
import { canListen, listen } from '../lib/voice'
import { useSession } from '../lib/session'
import { useSimple } from '../lib/simple'
import AutoMode from './AutoMode'
import { Blocks, CopyButton, Text } from '../lib/Rich'
import { MemoryPanel, ShareDialog, SharedView, type ShareInfo } from '../lib/CyanideTeam'
import { INCIDENT_FIELDS, SuggestionCard, type Incident, type Message } from './Chat'

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

/** Attached files on a question: names and sizes (the chat keeps no content). */
function Files({ list }: { list: { name: string; kind: string; size: number }[] }) {
  return (
    <ul className="flex flex-wrap justify-end gap-2" aria-label="Attached files">
      {list.map((f, i) => (
        <li key={i} className="mgr-file">{f.kind === 'image' ? <ImageIcon size={15} aria-hidden /> : <FileText size={15} aria-hidden />}
          <span className="max-w-[12rem] truncate">{f.name}</span><span className="text-[11px] text-muted">{sizeLabel(f.size)}</span></li>))}
    </ul>
  )
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
  const [editing, setEditing] = useState<string | null>(null) // key of the question being edited
  const [draft, setDraft] = useState('')
  const [act, setAct] = useState<string | null>(null) // the suggested action whose confirm card is open
  const [why, setWhy] = useState<{ id: string | number; note: string } | null>(null) // thumbs down: what was wrong
  const [about, setAbout] = useState('')
  const [text, setText] = useState('')
  const [asking, setAsking] = useState(false)
  const [note, setNote] = useState('')
  const [live, setLive] = useState<{ question: string; files: Attachment[]; steps: string[]; text: string } | null>(null)
  const [files, setFiles] = useState<Attachment[]>([])
  const [hearing, setHearing] = useState<null | (() => void)>(null) // stops voice input while listening
  const [heard, setHeard] = useState('') // words not yet final
  const [panel, setPanel] = useState<null | 'memory' | 'share'>(null)
  const [shares, setShares] = useState<ShareInfo[]>([])
  const [viewing, setViewing] = useState<string | null>(null) // a shared chat open instead of the conversation
  const abort = useRef<AbortController | null>(null)
  const picker = useRef<HTMLInputElement>(null)
  const end = useRef<HTMLDivElement>(null)

  const load = useCallback(async () => {
    try {
      const [h, i] = await Promise.all([api<History>('/chat?limit=200'), api<Incident[]>(`/incidents?fields=${INCIDENT_FIELDS}`)])
      const next = Array.isArray(h) ? { messages: h } : h
      setHist(next); setIncidents(i)
      return next
    } catch (e) { setNote(e instanceof ApiError ? `Cyanide is not available: ${e.message}` : 'Could not reach SentrAI.') }
  }, [])
  useEffect(() => { void load() }, [load])
  const loadShares = useCallback(() => api<{ shares: ShareInfo[] }>('/chat/shares').then((r) => setShares(r.shares)).catch(() => {}), [])
  useEffect(() => { void loadShares(); const t = setInterval(loadShares, 60000); return () => clearInterval(t) }, [loadShares])
  useEffect(() => { saveConvos(convos) }, [convos])
  useEffect(() => {
    const risk = () => api<{ band?: string }>('/risk').then((r) => r.band && setBand(r.band)).catch(() => {})
    void risk(); const t = setInterval(risk, 20000); return () => clearInterval(t)
  }, [])
  useEffect(() => { end.current?.scrollIntoView({ block: 'end' }) }, [hist?.messages.length, asking, live?.text.length, live?.steps.length])
  useEffect(() => () => { abort.current?.abort() }, [])

  const attach = async (list: FileList | File[] | null) => {
    const picked = [...(list ?? [])]
    if (!picked.length) return
    const room = MAX_FILES - files.length
    if (picked.length > room) setNote(`Attach up to ${MAX_FILES} files to one question.`)
    const got: Attachment[] = []
    for (const f of picked.slice(0, Math.max(0, room))) {
      try { got.push(await readFile(f)) } catch (e) { setNote(e instanceof Error ? e.message : `Could not read ${f.name}.`) }
    }
    if (got.length) setFiles((fs) => [...fs, ...got])
  }
  const talk = () => {
    if (hearing) { hearing(); return }
    const base = text ? text.replace(/\s*$/, ' ') : ''
    setNote('')
    const stopIt = listen((final, interim) => { setText(base + final); setHeard(interim) },
      (err) => { setHearing(null); setHeard(''); if (err) setNote(err) })
    setHearing(() => stopIt)
  }

  const ask = async (message: string) => {
    if ((!message.trim() && !files.length) || asking) return
    hearing?.()
    const sending = files
    const question = message.trim() || 'What does the attached file show?'
    const before = new Set((hist?.messages ?? []).map(key))
    let id = current
    if (!id) {
      id = `c${Date.now()}`
      const c: Convo = { id, title: question.slice(0, 80), at: new Date().toISOString(), ids: [] }
      setConvos((cs) => [c, ...cs]); setCurrent(id)
    }
    setAsking(true); setNote(''); setText(''); setFiles([])
    setLive({ question, files: sending, steps: [], text: '' })
    const ctl = new AbortController(); abort.current = ctl
    let stopped = false
    try {
      await stream('/chat/stream', { operator: me?.email ?? 'dashboard', message, incident: about || null,
        attachments: sending.length ? sending.map(({ name, kind, text, media_type, data }) => ({ name, kind, text, media_type, data })) : undefined },
      (e) => {
        if (e.type === 'step') setLive((l) => l && { ...l, steps: [...l.steps, String(e.text)] })
        else if (e.type === 'text') setLive((l) => l && { ...l, text: l.text + String(e.delta) })
        else if (e.type === 'error') setNote(`That did not go through: ${String(e.detail)}`)
      }, ctl.signal)
    } catch (e) {
      if (ctl.signal.aborted) stopped = true
      else setNote(e instanceof ApiError ? `That did not go through: ${e.message}` : 'That did not go through.')
    }
    abort.current = null
    // After Stop the core needs a moment to finish the step it is on and save what was sent.
    let next = await load()
    for (let i = 0; stopped && i < 10 && (next?.messages ?? []).filter((m) => !before.has(key(m))).length < 2; i++) {
      await new Promise((r) => setTimeout(r, 400)); next = await load()
    }
    const added = (next?.messages ?? []).map(key).filter((x) => !before.has(x))
    const cid = id
    setConvos((cs) => cs.map((c) => (c.id === cid ? { ...c, ids: [...c.ids, ...added], at: new Date().toISOString() } : c)))
    setLive(null); setAsking(false)
  }

  const rate = async (m: Message, vote: 'up' | 'down' | null, note = '') => {
    try { await api(`/chat/${m.id}/feedback`, { body: { vote, note } }); await load() }
    catch (e) { setNote(e instanceof ApiError ? `Could not save that: ${e.message}` : 'Could not save that.') }
  }
  const assistant = hist?.assistant || 'Cyanide'
  const convo = convos.find((c) => c.id === current)
  const ids = new Set(convo?.ids ?? [])
  const shown = convo ? (hist?.messages ?? []).filter((m) => ids.has(key(m))) : []
  const gone = !!convo && convo.ids.length > 0 && shown.length === 0
  const newChat = () => { setCurrent(null); setViewing(null); setNote(''); setText('') }
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
    <form onSubmit={(e) => { e.preventDefault(); void ask(text) }} className="w-full"
      onDragOver={(e) => { if (e.dataTransfer.types.includes('Files')) e.preventDefault() }}
      onDrop={(e) => { if (e.dataTransfer.files.length) { e.preventDefault(); void attach(e.dataTransfer.files) } }}>
      <label className="sr-only" htmlFor={inputId}>Ask {assistant}</label>
      <input ref={picker} type="file" multiple accept={ACCEPT} className="hidden" tabIndex={-1} aria-hidden
        onChange={(e) => { void attach(e.target.files); e.target.value = '' }} />
      <div className="mgr-box flex-col !items-stretch">
        {files.length > 0 && (
          <ul className="flex flex-wrap gap-2 px-1 pt-1" aria-label="Attached files">
            {files.map((f, i) => (
              <li key={i} className="mgr-file">
                {f.kind === 'image' ? <img src={`data:${f.media_type};base64,${f.data}`} alt="" className="h-8 w-8 rounded object-cover" /> : <FileText size={16} aria-hidden />}
                <span className="min-w-0"><span className="block max-w-[10rem] truncate">{f.name}</span><span className="block text-[11px] text-muted">{sizeLabel(f.size)}</span></span>
                <button type="button" className="mgr-x !opacity-100" aria-label={`Remove ${f.name}`} onClick={() => setFiles((fs) => fs.filter((_, k) => k !== i))}><X size={13} aria-hidden /></button>
              </li>))}
          </ul>)}
        <div className="flex items-center gap-2">
          <button type="button" className="mgr-icon" title="Attach a log or a screenshot" aria-label="Attach a log or a screenshot"
            disabled={asking || files.length >= MAX_FILES} onClick={() => picker.current?.click()}><Plus size={18} aria-hidden /></button>
          <textarea id={inputId} rows={1} value={heard ? `${text}${heard}` : text} disabled={asking} placeholder={hearing ? 'Listening…' : `Ask ${assistant} anything about your security`}
            onChange={(e) => setText(e.target.value)}
            onPaste={(e) => { const pics = [...e.clipboardData.files]; if (pics.length) { e.preventDefault(); void attach(pics) } }}
            onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); void ask(text) } }} />
          <label className="mgr-pick">
            <span className="sr-only">Talk about</span>
            <select value={about} onChange={(e) => setAbout(e.target.value)}>
              <option value="">{assistant} · everything</option>
              {openIncidents.map((i) => <option key={i.id} value={i.id}>{assistant} · {i.id}</option>)}
            </select>
            <ChevronDown size={14} aria-hidden />
          </label>
          {canListen() && !asking && (
            <button type="button" className={'mgr-icon' + (hearing ? ' mgr-hearing' : '')} onClick={talk} aria-pressed={!!hearing}
              title={hearing ? 'Stop listening' : 'Speak your question (your browser may send the audio to its speech service)'}
              aria-label={hearing ? 'Stop listening' : 'Speak your question'}>{hearing ? <MicOff size={18} aria-hidden /> : <Mic size={18} aria-hidden />}</button>)}
          {asking
            ? <button type="button" className="mgr-send" onClick={() => abort.current?.abort()} aria-label="Stop" title="Stop"><Square size={14} fill="currentColor" aria-hidden /></button>
            : <button className="mgr-send" disabled={!text.trim() && !files.length} aria-label="Send"><ArrowUp size={18} aria-hidden /></button>}
        </div>
      </div>
    </form>
  )

  const dialogs = (
    <>
      {panel === 'memory' && <MemoryPanel name={assistant} onClose={() => setPanel(null)} />}
      {panel === 'share' && convo && (
        <ShareDialog title={convo.title} messageIds={shown.map((m) => m.id)} onClose={() => setPanel(null)}
          onDone={(sh) => { setPanel(null); setNote(`Shared "${sh.title}" with ${sh.to.includes('everyone') ? 'everyone' : sh.to.join(', ')}.`); void loadShares() }} />)}
    </>
  )
  const [g1, g2] = GLOW[band] ?? GLOW.green
  return (
    <div className="mgr" style={{ '--glow-a': g1, '--glow-b': g2 } as React.CSSProperties}>
      <div className="mgr-glow" aria-hidden />
      {dialogs}
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
                    <button className="min-w-0 flex-1 text-left" onClick={() => { setCurrent(c.id); setViewing(null); setNote('') }} onDoubleClick={() => setRenaming(c.id)}
                      aria-current={c.id === current ? 'true' : undefined}>
                      <span className="flex items-center gap-2">{c.pinned ? <Pin size={13} className="shrink-0 text-muted" aria-label="Pinned" /> : <MessageSquare size={13} className="shrink-0 text-muted" aria-hidden />}<span className="truncate">{c.title}</span></span>
                      <span className="block pl-5 text-[11px] text-muted">{when(c.at)}</span>
                    </button>)}
                  <button className="mgr-x" onClick={() => patch(c.id, { pinned: !c.pinned })} title={c.pinned ? 'Unpin' : 'Pin to the top'} aria-label={(c.pinned ? 'Unpin ' : 'Pin ') + c.title}>{c.pinned ? <PinOff size={13} aria-hidden /> : <Pin size={13} aria-hidden />}</button>
                  <button className="mgr-x" onClick={() => setRenaming(c.id)} title="Rename" aria-label={`Rename ${c.title}`}><Pencil size={13} aria-hidden /></button>
                  <button className="mgr-x" onClick={() => forget(c.id)} title="Delete from this list" aria-label={`Delete ${c.title} from the list`}><X size={13} aria-hidden /></button>
                </li>))}
            </ul>
            {shares.length > 0 && (
              <>
                <p className="px-4 pb-1 pt-2 text-xs text-muted">Shared</p>
                <ul className="max-h-48 space-y-0.5 overflow-y-auto px-2 pb-3">
                  {shares.map((sh) => (
                    <li key={sh.id} className={'mgr-convo' + (viewing === sh.id ? ' is-on' : '')}>
                      <button className="min-w-0 flex-1 text-left" onClick={() => setViewing(sh.id)} aria-current={viewing === sh.id ? 'true' : undefined}>
                        <span className="flex items-center gap-2"><Users size={13} className="shrink-0 text-muted" aria-hidden /><span className="truncate">{sh.title}</span></span>
                        <span className="block truncate pl-5 text-[11px] text-muted">{sh.by === me?.email ? 'you shared' : sh.by} · {when(sh.at)}</span>
                      </button>
                    </li>))}
                </ul>
              </>)}
            <div className="border-t border-line p-2">
              <button className="mgr-convo w-full" onClick={() => setPanel('memory')}><Brain size={14} aria-hidden /> What {assistant} remembers</button>
              <p className="px-2 pt-1 text-[11px] text-muted">Your chat list is kept in this browser.</p>
            </div>
          </aside>)}
        <div className="flex min-w-0 flex-1 flex-col">
      <header className="mgr-noprint flex flex-wrap items-center justify-end gap-2 p-4 text-sm">
        {!side && <button className="mgr-icon mr-auto" onClick={() => setSide(true)} title="Show past conversations" aria-label="Show past conversations"><PanelLeftOpen size={16} aria-hidden /></button>}
        {chatting && !viewing && (convo?.ids.length ?? 0) > 0 && <button onClick={() => setPanel('share')} className="mgr-top" title="Send a copy to teammates"><Share2 size={14} aria-hidden /> Share</button>}
        {chatting && <button onClick={() => window.print()} className="mgr-top" title="Save this conversation as a PDF"><FileDown size={14} aria-hidden /> Export PDF</button>}
        <AutoMode />
        <button onClick={full} className="mgr-top" title="Every page, for IT staff"><LayoutDashboard size={14} aria-hidden /> Full dashboard</button>
        <button onClick={() => void signOut()} className="mgr-top"><LogOut size={14} aria-hidden /> Sign out</button>
      </header>

      {viewing ? (
        <main className="mx-auto w-full max-w-3xl flex-1 px-4">
          <SharedView id={viewing} me={me?.email} assistant={assistant} onRemoved={() => { setViewing(null); void loadShares() }} />
        </main>
      ) : !chatting ? (
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
          <h1 className="mgr-print-title hidden pt-4 text-xl font-semibold">{convo?.title ?? 'Conversation'} · {assistant} · {convo ? when(convo.at) : ''}</h1>
          <div className="flex-1 space-y-6 py-6" role="log" aria-live="polite" aria-label="Conversation">
            {shown.map((m, n) => m.role === 'operator' ? (
              editing === key(m) ? (
                <form key={m.id} className="ml-auto w-full max-w-[85%] space-y-2" onSubmit={(e) => { e.preventDefault(); setEditing(null); void ask(draft) }}>
                  <label className="sr-only" htmlFor={`${inputId}-edit`}>Edit your question</label>
                  <textarea id={`${inputId}-edit`} autoFocus rows={2} className="w-full rounded-2xl border border-line bg-surface-3 px-4 py-2.5 text-ink"
                    value={draft} onChange={(e) => setDraft(e.target.value)} onKeyDown={(e) => { if (e.key === 'Escape') setEditing(null) }} />
                  <div className="flex justify-end gap-2 text-sm">
                    <button type="button" className="mgr-top" onClick={() => setEditing(null)}>Cancel</button>
                    <button className="mgr-top bg-surface-3" disabled={!draft.trim() || asking}>Send</button>
                  </div>
                </form>
              ) : (
                <div key={m.id} className="group ml-auto flex w-fit max-w-[85%] items-start gap-1">
                  <span className="mgr-noprint flex opacity-0 transition-opacity group-hover:opacity-100 group-focus-within:opacity-100">
                    <CopyButton text={m.text} label="Copy question" />
                    <button type="button" className="rich-tool" title="Edit and send again" aria-label="Edit and send again" disabled={asking}
                      onClick={() => { setEditing(key(m)); setDraft(m.text) }}><Pencil size={14} aria-hidden /></button>
                  </span>
                  <div className="space-y-2">
                    {(m.attachments?.length ?? 0) > 0 && <Files list={m.attachments!} />}
                    <p className="whitespace-pre-wrap rounded-2xl bg-surface-3 px-4 py-2.5">{m.text}</p>
                  </div>
                </div>)
            ) : (
              <div key={m.id} className="space-y-3">
                <p className="text-xs text-muted">{assistant}{m.incident ? ` · about ${m.incident}` : ''}</p>
                <Text md={m.text} />
                <Blocks blocks={m.blocks} onOpen={(id) => void ask(`Explain ${id} in plain words`)} />
                {(m.suggestions?.length ?? 0) > 0 && (
                  <div className="mgr-noprint space-y-2">
                    <div className="flex flex-wrap gap-2" role="group" aria-label="Suggested actions">
                      {m.suggestions!.map((s, k) => {
                        const id = `${key(m)}#${k}`
                        return <button key={k} type="button" className={'mgr-act' + (act === id ? ' is-on' : '')} aria-expanded={act === id}
                          onClick={() => setAct(act === id ? null : id)}><Zap size={13} aria-hidden /> {s.label || `${s.decision} ${s.incident}`}</button>
                      })}
                    </div>
                    {m.suggestions!.map((s, k) => act === `${key(m)}#${k}` && (
                      <SuggestionCard key={k} s={s} inc={byId[String(s.incident)]} onDone={(t) => { setAct(null); setNote(t); void load() }} />))}
                  </div>)}
                <div className="mgr-noprint flex items-center gap-0.5 text-muted">
                  <CopyButton text={m.text} label="Copy answer" />
                  <button type="button" className="rich-tool" title="Ask again for a fresh answer" aria-label="Retry" disabled={asking || !(m.question || shown[n - 1]?.text)}
                    onClick={() => void ask(m.question || shown[n - 1]?.text || '')}><RotateCcw size={14} aria-hidden /></button>
                  <button type="button" className={'rich-tool' + (m.feedback?.vote === 'up' ? ' is-on' : '')} aria-pressed={m.feedback?.vote === 'up'}
                    title="Good answer" aria-label="Good answer" onClick={() => void rate(m, m.feedback?.vote === 'up' ? null : 'up')}>
                    <ThumbsUp size={14} fill={m.feedback?.vote === 'up' ? 'currentColor' : 'none'} aria-hidden /></button>
                  <button type="button" className={'rich-tool' + (m.feedback?.vote === 'down' ? ' is-on' : '')} aria-pressed={m.feedback?.vote === 'down'}
                    title="Not helpful" aria-label="Not helpful" onClick={() => (m.feedback?.vote === 'down' ? void rate(m, null) : setWhy({ id: m.id, note: '' }))}>
                    <ThumbsDown size={14} fill={m.feedback?.vote === 'down' ? 'currentColor' : 'none'} aria-hidden /></button>
                </div>
                {why?.id === m.id && (
                  <form className="mgr-noprint rich-frame flex flex-wrap items-center gap-2 p-2 text-sm" onSubmit={(e) => { e.preventDefault(); void rate(m, 'down', why.note); setWhy(null) }}>
                    <label className="min-w-0 flex-1"><span className="sr-only">What was wrong? (optional)</span>
                      <input autoFocus className="mgr-search" placeholder="What was wrong? (optional, helps tuning)" value={why.note} maxLength={500}
                        onChange={(e) => setWhy({ id: m.id, note: e.target.value })} onKeyDown={(e) => { if (e.key === 'Escape') setWhy(null) }} /></label>
                    <button type="button" className="mgr-top" onClick={() => setWhy(null)}>Cancel</button>
                    <button className="mgr-top">Send</button>
                  </form>)}
                {n === shown.length - 1 && !asking && (m.followups?.length ?? 0) > 0 && (
                  <div className="mgr-noprint flex flex-wrap gap-2">
                    {m.followups!.map((q) => <button key={q} className="mgr-chip" onClick={() => void ask(q)}>{q}</button>)}
                  </div>)}
              </div>))}
            {gone && <p className="text-sm text-muted">These messages are no longer on the server (the chat was cleared or is older than it keeps). Ask again to continue.</p>}
            {live && (
              <>
                <div className="ml-auto w-fit max-w-[85%] space-y-2">
                  {live.files.length > 0 && <Files list={live.files} />}
                  <p className="whitespace-pre-wrap rounded-2xl bg-surface-3 px-4 py-2.5">{live.question}</p>
                </div>
                <div className="space-y-3" aria-busy="true">
                  <p className="text-xs text-muted">{assistant}</p>
                  {!live.text && (
                    <ul className="space-y-1 text-sm text-muted" role="status">
                      {(live.steps.length ? live.steps : ['Thinking']).map((t, i, all) => (
                        <li key={i} className="flex items-center gap-2">{i === all.length - 1 ? <span className="mgr-dot" aria-hidden /> : <Check size={13} aria-hidden />}{t}…</li>))}
                    </ul>)}
                  {live.text && <Text md={live.text + ' ▍'} />}
                </div>
              </>)}
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
