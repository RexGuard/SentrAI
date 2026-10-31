// Guided setup on the Chat page: Cyanide asks the setup questions one at a time (core ui_setup.py / setup_chat.py).
// The conversation lives on the core for the signed-in person, never in the chat history: some answers are secrets.
import { useEffect, useRef, useState, type FormEvent } from 'react'
import { MessagesSquare, Send, X } from 'lucide-react'
import { api, ApiError } from '../lib/api'
import { btn, btnPrimary } from '../lib/ui'

export type Setup = {
  active: boolean; done: boolean; assistant: string; state?: string; secret?: boolean
  messages?: { role: string; text: string }[]; options?: { value: string; label: string }[]
}

export function SetupBanner({ setup, onChange, later, onLater }: { setup: Setup; onChange: (s: Setup) => void; later: boolean; onLater: () => void }) {
  const [err, setErr] = useState('')
  if (setup.active || setup.done || later) return null
  const start = () => api<Setup>('/ui/setup/start', { body: {} }).then(onChange).catch((e) => setErr(e instanceof ApiError ? e.message : 'Could not start setup.'))
  return (
    <div className="flex flex-wrap items-center gap-3 rounded-lg border border-line bg-surface p-3">
      <p className="min-w-0 flex-1"><b>New here?</b> {setup.assistant} can set SentrAI up with you in a few plain questions, so you don't need the Configuration page.</p>
      {err && <p role="alert" className="text-sm text-bad">{err}</p>}
      <button className={btnPrimary} onClick={() => void start()}><MessagesSquare size={14} aria-hidden /> Set up with {setup.assistant}</button>
      <button className={btn} onClick={onLater}>Not now</button>
    </div>
  )
}

export function SetupConversation({ setup, onChange, onLeave }: { setup: Setup; onChange: (s: Setup) => void; onLeave: () => void }) {
  const [text, setText] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const end = useRef<HTMLDivElement>(null)
  const messages = setup.messages ?? []
  useEffect(() => { end.current?.scrollIntoView({ block: 'end' }) }, [messages.length, busy])
  const send = async (answer: string) => {
    if (!answer.trim() || busy) return
    setBusy(true); setErr(''); setText('')
    try { onChange(await api<Setup>('/ui/setup/answer', { body: { text: answer } })) }
    catch (e) { setErr(e instanceof ApiError ? e.message : 'That did not go through.') }
    setBusy(false)
  }
  const leave = async () => { try { await api('/ui/setup/leave', { body: {} }) } catch { /* leaving is local anyway */ } onLeave() }
  const finished = setup.state === 'saved' || setup.state === 'cancelled'
  const asking = setup.state === 'asking' || setup.state === 'review'
  const last = messages.length - 1
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-3">
        <p className="min-w-0 flex-1 text-sm text-muted">Guided setup · nothing is saved until you confirm the summary · the Configuration page shows the same settings</p>
        <button className={btn} onClick={() => void leave()}><X size={14} aria-hidden /> {finished ? 'Close setup' : 'Leave setup'}</button>
      </div>
      <div className="h-[28rem] space-y-4 overflow-y-auto rounded-lg border border-line bg-surface p-4" role="log" aria-live="polite" aria-label="Guided setup" tabIndex={0}>
        {messages.map((m, n) => {
          const mine = m.role === 'user'
          return (
            <div key={n} className={'max-w-[85%] space-y-2 rounded-lg p-3 ' + (mine ? 'ml-auto bg-surface-3' : 'bg-surface-2')}>
              <p className="text-xs text-muted">{mine ? 'You' : setup.assistant}</p>
              <p className="whitespace-pre-wrap break-words">{m.text}</p>
              {n === last && !mine && setup.options?.length ? (
                <div className="flex flex-wrap gap-2 pt-1">
                  {setup.options.map((o, k) => (
                    <button key={o.value} className={k === 0 && setup.state === 'review' ? btnPrimary : btn} disabled={busy} onClick={() => void send(o.value)}>{o.label}</button>))}
                </div>) : null}
            </div>
          )
        })}
        {busy && <p className="text-muted" role="status">{setup.assistant} is reading your answer…</p>}
        <div ref={end} />
      </div>
      {err && <p role="alert" className="text-sm text-bad">{err}</p>}
      {asking && (
        <form className="flex gap-2" onSubmit={(e: FormEvent) => { e.preventDefault(); void send(text) }}>
          <label className="sr-only" htmlFor="setup-input">{setup.secret ? 'Your answer (hidden; it is never shown in the chat)' : 'Your answer'}</label>
          <input id="setup-input" key={messages.length} type={setup.secret ? 'password' : 'text'} autoComplete="off" value={text} onChange={(e) => setText(e.target.value)} disabled={busy}
            placeholder={setup.secret ? 'Your answer (hidden; it is never shown in the chat)' : 'Type your answer…'}
            className="min-w-0 flex-1 rounded-md border border-line bg-surface-2 px-3 py-2 text-ink placeholder:text-muted" />
          <button className={btnPrimary} disabled={busy || !text.trim()}><Send size={14} aria-hidden /> Send</button>
        </form>
      )}
    </div>
  )
}
