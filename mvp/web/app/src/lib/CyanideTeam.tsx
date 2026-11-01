// Cyanide's memory and shared chats, for the Manager view. Memory: standing instructions (Owner, Admin) and facts
// the team taught it, read before every answer. Shared chats: read-only copies sent to teammates or everyone.
import { useCallback, useEffect, useId, useState, type ReactNode } from 'react'
import { Brain, Share2, Trash2, Users, X } from 'lucide-react'
import { api, ApiError } from './api'
import { useSession } from './session'
import { Blocks, Text } from './Rich'
import type { Message } from '../pages/Chat'

type Fact = { id: string; text: string; by: string; at: string }
type Mem = { instructions: string; facts: Fact[]; updated_at?: string; updated_by?: string }
export type ShareInfo = { id: string; title: string; by: string; at: string; to: string[]; note?: string; count: number }

const err = (e: unknown, what: string) => (e instanceof ApiError ? `${what}: ${e.message}` : `${what}.`)
const day = (iso: string) => new Date(iso).toLocaleDateString([], { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' })

function Panel({ title, icon: Icon, onClose, children }: { title: string; icon: typeof Brain; onClose: () => void; children: ReactNode }) {
  const id = useId()
  useEffect(() => {
    const esc = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', esc); return () => window.removeEventListener('keydown', esc)
  }, [onClose])
  return (
    <div className="fixed inset-0 z-40 grid place-items-center bg-black/50 p-4" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose() }}>
      <section role="dialog" aria-modal="true" aria-labelledby={id} className="rich-frame max-h-[85vh] w-full max-w-lg overflow-y-auto !bg-[var(--surface)] p-5 shadow-2xl">
        <header className="mb-4 flex items-center gap-2">
          <Icon size={18} aria-hidden /><h2 id={id} className="text-lg font-semibold">{title}</h2>
          <button className="rich-tool ml-auto" onClick={onClose} aria-label="Close"><X size={16} aria-hidden /></button>
        </header>
        {children}
      </section>
    </div>
  )
}

const field = 'mgr-search !py-2 !text-sm'

export function MemoryPanel({ name, onClose }: { name: string; onClose: () => void }) {
  const { can } = useSession()
  const [mem, setMem] = useState<Mem | null>(null)
  const [draft, setDraft] = useState('')
  const [fact, setFact] = useState('')
  const [note, setNote] = useState('')
  const load = useCallback(async () => {
    try { const m = await api<Mem>('/chat/memory'); setMem(m); setDraft(m.instructions) } catch (e) { setNote(err(e, 'Could not load the memory')) }
  }, [])
  useEffect(() => { void load() }, [load])
  const run = async (fn: () => Promise<unknown>, done: string) => {
    setNote('')
    try { await fn(); await load(); setNote(done) } catch (e) { setNote(err(e, 'That did not go through')) }
  }
  const configure = can('configure'), act = can('act')
  return (
    <Panel title={`What ${name} remembers`} icon={Brain} onClose={onClose}>
      {!mem ? <p className="text-muted" role="status">Loading…</p> : (
        <div className="space-y-5 text-sm">
          <form className="space-y-2" onSubmit={(e) => { e.preventDefault(); void run(() => api('/chat/memory', { body: { instructions: draft } }), 'Instructions saved.') }}>
            <label className="block font-medium">Standing instructions
              <span className="block text-xs font-normal text-muted">How {name} should answer everyone, in every chat.</span>
              <textarea rows={3} maxLength={2000} className={field + ' mt-1 resize-y'} value={draft} disabled={!configure}
                placeholder="e.g. Answer in plain words; our managers are not IT people. Mention costs when you suggest a fix."
                onChange={(e) => setDraft(e.target.value)} />
            </label>
            {configure
              ? <button className="mgr-top" disabled={draft === mem.instructions}>Save instructions</button>
              : <p className="text-xs text-muted">Only an Owner or an Admin can change these.</p>}
          </form>
          <div className="space-y-2">
            <p className="font-medium">Things the team told {name}</p>
            {mem.facts.length === 0 && <p className="text-muted">Nothing yet. Add one below, or start a chat message with "Remember that".</p>}
            <ul className="space-y-1">
              {mem.facts.map((f) => (
                <li key={f.id} className="flex items-start gap-2 rounded-lg bg-surface-2 px-3 py-2">
                  <span className="min-w-0 flex-1">{f.text}<span className="block text-[11px] text-muted">{f.by} · {day(f.at)}</span></span>
                  {act && <button className="rich-tool" aria-label={`Forget: ${f.text}`} title="Forget"
                    onClick={() => void run(() => api(`/chat/memory/facts/${f.id}`, { method: 'DELETE' }), 'Forgotten.')}><Trash2 size={14} aria-hidden /></button>}
                </li>))}
            </ul>
            {act && (
              <form className="flex gap-2" onSubmit={(e) => { e.preventDefault(); if (fact.trim()) void run(async () => { await api('/chat/memory/facts', { body: { text: fact } }); setFact('') }, 'Remembered.') }}>
                <label className="min-w-0 flex-1"><span className="sr-only">Something to remember</span>
                  <input className={field} value={fact} maxLength={300} placeholder="e.g. rexguard is our game server" onChange={(e) => setFact(e.target.value)} /></label>
                <button className="mgr-top" disabled={!fact.trim()}>Remember</button>
              </form>)}
          </div>
          {note && <p role="status" className="text-soft">{note}</p>}
          <p className="text-xs text-muted">Everyone's chats with {name} use this. When an AI model is set up, it is sent to that provider with each question.</p>
        </div>)}
    </Panel>
  )
}

export function ShareDialog({ title, messageIds, onClose, onDone }: { title: string; messageIds: (string | number)[]; onClose: () => void; onDone: (s: ShareInfo) => void }) {
  const [who, setWho] = useState<'everyone' | 'people'>('everyone')
  const [emails, setEmails] = useState('')
  const [note, setNote] = useState('')
  const [error, setError] = useState('')
  const share = async () => {
    setError('')
    const to = who === 'everyone' ? ['everyone'] : emails.split(/[\s,;]+/).filter(Boolean)
    if (!to.length) return setError('Type at least one email address.')
    try { onDone(await api<ShareInfo>('/chat/shares', { body: { title, message_ids: messageIds, to, note } })) }
    catch (e) { setError(err(e, 'Could not share')) }
  }
  return (
    <Panel title="Share this chat" icon={Share2} onClose={onClose}>
      <form className="space-y-3 text-sm" onSubmit={(e) => { e.preventDefault(); void share() }}>
        <p className="text-soft">Teammates get a read-only copy of <b>{title}</b> ({messageIds.length} messages) under "Shared" in their chat list.</p>
        <fieldset className="space-y-1">
          <legend className="sr-only">Share with</legend>
          <label className="flex items-center gap-2"><input type="radio" checked={who === 'everyone'} onChange={() => setWho('everyone')} /> Everyone on the team</label>
          <label className="flex items-center gap-2"><input type="radio" checked={who === 'people'} onChange={() => setWho('people')} /> Only these people</label>
        </fieldset>
        {who === 'people' && <label className="block">Their dashboard email addresses<input autoFocus className={field + ' mt-1'} value={emails} onChange={(e) => setEmails(e.target.value)} placeholder="sam@example.com, lee@example.com" /></label>}
        <label className="block">Note (optional)<input className={field + ' mt-1'} value={note} maxLength={300} onChange={(e) => setNote(e.target.value)} placeholder="e.g. Can you check the second incident?" /></label>
        {error && <p role="alert" className="text-bad">{error}</p>}
        <div className="flex justify-end gap-2"><button type="button" className="mgr-top" onClick={onClose}>Cancel</button><button className="mgr-top bg-surface-3"><Share2 size={14} aria-hidden /> Share</button></div>
      </form>
    </Panel>
  )
}

/** A shared chat, read-only, in place of the conversation. */
export function SharedView({ id, me, assistant, onRemoved }: { id: string; me?: string; assistant: string; onRemoved: () => void }) {
  const { can } = useSession()
  const [share, setShare] = useState<(ShareInfo & { messages: Message[] }) | null>(null)
  const [note, setNote] = useState('')
  useEffect(() => {
    let live = true
    api<ShareInfo & { messages: Message[] }>(`/chat/shares/${id}`).then((s) => live && setShare(s)).catch((e) => live && setNote(err(e, 'Could not open it')))
    return () => { live = false }
  }, [id])
  if (!share) return <p className="py-10 text-center text-muted" role="status">{note || 'Opening…'}</p>
  return (
    <div className="space-y-6 py-6">
      <div className="rich-frame flex flex-wrap items-center gap-2 p-3 text-sm">
        <Users size={15} className="text-muted" aria-hidden />
        <span><b>{share.title}</b> · shared by {share.by === me ? 'you' : share.by} with {share.to.includes('everyone') ? 'everyone' : share.to.join(', ')} · {day(share.at)}</span>
        {(share.by === me || can('people')) && (
          <button className="rich-tool ml-auto" title="Remove this shared copy" aria-label="Remove this shared copy"
            onClick={() => void api(`/chat/shares/${id}`, { method: 'DELETE' }).then(onRemoved).catch((e) => setNote(err(e, 'Could not remove it')))}><Trash2 size={14} aria-hidden /></button>)}
        {share.note && <p className="basis-full text-soft">“{share.note}”</p>}
      </div>
      {share.messages.map((m) => m.role === 'operator' ? (
        <p key={m.id} className="ml-auto w-fit max-w-[85%] whitespace-pre-wrap rounded-2xl bg-surface-3 px-4 py-2.5">{m.text}<span className="block text-[11px] text-muted">{m.operator}</span></p>
      ) : (
        <div key={m.id} className="space-y-3">
          <p className="text-xs text-muted">{assistant}</p>
          <Text md={m.text} />
          <Blocks blocks={m.blocks} />
        </div>))}
      {note && <p role="status" className="text-sm text-soft">{note}</p>}
      <p className="text-center text-xs text-muted">A copy from {day(share.at)}. Buttons from the original answers are left out; ask {assistant} again for live data.</p>
    </div>
  )
}
