// Company Rules: the business teaches SentrAI about itself. Guides (policies, handbooks, how-tos) and quick facts
// (IT contact, how to report, approved and not-allowed apps, important systems). Sentry's answers, the Security
// Coach's notes and the phone app then use the company's own rules. Nothing is "trained": SentrAI looks up the few
// passages that match each question (core/app/knowledge.py). Changing anything needs Owner or Admin.
import { useCallback, useEffect, useRef, useState } from 'react'
import { BookMarked, FileUp, Link2, MessageCircleQuestion, Plus, Trash2, Type } from 'lucide-react'
import { api, ApiError } from '../lib/api'
import { btn, btnPrimary } from '../lib/ui'
import { useSession } from '../lib/session'
import { ask } from '../lib/notice'

type Guide = { id: string; kind: 'file' | 'text' | 'link'; title: string; source: string; url: string; by: string; at: string; for_staff: boolean; chars: number; passages: number }
type System = { name: string; what: string; looks_after: string; importance: 'critical' | 'important' | 'normal' }
type Facts = { it_contact: string; report_how: string; allowed_apps: string[]; blocked_apps: string[]; systems: System[]; extra: string; updated_at?: string }
type Page = { guides: Guide[]; facts: Facts; passages: number; empty: boolean; limits: { guides: number; file_mb: number } }
type Answer = { found: boolean; text: string; passages: { guide: string; title: string; text: string; url: string }[]; help: string }

const card = 'rounded-lg border border-line bg-surface p-4'
const field = 'mt-1 block w-full rounded-md border border-line bg-transparent px-2 py-1'
const IMPORTANCE: Record<System['importance'], string> = { critical: 'Critical', important: 'Important', normal: 'Normal' }
const KIND_ICON = { file: FileUp, text: Type, link: Link2 }

function toBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const r = new FileReader()
    r.onload = () => resolve(String(r.result).split(',', 2)[1] ?? '')
    r.onerror = () => reject(new Error('Could not read that file.'))
    r.readAsDataURL(file)
  })
}

export default function Rules() {
  const { can } = useSession()
  const off = !can('configure')
  const [page, setPage] = useState<Page | null>(null)
  const [facts, setFacts] = useState<Facts | null>(null)
  const [error, setError] = useState('')
  const [note, setNote] = useState('')
  const [mode, setMode] = useState<'file' | 'text' | 'link'>('file')
  const [title, setTitle] = useState('')
  const [text, setText] = useState('')
  const [url, setUrl] = useState('')
  const [forStaff, setForStaff] = useState(true)
  const [busy, setBusy] = useState(false)
  const [q, setQ] = useState('')
  const [answer, setAnswer] = useState<Answer | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)

  const load = useCallback(async () => {
    try { const p = await api<Page>('/ui/knowledge'); setPage(p); setFacts(p.facts); setError('') }
    catch (e) { setError(e instanceof ApiError ? e.message : 'Could not reach SentrAI.') }
  }, [])
  useEffect(() => { void load() }, [load])

  const fail = (e: unknown, what: string) => setError(e instanceof ApiError || e instanceof Error ? e.message : what)

  const addGuide = async () => {
    setError(''); setNote(''); setBusy(true)
    try {
      let body: Record<string, unknown> = { kind: mode, title: title.trim(), for_staff: forStaff }
      if (mode === 'file') {
        const f = fileRef.current?.files?.[0]
        if (!f) throw new Error('Pick a file first.')
        if (f.size > (page?.limits.file_mb ?? 5) * 1024 * 1024) throw new Error(`That file is bigger than ${page?.limits.file_mb ?? 5} MB.`)
        body = { ...body, name: f.name, content_base64: await toBase64(f) }
      } else if (mode === 'link') body = { ...body, url: url.trim(), text }
      else body = { ...body, text }
      const g = await api<Guide & { replaced: boolean }>('/ui/knowledge/guides', { body })
      setNote(`${g.replaced ? 'Updated' : 'Learned'} “${g.title}”. Sentry, the Security Coach and the phone app use it from now on.`)
      setTitle(''); setText(''); setUrl(''); if (fileRef.current) fileRef.current.value = ''
      await load()
    } catch (e) { fail(e, 'Could not add that.') } finally { setBusy(false) }
  }

  const remove = async (g: Guide) => {
    const ok = await ask({ title: `Remove “${g.title}”?`, body: 'SentrAI forgets it right away. Sentry, the coach and the phone app stop using it.', confirm: 'Remove', danger: true })
    if (ok === null) return
    try { await api(`/ui/knowledge/guides/${g.id}`, { method: 'DELETE' }); setNote(`Removed “${g.title}”.`); await load() }
    catch (e) { fail(e, 'Could not remove it.') }
  }

  const saveFacts = async () => {
    if (!facts) return
    setError(''); setNote('')
    try {
      const p = await api<Page>('/ui/knowledge/facts', { body: { ...facts, systems: facts.systems.filter((s) => s.name.trim()) } })
      setPage(p); setFacts(p.facts); setNote('Saved. SentrAI uses these facts from now on.')
    } catch (e) { fail(e, 'Could not save.') }
  }

  const tryIt = async () => {
    if (!q.trim()) return
    try { setAnswer(await api<Answer>('/ui/knowledge/ask?' + new URLSearchParams({ q: q.trim(), staff: 'true' }))) }
    catch (e) { fail(e, 'Could not look that up.') }
  }

  if (!page || !facts) return <section className="space-y-4"><h1 className="text-2xl font-semibold">Company Rules</h1>{error ? <p role="alert" className="text-bad">{error}</p> : <p className="text-muted" role="status">Loading…</p>}</section>
  const set = (patch: Partial<Facts>) => setFacts({ ...facts, ...patch })
  const setSystem = (i: number, patch: Partial<System>) => set({ systems: facts.systems.map((s, j) => (j === i ? { ...s, ...patch } : s)) })
  const list = (v: string) => v.split(/[,\n]/).map((x) => x.trim()).filter(Boolean)

  return (
    <section className="space-y-5">
      <header>
        <h1 className="flex items-center gap-2 text-2xl font-semibold"><BookMarked size={22} aria-hidden /> Company Rules</h1>
        <p className="text-sm text-muted">Teach SentrAI how your company does things. Sentry’s answers, the coach’s notes to staff and the phone app then follow your rules, not only general advice.</p>
      </header>
      {error && <p role="alert" className="rounded-md border border-line bg-surface p-3 text-bad">{error}</p>}
      {note && <p role="status" className="rounded-md border border-line bg-surface p-3">{note}</p>}

      <p className="rounded-md border border-line bg-surface p-3 text-sm text-soft">
        How it works: SentrAI keeps your guides on your own panel and splits them into short passages. When someone asks a question, or the coach writes a note, SentrAI finds the few passages that match and quotes them, saying which guide they came from. Nothing is sent away to be learned, and removing a guide removes it everywhere at once.
      </p>

      <div className="grid gap-4 lg:grid-cols-[3fr_2fr]">
        <div className={card}>
          <h2 className="mb-1 font-semibold">1. Your guides</h2>
          <p className="mb-3 text-sm text-muted">Security policy, staff handbook, how to work from home, what to do if a laptop is lost. Word, PDF, text or web page files, up to {page.limits.file_mb} MB each.</p>
          <div className="mb-3 flex flex-wrap gap-2" role="tablist">
            {([['file', 'Upload a file', FileUp], ['text', 'Type a rule', Type], ['link', 'Add a link', Link2]] as const).map(([k, label, Icon]) => (
              <button key={k} role="tab" aria-selected={mode === k} className={mode === k ? btnPrimary : btn} onClick={() => setMode(k)}><Icon size={14} aria-hidden /> {label}</button>))}
          </div>
          <div className="space-y-2">
            {mode === 'file' && <label className="block text-sm">File<input ref={fileRef} type="file" disabled={off} accept=".pdf,.docx,.txt,.md,.csv,.html,.htm" className="mt-1 block w-full text-sm" /></label>}
            {mode === 'link' && <label className="block text-sm">Web address<input type="url" value={url} disabled={off} onChange={(e) => setUrl(e.target.value)} className={field} placeholder="https://intranet.yourcompany.com/security" /></label>}
            <label className="block text-sm">Name {mode === 'file' && <span className="text-muted">(leave empty to use the file’s name)</span>}<input value={title} disabled={off} onChange={(e) => setTitle(e.target.value)} className={field} placeholder={mode === 'text' ? 'For example: Working from home' : 'For example: Staff handbook'} /></label>
            {mode !== 'file' && <label className="block text-sm">{mode === 'link' ? 'What the page says, in a few lines (SentrAI never opens the link)' : 'The rule'}<textarea value={text} disabled={off} rows={4} onChange={(e) => setText(e.target.value)} className={field} placeholder={mode === 'text' ? 'For example: Only use the office VPN on public wifi. Never save customer files on a personal laptop.' : ''} /></label>}
            <label className="flex items-start gap-2 text-sm"><input type="checkbox" className="mt-1 accent-[var(--accent)]" disabled={off} checked={forStaff} onChange={() => setForStaff(!forStaff)} /><span>Staff can see it<span className="block text-xs text-muted">Off: Sentry uses it for owners and admins, but the coach and the phone app never quote it.</span></span></label>
            <button className={btnPrimary} disabled={off || busy} onClick={() => void addGuide()}><Plus size={14} aria-hidden /> {busy ? 'Reading…' : 'Teach SentrAI'}</button>
          </div>
          <ul className="mt-4 divide-y divide-line-soft">
            {!page.guides.length && <li className="py-2 text-sm text-muted">No guides yet. Until you add some, SentrAI gives general advice.</li>}
            {page.guides.map((g) => { const Icon = KIND_ICON[g.kind]; return (
              <li key={g.id} className="flex items-start justify-between gap-2 py-2 text-sm">
                <span className="min-w-0">
                  <span className="flex items-center gap-1.5 font-medium"><Icon size={14} aria-hidden className="shrink-0 text-muted" /> {g.url ? <a href={g.url} target="_blank" rel="noreferrer noopener">{g.title}</a> : g.title}</span>
                  <span className="block text-xs text-muted">{g.passages} passage{g.passages === 1 ? '' : 's'} · added {g.at.slice(0, 10)} by {g.by}{g.for_staff ? '' : ' · owners and admins only'}</span>
                </span>
                <button className={btn} disabled={off} onClick={() => void remove(g)} aria-label={`Remove ${g.title}`}><Trash2 size={14} aria-hidden /></button>
              </li>) })}
          </ul>
        </div>

        <div className={card}>
          <h2 className="mb-1 flex items-center gap-2 font-semibold"><MessageCircleQuestion size={16} aria-hidden /> Try a question</h2>
          <p className="mb-3 text-sm text-muted">See what a member of staff would get in the phone app.</p>
          <div className="flex gap-2">
            <input value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter') void tryIt() }} className={field + ' mt-0'} placeholder="Can I use WhatsApp for work?" aria-label="Question" />
            <button className={btn} onClick={() => void tryIt()}>Ask</button>
          </div>
          {answer && (
            <div className="mt-3 space-y-2 text-sm">
              <p className="whitespace-pre-line">{answer.text.replace(/\*\*/g, '')}</p>
              {answer.passages.map((p, i) => (
                <blockquote key={i} className="rounded-md border border-line-soft p-2 text-soft">{p.text}<span className="mt-1 block text-xs text-muted">From “{p.title}”</span></blockquote>))}
              {answer.help && <p className="text-muted">{answer.help}</p>}
            </div>)}
        </div>
      </div>

      <div className={card}>
        <h2 className="mb-1 font-semibold">2. Quick facts</h2>
        <p className="mb-3 text-sm text-muted">Short answers SentrAI should always know. The coach adds your IT contact to its notes, and checks apps against your lists.</p>
        <div className="grid gap-3 md:grid-cols-2">
          <label className="text-sm">Who staff ask for IT or security help<input value={facts.it_contact} disabled={off} onChange={(e) => set({ it_contact: e.target.value })} className={field} placeholder="Maria in IT, maria@yourcompany.com, +65 ..." /></label>
          <label className="text-sm">How to report something suspicious<input value={facts.report_how} disabled={off} onChange={(e) => set({ report_how: e.target.value })} className={field} placeholder="Tap “Something looks wrong” in the SentrAI app" /></label>
          <label className="text-sm">Apps staff may use for work<textarea rows={2} defaultValue={facts.allowed_apps.join(', ')} key={'a' + (facts.updated_at ?? '')} disabled={off} onBlur={(e) => set({ allowed_apps: list(e.target.value) })} className={field} placeholder="Slack, Google Drive, Bitwarden" /></label>
          <label className="text-sm">Apps staff must not use for work<textarea rows={2} defaultValue={facts.blocked_apps.join(', ')} key={'b' + (facts.updated_at ?? '')} disabled={off} onBlur={(e) => set({ blocked_apps: list(e.target.value) })} className={field} placeholder="WhatsApp, WeTransfer, personal Dropbox" /></label>
        </div>
        <h3 className="mb-1 mt-4 text-sm font-semibold">Important systems</h3>
        <p className="mb-2 text-xs text-muted">The things your business runs on, so Sentry knows what matters most (for example your accounts software, online shop or customer list).</p>
        <div className="space-y-2">
          {facts.systems.map((s, i) => (
            <div key={i} className="grid gap-2 rounded-md border border-line-soft p-2 md:grid-cols-[1fr_2fr_1fr_1fr_auto]">
              <input aria-label="Name" value={s.name} disabled={off} onChange={(e) => setSystem(i, { name: e.target.value })} className={field + ' mt-0'} placeholder="Xero" />
              <input aria-label="What it is for" value={s.what} disabled={off} onChange={(e) => setSystem(i, { what: e.target.value })} className={field + ' mt-0'} placeholder="Accounts and invoices" />
              <input aria-label="Who looks after it" value={s.looks_after} disabled={off} onChange={(e) => setSystem(i, { looks_after: e.target.value })} className={field + ' mt-0'} placeholder="Finance team" />
              <select aria-label="How important" value={s.importance} disabled={off} onChange={(e) => setSystem(i, { importance: e.target.value as System['importance'] })} className={field + ' mt-0'}>
                {Object.entries(IMPORTANCE).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
              </select>
              <button className={btn} disabled={off} aria-label={`Remove ${s.name || 'system'}`} onClick={() => set({ systems: facts.systems.filter((_, j) => j !== i) })}><Trash2 size={14} aria-hidden /></button>
            </div>))}
          <button className={btn} disabled={off} onClick={() => set({ systems: [...facts.systems, { name: '', what: '', looks_after: '', importance: 'important' }] })}><Plus size={14} aria-hidden /> Add a system</button>
        </div>
        <label className="mt-4 block text-sm">Anything else SentrAI should know<textarea rows={3} value={facts.extra} disabled={off} onChange={(e) => set({ extra: e.target.value })} className={field} placeholder="We close at 6pm. Nobody should sign in at night except the night shift at the warehouse." /></label>
        <div className="mt-3"><button className={btnPrimary} disabled={off} onClick={() => void saveFacts()}>Save quick facts</button>{off && <span className="ml-2 text-xs text-muted">Only an Owner or Admin can change these.</span>}</div>
      </div>
    </section>
  )
}
