import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react'
import Stat from '../lib/Stat'
import { Link } from 'react-router-dom'
import { Bell, Bot, Check, Copy, Trash2, KeyRound, ListChecks, MoreVertical, Pencil, Plus, Shield, ShieldCheck, ShieldOff, UserRound, X } from 'lucide-react'
import { api, ApiError } from '../lib/api'
import { btn, btnPrimary } from '../lib/ui'
import { useSession } from '../lib/session'
import { useFilters, type Filter } from '../lib/Filters'
import { ask } from '../lib/notice'

type Machine = {
  name: string; host: string; place: string; online: boolean; waiting: boolean; index: number | null; band: string
  threshold: number; monitor_only: boolean; open: number; contained: number; blocked: number; last_seen: string
  services: string[]; hardware: { cpu: number | null; memory: number | null; disk: number | null }; sessions: number | null
  owner: Owner | null
}
/** Who answers for a machine and gets its alerts: a person from Routing, or the AI agent (with a person as backup). */
type Owner = { kind: 'person' | 'agent'; name: string; contact: string; backup: string; backup_name: string; missing?: boolean }
type Contact = { id: string; name: string }
type Page = {
  panel: boolean; machines: Machine[]; panel_info: { panel_url: string; pin: string }
  stats: { machines: number; online: number; offline: number; need_a_look: number; blocks: number }
  band_words: Record<string, string>; contacts: Contact[]; agent_name: string
}
type Made = { code: string; expires_at: string; https: boolean; pin: string | null; commands: { linux: string; windows: string } }

// One fixed grid for every row, after Erick's sketch: name (with rename), status, risk level, actions.
const ROW = 'grid items-center gap-x-6 gap-y-2 grid-cols-[minmax(0,1fr)_auto] md:grid-cols-[minmax(12rem,2fr)_minmax(9rem,1fr)_7rem_7rem]'
const stateWord = (m: Machine) => (m.waiting ? 'Waiting' : !m.online ? 'Offline' : m.monitor_only ? 'Protection off' : 'Protected')
const FILTERS: Filter<Machine>[] = [
  { key: 'state', label: 'State', get: stateWord },
  { key: 'risk', label: 'Risk', get: (m) => riskOf(m.index).word },
  { key: 'place', label: 'Kind', get: (m) => m.place }, { key: 'services', label: 'Service', get: (m) => m.services },
]
const NO_M: Machine[] = []

/** Risk level in words: under 30 Low, 30-59 Medium, 60-79 High, 80-100 Critical. */
export function riskOf(index: number | null): { word: string; tone: string } {
  if (index == null) return { word: 'No data', tone: 'text-muted' }
  const v = Math.round(index)
  return v >= 80 ? { word: 'Critical', tone: 'text-bad' } : v >= 60 ? { word: 'High', tone: 'text-warn' } : v >= 30 ? { word: 'Medium', tone: 'text-soft' } : { word: 'Low', tone: 'text-ok' }
}

// Status as words with a small shield: Protected, Protection off, Waiting, Offline. The hover says more.
function Status({ m }: { m: Machine }) {
  const word = stateWord(m)
  const [Icon, tone, detail] = word === 'Protected' ? [ShieldCheck, 'text-ok', 'Watched and protected.']
    : word === 'Protection off' ? [ShieldOff, 'text-warn', 'Watched and reported on, but nothing is blocked on it.']
    : word === 'Waiting' ? [Shield, 'text-warn', 'It has joined but has not sent anything yet.']
    : [ShieldOff, 'text-muted', m.last_seen ? `Last heard from ${m.last_seen}.` : 'It has not reported in.']
  return <span className={'inline-flex items-center gap-1.5 text-sm ' + tone} title={detail}><Icon size={15} aria-hidden />{word}</span>
}

function Risk({ m }: { m: Machine }) {
  const r = riskOf(m.index)
  return (
    <span className="flex flex-col leading-tight" aria-label={`Risk ${m.index == null ? 'unknown' : Math.round(m.index)}, ${r.word}`}>
      <span className={'text-lg font-semibold tabular-nums ' + r.tone}>{m.index == null ? '-' : Math.round(m.index)}</span>
      <span className={'text-xs ' + r.tone}>{r.word}</span>
    </span>
  )
}

// The name, with a pencil to rename it in place. The host name stays underneath as its id.
function Name({ m, canRename, done }: { m: Machine; canRename: boolean; done: (msg: string) => void }) {
  const [editing, setEditing] = useState(false)
  const [text, setText] = useState(m.name)
  const [err, setErr] = useState('')
  const save = async () => {
    setErr('')
    try { done((await api<{ message: string }>(`/ui/machines/${encodeURIComponent(m.host)}/rename`, { body: { name: text } })).message); setEditing(false) }
    catch (e) { setErr(e instanceof ApiError ? e.message : 'Could not rename it.') }
  }
  if (editing) return (
    <form className="flex min-w-0 items-center gap-1" onSubmit={(e) => { e.preventDefault(); void save() }}>
      <label htmlFor={`rn-${m.host}`} className="sr-only">New name for {m.host}</label>
      <input id={`rn-${m.host}`} autoFocus maxLength={60} value={text} onChange={(e) => setText(e.target.value)} placeholder={m.host}
        onKeyDown={(e) => { if (e.key === 'Escape') { setEditing(false); setText(m.name) } }}
        className="min-w-0 flex-1 rounded-md border border-line bg-surface-2 px-2 py-1 text-ink" />
      <button type="submit" className="rounded-md p-1 text-ok hover:bg-surface-2" aria-label="Save name"><Check size={15} aria-hidden /></button>
      <button type="button" className="rounded-md p-1 text-muted hover:bg-surface-2" aria-label="Cancel" onClick={() => { setEditing(false); setText(m.name) }}><X size={15} aria-hidden /></button>
      {err && <span role="alert" className="text-xs text-bad">{err}</span>}
    </form>
  )
  return (
    <div className="min-w-0">
      <p className="flex min-w-0 items-center gap-1.5 font-medium">
        {m.host ? <Link to={`/machines/${encodeURIComponent(m.host)}`} className="truncate underline-offset-2 hover:underline">{m.name}</Link> : <span className="truncate">{m.name}</span>}
        {m.host && canRename && <button className="shrink-0 rounded-md p-1 text-muted hover:bg-surface-2 hover:text-ink" aria-label={`Rename ${m.name}`} title="Rename"
          onClick={() => { setText(m.name); setEditing(true) }}><Pencil size={13} aria-hidden /></button>}
      </p>
      <p className="truncate text-xs text-muted">{m.name !== m.host && m.host ? `${m.host} · ` : ''}{m.place}{m.services.length ? ` · ${m.services.join(', ')}` : ''}</p>
      {m.owner && <p className={'flex items-center gap-1 truncate text-xs ' + (m.owner.missing ? 'text-warn' : 'text-soft')}>
        {m.owner.kind === 'agent' ? <Bot size={12} aria-hidden /> : <UserRound size={12} aria-hidden />}
        {m.owner.kind === 'agent' ? `${m.owner.name} handles its alerts${m.owner.backup_name ? ` · backup ${m.owner.backup_name}` : ''}`
          : m.owner.missing ? `Responsible: ${m.owner.contact} (no longer in Routing)` : `Responsible: ${m.owner.name}`}
      </p>}
    </div>
  )
}

// The row's three-dot menu: the less used actions, with Delete last. Closes on Escape or a click elsewhere.
function RowMenu({ label, children }: { label: string; children: (close: () => void) => ReactNode }) {
  const [open, setOpen] = useState(false)
  const box = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!open) return
    const away = (e: MouseEvent) => { if (!box.current?.contains(e.target as Node)) setOpen(false) }
    const esc = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(false) }
    document.addEventListener('mousedown', away); document.addEventListener('keydown', esc)
    return () => { document.removeEventListener('mousedown', away); document.removeEventListener('keydown', esc) }
  }, [open])
  return (
    <div ref={box} className="relative">
      <button className={btn} aria-haspopup="menu" aria-expanded={open} aria-label={label} title="More" onClick={() => setOpen(!open)}>
        <MoreVertical size={14} aria-hidden />
      </button>
      {open && <div role="menu" className="absolute right-0 z-20 mt-1 w-56 overflow-hidden rounded-md border border-line bg-surface py-1 shadow-lg">
        {children(() => setOpen(false))}
      </div>}
    </div>
  )
}
const item = 'flex w-full items-center gap-2 px-3 py-2 text-left text-sm hover:bg-surface-2 disabled:cursor-not-allowed disabled:opacity-50'

// Who answers for the machine: a person from Routing gets its alerts, or the AI agent handles them for the owner.
function OwnerForm({ m, page, done, cancel }: { m: Machine; page: Page; done: (msg: string) => void; cancel: () => void }) {
  const [kind, setKind] = useState<'person' | 'agent' | ''>(m.owner?.kind ?? 'person')
  const [contact, setContact] = useState(m.owner?.kind === 'person' ? m.owner.contact : page.contacts[0]?.id ?? '')
  const [backup, setBackup] = useState(m.owner?.kind === 'agent' ? m.owner.backup : '')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const save = async (k: string) => {
    setErr(''); setBusy(true)
    try { done((await api<{ message: string }>(`/ui/machines/${encodeURIComponent(m.host)}/owner`, { body: { kind: k, contact, backup } })).message) }
    catch (e) { setErr(e instanceof ApiError ? e.message : 'Could not save who is responsible.') }
    setBusy(false)
  }
  const field = 'mt-1 block w-full rounded-md border border-line bg-surface px-3 py-1.5 text-ink'
  return (
    <form className="col-span-full space-y-3 rounded-lg border border-line bg-surface-2 p-4" onSubmit={(e) => { e.preventDefault(); void save(kind) }}>
      <h3 className="font-semibold">Who is responsible for {m.name}? <span className="font-normal text-muted">· they get its alerts and the bell pings them</span></h3>
      <fieldset className="flex flex-wrap gap-4 text-sm">
        <legend className="sr-only">Responsible</legend>
        <label className="flex items-center gap-2"><input type="radio" name={`ok-${m.host}`} checked={kind === 'person'} onChange={() => setKind('person')} /> A person</label>
        <label className="flex items-center gap-2"><input type="radio" name={`ok-${m.host}`} checked={kind === 'agent'} onChange={() => setKind('agent')} /> The AI agent (Sentry)</label>
      </fieldset>
      {kind === 'person' && (page.contacts.length
        ? <label className="block text-sm text-soft">Person (from Routing)
            <select className={field} value={contact} onChange={(e) => setContact(e.target.value)}>
              {page.contacts.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
            </select></label>
        : <p className="text-sm text-warn">Nobody is in Routing yet. Add people there first.</p>)}
      {kind === 'agent' && <>
        <p className="text-sm text-soft">For a server nobody watches. It handles this machine's alerts for you: it signs off ones that are already contained, and hands anything that needs a decision to the backup. It never approves or undoes anything, and automatic protection keeps working.</p>
        <label className="block text-sm text-soft">Backup person, for decisions
          <select className={field} value={backup} onChange={(e) => setBackup(e.target.value)}>
            <option value="">Whoever the Routing rules pick</option>
            {page.contacts.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
          </select></label>
      </>}
      {err && <p role="alert" className="text-sm text-bad">{err}</p>}
      <div className="flex flex-wrap gap-2">
        <button type="submit" className={btnPrimary} disabled={busy || (kind === 'person' && !contact)}><Check size={14} aria-hidden /> Save</button>
        {m.owner && <button type="button" className={btn} disabled={busy} onClick={() => void save('')}>Nobody (Routing rules decide)</button>}
        <button type="button" className={btn} onClick={cancel}>Cancel</button>
      </div>
    </form>
  )
}

function AddMachine({ page, onMade }: { page: Page; onMade: () => void }) {
  const { can } = useSession()
  const [name, setName] = useState('')
  const [url, setUrl] = useState(page.panel_info.panel_url || (location.protocol === 'https:' ? location.origin : ''))
  const [made, setMade] = useState<Made | null>(null)
  const [err, setErr] = useState('')
  const field = 'mt-1 block w-full rounded-md border border-line bg-surface-2 px-3 py-1.5 text-ink'
  const make = async () => {
    setErr('')
    try { setMade(await api<Made>('/ui/machines/join-code', { body: { name, panel_url: url } })); onMade() }
    catch (e) { setErr(e instanceof ApiError ? e.message : 'Could not make a join code.') }
  }
  if (!page.panel) return <p className="rounded-md border border-line bg-surface-2 p-3 text-soft">Turn on central panel mode first (see the note above).</p>
  const copy = (t: string) => void navigator.clipboard?.writeText(t)
  return (
    <div className="space-y-3 rounded-lg border border-line bg-surface-2 p-4">
      <h3 className="font-semibold">Add machine <span className="font-normal text-muted">· a one-time join code, valid for 24 hours</span></h3>
      <label className="block text-sm text-soft">Machine name (optional)
        <input className={field} value={name} onChange={(e) => setName(e.target.value)} placeholder="web-01" /></label>
      <label className="block text-sm text-soft">Panel address the machine will use
        <input className={field} value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://…" /></label>
      <button className={btnPrimary} disabled={!can('configure')} onClick={() => void make()}
        title={can('configure') ? undefined : 'Your role can read everything but change nothing.'}><KeyRound size={14} aria-hidden /> Make join code</button>
      {err && <p role="alert" className="text-bad">{err}</p>}
      {made && (
        <div className="space-y-2" role="status">
          <p>Join code <b className="font-mono">{made.code}</b> · works once, until {new Date(made.expires_at).toLocaleString()}</p>
          {(['linux', 'windows'] as const).map((os) => (
            <div key={os}>
              <p className="text-sm text-soft">{os === 'linux' ? 'On a Linux server, from a SentrAI checkout:' : 'On Windows, from a SentrAI checkout in an Administrator PowerShell:'}</p>
              <div className="flex items-start gap-2 rounded-md border border-line bg-bg p-2">
                <code className="min-w-0 flex-1 break-all font-mono text-xs">{made.commands[os]}</code>
                <button className="text-soft" aria-label={`Copy the ${os} command`} onClick={() => copy(made.commands[os])}><Copy size={14} aria-hidden /></button>
              </div>
            </div>
          ))}
          {!made.https && <p className="text-warn">Other machines refuse a plain http:// panel. Install the panel with sudo ./deploy/install.sh --panel to open its HTTPS port for agents.</p>}
        </div>
      )}
    </div>
  )
}

export default function Machines() {
  const [page, setPage] = useState<Page | null>(null)
  const [error, setError] = useState('')
  const [adding, setAdding] = useState(false)
  const load = useCallback(async () => {
    try { setPage(await api<Page>('/ui/machines')); setError('') } catch (e) { setError(e instanceof ApiError ? e.message : 'Could not load machines.') }
  }, [])
  useEffect(() => { void load(); const t = setInterval(() => void load(), 10000); return () => clearInterval(t) }, [load])
  const s = page?.stats
  const { can } = useSession()
  const [note, setNote] = useState('')
  const remove = async (m: Machine) => {
    const ok = await ask({ title: `Delete ${m.name} from the panel?`, confirm: 'Delete', danger: true, body: [
      "Its agent's key is revoked, so it stops reporting and its queued jobs are cancelled. The agent stays installed on that computer until you uninstall it there.",
      "Its incidents and audit records are kept: the audit trail can't be edited, and they still show on All Incidents and Activity Log.",
      'It stays off this list until you join it again with a new code.',
      'This is written to the audit log under your name.'] })
    if (ok === null) return
    try { setNote((await api<{ message: string }>(`/ui/machines/${encodeURIComponent(m.host)}/delete`, { body: {} })).message); await load() }
    catch (e) { setNote(e instanceof ApiError ? e.message : 'The machine could not be deleted.') }
  }
  const [owning, setOwning] = useState('')
  const ping = async (m: Machine) => {
    if (!m.owner) { setOwning(m.host); return }
    try { setNote((await api<{ message: string }>(`/ui/machines/${encodeURIComponent(m.host)}/ping`, { body: {} })).message); await load() }
    catch (e) { setNote(e instanceof ApiError ? e.message : 'Could not ping them.') }
  }
  const list = useFilters(page?.machines ?? NO_M, FILTERS, (m) => [m.name, m.host, m.place, m.services], 'machines')
  return (
    <section className="space-y-4">
      <header>
        <h1 className="text-2xl font-semibold">Computers</h1>
        <p className="text-sm text-muted">Every computer that reports to this panel, and adding a new one</p>
      </header>
      {error && <p role="alert" className="rounded-md border border-line bg-surface p-3 text-bad">{error}</p>}
      {note && <p role="status" className="rounded-md border border-line bg-surface p-3">{note}</p>}
      {page && s && (
        <>
          <div className="grid grid-cols-2 gap-3">
            <Stat label="Registered machines" value={s.machines} note={page.panel ? 'joined this panel' : 'this computer'} />
            <Stat label="Online" value={s.online} note={`${s.offline} offline or waiting`} hot={s.offline > 0} tone="bad" />
          </div>
          {!page.panel && <p className="rounded-md border border-line bg-surface p-3 text-soft">This core adds every machine into one score. To run it as a central panel, set SENTRAI_RISK_SCOPE=host (and SENTRAI_FIREWALL=off) on it and restart the core: each machine is then scored and blocked on its own.</p>}
          <div className="space-y-3 rounded-lg border border-line bg-surface p-4">
            <div className="flex items-center justify-between gap-3">
              <h2 className="font-semibold">Machine List <span className="font-normal text-muted">· highest risk first</span></h2>
              <button className={btn} aria-expanded={adding} onClick={() => setAdding(!adding)}><Plus size={14} aria-hidden /> Add machine</button>
            </div>
            {adding && <AddMachine page={page} onMade={() => void load()} />}
            {list.bar}
            {list.active && list.rows.length === 0 && <p className="text-soft">No machines match these filters.</p>}
            <div className={ROW + ' hidden border-b border-line pb-2 text-xs font-medium uppercase tracking-wide text-muted md:grid'} aria-hidden>
              <span>Name</span><span>Status</span><span>Risk level</span><span className="text-right">Actions</span>
            </div>
            <ul className="divide-y divide-line-soft">
              {list.rows.map((m) => (
                <li key={m.host || m.name} className={ROW + ' py-3'}>
                  <Name m={m} canRename={page.panel && can('configure')} done={(msg) => { setNote(msg); void load() }} />
                  <span className="hidden md:block"><Status m={m} /></span>
                  <span className="hidden md:block"><Risk m={m} /></span>
                  <div className="flex items-center justify-end gap-2">
                    <span className="md:hidden"><Status m={m} /></span>
                    {m.host && page.panel && <button className={btn + ' relative'} onClick={() => void ping(m)}
                      aria-label={m.owner ? `Ping ${m.owner.name} about ${m.name}: ${m.open} open alerts` : `Set who is responsible for ${m.name}`}
                      title={m.owner ? `Ping ${m.owner.name}` + (m.open ? ` · ${m.open} open alert${m.open === 1 ? '' : 's'}` : ' · no open alerts')
                        : 'Nobody is responsible yet: set someone to ping'}>
                      {m.owner?.kind === 'agent' ? <Bot size={14} aria-hidden /> : <Bell size={14} aria-hidden />}
                      {m.open > 0 && <span className="absolute -right-1.5 -top-1.5 min-w-4 rounded-full bg-bad px-1 text-center text-[10px] font-semibold leading-4 text-white" aria-hidden>{m.open}</span>}
                    </button>}
                    {m.host && <RowMenu label={`More for ${m.name}`}>{(close) => <>
                      <Link role="menuitem" to={`/machines/${encodeURIComponent(m.host)}?tab=Incidents`} className={item} onClick={close}>
                        <ListChecks size={14} aria-hidden /> Open alerts{m.open ? ` (${m.open})` : ''}</Link>
                      {page.panel && <button role="menuitem" className={item} disabled={!can('configure')}
                        title={can('configure') ? undefined : 'Only an Owner or Admin can change who is responsible.'}
                        onClick={() => { close(); setOwning(m.host) }}><UserRound size={14} aria-hidden /> Who is responsible…</button>}
                      {page.panel && <button role="menuitem" className={item + ' text-bad'} disabled={!can('configure')}
                        title={can('configure') ? `Delete ${m.name} from the panel` : 'Only an Owner or Admin can delete a machine.'}
                        onClick={() => { close(); void remove(m) }}><Trash2 size={14} aria-hidden /> Delete</button>}
                    </>}</RowMenu>}
                  </div>
                  {owning === m.host && m.host && <OwnerForm m={m} page={page} cancel={() => setOwning('')}
                    done={(msg) => { setOwning(''); setNote(msg); void load() }} />}
                </li>
              ))}
            </ul>
          </div>
        </>
      )}
    </section>
  )
}
