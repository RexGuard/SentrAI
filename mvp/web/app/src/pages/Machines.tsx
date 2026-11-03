import { useCallback, useEffect, useState } from 'react'
import Stat from '../lib/Stat'
import { Link } from 'react-router-dom'
import { Bell, Check, Copy, Trash2, KeyRound, Pencil, Plus, Shield, ShieldCheck, ShieldOff, X } from 'lucide-react'
import { api, ApiError } from '../lib/api'
import { btn, btnPrimary } from '../lib/ui'
import { useSession } from '../lib/session'
import { useFilters, type Filter } from '../lib/Filters'
import { ask } from '../lib/notice'

type Machine = {
  name: string; host: string; place: string; online: boolean; waiting: boolean; index: number | null; band: string
  threshold: number; monitor_only: boolean; open: number; contained: number; blocked: number; last_seen: string
  services: string[]; hardware: { cpu: number | null; memory: number | null; disk: number | null }; sessions: number | null
}
type Page = {
  panel: boolean; machines: Machine[]; panel_info: { panel_url: string; pin: string }
  stats: { machines: number; online: number; offline: number; need_a_look: number; blocks: number }
  band_words: Record<string, string>
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
    </div>
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
                    {m.host && <Link to={`/machines/${encodeURIComponent(m.host)}?tab=Incidents`} className={btn + ' relative'} aria-label={`Alerts on ${m.name}: ${m.open} open`}
                      title={m.open ? `${m.open} open alert${m.open === 1 ? '' : 's'}` : 'No open alerts'}>
                      <Bell size={14} aria-hidden />
                      {m.open > 0 && <span className="absolute -right-1.5 -top-1.5 min-w-4 rounded-full bg-bad px-1 text-center text-[10px] font-semibold leading-4 text-white" aria-hidden>{m.open}</span>}
                    </Link>}
                    {m.host && page.panel && <button className={btn + ' text-bad'} disabled={!can('configure')} aria-label={`Delete ${m.name}`}
                      title={can('configure') ? `Delete ${m.name} from the panel` : 'Only an Owner or Admin can delete a machine.'} onClick={() => void remove(m)}><Trash2 size={14} aria-hidden /></button>}
                  </div>
                </li>
              ))}
            </ul>
          </div>
        </>
      )}
    </section>
  )
}
