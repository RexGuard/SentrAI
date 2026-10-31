import { Fragment, useCallback, useEffect, useState } from 'react'
import Stat from '../lib/Stat'
import { ChevronDown, ChevronRight } from 'lucide-react'
import { Link } from 'react-router-dom'
import { api, ApiError } from '../lib/api'
import { btn, btnPrimary } from '../lib/ui'
import { useSession } from '../lib/session'

type Row = {
  id: string; what: string; host: string; severity: string; status: string; owner: string; backup: string
  open_for: string; needs: string; closed: boolean; attention: boolean; wave: string; summary: string
}
type Wave = { id: string; what: string; machine: string; addresses: number; networks: string; started: string; last_seen: string; going: boolean }
type Page = {
  counts: { open: number; attention: number; overdue: number; escalated: number; unassigned: number; mine: number }
  todo: Row[]; todo_waves: { id: string; line: string; count: number }[]; all: Row[]; waves: Wave[]
  contacts: { id: string; name: string }[]
}
type Tab = 'todo' | 'all' | 'waves'

const sevColor: Record<string, string> = { critical: 'text-crit', high: 'text-bad', medium: 'text-warn', low: 'text-ok' }
const field = 'mt-1 block rounded-md border border-line bg-surface-2 px-2 py-1.5 text-ink'

function Details({ r, contacts, done }: { r: Row; contacts: Page['contacts']; done: (note: string) => void }) {
  const { me, can } = useSession()
  const op = me?.email ?? 'dashboard'
  const [assignee, setAssignee] = useState(contacts[0]?.name ?? '')
  const [note, setNote] = useState('')
  const [err, setErr] = useState('')
  const off = !can('act')
  const run = async (fn: () => Promise<unknown>, msg: string) => {
    setErr('')
    try { await fn(); done(msg) } catch (e) { setErr(e instanceof ApiError ? e.message : 'That did not go through.') }
  }
  const id = encodeURIComponent(r.id)
  return (
    <div className="space-y-3">
      <p className="text-soft">{r.summary || `${r.what} on ${r.host}.`}</p>
      {err && <p role="alert" className="text-bad">{err}</p>}
      {!r.closed && (
        <div className="flex flex-wrap items-end gap-3">
          <label className="text-sm text-soft">Give it to
            <select className={field} value={assignee} onChange={(e) => setAssignee(e.target.value)}>
              {contacts.map((c) => <option key={c.id} value={c.name}>{c.name}</option>)}
            </select></label>
          <button className={btn} disabled={off || !assignee} title={off ? 'Your role can read everything but change nothing.' : undefined}
            onClick={() => void run(() => api(`/incidents/${id}/assign`, { body: { operator: op, assignee, note: '' } }), `${r.id} given to ${assignee}`)}>Assign</button>
          <label className="text-sm text-soft">Closing note
            <input className={field + ' w-64 max-w-full'} value={note} onChange={(e) => setNote(e.target.value)} /></label>
          <button className={btnPrimary} disabled={off || !note.trim()}
            onClick={() => void run(() => api(`/incidents/${id}/resolve`, { body: { operator: op, note: note.trim() } }), `${r.id} resolved`)}>Resolve</button>
        </div>
      )}
    </div>
  )
}

function Board({ rows, contacts, done, empty }: { rows: Row[]; contacts: Page['contacts']; done: (n: string) => void; empty: string }) {
  const [open, setOpen] = useState<string | null>(null)
  if (!rows.length) return <p className="text-soft">{empty}</p>
  return (
    <div className="overflow-x-auto" role="region" aria-label="Incidents" tabIndex={0}>
      <table className="w-full text-left text-sm">
        <thead className="border-b border-line text-xs uppercase tracking-wide text-muted">
          <tr><th className="w-8 p-2"><span className="sr-only">Details</span></th>
            {['Incident', 'What', 'Host', 'Severity', 'Status', 'Owner', 'Backup', 'Open for', 'Needs'].map((h) => <th key={h} className="p-2 font-medium">{h}</th>)}</tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <Fragment key={r.id}>
              <tr className="border-b border-line-soft hover:bg-surface-2">
                <td className="p-2"><button aria-expanded={open === r.id} aria-label={`Details of ${r.id}`} className="text-soft" onClick={() => setOpen(open === r.id ? null : r.id)}>
                  {open === r.id ? <ChevronDown size={16} aria-hidden /> : <ChevronRight size={16} aria-hidden />}</button></td>
                <td className="p-2 font-mono text-xs">{r.id}</td><td className="p-2">{r.what}</td><td className="p-2">{r.host}</td>
                <td className={'p-2 font-medium capitalize ' + (sevColor[r.severity] ?? '')}>{r.severity}</td>
                <td className="p-2">{r.status}</td><td className="p-2">{r.owner}</td><td className="p-2">{r.backup}</td>
                <td className="p-2 whitespace-nowrap">{r.open_for}</td><td className="p-2 text-soft">{r.needs}</td>
              </tr>
              {open === r.id && <tr className="border-b border-line-soft bg-surface-2"><td colSpan={10} className="p-4"><Details r={r} contacts={contacts} done={done} /></td></tr>}
            </Fragment>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export default function Incidents() {
  const [page, setPage] = useState<Page | null>(null)
  const [error, setError] = useState('')
  const [note, setNote] = useState('')
  const [tab, setTab] = useState<Tab>('todo')
  const [closed, setClosed] = useState(false)
  const [mine, setMine] = useState(false)
  const load = useCallback(async () => {
    try { setPage(await api<Page>(`/ui/incidents?closed=${closed}&mine=${mine}`)); setError('') }
    catch (e) { setError(e instanceof ApiError ? e.message : 'Could not load incidents.') }
  }, [closed, mine])
  useEffect(() => { void load(); const t = setInterval(() => void load(), 10000); return () => clearInterval(t) }, [load])
  const done = (n: string) => { setNote(n); void load() }
  const c = page?.counts
  const tabs: [Tab, string][] = page ? [
    ['todo', `Needs a person (${page.todo.length + page.todo_waves.reduce((a, w) => a + w.count, 0)})`],
    ['all', `All incidents (${c?.open} open)`], ...(page.waves.length ? [['waves', `Waves (${page.waves.length})`] as [Tab, string]] : [])] : []

  return (
    <section className="space-y-4">
      <header>
        <h1 className="text-2xl font-semibold">Incidents</h1>
        <p className="text-sm text-muted">who owns each incident, and what still needs a person</p>
      </header>
      {error && <p role="alert" className="rounded-md border border-line bg-surface p-3 text-bad">{error}</p>}
      {note && <p role="status" className="rounded-md border border-line bg-surface p-3">{note}</p>}
      {page && c && (
        <>
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
            <Stat label="Open" value={c.open} note="not resolved yet" />
            <Stat label="Needs attention" value={c.attention} note={`${c.unassigned} with no owner`} hot={c.attention > 0} />
            <Stat label="Overdue" value={c.overdue} note="past the SLA, nobody answered" hot={c.overdue > 0} />
            <Stat label="Escalated" value={c.escalated} note="handed to a backup contact" hot={c.escalated > 0} />
            <Stat label="Yours" value={c.mine} note="owned by you" />
          </div>
          <div role="tablist" aria-label="Part of the Incidents page" className="flex flex-wrap gap-2">
            {tabs.map(([t, label]) => (
              <button key={t} role="tab" aria-selected={tab === t} onClick={() => setTab(t)}
                className={'rounded-md px-3 py-1.5 text-sm ' + (tab === t ? 'bg-surface-3 text-ink' : 'text-soft hover:bg-surface-2')}>{label}</button>
            ))}
          </div>
          <div className="space-y-3 rounded-lg border border-line bg-surface p-4">
            {tab === 'todo' && (
              <>
                <h2 className="font-semibold">Needs attention <span className="font-normal text-muted">· most urgent first</span></h2>
                {page.todo_waves.map((w) => <p key={w.id}><b>{w.id}</b> · {w.line}. Approve or reject them together on Approvals (group by type).</p>)}
                <Board rows={page.todo} contacts={page.contacts} done={done} empty="Nothing needs a person right now. Every open incident is in hand." />
              </>
            )}
            {tab === 'all' && (
              <>
                <h2 className="font-semibold">All incidents <span className="font-normal text-muted">· owner, backup and what each one still needs</span></h2>
                <div className="flex flex-wrap gap-4 text-sm text-soft">
                  <label className="flex items-center gap-2"><input type="checkbox" checked={closed} onChange={(e) => setClosed(e.target.checked)} /> Show resolved and rejected</label>
                  <label className="flex items-center gap-2"><input type="checkbox" checked={mine} onChange={(e) => setMine(e.target.checked)} /> Only mine</label>
                </div>
                <Board rows={page.all} contacts={page.contacts} done={done} empty="No incidents. All quiet at the gate." />
              </>
            )}
            {tab === 'waves' && (
              <>
                <h2 className="font-semibold">Waves <span className="font-normal text-muted">· many addresses doing the same thing to one machine, handled as one</span></h2>
                <div className="overflow-x-auto" role="region" aria-label="Waves" tabIndex={0}>
                  <table className="w-full text-left text-sm">
                    <thead className="border-b border-line text-xs uppercase tracking-wide text-muted">
                      <tr>{['Wave', 'What', 'Machine', 'Addresses', 'Top networks', 'Started', 'Last seen', 'Now'].map((h) => <th key={h} className="p-2 font-medium">{h}</th>)}</tr>
                    </thead>
                    <tbody>
                      {page.waves.map((w) => (
                        <tr key={w.id} className="border-b border-line-soft last:border-0">
                          <td className="p-2 font-mono text-xs">{w.id}</td><td className="p-2">{w.what}</td><td className="p-2">{w.machine}</td>
                          <td className="p-2">{w.addresses}</td><td className="p-2">{w.networks}</td><td className="p-2">{w.started}</td>
                          <td className="p-2">{w.last_seen}</td><td className="p-2">{w.going ? 'Going' : 'Quiet'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </>
            )}
          </div>
          <p className="text-sm"><Link to="/routing" className="underline">Who gets what</Link> <span className="text-muted">· the routing rules: who owns an incident, who is told and who covers</span></p>
        </>
      )}
    </section>
  )
}
