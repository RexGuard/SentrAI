// Command center: the main things on one page (risk, what waits for a decision, incidents that need a person,
// machines and Cyanide), so a demo or a busy shift never has to hop between pages. The full pages stay.
import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { Check, ChevronRight, X } from 'lucide-react'
import { api, ApiError } from '../lib/api'
import { btn } from '../lib/ui'
import { useSession } from '../lib/session'
import Stat from '../lib/Stat'
import Chat from './Chat'
import { Chart, type Point } from './Review'
import { ask } from '../lib/notice'

type Risk = { risk_index?: number; band?: string; threshold?: number; history?: Point[] }
type ApprovalRow = { id: string; what: string; host: string; severity: string; status: string; target: string; needs: string[]; can: { decide: boolean } }
type Approvals = { headline: string; total: number; rows: ApprovalRow[]; rows_total?: number; protection_on: boolean }
type IncRow = { id: string; what: string; host: string; severity: string; owner: string; open_for: string; needs: string }
type Incidents = { counts: { open: number; attention: number; overdue: number }; todo: IncRow[]; todo_total?: number }
type MachineRow = { name: string; host: string; online: boolean; waiting: boolean; index: number | null; band: string; open: number }

const bandColor: Record<string, string> = { green: 'var(--green)', amber: 'var(--amber)', red: 'var(--red)', critical: 'var(--critical)' }
const sevColor: Record<string, string> = { critical: 'text-crit', high: 'text-bad', medium: 'text-warn', low: 'text-ok' }
const SHOW = 8

function Card({ title, to, more, children }: { title: string; to: string; more?: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0 space-y-2 rounded-lg border border-line bg-surface p-4">
      <div className="flex items-center justify-between gap-2">
        <h2 className="font-semibold">{title}</h2>
        <Link to={to} className="inline-flex items-center gap-0.5 text-sm text-soft hover:text-ink">{more ?? 'Open page'} <ChevronRight size={14} aria-hidden /></Link>
      </div>
      {children}
    </div>
  )
}

export default function Command() {
  const { can } = useSession()
  const [risk, setRisk] = useState<Risk | null>(null)
  const [appr, setAppr] = useState<Approvals | null>(null)
  const [incs, setIncs] = useState<Incidents | null>(null)
  const [machines, setMachines] = useState<MachineRow[]>([])
  const [error, setError] = useState('')
  const [note, setNote] = useState('')
  const load = useCallback(async () => {
    try {
      const [r, a, i, m] = await Promise.all([api<Risk>('/risk'), api<Approvals>(`/ui/approvals?brief=${SHOW}`), api<Incidents>(`/ui/incidents?brief=${SHOW}`),
        api<{ machines: MachineRow[] }>('/ui/machines')])
      setRisk(r); setAppr(a); setIncs(i); setMachines(m.machines); setError('')
    } catch (e) { setError(e instanceof ApiError ? e.message : 'Could not reach SentrAI.') }
  }, [])
  useEffect(() => { void load(); const t = setInterval(() => void load(), 10000); return () => clearInterval(t) }, [load])

  const decide = async (verb: 'approve' | 'reject', r: ApprovalRow) => {
    let justification = ''
    if (verb === 'reject') {
      justification = (await ask({ title: `Reject ${r.id}?`, confirm: 'Reject', danger: true,
        input: { label: 'Why? (written to the audit log)', required: true } })) ?? ''
      if (!justification.trim()) return
    }
    try { setNote((await api<{ message: string }>('/ui/approvals/bulk', { body: { verb, ids: [r.id], justification } })).message); await load() }
    catch (e) { setNote(e instanceof ApiError ? e.message : 'That did not go through.') }
  }

  const threshold = Number(risk?.threshold ?? 80)
  const hist = (risk?.history ?? []).filter((p) => typeof p.risk_index === 'number')
  const online = machines.filter((m) => m.online).length
  const off = !can('act')
  return (
    <section className="space-y-4">
      <header>
        <h1 className="text-2xl font-semibold">Command center</h1>
        <p className="text-sm text-muted">risk, decisions, incidents, machines and Cyanide on one page</p>
      </header>
      {error && <p role="alert" className="rounded-md border border-line bg-surface p-3 text-bad">{error}</p>}
      {note && <p role="status" className="rounded-md border border-line bg-surface p-3">{note}</p>}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Stat label="Risk now" value={risk?.risk_index != null ? Math.round(risk.risk_index) : '-'} note={`acts on its own at ${threshold}`} hot={(risk?.risk_index ?? 0) >= threshold} />
        <Stat label="Waiting on you" value={appr?.total ?? '-'} note="requests to approve or reject" hot={!!appr?.total} />
        <Stat label="Incidents open" value={incs?.counts.open ?? '-'} note={`${incs?.counts.attention ?? 0} need a person · ${incs?.counts.overdue ?? 0} overdue`} hot={!!incs?.counts.overdue} />
        <Stat label="Machines online" value={machines.length ? `${online} of ${machines.length}` : '-'} note="reporting to this panel" hot={online < machines.length} />
      </div>
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_26rem]">
        <div className="min-w-0 space-y-4">
          <Card title="Risk over time" to="/review" more="Review">
            {hist.length < 2 ? <p className="text-soft">No history yet. The core adds a point on every risk change.</p> : <Chart points={hist} threshold={threshold} />}
          </Card>
          <div className="grid gap-4 lg:grid-cols-2">
            <Card title={`Waiting for a decision${appr?.total ? ` (${appr.total})` : ''}`} to="/approvals" more="All approvals">
              {!appr ? <p className="text-muted" role="status">Loading…</p> : appr.rows.length === 0 ? <p className="text-ok">Nothing waiting. All quiet at the gate.</p> : (
                <ul className="divide-y divide-line-soft">
                  {appr.rows.slice(0, SHOW).map((r) => (
                    <li key={r.id} className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-2 py-2 text-sm">
                      <div className="min-w-0">
                        <p className="truncate"><span className="font-mono text-xs">{r.id}</span> · {r.what}</p>
                        <p className="truncate text-xs text-muted"><span className={'capitalize ' + (sevColor[r.severity] ?? '')}>{r.severity}</span> · {r.host}{r.target ? ` · ${r.target}` : ''}</p>
                      </div>
                      {r.can.decide && (
                        <div className="flex gap-1">
                          <button className={btn} disabled={off || !appr.protection_on} aria-label={`Approve ${r.id}`}
                            title={off ? 'Your role can read everything but change nothing.' : !appr.protection_on ? 'Protection is off: turn it on to apply anything.' : 'Approve'} onClick={() => void decide('approve', r)}><Check size={14} aria-hidden /></button>
                          <button className={btn} disabled={off} aria-label={`Reject ${r.id}`} title="Reject (asks why)" onClick={() => void decide('reject', r)}><X size={14} aria-hidden /></button>
                        </div>)}
                    </li>))}
                </ul>)}
              {appr && (appr.rows_total ?? appr.rows.length) > SHOW && <p className="text-xs text-muted">… and {(appr.rows_total ?? appr.rows.length) - SHOW} more on Approvals.</p>}
            </Card>
            <Card title="Needs a person" to="/incidents" more="All incidents">
              {!incs ? <p className="text-muted" role="status">Loading…</p> : incs.todo.length === 0 ? <p className="text-ok">Every open incident is in hand.</p> : (
                <ul className="divide-y divide-line-soft">
                  {incs.todo.slice(0, SHOW).map((r) => (
                    <li key={r.id} className="py-2 text-sm">
                      <p className="truncate"><span className="font-mono text-xs">{r.id}</span> · {r.what} <span className={'capitalize ' + (sevColor[r.severity] ?? '')}>· {r.severity}</span></p>
                      <p className="truncate text-xs text-muted">{r.host} · {r.owner} · {r.open_for} · {r.needs}</p>
                    </li>))}
                </ul>)}
              {incs && (incs.todo_total ?? incs.todo.length) > SHOW && <p className="text-xs text-muted">… and {(incs.todo_total ?? incs.todo.length) - SHOW} more on Incidents.</p>}
            </Card>
          </div>
          <Card title="Machines" to="/machines" more="All machines">
            {machines.length === 0 ? <p className="text-soft">No machines yet.</p> : (
              <ul className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-4">
                {machines.map((m) => {
                  const body = (
                    <>
                      <span className="min-w-0 truncate">{m.name}<span className="ml-2 text-xs text-muted">{m.waiting ? 'waiting' : !m.online ? 'offline' : m.open ? `${m.open} open` : 'calm'}</span></span>
                      <b className="text-lg" style={{ color: m.online && !m.waiting ? bandColor[m.band] : undefined }}>{m.online && !m.waiting && m.index != null ? Math.round(m.index) : '-'}</b>
                    </>)
                  const cls = 'flex items-center justify-between gap-2 rounded-md border border-line-soft px-3 py-1.5 text-sm'
                  return <li key={m.name}>{m.host ? <Link to={`/machines/${encodeURIComponent(m.host)}`} className={cls + ' hover:bg-surface-2'}>{body}</Link> : <div className={cls}>{body}</div>}</li>
                })}
              </ul>)}
          </Card>
        </div>
        <div className="xl:sticky xl:top-4 xl:h-[calc(100vh-7rem)]">
          <div className="flex h-[36rem] flex-col gap-2 rounded-lg border border-line bg-surface p-4 xl:h-full">
            <div className="flex items-center justify-between"><h2 className="font-semibold">Ask Cyanide</h2><Link to="/chat" className="text-sm text-soft hover:text-ink">Full page</Link></div>
            <div className="min-h-0 flex-1"><Chat compact /></div>
          </div>
        </div>
      </div>
    </section>
  )
}
