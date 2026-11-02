// Command center: what needs a person as one bubble per severity (Critical / High / Medium), the risk over time,
// the machines and Cyanide, so a non-IT person sees at a glance where to start. A bubble opens that severity's risks
// (pages/RiskList.tsx); the full Approvals and Incidents pages stay.
import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { ChevronRight } from 'lucide-react'
import { api, ApiError } from '../lib/api'
import Chat from './Chat'
import { Chart, type Point } from './Review'
import { SeverityBubbles, type Risks } from '../lib/Risks'

type Risk = { risk_index?: number; band?: string; threshold?: number; history?: Point[] }
type MachineRow = { name: string; host: string; online: boolean; waiting: boolean; index: number | null; band: string; open: number }

const bandColor: Record<string, string> = { green: 'var(--green)', amber: 'var(--amber)', red: 'var(--red)', critical: 'var(--critical)' }

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
  const [risk, setRisk] = useState<Risk | null>(null)
  const [risks, setRisks] = useState<Risks | null>(null)
  const [machines, setMachines] = useState<MachineRow[]>([])
  const [error, setError] = useState('')
  const load = useCallback(async () => {
    try {
      const [r, k, m] = await Promise.all([api<Risk>('/risk'), api<Risks>('/ui/risks'), api<{ machines: MachineRow[] }>('/ui/machines')])
      setRisk(r); setRisks(k); setMachines(m.machines); setError('')
    } catch (e) { setError(e instanceof ApiError ? e.message : 'Could not reach SentrAI.') }
  }, [])
  useEffect(() => { void load(); const t = setInterval(() => void load(), 10000); return () => clearInterval(t) }, [load])

  const threshold = Number(risk?.threshold ?? 80)
  const hist = (risk?.history ?? []).filter((p) => typeof p.risk_index === 'number')
  const online = machines.filter((m) => m.online).length
  return (
    <section className="space-y-4">
      <header>
        <h1 className="text-2xl font-semibold">Command center</h1>
        <p className="text-sm text-muted">what needs a person, by how serious it is</p>
      </header>
      {error && <p role="alert" className="rounded-md border border-line bg-surface p-3 text-bad">{error}</p>}
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_26rem]">
        <div className="min-w-0 space-y-4">
          <div className="space-y-3 rounded-lg border border-line bg-surface p-4">
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <h2 className="font-semibold">{risks?.headline ?? 'Looking…'}</h2>
              <p className="text-sm text-muted">
                Risk now <b className={(risk?.risk_index ?? 0) >= threshold ? 'text-bad' : 'text-ink'}>{risk?.risk_index != null ? Math.round(risk.risk_index) : '-'}</b> of 100
                · acts on its own at {threshold}{machines.length ? ` · ${online} of ${machines.length} machines online` : ''}
              </p>
            </div>
            <SeverityBubbles data={risks} />
            <p className="text-xs text-muted">Each bubble joins what waits for a decision and what needs a person. Full lists: <Link to="/approvals" className="underline">Approvals</Link> · <Link to="/incidents" className="underline">Incidents</Link></p>
          </div>
          <Card title="Risk over time" to="/review" more="Review">
            {hist.length < 2 ? <p className="text-soft">No history yet. The core adds a point on every risk change.</p> : <Chart points={hist} threshold={threshold} />}
          </Card>
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
