import { useCallback, useEffect, useState } from 'react'
import { api, ApiError } from '../lib/api'
import { useFilters, type Filter } from '../lib/Filters'

type Point = { t: string; risk_index: number }
type Risk = { risk_index?: number; raw_score?: number; threshold?: number; history?: Point[] }
type Inc = {
  id: string; category?: string; status?: string; base_points?: number; ai_confidence?: number; asset_criticality?: number
  points?: number; inaction_penalty?: number; time_unaddressed_hours?: number
}
type MachineRow = { name: string; online: boolean; index: number | null; band: string; open: number }

const ACTIVE = ['open', 'acknowledged']
const label = (s?: string) => (s ? s.replace(/_/g, ' ').replace(/^./, (c) => c.toUpperCase()) : 'Unknown')
const span = (h: number) => { const m = Math.floor(h * 60); return m < 1 ? 'under 1 min' : m < 60 ? `${m} min` : m < 1440 ? `${Math.floor(m / 60)} h ${m % 60} min` : `${Math.floor(m / 1440)} d ${Math.floor((m % 1440) / 60)} h` }
const bandColor: Record<string, string> = { green: 'var(--green)', amber: 'var(--amber)', red: 'var(--red)', critical: 'var(--critical)' }

type Line = { i: Inc; counts: number }
const LINES: Filter<Line>[] = [
  { key: 'category', label: 'Category', get: (l) => label(l.i.category) }, { key: 'status', label: 'Status', get: (l) => label(l.i.status) },
  { key: 'counts', label: 'Counts now', get: (l) => (l.counts > 0 ? 'Adds to the score' : 'Adds nothing') },
]

function Stat({ label: l, value, note, hot }: { label: string; value: string; note: string; hot?: boolean }) {
  return (
    <div className="rounded-lg border border-line bg-surface p-4">
      <p className="text-xs uppercase tracking-wide text-muted">{l}</p>
      <p className={'text-2xl font-semibold ' + (hot ? 'text-warn' : '')}>{value}</p>
      <p className="text-xs text-muted">{note}</p>
    </div>
  )
}

function Chart({ points, threshold }: { points: Point[]; threshold: number }) {
  const W = 1200, H = 150, P = 26
  const ts = points.map((p) => new Date(p.t).getTime())
  const t0 = Math.min(...ts), t1 = Math.max(...ts, t0 + 1)
  const x = (t: number) => P + ((t - t0) / (t1 - t0)) * (W - 2 * P)
  const y = (v: number) => H - P - (Math.max(0, Math.min(100, v)) / 100) * (H - 2 * P)
  const d = points.map((p, i) => `${i ? 'L' : 'M'}${x(ts[i]).toFixed(1)},${y(p.risk_index).toFixed(1)}`).join(' ')
  const last = points[points.length - 1]
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full" role="img" aria-label={`Risk over time. Now ${last.risk_index} of 100, threshold ${threshold}.`}>
      {[0, 50, 100].map((v) => <g key={v}><line x1={P} x2={W - P} y1={y(v)} y2={y(v)} stroke="var(--line-soft)" /><text x={4} y={y(v) + 4} fontSize="13" fill="var(--ink-muted)">{v}</text></g>)}
      <line x1={P} x2={W - P} y1={y(threshold)} y2={y(threshold)} stroke="var(--critical)" strokeDasharray="5 4" />
      <text x={W - P} y={y(threshold) - 4} fontSize="13" textAnchor="end" fill="var(--ink-muted)">threshold {threshold}</text>
      <path d={d} fill="none" stroke="var(--ink)" strokeWidth="2" />
      <circle cx={x(ts[ts.length - 1])} cy={y(last.risk_index)} r="4" fill="var(--ink)" />
      <text x={P} y={H - 6} fontSize="13" fill="var(--ink-muted)">{new Date(t0).toLocaleTimeString()}</text>
      <text x={W - P} y={H - 6} fontSize="13" textAnchor="end" fill="var(--ink-muted)">{new Date(t1).toLocaleTimeString()}</text>
    </svg>
  )
}

export default function Review() {
  const [risk, setRisk] = useState<Risk | null>(null)
  const [incs, setIncs] = useState<Inc[]>([])
  const [machines, setMachines] = useState<MachineRow[]>([])
  const [error, setError] = useState('')
  const load = useCallback(async () => {
    try {
      const [r, i, m] = await Promise.all([api<Risk>('/risk'), api<Inc[]>('/incidents'), api<{ machines: MachineRow[] }>('/ui/machines')])
      setRisk(r); setIncs(i); setMachines(m.machines); setError('')
    } catch (e) { setError(e instanceof ApiError ? e.message : 'Could not load the review.') }
  }, [])
  useEffect(() => { void load(); const t = setInterval(() => void load(), 10000); return () => clearInterval(t) }, [load])

  const threshold = Number(risk?.threshold ?? 80)
  const active = incs.filter((i) => ACTIVE.includes(String(i.status)))
  const waiting = incs.filter((i) => ACTIVE.includes(String(i.status)) || i.status === 'contained')
  const penalty = active.reduce((a, i) => a + Number(i.inaction_penalty ?? 0), 0)
  const hist = (risk?.history ?? []).filter((p) => typeof p.risk_index === 'number')
  const peak = Math.max(0, Number(risk?.risk_index ?? 0), ...hist.map((p) => p.risk_index))
  const rows = [...incs].map((i) => ({ i, counts: ACTIVE.includes(String(i.status)) ? Math.round((Number(i.points ?? 0) + Number(i.inaction_penalty ?? 0)) * 10) / 10 : 0 })).sort((a, b) => b.counts - a.counts)
  const lines = useFilters(rows, LINES, (l) => [l.i.id, l.i.category, l.i.status], 'incidents')
  const online = machines.filter((m) => m.online).length

  return (
    <section className="space-y-4">
      <header>
        <h1 className="text-2xl font-semibold">Review</h1>
        <p className="text-sm text-muted">how close SentrAI is to acting on its own, and why</p>
      </header>
      {error && <p role="alert" className="rounded-md border border-line bg-surface p-3 text-bad">{error}</p>}
      {risk && (
        <>
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            <Stat label="Peak so far" value={String(Math.round(peak))} note="on this computer" hot={peak >= threshold} />
            <Stat label="Waiting on you" value={String(waiting.length)} note={`${waiting.length - active.length} contained · ${active.length} open`} hot={waiting.length > 0} />
            <Stat label="Inaction penalty" value={`+${Math.round(penalty)}`} note="+5 per hour nobody responds" hot={penalty > 0} />
            <Stat label="Raw score" value={Number(risk.raw_score ?? 0).toFixed(1)} note="points before scaling to 0-100" />
          </div>
          <div className="space-y-2 rounded-lg border border-line bg-surface p-4">
            <h2 className="font-semibold">Risk over time <span className="font-normal text-muted">· dashed line is the threshold</span></h2>
            {hist.length < 2 ? <p className="text-soft">No history yet. The core adds a point on every risk change.</p> : <Chart points={hist} threshold={threshold} />}
          </div>
          <div>
            <div className="space-y-2 rounded-lg border border-line bg-surface p-4">
              <h2 className="font-semibold">Machines <span className="font-normal text-muted">· {online} of {machines.length} online · SentrAI acts on its own above the threshold</span></h2>
              <ul className="grid gap-x-6 divide-line-soft sm:grid-cols-2 xl:grid-cols-3">
                {machines.map((m) => (
                  <li key={m.name} className="flex items-center justify-between gap-3 border-b border-line-soft py-2 text-sm">
                    <span>{m.name}<span className="ml-2 text-xs text-muted">{m.online ? (m.open ? `${m.open} open` : 'calm') : 'offline'}</span></span>
                    <b className="text-lg" style={{ color: m.online ? bandColor[m.band] : undefined }}>{m.online && m.index != null ? Math.round(m.index) : '-'}</b>
                  </li>
                ))}
              </ul>
            </div>
          </div>
          <div className="space-y-3 rounded-lg border border-line bg-surface p-4">
            <h2 className="font-semibold">What adds to the score <span className="font-normal text-muted">· one row per incident</span></h2>
            <p className="text-sm text-soft">Each incident adds base points × AI confidence × how critical the target is, plus 5 for every hour nobody responds. The 0-100 index is 100 × (1 − e^(−raw ÷ 60)), so it slows down near the top.</p>
            {lines.bar}
            {rows.length === 0 ? <p className="text-soft">All quiet at the gate. No incidents.</p> : (
              <div className="overflow-x-auto" role="region" aria-label="What adds to the score" tabIndex={0}>
                <table className="w-full text-left text-sm">
                  <thead className="border-b border-line text-xs uppercase tracking-wide text-muted"><tr>{['Incident', 'Category', 'Status', 'Base', 'Confidence', 'Criticality', 'Points', 'Inaction penalty', 'Unanswered for', 'Counts now'].map((h) => <th key={h} className="p-2 font-medium">{h}</th>)}</tr></thead>
                  <tbody>{lines.rows.map(({ i, counts }) => (
                    <tr key={i.id} className="border-b border-line-soft last:border-0">
                      <td className="p-2 font-mono text-xs">{i.id}</td><td className="p-2">{label(i.category)}</td><td className="p-2">{label(i.status)}</td>
                      <td className="p-2">{i.base_points ?? '-'}</td><td className="p-2">{typeof i.ai_confidence === 'number' ? i.ai_confidence.toFixed(2) : '-'}</td>
                      <td className="p-2">{i.asset_criticality ?? '-'}</td><td className="p-2">{Math.round(Number(i.points ?? 0) * 10) / 10}</td>
                      <td className="p-2">+{Math.round(Number(i.inaction_penalty ?? 0))} pts</td>
                      <td className="p-2">{ACTIVE.includes(String(i.status)) ? span(Number(i.time_unaddressed_hours ?? 0)) : '-'}</td><td className="p-2 font-medium">{counts}</td>
                    </tr>))}</tbody>
                </table>
              </div>)}
          </div>
        </>
      )}
    </section>
  )
}
