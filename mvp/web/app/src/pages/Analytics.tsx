import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, ApiError } from '../lib/api'
import Stat from '../lib/Stat'
import { useFilters, type Filter } from '../lib/Filters'
import { PlaybookCard, type Pattern } from '../lib/Fixes'

type Row = {
  id: string; what: string; category: string; severity: string; host: string; status: string; closed: boolean
  attacker: string; user: string; opened: string; day: string; contain_min: number | null; close_min: number | null
  answer_min: number | null; contain: string; close: string; auto: boolean; pattern: string; pattern_label: string
}
type Page = { rows: Row[]; patterns: Pattern[]; ai: boolean }

const FILTERS: Filter<Row>[] = [
  { key: 'what', label: 'Type', get: (r) => r.what }, { key: 'severity', label: 'Severity', get: (r) => r.severity },
  { key: 'host', label: 'Machine', get: (r) => r.host }, { key: 'status', label: 'Status', get: (r) => r.status },
  { key: 'attacker', label: 'Source', get: (r) => r.attacker }, { key: 'pattern', label: 'Pattern', get: (r) => r.pattern_label },
  { key: 'opened', label: 'Opened', get: (r) => r.opened, kind: 'date' },
]
const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']
const sevVar: Record<string, string> = { critical: 'var(--critical)', high: 'var(--red)', medium: 'var(--amber)', low: 'var(--green)' }

const median = (xs: number[]) => { if (!xs.length) return null; const s = [...xs].sort((a, b) => a - b); return s[Math.floor(s.length / 2)] }
const span = (m: number | null) => m == null ? '-' : m < 1 ? 'under 1 min' : m < 60 ? `${Math.round(m)} min` : m < 1440 ? `${(m / 60).toFixed(1)} h` : `${(m / 1440).toFixed(1)} d`
const countBy = (rows: Row[], get: (r: Row) => string) => {
  const m = new Map<string, number>()
  rows.forEach((r) => m.set(get(r), (m.get(get(r)) ?? 0) + 1))
  return [...m.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
}
const top = (pairs: [string, number][], n = 8): [string, number][] => pairs.length <= n ? pairs
  : [...pairs.slice(0, n - 1), ['Other', pairs.slice(n - 1).reduce((a, [, c]) => a + c, 0)]]

/** A ranked list of horizontal bars: one series, the label and value always in text. */
function Bars({ title, pairs, color, fmt = String, note }: {
  title: string; pairs: [string, number][]; color?: (k: string) => string; fmt?: (v: number) => string; note?: string
}) {
  const max = Math.max(1, ...pairs.map(([, v]) => v))
  return (
    <div className="rounded-lg border border-line bg-surface p-4">
      <h2 className="font-semibold">{title}</h2>
      {note && <p className="text-xs text-muted">{note}</p>}
      {pairs.length === 0 ? <p className="mt-2 text-sm text-soft">No incidents.</p> : (
        <ul className="mt-3 space-y-2">
          {pairs.map(([k, v]) => (
            <li key={k} title={`${k}: ${fmt(v)}`}>
              <div className="flex justify-between gap-2 text-sm"><span className="truncate">{k}</span><span className="tabular-nums text-soft">{fmt(v)}</span></div>
              <div className="mt-1 h-2 rounded bg-surface-3" aria-hidden>
                <div className="h-full rounded" style={{ width: `${Math.max(2, (v / max) * 100)}%`, background: color?.(k) ?? 'var(--ink-soft)' }} />
              </div>
            </li>
          ))}
        </ul>)}
    </div>
  )
}

/** Incidents over time: one column per hour when the rows span two days or less, else one per day (at most 60). */
function Trend({ rows }: { rows: Row[] }) {
  const { buckets, hourly } = useMemo(() => {
    const times = rows.map((r) => Date.parse(r.opened)).filter((t) => !Number.isNaN(t))
    if (!times.length) return { buckets: [], hourly: false }
    const lo = Math.min(...times), hi = Math.max(...times)
    const hourly = hi - lo <= 2 * 86400000
    const step = hourly ? 3600000 : 86400000
    const floor = (t: number) => Math.floor(t / step) * step
    const per = new Map<number, { all: number; open: number }>()
    rows.forEach((r) => { const t = Date.parse(r.opened); if (Number.isNaN(t)) return; const k = floor(t); const d = per.get(k) ?? { all: 0, open: 0 }; d.all++; if (!r.closed) d.open++; per.set(k, d) })
    const out: { at: number; label: string; all: number; open: number }[] = []
    for (let t = Math.max(floor(lo), floor(hi) - 59 * step); t <= floor(hi); t += step) {
      const d = new Date(t)
      out.push({ at: t, label: hourly ? d.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : d.toLocaleDateString(), ...(per.get(t) ?? { all: 0, open: 0 }) })
    }
    return { buckets: out, hourly }
  }, [rows])
  const [hover, setHover] = useState<number | null>(null)
  const max = Math.max(1, ...buckets.map((d) => d.all))
  const h = hover != null ? buckets[hover] : buckets[buckets.length - 1]
  const unit = hourly ? 'hour' : 'day'
  return (
    <div className="rounded-lg border border-line bg-surface p-4">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h2 className="font-semibold">Incidents per {unit}</h2>
        {h && <p className="text-sm text-soft" aria-live="polite"><b className="text-ink">{h.label}</b> · {h.all} incident{h.all === 1 ? '' : 's'}{h.open ? `, ${h.open} still open` : ''}</p>}
      </div>
      {buckets.length === 0 ? <p className="mt-2 text-sm text-soft">No incidents.</p> : (
        <>
          <div className="mt-3 flex h-36 items-end gap-0.5 border-b border-line" role="img"
            aria-label={`Incidents per ${unit} from ${buckets[0].label} to ${buckets[buckets.length - 1].label}, most in one ${unit} ${max}`}
            onMouseLeave={() => setHover(null)}>
            {buckets.map((d, i) => (
              <div key={d.at} className="flex h-full flex-1 items-end" onMouseEnter={() => setHover(i)} title={`${d.label}: ${d.all}`}>
                <div className="mx-auto w-full max-w-10 rounded-t" style={{ height: `${(d.all / max) * 100}%`, minHeight: d.all ? 2 : 0,
                  background: hover === i ? 'var(--ink)' : 'var(--ink-soft)' }} />
              </div>
            ))}
          </div>
          <div className="mt-1 flex justify-between text-xs text-muted"><span>{buckets[0].label}</span><span>most in one {unit}: {max}</span><span>{buckets[buckets.length - 1].label}</span></div>
        </>)}
    </div>
  )
}

function Offenders({ rows }: { rows: Row[] }) {
  const list = useMemo(() => {
    const by = new Map<string, Row[]>()
    rows.filter((r) => r.attacker !== 'Unknown').forEach((r) => by.set(r.attacker, [...(by.get(r.attacker) ?? []), r]))
    return [...by.entries()].filter(([, rs]) => rs.length > 1).map(([a, rs]) => ({
      attacker: a, count: rs.length, machines: [...new Set(rs.map((r) => r.host))], types: [...new Set(rs.map((r) => r.what))],
      first: rs.map((r) => r.opened).sort()[0], last: rs.map((r) => r.opened).sort().slice(-1)[0], open: rs.filter((r) => !r.closed).length,
    })).sort((a, b) => b.count - a.count).slice(0, 15)
  }, [rows])
  return (
    <div className="rounded-lg border border-line bg-surface p-4">
      <h2 className="font-semibold">Repeat offenders <span className="font-normal text-muted">· sources behind more than one incident</span></h2>
      {list.length === 0 ? <p className="mt-2 text-sm text-soft">No source came back more than once.</p> : (
        <div className="mt-2 overflow-x-auto" role="region" aria-label="Repeat offenders" tabIndex={0}>
          <table className="w-full text-left text-sm">
            <thead className="border-b border-line text-xs uppercase tracking-wide text-muted">
              <tr>{['Source', 'Incidents', 'Open', 'Machines', 'Types', 'First seen', 'Last seen'].map((x) => <th key={x} className="p-2 font-medium">{x}</th>)}</tr></thead>
            <tbody>{list.map((o) => (
              <tr key={o.attacker} className="border-b border-line-soft last:border-0">
                <td className="p-2 font-mono text-xs">{o.attacker}</td><td className="p-2 tabular-nums">{o.count}</td><td className="p-2 tabular-nums">{o.open}</td>
                <td className="p-2">{o.machines.join(', ')}</td><td className="p-2">{o.types.join(', ')}</td>
                <td className="p-2 whitespace-nowrap">{new Date(o.first).toLocaleString()}</td><td className="p-2 whitespace-nowrap">{new Date(o.last).toLocaleString()}</td>
              </tr>))}</tbody>
          </table>
        </div>)}
    </div>
  )
}

export default function Analytics() {
  const [page, setPage] = useState<Page | null>(null)
  const [error, setError] = useState('')
  const [tab, setTab] = useState<'charts' | 'fixes' | 'table'>('charts')
  const load = useCallback(async () => {
    try { setPage(await api<Page>('/ui/analytics')); setError('') }
    catch (e) { setError(e instanceof ApiError ? e.message : 'Could not load analytics.') }
  }, [])
  useEffect(() => { void load(); const t = setInterval(() => void load(), 30000); return () => clearInterval(t) }, [load])
  const rows = page?.rows ?? []
  const f = useFilters(rows, FILTERS, (r) => [r.id, r.what, r.host, r.attacker, r.user, r.status, r.pattern_label], 'incidents')
  const shown = f.rows

  const stats = useMemo(() => {
    const contain = shown.map((r) => r.contain_min).filter((v): v is number => v != null)
    const close = shown.map((r) => r.close_min).filter((v): v is number => v != null)
    const per = new Map<string, number>()
    shown.forEach((r) => { if (r.attacker !== 'Unknown') per.set(r.attacker, (per.get(r.attacker) ?? 0) + 1) })
    const containByType = new Map<string, number[]>()
    shown.forEach((r) => { if (r.contain_min != null) containByType.set(r.what, [...(containByType.get(r.what) ?? []), r.contain_min]) })
    return {
      open: shown.filter((r) => !r.closed).length, contain: median(contain), close: median(close),
      repeat: [...per.values()].filter((n) => n > 1).length, auto: shown.filter((r) => r.auto).length,
      containByType: [...containByType.entries()].map(([k, v]) => [k, median(v) ?? 0] as [string, number]).sort((a, b) => b[1] - a[1]),
    }
  }, [shown])
  const seen = useMemo(() => new Set(shown.map((r) => r.pattern)), [shown])
  const tabs: [typeof tab, string][] = [['charts', 'Charts'], ['fixes', `Similar incidents and fixes (${page?.patterns.filter((p) => seen.has(p.id)).length ?? 0})`], ['table', `Incidents (${shown.length})`]]

  return (
    <section className="space-y-4">
      <header>
        <h1 className="text-2xl font-semibold">Analytics</h1>
        <p className="text-sm text-muted">how incidents add up over time, who keeps coming back, and fixes learned from similar ones</p>
      </header>
      {error && <p role="alert" className="rounded-md border border-line bg-surface p-3 text-bad">{error}</p>}
      {!page && !error && <p className="text-muted" role="status">Loading…</p>}
      {page && rows.length === 0 && <p className="text-soft">No incidents yet, so nothing to chart. All quiet at the gate.</p>}
      {page && rows.length > 0 && (
        <>
          {f.bar}
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-6">
            <Stat label="Incidents" value={shown.length} note={f.active ? 'matching the filters' : 'all time'} />
            <Stat label="Still open" value={stats.open} note="not resolved yet" hot={stats.open > 0} />
            <Stat label="Time to contain" value={span(stats.contain)} note="median, opened to blocked" />
            <Stat label="Time to close" value={span(stats.close)} note="median, opened to resolved" />
            <Stat label="Repeat offenders" value={stats.repeat} note="sources seen more than once" hot={stats.repeat > 0} />
            <Stat label="Handled automatically" value={shown.length ? `${Math.round((stats.auto / shown.length) * 100)}%` : '-'} note={`${stats.auto} within the guardrails`} />
          </div>
          <div role="tablist" aria-label="Part of the Analytics page" className="flex flex-wrap gap-2">
            {tabs.map(([t, label]) => (
              <button key={t} role="tab" aria-selected={tab === t} onClick={() => setTab(t)}
                className={'rounded-md px-3 py-1.5 text-sm ' + (tab === t ? 'bg-surface-3 text-ink' : 'text-soft hover:bg-surface-2')}>{label}</button>
            ))}
          </div>
          {f.active && shown.length === 0 && <p className="text-soft">No incidents match these filters.</p>}
          {tab === 'charts' && shown.length > 0 && (
            <div className="space-y-3">
              <Trend rows={shown} />
              <div className="grid gap-3 lg:grid-cols-2">
                <Bars title="By type" pairs={top(countBy(shown, (r) => r.what))} />
                <Bars title="By severity" pairs={countBy(shown, (r) => r.severity.charAt(0).toUpperCase() + r.severity.slice(1)).sort((a, b) => SEV_ORDER.indexOf(a[0].toLowerCase()) - SEV_ORDER.indexOf(b[0].toLowerCase()))} color={(k) => sevVar[k.toLowerCase()] ?? 'var(--ink-soft)'} />
                <Bars title="By machine" pairs={top(countBy(shown, (r) => r.host))} />
                <Bars title="By source" pairs={top(countBy(shown, (r) => r.attacker))} note="the address (or account) behind each incident" />
                <Bars title="Time to contain, by type" pairs={stats.containByType} fmt={span} note="median minutes from opened to blocked; only incidents that were contained" />
              </div>
              <Offenders rows={shown} />
            </div>
          )}
          {tab === 'fixes' && (
            <div className="space-y-3">
              <p className="text-sm text-soft">Incidents of the same type on the same layer are grouped, across every machine. Each group gets a playbook written from how past ones were handled{page.ai ? '; Draft with AI asks the AI model to write a better one from the same history' : ''}. Open an incident on <Link to="/incidents" className="underline">Incidents</Link> to see the ones most like it.</p>
              {page.patterns.filter((p) => seen.has(p.id)).map((p) => (
                <details key={p.id} className="rounded-lg border border-line bg-surface-2 p-3" open={p.open > 0}>
                  <summary className="cursor-pointer text-sm"><b>{p.label}</b> <span className="text-muted">· {p.count} incident{p.count === 1 ? '' : 's'} on {p.machines.length} machine{p.machines.length === 1 ? '' : 's'} ({p.machines.slice(0, 4).map((m) => `${m.host} ${m.count}`).join(', ')}){p.open ? `, ${p.open} open` : ''}</span></summary>
                  <div className="mt-3"><PlaybookCard p={p} ai={page.ai} changed={() => void load()} /></div>
                </details>
              ))}
            </div>
          )}
          {tab === 'table' && shown.length > 0 && (
            <div className="overflow-x-auto rounded-lg border border-line bg-surface" role="region" aria-label="Incidents" tabIndex={0}>
              <table className="w-full text-left text-sm">
                <thead className="border-b border-line text-xs uppercase tracking-wide text-muted">
                  <tr>{['Incident', 'Type', 'Machine', 'Severity', 'Status', 'Source', 'Opened', 'Contained in', 'Closed in', 'Pattern'].map((h) => <th key={h} className="p-2 font-medium">{h}</th>)}</tr></thead>
                <tbody>{shown.slice(0, 500).map((r) => (
                  <tr key={r.id} className="border-b border-line-soft last:border-0">
                    <td className="p-2 font-mono text-xs">{r.id}</td><td className="p-2">{r.what}</td><td className="p-2">{r.host}</td>
                    <td className="p-2 capitalize">{r.severity}</td><td className="p-2 capitalize">{r.status}</td><td className="p-2 font-mono text-xs">{r.attacker}</td>
                    <td className="p-2 whitespace-nowrap">{r.opened ? new Date(r.opened).toLocaleString() : '-'}</td>
                    <td className="p-2 whitespace-nowrap">{r.contain}</td><td className="p-2 whitespace-nowrap">{r.close}</td><td className="p-2 text-soft">{r.pattern_label}</td>
                  </tr>))}</tbody>
              </table>
              {shown.length > 500 && <p className="p-2 text-xs text-muted">Showing the newest 500. Narrow the filters to see others.</p>}
            </div>
          )}
        </>
      )}
    </section>
  )
}
