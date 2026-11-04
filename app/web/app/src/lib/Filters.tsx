// One filter bar for every table: a text search, a pick list per column, and a date range where rows carry a time.
import { isValidElement, useMemo, useState, type ReactNode } from 'react'
import { Search, X } from 'lucide-react'

export type Filter<T> = {
  key: string
  label: string
  get: (r: T) => unknown
  /** 'pick' (default) lists the values found in the rows; 'date' gives a from/to range on an ISO time. */
  kind?: 'pick' | 'date'
}

const field = 'rounded-md border border-line bg-surface-2 px-2 py-1.5 text-sm text-ink'
const words = (v: unknown) => (v == null ? '' : Array.isArray(v) ? v.join(' ') : typeof v === 'object' ? JSON.stringify(v) : String(v))
const pickValues = (v: unknown): string[] => (Array.isArray(v) ? v.map(String) : v == null || v === '' ? [] : [String(v)])
const day = (iso: unknown) => { const t = Date.parse(String(iso ?? '')); return Number.isNaN(t) ? null : t }

/** Filters `rows` and returns the bar to show above the table. `text` lists what the search box looks in. */
export function useFilters<T>(rows: T[], filters: Filter<T>[], text: (r: T) => unknown[], name = 'rows') {
  const [q, setQ] = useState('')
  const [picked, setPicked] = useState<Record<string, string>>({})
  const [from, setFrom] = useState<Record<string, string>>({})
  const [to, setTo] = useState<Record<string, string>>({})

  // Pick lists show only values that occur; a column with no values gets no list.
  const options = useMemo(() => Object.fromEntries(filters.filter((f) => f.kind !== 'date').map((f) => {
    const seen = new Set<string>()
    rows.forEach((r) => pickValues(f.get(r)).forEach((v) => seen.add(v)))
    return [f.key, [...seen].sort((a, b) => a.localeCompare(b, undefined, { numeric: true }))]
  })), [rows, filters])
  const dated = useMemo(() => filters.filter((f) => f.kind === 'date' && rows.some((r) => day(f.get(r)) != null)), [rows, filters])

  const out = useMemo(() => {
    const needle = q.trim().toLowerCase()
    return rows.filter((r) => {
      if (needle && !text(r).map(words).join(' ').toLowerCase().includes(needle)) return false
      for (const f of filters) {
        if (f.kind === 'date') {
          const t = day(f.get(r))
          const a = from[f.key] ? Date.parse(from[f.key] + 'T00:00:00') : null
          const b = to[f.key] ? Date.parse(to[f.key] + 'T23:59:59.999') : null
          if ((a != null || b != null) && t == null) return false
          if (a != null && t! < a) return false
          if (b != null && t! > b) return false
        } else if (picked[f.key] && !pickValues(f.get(r)).includes(picked[f.key])) return false
      }
      return true
    })
  }, [rows, filters, text, q, picked, from, to])

  const active = !!q.trim() || Object.values(picked).some(Boolean) || Object.values(from).some(Boolean) || Object.values(to).some(Boolean)
  const clear = () => { setQ(''); setPicked({}); setFrom({}); setTo({}) }

  const bar: ReactNode = rows.length === 0 ? null : (
    <div className="flex flex-wrap items-end gap-2" role="search" aria-label={`Filter ${name}`}>
      <label className="relative min-w-48 flex-1">
        <span className="sr-only">Search {name}</span>
        <Search size={14} aria-hidden className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-muted" />
        <input className={field + ' w-full pl-8'} value={q} onChange={(e) => setQ(e.target.value)} placeholder={`Search ${name}…`} />
      </label>
      {filters.filter((f) => f.kind !== 'date' && (options[f.key]?.length ?? 0) > 0).map((f) => (
        <label key={f.key} className="text-xs text-muted">
          <span className="block">{f.label}</span>
          <select className={field + ' max-w-48'} value={picked[f.key] ?? ''} onChange={(e) => setPicked((p) => ({ ...p, [f.key]: e.target.value }))}>
            <option value="">All</option>
            {options[f.key].map((v) => <option key={v} value={v}>{v}</option>)}
          </select>
        </label>
      ))}
      {dated.map((f) => (
        <fieldset key={f.key} className="flex items-end gap-1 text-xs text-muted">
          <legend className="sr-only">{f.label}</legend>
          <label><span className="block">{f.label} from</span>
            <input type="date" className={field} value={from[f.key] ?? ''} onChange={(e) => setFrom((p) => ({ ...p, [f.key]: e.target.value }))} /></label>
          <label><span className="block">to</span>
            <input type="date" className={field} value={to[f.key] ?? ''} onChange={(e) => setTo((p) => ({ ...p, [f.key]: e.target.value }))} /></label>
        </fieldset>
      ))}
      {active && (
        <button className="inline-flex items-center gap-1 rounded-md px-2 py-1.5 text-sm text-soft hover:bg-surface-2" onClick={clear}>
          <X size={14} aria-hidden /> Clear
        </button>
      )}
      <p className="w-full text-xs text-muted" role="status">{active ? `Showing ${out.length} of ${rows.length} ${name}` : `${rows.length} ${name}`}</p>
    </div>
  )
  return { rows: out, bar, active }
}

/** The words a table cell shows, for searching cells that hold markup. */
export function nodeText(n: ReactNode): string {
  if (n == null || typeof n === 'boolean') return ''
  if (typeof n === 'string' || typeof n === 'number') return String(n)
  if (Array.isArray(n)) return n.map(nodeText).join(' ')
  if (isValidElement(n)) return nodeText((n.props as { children?: ReactNode }).children)
  return ''
}

/** Pick lists for a plain table of cells: every column with a few repeating values gets one. */
export function cellFilters(head: string[], rows: ReactNode[][], skip: string[] = []): Filter<ReactNode[]>[] {
  return head.flatMap((h, i) => {
    if (skip.includes(h)) return []
    const seen = new Set(rows.map((r) => nodeText(r[i]).trim()).filter(Boolean))
    return seen.size > 1 && seen.size <= 15 && seen.size < rows.length ? [{ key: String(i), label: h, get: (r: ReactNode[]) => nodeText(r[i]).trim() }] : []
  })
}

/** A long table draws its first rows only, with a button for more: a page with a thousand incidents then opens and
 *  refreshes as fast as one with fifty. Filters and search still look at every row. Starts again when `reset`
 *  changes (a new filter). */
export function useShowMore<T>(rows: T[], reset: unknown = null, step = 50) {
  const [limit, setLimit] = useState(step)
  const [last, setLast] = useState(reset)
  if (last !== reset) { setLast(reset); setLimit(step) }
  const left = rows.length - limit
  const more: ReactNode = left <= 0 ? null : (
    <div className="flex flex-wrap items-center gap-2 p-2 text-sm text-soft">
      <span>Showing {limit} of {rows.length}.</span>
      <button className="rounded-md border border-line px-2 py-1 hover:bg-surface-2" onClick={() => setLimit(limit + step)}>Show {Math.min(step, left)} more</button>
      {left > step && <button className="rounded-md px-2 py-1 hover:bg-surface-2" onClick={() => setLimit(rows.length)}>Show all {rows.length}</button>}
    </div>
  )
  return { shown: left > 0 ? rows.slice(0, limit) : rows, more }
}
