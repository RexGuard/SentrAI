import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { Bot, CheckCircle2, FileDown, ShieldAlert, UserRound } from 'lucide-react'
import { api, ApiError } from '../lib/api'
import { btn, btnPrimary } from '../lib/ui'
import { useFilters, type Filter } from '../lib/Filters'

type Entry = {
  seq: number | null; date: string; time: string; agent: string; person: string; type: string; summary: string; hash: string; ts?: string
}
type AgentRow = { agent: string; role: string; can_act: string; records: number; last: string }
type Page = {
  chain_valid: boolean | null; first_invalid_seq: number | null; count: number; head_hash: string
  feed: Entry[]; agents: AgentRow[]
}

const PAGE = 200
const FEED: Filter<Entry>[] = [
  { key: 'type', label: 'Type', get: (e) => e.type },
  { key: 'who', label: 'Who', get: (e) => (e.person ? 'People' : 'Agents') },
]
const NONE: Entry[] = []
const key = (e: Entry) => `${e.seq}-${e.hash}`
const who = (e: Entry) => (e.person ? e.person : e.agent)

/** Newest first, one row per #, whatever order the pages arrived in. */
function merge(a: Entry[], b: Entry[]): Entry[] {
  const by = new Map<string, Entry>()
  for (const e of [...a, ...b]) by.set(key(e), e)
  return [...by.values()].sort((x, y) => (y.seq ?? 0) - (x.seq ?? 0))
}

// One hover card for the whole table: it is drawn only for the name under the pointer (or keyboard focus), so a
// page of 500 records has one card in it, not 500.
type Hover = { e: Entry; x: number; y: number }
function HoverCard({ h, agents }: { h: Hover; agents: AgentRow[] }) {
  const a = h.e.person ? undefined : agents.find((r) => r.agent === h.e.agent)
  return createPortal(
    <div role="tooltip" id="audit-card" className="pointer-events-none fixed z-50 w-72 rounded-xl border border-line bg-bg p-3 text-sm shadow-lg"
      style={{ left: Math.min(h.x, window.innerWidth - 300), top: h.y + 6 }}>
      <p className="flex items-center gap-2 font-semibold">{h.e.person ? <UserRound size={15} aria-hidden /> : <Bot size={15} aria-hidden />}{who(h.e)}</p>
      <p className="text-xs text-muted">{h.e.person ? 'A person, signed in to the panel' : a ? `${a.role} · ${a.can_act === 'Yes' ? 'can take actions' : 'reports only'}` : 'A SentrAI agent'}</p>
      {a && <p className="mt-1 text-xs text-soft">{a.records} records lately, last at {a.last}</p>}
      <p className="mt-2 border-t border-line-soft pt-2 text-xs text-soft"><b className="text-ink">{h.e.type}</b> · #{h.e.seq ?? '-'} · {h.e.date} {h.e.time}</p>
      <p className="mt-1 font-mono text-[11px] text-muted">Record hash {h.e.hash}</p>
    </div>, document.body)  // on the page itself: the content panel's blur would pin a fixed card to the panel
}

export default function Audit() {
  const [page, setPage] = useState<Page | null>(null)
  const [rows, setRows] = useState<Entry[]>([])
  const [error, setError] = useState('')
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)
  const [picked, setPicked] = useState<Set<string>>(new Set())
  const [hover, setHover] = useState<Hover | null>(null)
  const timer = useRef<number | undefined>(undefined)

  const load = useCallback(async () => {
    try { const p = await api<Page>(`/ui/audit?limit=${PAGE}`); setPage(p); setRows((r) => merge(r, p.feed)); setError('') }
    catch (e) { setError(e instanceof ApiError ? `Could not load the activity log: ${e.message}` : 'Could not load the activity log.') }
  }, [])
  useEffect(() => { void load(); const t = setInterval(() => void load(), 10000); return () => clearInterval(t) }, [load])
  const oldest = rows.length ? rows[rows.length - 1].seq : null
  const older = async () => {
    if (!oldest) return
    setBusy(true)
    try { const p = await api<Page>(`/ui/audit?limit=${PAGE}&before=${oldest}`); setRows((r) => merge(r, p.feed)) }
    catch (e) { setNote(e instanceof ApiError ? e.message : 'Could not load older records.') }
    setBusy(false)
  }

  const feed = useFilters(rows.length ? rows : NONE, FEED, (e) => [e.seq, e.agent, e.person, e.type, e.summary, e.hash], 'records')
  const shownKeys = useMemo(() => feed.rows.map(key), [feed.rows])
  const allOn = shownKeys.length > 0 && shownKeys.every((k) => picked.has(k))
  const toggleAll = () => setPicked((p) => { const n = new Set(p); shownKeys.forEach((k) => (allOn ? n.delete(k) : n.add(k))); return n })
  const toggle = (k: string) => setPicked((p) => { const n = new Set(p); if (n.has(k)) n.delete(k); else n.add(k); return n })
  const chosen = rows.filter((e) => picked.has(key(e)) && e.seq != null)

  const exportPdf = async () => {
    setBusy(true); setNote('')
    // The chosen records, or every record shown (all of the log when nothing is filtered or chosen).
    const body = chosen.length ? { seqs: chosen.map((e) => e.seq) } : feed.active ? { seqs: feed.rows.filter((e) => e.seq != null).map((e) => e.seq) } : { all: true }
    try {
      const res = await fetch('/api/ui/audit/pdf', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'X-SentrAI-Web': '1' }, body: JSON.stringify(body) })
      if (!res.ok) { let d = res.statusText; try { d = (await res.json()).detail ?? d } catch { /* not JSON */ } throw new Error(d) }
      const url = URL.createObjectURL(await res.blob())
      const a = document.createElement('a'); a.href = url; a.download = 'sentrai-activity-log.pdf'; a.click()
      setTimeout(() => URL.revokeObjectURL(url), 1000)
    } catch (e) { setNote(`Could not make the PDF: ${e instanceof Error ? e.message : 'failed'}`) }
    setBusy(false)
  }

  const show = (e: Entry, el: HTMLElement) => { window.clearTimeout(timer.current); const r = el.getBoundingClientRect(); setHover({ e, x: r.left, y: r.bottom }) }
  const hide = () => { timer.current = window.setTimeout(() => setHover(null), 80) }

  return (
    <section className="space-y-4">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold">Activity Log</h1>
          <p className="text-sm text-muted">Every action by every agent and person, in the order it happened, hash-chained</p>
        </div>
        <button className={btnPrimary} disabled={busy || !rows.length} onClick={() => void exportPdf()}>
          <FileDown size={14} aria-hidden /> {chosen.length ? `Export ${chosen.length} to PDF` : 'Export to PDF'}
        </button>
      </header>
      {error && <p role="alert" className="rounded-md border border-line bg-surface p-3 text-bad">{error}</p>}
      {note && <p role="status" className="rounded-md border border-line bg-surface p-3">{note}</p>}
      {page && (
        <div className="min-w-0 space-y-3 rounded-lg border border-line bg-surface p-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h2 className="font-semibold">Agent Activity <span className="font-normal text-muted">· {rows.length} of {page.count} records, newest first</span></h2>
            {page.chain_valid === false
              ? <span className="inline-flex items-center gap-1 text-crit"><ShieldAlert size={16} aria-hidden /> Chain broken at #{page.first_invalid_seq}</span>
              : <span className="inline-flex items-center gap-1 text-ok"><CheckCircle2 size={16} aria-hidden /> Chain intact</span>}
          </div>
          {feed.bar}
          {rows.length === 0 ? <p className="text-soft">No activity yet.</p> : feed.rows.length === 0 ? <p className="text-soft">No records match these filters.</p> : (
            <div className="overflow-x-auto" role="region" aria-label="Agent activity" tabIndex={0}>
              <table className="w-full text-left text-sm">
                <thead className="border-b border-line text-xs uppercase tracking-wide text-muted">
                  <tr>
                    <th className="w-10 p-2"><input type="checkbox" checked={allOn} onChange={toggleAll} aria-label="Select all shown records" className="accent-[var(--accent)]" /></th>
                    <th className="w-36 p-2 font-medium">When · #</th>
                    <th className="p-2 font-medium">Who and what was done</th>
                  </tr>
                </thead>
                <tbody>
                  {feed.rows.map((e) => {
                    const k = key(e)
                    return (
                      <tr key={k} className={'border-b border-line-soft align-top last:border-0 ' + (picked.has(k) ? 'bg-surface-2' : '')}>
                        <td className="p-2"><input type="checkbox" checked={picked.has(k)} onChange={() => toggle(k)} aria-label={`Select #${e.seq}`} className="accent-[var(--accent)]" /></td>
                        <td className="p-2 text-xs text-muted">{e.date}<br />{e.time}<br /><span className="font-mono">#{e.seq ?? '-'}</span></td>
                        <td className="min-w-0 p-2">
                          <span tabIndex={0} className="inline-flex cursor-default items-center gap-1.5 font-semibold underline decoration-dotted underline-offset-4"
                            aria-describedby={hover?.e === e ? 'audit-card' : undefined}
                            onMouseEnter={(ev) => show(e, ev.currentTarget)} onMouseLeave={hide} onFocus={(ev) => show(e, ev.currentTarget)} onBlur={hide}>
                            {e.person ? <UserRound size={14} aria-hidden /> : <Bot size={14} aria-hidden />}{who(e)}
                          </span>
                          <p className="mt-0.5 break-words text-soft"><span className="text-muted">{e.type}:</span> {e.summary}</p>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
          {oldest != null && oldest > 1 && <button className={btn} disabled={busy} onClick={() => void older()}>Show older records</button>}
        </div>
      )}
      {hover && page && <HoverCard h={hover} agents={page.agents} />}
    </section>
  )
}
