import { useCallback, useEffect, useState } from 'react'
import { api, ApiError } from '../lib/api'
import { btn, btnPrimary } from '../lib/ui'
import { useSession } from '../lib/session'

type Report = {
  id: string; status: string; kind_label?: string; reporter?: string; contact?: string; where?: string; host?: string
  received_at?: string; channel?: string; incident?: string; assignee?: string; text?: string
  triage?: { kind?: string; urgency?: string; by?: string; summary?: string; for_tech?: string; advice?: string[] }
  notes?: { by: string; at: string; text: string }[]
}
type Data = { reports: Report[]; counts: Record<string, number> }

const FILTERS: [string, string | null][] = [['Open', 'open'], ['New', 'new'], ['Reviewing', 'reviewing'], ['Resolved', 'resolved'], ['Not a threat', 'not_a_threat'], ['All', null]]
const LABEL: Record<string, string> = { new: 'New', reviewing: 'Reviewing', resolved: 'Resolved', not_a_threat: 'Not a threat' }
const urgColor: Record<string, string> = { high: 'text-crit', medium: 'text-warn', low: 'text-ok' }
const field = 'mt-1 block rounded-md border border-line bg-surface-2 px-3 py-1.5 text-ink'

function Stat({ label, value, note, hot }: { label: string; value: number; note: string; hot?: boolean }) {
  return (
    <div className="rounded-lg border border-line bg-surface p-4">
      <p className="text-xs uppercase tracking-wide text-muted">{label}</p>
      <p className={'text-2xl font-semibold ' + (hot ? 'text-warn' : '')}>{value}</p>
      <p className="text-xs text-muted">{note}</p>
    </div>
  )
}

function Detail({ r, done }: { r: Report; done: (msg: string) => void }) {
  const { me, can } = useSession()
  const op = me?.email ?? 'dashboard'
  const t = r.triage ?? {}
  const [who, setWho] = useState(r.assignee || op)
  const [note, setNote] = useState('')
  const [err, setErr] = useState('')
  const open = r.status === 'new' || r.status === 'reviewing'
  const send = async (status: string | null) => {
    if (status && !note.trim()) return setErr('Add a short note saying what you found before closing it.')
    setErr('')
    try {
      await api(`/staff-reports/${encodeURIComponent(r.id)}`, { body: { operator: op, status, assignee: who.trim(), note: note.trim() || null } })
      done(`${r.id} updated`)
    } catch (e) { setErr(e instanceof ApiError ? e.message : 'That did not go through.') }
  }
  const off = !can('act')
  const why = off ? 'Your role can read everything but change nothing.' : undefined
  return (
    <div className="space-y-4 p-4">
      <dl className="grid grid-cols-2 gap-3 text-sm lg:grid-cols-3">
        {([['Reported by', r.reporter || 'anonymous'], ['Contact', r.contact || '-'], ['Where', `${r.where || '-'}${r.host ? ` · ${r.host}` : ''}`],
          ['Received', `${r.received_at ? new Date(r.received_at).toLocaleString() : '-'} · ${r.channel || '-'}`],
          ['Sorted by', t.by === 'ai' ? 'AI model' : 'Keyword rules'], ['Incident', r.incident || '-']] as [string, string][]).map(([k, v]) => (
          <div key={k}><dt className="text-xs text-muted">{k}</dt><dd className="font-medium">{v}</dd></div>
        ))}
      </dl>
      <div><h2 className="text-sm font-semibold">What they wrote</h2><p className="whitespace-pre-wrap text-soft">{r.text}</p></div>
      <div className="grid gap-4 lg:grid-cols-2">
        <div className="space-y-2">
          <div><h2 className="text-sm font-semibold">Summary</h2><p className="text-soft">{t.summary || '-'}</p></div>
          <div><h2 className="text-sm font-semibold">Check first</h2><p className="text-soft">{t.for_tech || '-'}</p></div>
        </div>
        <div><h2 className="text-sm font-semibold">What the reporter was told</h2>
          {t.advice?.length ? <ol className="list-decimal pl-5 text-soft">{t.advice.map((a, i) => <li key={i}>{a}</li>)}</ol> : <p className="text-soft">-</p>}</div>
      </div>
      {r.notes?.length ? <div><h2 className="text-sm font-semibold">Notes</h2>{r.notes.map((n, i) => <p key={i} className="text-soft"><b>{n.by}</b> · {new Date(n.at).toLocaleTimeString()}<br />{n.text}</p>)}</div> : null}
      {open && (
        <form className="space-y-2" onSubmit={(e) => { e.preventDefault(); void send(null) }}>
          <div className="flex flex-wrap gap-3">
            <label className="text-sm text-soft">Handled by<input className={field} value={who} onChange={(e) => setWho(e.target.value)} /></label>
            <label className="min-w-64 flex-1 text-sm text-soft">Note<input className={field + ' w-full'} value={note} onChange={(e) => setNote(e.target.value)} placeholder="What you found or did (needed to close)" /></label>
          </div>
          {err && <p role="alert" className="text-bad">{err}</p>}
          <div className="flex flex-wrap gap-2">
            <button className={btn} disabled={off} title={why}>Save</button>
            <button type="button" className={btnPrimary} disabled={off} title={why} onClick={() => void send('resolved')}>Resolved</button>
            <button type="button" className={btn} disabled={off} title={why} onClick={() => void send('not_a_threat')}>Not a threat</button>
          </div>
        </form>
      )}
    </div>
  )
}

export default function Staff() {
  const [data, setData] = useState<Data | null>(null)
  const [error, setError] = useState('')
  const [note, setNote] = useState('')
  const [filter, setFilter] = useState('open')
  const [openId, setOpenId] = useState<string | null>(null)
  const load = useCallback(async () => {
    try { setData(await api<Data>('/staff-reports')); setError('') } catch (e) { setError(e instanceof ApiError ? e.message : 'Could not load staff reports.') }
  }, [])
  useEffect(() => { void load(); const t = setInterval(() => void load(), 10000); return () => clearInterval(t) }, [load])
  const counts = data?.counts ?? {}
  const want = FILTERS.find(([, v]) => (v ?? 'all') === filter)?.[1] ?? null
  const reports = (data?.reports ?? []).filter((r) => want === null || r.status === want || (want === 'open' && (r.status === 'new' || r.status === 'reviewing')))

  return (
    <section className="space-y-4">
      <header>
        <h1 className="text-2xl font-semibold">Staff reports</h1>
        <p className="text-sm text-muted">what people at the business flagged · a person reads and closes each one</p>
      </header>
      {error && <p role="alert" className="rounded-md border border-line bg-surface p-3 text-bad">{error}</p>}
      {note && <p role="status" className="rounded-md border border-line bg-surface p-3">{note}</p>}
      {data && (
        <>
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            <Stat label="New" value={counts.new ?? 0} note="nobody has picked these up" hot={!!counts.new} />
            <Stat label="Reviewing" value={counts.reviewing ?? 0} note="someone is on it" />
            <Stat label="Resolved" value={counts.resolved ?? 0} note="real problems dealt with" />
            <Stat label="Not a threat" value={counts.not_a_threat ?? 0} note="checked and harmless" />
          </div>
          <p className="text-sm text-muted">Staff report from the open report page, which needs no sign-in and is still served by the current console (add <code className="font-mono">/?report</code> to its address).</p>
          <div role="tablist" aria-label="Show" className="flex flex-wrap gap-2">
            {FILTERS.map(([label, v]) => (
              <button key={label} role="tab" aria-selected={filter === (v ?? 'all')} onClick={() => setFilter(v ?? 'all')}
                className={'rounded-md px-3 py-1.5 text-sm ' + (filter === (v ?? 'all') ? 'bg-surface-3 text-ink' : 'text-soft hover:bg-surface-2')}>{label}</button>
            ))}
          </div>
          {reports.length === 0
            ? <p className={'rounded-lg border border-line bg-surface p-4 ' + (filter === 'open' ? 'text-ok' : 'text-soft')}>{filter === 'open' ? 'No open staff reports. All quiet.' : 'No staff reports here.'}</p>
            : reports.map((r) => {
              const t = r.triage ?? {}
              const expanded = (openId ?? (reports[0]?.status === 'new' ? reports[0].id : null)) === r.id
              return (
                <div key={r.id} className="rounded-lg border border-line bg-surface">
                  <button aria-expanded={expanded} className="flex w-full flex-wrap items-center gap-x-3 p-3 text-left text-sm" onClick={() => setOpenId(expanded ? '' : r.id)}>
                    <span className="font-mono text-xs">{r.id}</span><span>{r.kind_label || t.kind}</span>
                    <span className={'font-medium capitalize ' + (urgColor[t.urgency ?? ''] ?? '')}>{t.urgency}</span>
                    <span className="text-soft">{r.reporter || 'anonymous'}</span><span className="text-muted">{LABEL[r.status] ?? r.status}</span>
                    {r.assignee && <span className="text-muted">With {r.assignee}</span>}
                  </button>
                  {expanded && <div className="border-t border-line"><Detail r={r} done={(m) => { setNote(m); void load() }} /></div>}
                </div>
              )
            })}
        </>
      )}
    </section>
  )
}
