// One severity's risks as bubbles (opened from the Command center's grouped buttons). Approvals and incidents that
// need a person are one list here; a wave of many addresses doing the same thing is one bubble.
import { useCallback, useEffect, useState } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { ChevronLeft } from 'lucide-react'
import { api, ApiError } from '../lib/api'
import { btn } from '../lib/ui'
import { LEVEL_TEXT, RiskBubble, RiskDetail, type Level, type Risks } from '../lib/Risks'

const LEVELS: Level[] = ['critical', 'high', 'medium', 'low']
const PAGE = 30

export default function RiskList() {
  const { severity = 'critical' } = useParams()
  const level = (LEVELS.includes(severity as Level) ? severity : 'critical') as Level
  const [params, setParams] = useSearchParams()
  const go = useNavigate()
  const [data, setData] = useState<Risks | null>(null)
  const [error, setError] = useState('')
  const [note, setNote] = useState('')
  const [shown, setShown] = useState(PAGE)
  const load = useCallback(async () => {
    try { setData(await api<Risks>(`/ui/risks?severity=${level}`)); setError('') }
    catch (e) { setError(e instanceof ApiError ? e.message : 'Could not load the risks.') }
  }, [level])
  useEffect(() => { setShown(PAGE); void load(); const t = setInterval(() => void load(), 10000); return () => clearInterval(t) }, [load])

  const openId = params.get('open')
  const rows = data?.rows ?? []
  const open = rows.find((r) => r.id === openId) ?? null
  const setOpen = (id: string | null) => setParams(id ? { open: id } : {}, { replace: !id })
  const t = LEVEL_TEXT[level]
  const count = data?.levels.find((l) => l.severity === level)?.count ?? 0

  return (
    <section className="space-y-4">
      <header className="space-y-2">
        <Link to="/command" className="inline-flex items-center gap-0.5 text-sm text-soft hover:text-ink"><ChevronLeft size={14} aria-hidden /> Command center</Link>
        <h1 className="text-2xl font-semibold"><span style={{ color: t.color }}>{t.name}</span> risks <span className="font-normal text-muted">({count})</span></h1>
        <p className="text-sm text-muted">Open a bubble to see what happened, what it means and what to do.</p>
        <div role="tablist" aria-label="Severity" className="flex flex-wrap gap-2">
          {LEVELS.map((l) => {
            const n = data?.levels.find((x) => x.severity === l)?.count ?? 0
            if (l === 'low' && !n && level !== 'low') return null
            return <button key={l} role="tab" aria-selected={l === level} onClick={() => go(`/risks/${l}`)}
              className={'rounded-full border px-3 py-1 text-sm ' + (l === level ? 'bg-surface-3 text-ink' : 'text-soft hover:bg-surface-2')}
              style={{ borderColor: l === level ? LEVEL_TEXT[l].color : 'var(--line)' }}>{LEVEL_TEXT[l].name} · {n}</button>
          })}
        </div>
      </header>
      {error && <p role="alert" className="rounded-md border border-line bg-surface p-3 text-bad">{error}</p>}
      {note && <p role="status" className="rounded-md border border-line bg-surface p-3">{note}</p>}
      {!data ? <p className="text-muted" role="status">Loading…</p> : rows.length === 0 ? (
        <p className="rounded-[2rem] border border-line bg-surface p-6 text-ok">Nothing {t.name.toLowerCase()} needs a person. All quiet at the gate.</p>
      ) : (
        <>
          <ul className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4">
            {rows.slice(0, shown).map((r) => <li key={r.id}><RiskBubble r={r} onOpen={() => setOpen(r.id)} /></li>)}
          </ul>
          {rows.length > shown && <button className={btn} onClick={() => setShown(shown + PAGE)}>Show {Math.min(PAGE, rows.length - shown)} more of {rows.length - shown}</button>}
        </>
      )}
      {open && data && <RiskDetail key={open.id} r={open} protectionOn={data.protection_on} onClose={() => setOpen(null)}
        onDone={(n) => { setNote(n); setOpen(null); void load() }} />}
    </section>
  )
}
