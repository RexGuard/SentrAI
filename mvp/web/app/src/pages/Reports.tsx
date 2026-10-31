import { useCallback, useEffect, useState } from 'react'
import Markdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { Download, Send } from 'lucide-react'
import { api, ApiError } from '../lib/api'
import { btn, btnPrimary } from '../lib/ui'
import { useSession } from '../lib/session'

type Sched = { every: string; at: string; day: string; to: string; next_at?: string }
type Incident = { id: string; category?: string; opened_at?: string }

const EVERY: Record<string, string> = { daily: 'Every day', weekly: 'Every week', off: 'Off' }
const DAYS: Record<string, string> = { mon: 'Monday', tue: 'Tuesday', wed: 'Wednesday', thu: 'Thursday', fri: 'Friday', sat: 'Saturday', sun: 'Sunday' }
const field = 'mt-1 block rounded-md border border-line bg-surface-2 px-3 py-1.5 text-ink'
const link = btn + ' no-underline'

function Doc({ md, label }: { md: string; label: string }) {
  return (
    <div className="max-h-[32rem] overflow-y-auto rounded-md border border-line bg-surface-2 p-4 text-sm leading-relaxed" role="region" aria-label={label} tabIndex={0}>
      <Markdown remarkPlugins={[remarkGfm]} components={{
        table: ({ children }) => <div className="mb-2 overflow-x-auto" tabIndex={0}><table className="w-full text-left text-xs">{children}</table></div>,
        th: ({ children }) => <th className="border-b border-line p-1.5 font-medium text-muted">{children ?? <span className="sr-only">Detail</span>}</th>,
        td: ({ children }) => <td className="border-b border-line-soft p-1.5 align-top">{children}</td>,
        h1: ({ children }) => <h3 className="mb-2 mt-3 text-lg font-semibold">{children}</h3>,
        h2: ({ children }) => <h3 className="mb-2 mt-3 text-base font-semibold">{children}</h3>,
        h3: ({ children }) => <h4 className="mb-1 mt-2 font-semibold">{children}</h4>,
        p: ({ children }) => <p className="mb-2">{children}</p>,
        ul: ({ children }) => <ul className="mb-2 list-disc pl-5">{children}</ul>,
        ol: ({ children }) => <ol className="mb-2 list-decimal pl-5">{children}</ol>,
        code: ({ children }) => <code className="font-mono text-xs">{children}</code>,
        a: ({ children }) => <span className="underline">{children}</span>,
      }}>{md}</Markdown>
    </div>
  )
}

function Summary() {
  const { me, can } = useSession()
  const op = me?.email ?? 'dashboard'
  const [sched, setSched] = useState<Sched | null>(null)
  const [period, setPeriod] = useState<'daily' | 'weekly'>('daily')
  const [md, setMd] = useState('')
  const [note, setNote] = useState('')
  const [err, setErr] = useState('')
  const off = !can('configure')
  useEffect(() => { api<Sched>('/summary/schedule').then((s) => { setSched(s); setPeriod(s.every === 'weekly' ? 'weekly' : 'daily') }).catch(() => {}) }, [])
  useEffect(() => { setMd(''); api<string>(`/summary/${period}.md`).then(setMd).catch((e) => setErr(e instanceof ApiError ? `The summary could not be made: ${e.message}` : 'The summary could not be made.')) }, [period])
  if (!sched) return null
  const save = async () => {
    setErr('')
    try { const s = await api<Sched>('/summary/schedule', { body: { operator: op, every: sched.every, at: sched.at, day: sched.day, to: sched.to } }); setSched(s); setNote('Summary schedule saved') }
    catch (e) { setErr(e instanceof ApiError ? e.message : 'Could not save.') }
  }
  const sendNow = async () => { try { await api('/summary/send', { body: { operator: op } }); setNote('Summary sent to the alert channels') } catch (e) { setErr(e instanceof ApiError ? e.message : 'Could not send.') } }
  return (
    <div className="grid gap-4 lg:grid-cols-[4fr_8fr]">
      <form className="space-y-3 rounded-lg border border-line bg-surface p-4" onSubmit={(e) => { e.preventDefault(); void save() }}>
        <h2 className="font-semibold">Client summary <span className="font-normal text-muted">· {sched.next_at ? `next: ${sched.next_at.slice(0, 16).replace('T', ' ')}` : 'not scheduled'}</span></h2>
        <fieldset className="flex flex-wrap gap-3"><legend className="text-sm text-soft">Send it</legend>
          {Object.entries(EVERY).map(([k, v]) => <label key={k} className="flex items-center gap-1 text-sm"><input type="radio" name="every" checked={sched.every === k} onChange={() => setSched({ ...sched, every: k })} /> {v}</label>)}
        </fieldset>
        <div className="flex flex-wrap gap-3">
          <label className="text-sm text-soft">At (local time)<input className={field + ' w-28'} value={sched.at} onChange={(e) => setSched({ ...sched, at: e.target.value })} /></label>
          <label className="text-sm text-soft">On (weekly)<select className={field} value={sched.day} onChange={(e) => setSched({ ...sched, day: e.target.value })}>{Object.entries(DAYS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label>
        </div>
        <label className="block text-sm text-soft">Addressed to<input className={field + ' w-full'} value={sched.to} onChange={(e) => setSched({ ...sched, to: e.target.value })} /></label>
        <div className="flex gap-2">
          <button className={btnPrimary} disabled={off} title={off ? 'Your role can read everything but change nothing.' : undefined}>Save</button>
          <button type="button" className={btn} disabled={off} onClick={() => void sendNow()}><Send size={14} aria-hidden /> Send one now</button>
        </div>
        {note && <p role="status" className="text-sm">{note}</p>}
      </form>
      <div className="min-w-0 space-y-3 rounded-lg border border-line bg-surface p-4">
        <div className="flex flex-wrap items-center gap-2">
          <div role="tablist" aria-label="Period" className="flex gap-2">
            {(['daily', 'weekly'] as const).map((p) => <button key={p} role="tab" aria-selected={period === p} onClick={() => setPeriod(p)}
              className={'rounded-md px-3 py-1.5 text-sm ' + (period === p ? 'bg-surface-3' : 'text-soft hover:bg-surface-2')}>{p === 'daily' ? 'Last 24 hours' : 'Last 7 days'}</button>)}
          </div>
          <a className={link + ' ml-auto'} href={`/api/summary/${period}.pdf`} download><Download size={14} aria-hidden /> PDF (one page)</a>
          <a className={link} href={`/api/summary/${period}.md`} download><Download size={14} aria-hidden /> Markdown</a>
        </div>
        {err && !md ? <p role="alert" className="text-bad">{err}</p> : md ? <Doc md={md} label="Client summary" /> : <p className="text-muted" role="status">Loading…</p>}
      </div>
    </div>
  )
}

export default function Reports() {
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [pick, setPick] = useState('')
  const [md, setMd] = useState<string | null>(null)
  const [error, setError] = useState('')
  const load = useCallback(async () => {
    try {
      const list = (await api<Incident[]>('/incidents')).sort((a, b) => String(b.opened_at).localeCompare(String(a.opened_at)))
      setIncidents(list); setPick((p) => p || list[0]?.id || ''); setError('')
    } catch (e) { setError(e instanceof ApiError ? e.message : 'Could not load incidents.') }
  }, [])
  useEffect(() => { void load() }, [load])
  useEffect(() => { if (!pick) return; setMd(null); api<string>(`/reports/${encodeURIComponent(pick)}.md`).then(setMd).catch(() => setMd('')) }, [pick])
  const id = encodeURIComponent(pick)
  return (
    <section className="space-y-4">
      <header>
        <h1 className="text-2xl font-semibold">Reports</h1>
        <p className="text-sm text-muted">a one-page summary for the client, and one evidence report for every incident</p>
      </header>
      {error && <p role="alert" className="rounded-md border border-line bg-surface p-3 text-bad">{error}</p>}
      <Summary />
      {incidents.length === 0 ? <p className="rounded-lg border border-line bg-surface p-4 text-soft">No incidents yet, so no reports.</p> : (
        <div className="space-y-3 rounded-lg border border-line bg-surface p-4">
          <h2 className="font-semibold">Evidence report</h2>
          <div className="flex flex-wrap items-end gap-3">
            <label className="text-sm text-soft">Open report for
              <select className={field} value={pick} onChange={(e) => setPick(e.target.value)}>
                {incidents.map((i) => <option key={i.id} value={i.id}>{i.id} · {(i.category ?? '').replace(/_/g, ' ')}</option>)}
              </select></label>
            {md && <>
              <a className={btnPrimary + ' no-underline'} href={`/api/reports/${id}.pdf`} download><Download size={14} aria-hidden /> PDF</a>
              <a className={link} href={`/api/reports/${id}.md`} download><Download size={14} aria-hidden /> Markdown</a>
            </>}
          </div>
          {md === null ? <p className="text-muted" role="status">Loading…</p> : md ? <Doc md={md} label="Evidence report" /> : <p className="text-soft">No report for this incident yet.</p>}
        </div>
      )}
    </section>
  )
}
