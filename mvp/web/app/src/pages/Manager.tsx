// Manager view: the one page a manager or owner reads in a minute. Are we safe, what happened, what SentrAI did
// about it, what still needs a person, and the proof that the record was not changed. Plain words only: every
// figure comes from the client summary (GET /summary/{daily|weekly}), which already speaks without internal part
// names, plus the backups and approvals the dashboard shows elsewhere.
import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { CheckCircle2, ChevronRight, Download, ShieldAlert, ShieldCheck } from 'lucide-react'
import { api, ApiError } from '../lib/api'
import { btn } from '../lib/ui'
import Stat from '../lib/Stat'

type Attention = { incident: string; what: string; machine: string; severity: string; open_for: string; seen_by_staff: boolean; late: boolean; next_step: string }
type Summary = {
  headline: string; period_text: string; title: string
  numbers: { threats: number; stopped_automatically: number; handled_by_staff: number; closed: number; need_attention: number; late_response: number; alerts_sent: number }
  risk_now: { index: number | null; band: string }
  attention: Attention[]
  kinds: { what: string; count: number }[]
  machines: { machine: string; threats: number; stopped: number; open: number }[]
  actions: { done: Record<string, number>; total: number; undone: number; expired: number; permanent: number }
  proof: { chain_valid: boolean; records: number; short: string }
  responsible?: string
}
type Backups = { backups: { id: string; created?: string; verified?: { ok?: boolean | null } }[]; overdue?: boolean; last_error?: { error?: string } }

// The risk band, as a manager would say it.
const SAFE: Record<string, { word: string; line: string; cls: string }> = {
  green: { word: 'Safe', line: 'Nothing unusual right now.', cls: 'text-ok' },
  amber: { word: 'Watchful', line: 'Some suspicious activity. SentrAI is watching it closely.', cls: 'text-warn' },
  red: { word: 'Under attack', line: 'An attack is in progress. SentrAI is blocking it; your IT contact is told.', cls: 'text-bad' },
  critical: { word: 'Serious attack', line: 'A serious attack. Your IT contact should act now.', cls: 'text-crit' },
}
const ago = (iso?: string) => {
  if (!iso) return ''
  const h = (Date.now() - new Date(iso).getTime()) / 3600000
  return h < 1 ? 'less than an hour ago' : h < 48 ? `${Math.round(h)} hours ago` : `${Math.round(h / 24)} days ago`
}

function Box({ title, children, to, more }: { title: string; children: React.ReactNode; to?: string; more?: string }) {
  return (
    <div className="min-w-0 space-y-2 rounded-lg border border-line bg-surface p-4">
      <div className="flex items-center justify-between gap-2">
        <h2 className="font-semibold">{title}</h2>
        {to && <Link to={to} className="inline-flex items-center gap-0.5 text-sm text-soft hover:text-ink">{more ?? 'More'} <ChevronRight size={14} aria-hidden /></Link>}
      </div>
      {children}
    </div>
  )
}

export default function Manager() {
  const [period, setPeriod] = useState<'daily' | 'weekly'>('weekly')
  const [sum, setSum] = useState<Summary | null>(null)
  const [bk, setBk] = useState<Backups | null>(null)
  const [waiting, setWaiting] = useState<number | null>(null)
  const [error, setError] = useState('')
  const load = useCallback(async () => {
    try { setSum(await api<Summary>(`/summary/${period}`)); setError('') }
    catch (e) { setError(e instanceof ApiError ? e.message : 'Could not reach SentrAI.') }
    api<Backups>('/backups').then(setBk).catch(() => setBk(null))
    api<{ total: number }>('/ui/approvals').then((a) => setWaiting(a.total)).catch(() => setWaiting(null))
  }, [period])
  useEffect(() => { void load(); const t = setInterval(() => void load(), 30000); return () => clearInterval(t) }, [load])

  const safe = SAFE[sum?.risk_now.band ?? ''] ?? { word: 'Checking…', line: '', cls: '' }
  const n = sum?.numbers
  const label = period === 'daily' ? 'today' : 'this week'
  const latest = [...(bk?.backups ?? [])].sort((a, b) => (b.created ?? '').localeCompare(a.created ?? ''))[0]
  const did = Object.entries(sum?.actions.done ?? {}).sort((a, b) => b[1] - a[1])
  return (
    <section className="space-y-4">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold">Manager view</h1>
          <p className="text-sm text-muted">your security in plain words{sum ? ` · ${sum.period_text}` : ''}</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <div role="group" aria-label="Period" className="flex overflow-hidden rounded-md border border-line text-sm">
            {(['daily', 'weekly'] as const).map((p) => (
              <button key={p} aria-pressed={period === p} onClick={() => setPeriod(p)}
                className={'px-3 py-1.5 ' + (period === p ? 'bg-surface-3 text-ink' : 'text-soft hover:bg-surface-2')}>{p === 'daily' ? 'Today' : 'This week'}</button>))}
          </div>
          <a className={btn + ' no-underline'} href={`/api/summary/${period}.pdf`} download><Download size={14} aria-hidden /> One-page PDF</a>
        </div>
      </header>
      {error && <p role="alert" className="rounded-md border border-line bg-surface p-3 text-bad">{error}</p>}

      <div className="flex flex-wrap items-center gap-4 rounded-xl border border-line bg-surface p-5">
        {sum?.risk_now.band === 'green' ? <ShieldCheck size={40} className="text-ok" aria-hidden /> : <ShieldAlert size={40} className={safe.cls} aria-hidden />}
        <div className="min-w-0 flex-1">
          <p className="text-sm text-muted">Are we safe right now?</p>
          <p className={'text-3xl font-semibold ' + safe.cls}>{safe.word}</p>
          <p className="text-soft">{safe.line}</p>
        </div>
        <p className="max-w-xl text-lg">{sum?.headline ?? 'Loading…'}</p>
      </div>

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Stat label={`Threats ${label}`} value={n?.threats ?? '-'} note="attempts SentrAI noticed" />
        <Stat label="Stopped on its own" value={n?.stopped_automatically ?? '-'} note="blocked without waiting for anyone" />
        <Stat label="Handled by your staff" value={n?.handled_by_staff ?? '-'} note={`${n?.closed ?? 0} closed ${label}`} />
        <Stat label="Still needs a person" value={n?.need_attention ?? '-'} note={`problems still open · ${waiting ?? 0} requests wait for an OK`}
          hot={!!n?.need_attention || !!waiting} />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Box title="What needs attention" to="/incidents" more="Details">
          {!sum ? <p className="text-muted" role="status">Loading…</p> : sum.attention.length === 0 ? <p className="text-ok">Nothing needs you. Everything is in hand.</p> : (
            <ul className="divide-y divide-line-soft">
              {sum.attention.slice(0, 6).map((a) => (
                <li key={a.incident} className="py-2 text-sm">
                  <p><b>{a.what}</b> on {a.machine} <span className="text-muted">· open {a.open_for}{a.late ? ' · late' : ''}{a.seen_by_staff ? ' · staff are on it' : ''}</span></p>
                  <p className="text-soft">Next: {a.next_step}</p>
                </li>))}
            </ul>)}
        </Box>
        <Box title="What SentrAI did about it">
          {!sum ? <p className="text-muted" role="status">Loading…</p> : did.length === 0 ? <p className="text-soft">SentrAI did not need to step in {label}.</p> : (
            <>
              <ul className="space-y-1 text-sm">{did.map(([what, count]) => <li key={what} className="flex justify-between gap-2"><span>{what.charAt(0).toUpperCase() + what.slice(1)}</span><b className="tabular-nums">{count}</b></li>)}</ul>
              <p className="text-xs text-muted">Every step is temporary, ends on its own and can be undone.
                {sum.actions.undone ? ` ${sum.actions.undone} undone by your staff.` : ''}{sum.actions.permanent ? ` ${sum.actions.permanent} made permanent by your staff.` : ''}</p>
            </>)}
        </Box>
        <Box title={`Kinds of threat ${label}`} to="/analytics" more="Charts">
          {!sum ? <p className="text-muted" role="status">Loading…</p> : sum.kinds.length === 0 ? <p className="text-soft">None.</p> : (
            <ul className="space-y-1.5 text-sm">
              {sum.kinds.map((k) => {
                const max = Math.max(...sum.kinds.map((x) => x.count))
                return (
                  <li key={k.what}>
                    <div className="flex justify-between gap-2"><span>{k.what}</span><b className="tabular-nums">{k.count}</b></div>
                    <div className="mt-0.5 h-1.5 rounded bg-surface-2"><div className="h-1.5 rounded bg-ink/70" style={{ width: `${(k.count / max) * 100}%` }} /></div>
                  </li>)
              })}
            </ul>)}
        </Box>
        <Box title="Can we trust these numbers?">
          {!sum ? <p className="text-muted" role="status">Loading…</p> : (
            <ul className="space-y-2 text-sm">
              <li className="flex gap-2">{sum.proof.chain_valid ? <CheckCircle2 size={16} className="mt-0.5 shrink-0 text-ok" aria-hidden /> : <ShieldAlert size={16} className="mt-0.5 shrink-0 text-bad" aria-hidden />}
                <span>{sum.proof.chain_valid ? `The activity record is intact: ${sum.proof.records} entries, none changed or removed.` : 'Warning: the activity record has been changed. Ask your IT contact now.'}
                  <span className="block text-xs text-muted">Check code {sum.proof.short}</span></span></li>
              <li className="flex gap-2">{latest && latest.verified?.ok !== false && !bk?.overdue ? <CheckCircle2 size={16} className="mt-0.5 shrink-0 text-ok" aria-hidden /> : <ShieldAlert size={16} className="mt-0.5 shrink-0 text-warn" aria-hidden />}
                <span>{!bk ? 'Backups are not set up on this server.' : !latest ? 'No backup has been made yet.' : `Last backup ${ago(latest.created)}${latest.verified?.ok ? ', checked and intact' : latest.verified?.ok === false ? ', but its check found a problem' : ''}.`}
                  {bk?.overdue && <span className="block text-xs text-warn">The next backup is late.</span>}
                  <Link to="/backups" className="block text-xs text-soft hover:text-ink">See backups</Link></span></li>
              {sum.responsible && <li className="text-soft">On duty: {sum.responsible}</li>}
            </ul>)}
        </Box>
      </div>
    </section>
  )
}
