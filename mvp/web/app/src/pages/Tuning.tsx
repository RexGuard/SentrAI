// Tuning: what made the most alerts this week and what would quiet it without hiding real attacks. A new install
// uses general baselines, so the first week is louder; this page shows where the noise comes from and which setting
// on Configuration would fix it. Nothing changes on its own.
import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { BellRing, Leaf } from 'lucide-react'
import { api, ApiError } from '../lib/api'
import Stat from '../lib/Stat'

type Row = { kind: 'machine' | 'network'; key: string; what: string; incidents: number; false_alarms: number; addresses: number; per_day: number
  suggestion: { do: 'trust' | 'busy' | 'review' | 'keep'; text: string; where: string } }
type Page = { days: number; incidents: number; alerts: number; alerts_per_day: number; noisy: boolean; false_alarms: number
  learning: { day: number; of: number; on: boolean }; settings: { busy_server: boolean; trusted: string[] }; rows: Row[] }

const DO: Record<Row['suggestion']['do'], { label: string; cls: string }> = {
  trust: { label: 'Trust it', cls: 'border-ok text-ok' }, busy: { label: 'Group into waves', cls: 'border-warn text-warn' },
  review: { label: 'Have a look', cls: 'border-line text-soft' }, keep: { label: 'Keep alerting', cls: 'border-line text-muted' },
}

export default function Tuning() {
  const [page, setPage] = useState<Page | null>(null)
  const [error, setError] = useState('')
  useEffect(() => { api<Page>('/ui/tuning').then(setPage).catch((e) => setError(e instanceof ApiError ? e.message : 'Could not reach SentrAI.')) }, [])
  return (
    <section className="space-y-4">
      <header>
        <h1 className="text-2xl font-semibold">Tuning</h1>
        <p className="text-sm text-muted">where this week's alerts come from, and how to quiet the noise without hiding real attacks</p>
      </header>
      {error && <p role="alert" className="rounded-md border border-line bg-surface p-3 text-bad">{error}</p>}
      {!page ? !error && <p className="text-muted" role="status">Loading…</p> : (
        <>
          {page.learning.on && (
            <p className="flex items-start gap-2 rounded-md border border-line bg-surface p-3 text-sm">
              <Leaf size={16} className="mt-0.5 shrink-0 text-ok" aria-hidden />
              <span><b>Learning week: day {page.learning.day} of {page.learning.of}.</b> SentrAI starts with general rules, so expect more alerts this week.
                Close the ones that are not real attacks with a short note (for example "our uptime monitor"); this page learns from those notes.</span>
            </p>)}
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            <Stat label={`Alerts, last ${page.days} days`} value={page.alerts} note={`${page.alerts_per_day} a day`} hot={page.noisy} />
            <Stat label="Incidents" value={page.incidents} note={`last ${page.days} days`} />
            <Stat label="Not real attacks" value={page.false_alarms} note="closed by staff as false alarms" hot={page.false_alarms > 0} />
            <Stat label="Busy server mode" value={page.settings.busy_server ? 'On' : 'Off'} note={`${page.settings.trusted.length} trusted addresses or networks`} />
          </div>
          {page.noisy && (
            <p className="flex items-start gap-2 rounded-md border border-line bg-surface p-3 text-sm text-warn"><BellRing size={16} className="mt-0.5 shrink-0" aria-hidden />
              More than 20 alerts a day is more than one or two people can read with care. Start with the suggestions at the top.</p>)}
          <div className="overflow-x-auto rounded-lg border border-line bg-surface" tabIndex={0}>
            <table className="w-full min-w-[52rem] text-left text-sm">
              <thead className="text-xs text-muted">
                <tr className="border-b border-line"><th className="p-3 font-medium">Source</th><th className="p-3 font-medium">What</th>
                  <th className="p-3 font-medium">Incidents</th><th className="p-3 font-medium">Not real</th><th className="p-3 font-medium">Suggestion</th></tr>
              </thead>
              <tbody>
                {page.rows.length === 0 ? <tr><td colSpan={5} className="p-3 text-ok">Nothing noisy this week.</td></tr> : page.rows.map((r) => (
                  <tr key={r.kind + r.key + r.what} className="border-b border-line-soft align-top">
                    <td className="p-3"><span className="font-mono text-xs">{r.key}</span><span className="block text-xs text-muted">{r.kind === 'machine' ? 'machine' : 'network'} · {r.addresses} address{r.addresses === 1 ? '' : 'es'}</span></td>
                    <td className="p-3">{r.what}</td>
                    <td className="p-3 tabular-nums">{r.incidents}<span className="block text-xs text-muted">{r.per_day} a day</span></td>
                    <td className="p-3 tabular-nums">{r.false_alarms}</td>
                    <td className="p-3">
                      <span className={'mr-2 inline-block rounded border px-1.5 py-0.5 text-xs ' + DO[r.suggestion.do].cls}>{DO[r.suggestion.do].label}</span>
                      <span className="text-soft">{r.suggestion.text}</span>
                      {r.suggestion.where && <Link to="/config" className="block text-xs text-soft underline">Set {r.suggestion.where === 'TRUSTED_IPS' ? 'Trusted addresses' : 'Busy server'} on Configuration</Link>}
                    </td>
                  </tr>))}
              </tbody>
            </table>
          </div>
          <p className="text-xs text-muted">Nothing changes on its own. Trusted addresses are never analysed, so only trust what you own or a service you chose.</p>
        </>)}
    </section>
  )
}
