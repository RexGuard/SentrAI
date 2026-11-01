// Privacy: what SentrAI records about people, why, who can see it and how long it is kept (PDPA). The Owner or an
// Admin sets the retention periods and the contact; HR downloads a staff notice built from them. SentrAI flags data
// older than its period and deletes nothing on its own.
import { useCallback, useEffect, useState } from 'react'
import { AlertTriangle, CheckCircle2, Download, Save } from 'lucide-react'
import { api, ApiError } from '../lib/api'
import { btn, btnPrimary } from '../lib/ui'
import { useSession } from '../lib/session'

type Kind = { key: string; what: string; about: string; why: string; months: number | null; kept: string; who: string; oldest_days: number | null; over: boolean }
type Policy = { organisation: string; contact: string; months: Record<string, number | null>; updated_at?: string; updated_by?: string }
type Page = { policy: Policy; kinds: Kind[]; over: string[]; ai_on: boolean }

const field = 'mt-1 block w-full rounded-md border border-line bg-surface-2 px-3 py-1.5 text-ink'
const age = (d: number | null) => (d == null ? 'not dated' : d === 0 ? 'today' : d < 60 ? `${d} days` : `${Math.round(d / 30.4)} months`)

export default function Privacy() {
  const { can } = useSession()
  const [page, setPage] = useState<Page | null>(null)
  const [draft, setDraft] = useState<Policy | null>(null)
  const [note, setNote] = useState('')
  const [error, setError] = useState('')
  const load = useCallback(async () => {
    try { const p = await api<Page>('/ui/privacy'); setPage(p); setDraft(p.policy); setError('') }
    catch (e) { setError(e instanceof ApiError ? e.message : 'Could not reach SentrAI.') }
  }, [])
  useEffect(() => { void load() }, [load])
  const off = !can('configure')
  const save = async () => {
    if (!draft) return
    setError(''); setNote('')
    try { const p = await api<Page>('/ui/privacy', { body: draft }); setPage(p); setDraft(p.policy); setNote('Privacy policy saved and written to the audit record.') }
    catch (e) { setError(e instanceof ApiError ? e.message : 'Could not save.') }
  }
  const setMonths = (key: string, v: string) => draft && setDraft({ ...draft, months: { ...draft.months, [key]: v === '' ? null : Math.max(0, Math.min(120, Number(v))) } })

  return (
    <section className="space-y-4">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold">Privacy and data</h1>
          <p className="text-sm text-muted">what SentrAI records about people, why, who can see it and how long it is kept</p>
        </div>
        <a className={btn + ' no-underline'} href="/api/ui/privacy/notice.md" download><Download size={14} aria-hidden /> Staff notice for HR</a>
      </header>
      {error && <p role="alert" className="rounded-md border border-line bg-surface p-3 text-bad">{error}</p>}
      {note && <p role="status" className="rounded-md border border-line bg-surface p-3">{note}</p>}
      {page && (
        <p className={'flex items-start gap-2 rounded-md border border-line bg-surface p-3 text-sm ' + (page.over.length ? 'text-warn' : '')}>
          {page.over.length ? <AlertTriangle size={16} className="mt-0.5 shrink-0" aria-hidden /> : <CheckCircle2 size={16} className="mt-0.5 shrink-0 text-ok" aria-hidden />}
          {page.over.length
            ? `Some data is older than your policy allows: ${page.kinds.filter((k) => k.over).map((k) => k.what.toLowerCase()).join(', ')}. Archive or remove it, or change the period.`
            : 'All data SentrAI can date is within your retention periods.'}
        </p>)}

      {!page || !draft ? <p className="text-muted" role="status">Loading…</p> : (
        <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); void save() }}>
          <div className="grid gap-3 rounded-lg border border-line bg-surface p-4 md:grid-cols-2">
            <label className="text-sm text-soft">Organisation name (used in the staff notice)
              <input className={field} value={draft.organisation} disabled={off} onChange={(e) => setDraft({ ...draft, organisation: e.target.value })} placeholder="e.g. Acme Learning Centre" /></label>
            <label className="text-sm text-soft">Who staff contact about their data
              <input className={field} value={draft.contact} disabled={off} onChange={(e) => setDraft({ ...draft, contact: e.target.value })} placeholder="e.g. Data Protection Officer, dpo@example.com" /></label>
          </div>
          <div className="overflow-x-auto rounded-lg border border-line bg-surface" tabIndex={0}>
            <table className="w-full min-w-[56rem] text-left text-sm">
              <thead className="text-xs text-muted">
                <tr className="border-b border-line">
                  <th className="p-3 font-medium">What is recorded</th><th className="p-3 font-medium">Why</th>
                  <th className="p-3 font-medium">Who can see it</th><th className="w-40 p-3 font-medium">Keep for (months)</th>
                  <th className="w-28 p-3 font-medium">Oldest</th>
                </tr>
              </thead>
              <tbody>
                {page.kinds.map((k) => (
                  <tr key={k.key} className="border-b border-line-soft align-top">
                    <td className="p-3"><b>{k.what}</b><span className="block text-xs text-muted">{k.about}</span></td>
                    <td className="p-3 text-soft">{k.why}</td>
                    <td className="p-3 text-soft">{k.who}</td>
                    <td className="p-3">
                      <input type="number" min={0} max={120} className={field} aria-label={`Keep ${k.what} for how many months`} disabled={off}
                        value={draft.months[k.key] ?? ''} placeholder="while it exists" onChange={(e) => setMonths(k.key, e.target.value)} />
                    </td>
                    <td className={'p-3 tabular-nums ' + (k.over ? 'text-warn' : 'text-soft')}>{age(k.oldest_days)}{k.over && <span className="block text-xs">past its period</span>}</td>
                  </tr>))}
              </tbody>
            </table>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <button type="submit" className={btnPrimary} disabled={off} title={off ? 'Only an Owner or Admin can change the policy.' : undefined}><Save size={14} aria-hidden /> Save policy</button>
            {page.policy.updated_at && <span className="text-xs text-muted">Last changed {page.policy.updated_at.slice(0, 16).replace('T', ' ')} by {page.policy.updated_by}</span>}
          </div>
          <p className="max-w-3xl text-xs text-muted">SentrAI shows what is past its period but never deletes on its own. The audit record is tamper-proof, so it is archived as a whole rather than trimmed.
            Check the staff notice with your data protection officer against the PDPA and your own HR and IT policies before you share it.</p>
        </form>)}
    </section>
  )
}
