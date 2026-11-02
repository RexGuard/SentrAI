// Fixes learned from similar past incidents: a pattern's playbook card, and the "similar incidents" panel
// shown under an incident. Playbooks are advice only: any block still goes through Approvals and the guardrails.
import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { Sparkles, Undo2 } from 'lucide-react'
import { api, ApiError } from './api'
import { btn } from './ui'
import { useSession } from './session'

export type Playbook = {
  title: string; summary: string; steps: string[]; prevent: string[]; watch_for: string; source: 'rules' | 'ai'
  drafted_at?: string; drafted_by?: string; based_on?: number
}
export type Pattern = {
  id: string; label: string; count: number; open: number; closed: number
  machines: { host: string; count: number }[]; here: number | null; elsewhere: number | null
  attackers: { address: string; count: number }[]; last: string
  history: { held: Record<string, number>; rolled_back: Record<string, number>; notes: { text: string; times: number }[] }
  playbook: Playbook; rules: Playbook
}
export type SimilarRow = {
  id: string; what: string; host: string; severity: string; status: string; closed: boolean; attacker: string
  opened: string; contain: string; close: string; score: number; why: string[]; note: string
}

export function PlaybookCard({ p, ai, changed }: { p: Pattern; ai: boolean; changed: () => void }) {
  const { can } = useSession()
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const pb = p.playbook
  const off = !can('act')
  const call = async (path: string) => {
    setBusy(true); setErr('')
    try { await api(path, { body: { pattern: p.id } }); changed() }
    catch (e) { setErr(e instanceof ApiError ? e.message : 'That did not go through.') }
    finally { setBusy(false) }
  }
  return (
    <div className="space-y-2 rounded-lg border border-line bg-surface p-4">
      <div className="flex flex-wrap items-start gap-2">
        <div className="min-w-0 flex-1">
          <h3 className="font-semibold">{pb.title}</h3>
          <p className="text-xs text-muted">
            {pb.source === 'ai' ? `Drafted by AI from ${pb.based_on ?? p.count} past incidents${pb.drafted_by ? ` (asked by ${pb.drafted_by})` : ''}` : 'Written from past incidents and the usual steps (no AI)'}
          </p>
        </div>
        {pb.source === 'ai' ? (
          <button className={btn} disabled={busy || off} onClick={() => void call('/ui/analytics/playbooks/forget')}
            title="Go back to the playbook written without AI"><Undo2 size={14} aria-hidden /> Use rules version</button>
        ) : (
          <button className={btn} disabled={busy || off || !ai}
            title={!ai ? 'Add an AI model on Configuration to draft playbooks with AI.' : off ? 'Your role can read everything but change nothing.' : 'The AI reads how past ones were handled and writes the steps'}
            onClick={() => void call('/ui/analytics/playbooks/draft')}><Sparkles size={14} aria-hidden /> {busy ? 'Drafting…' : 'Draft with AI'}</button>
        )}
      </div>
      {err && <p role="alert" className="text-sm text-bad">{err}</p>}
      {pb.summary && <p className="text-sm text-soft">{pb.summary}</p>}
      <ol className="list-decimal space-y-1 pl-5 text-sm">{pb.steps.map((s, i) => <li key={i}>{s}</li>)}</ol>
      {pb.prevent.length > 0 && (
        <div className="text-sm"><p className="font-medium">So it does not happen again</p>
          <ul className="list-disc pl-5 text-soft">{pb.prevent.map((s, i) => <li key={i}>{s}</li>)}</ul></div>
      )}
      {pb.watch_for && <p className="text-sm"><span className="font-medium">Watch for:</span> <span className="text-soft">{pb.watch_for}</span></p>}
      <p className="text-xs text-muted">Advice only. Any block still goes through <Link to="/command" className="underline">Command center</Link> and the automation guardrails.</p>
    </div>
  )
}

/** Under one incident: the incidents most like it (on any machine) and its pattern's playbook. */
export function SimilarIncidents({ incident }: { incident: string }) {
  const [data, setData] = useState<{ similar: SimilarRow[]; pattern: Pattern; ai: boolean } | null>(null)
  const [err, setErr] = useState('')
  const load = useCallback(async () => {
    try { setData(await api(`/ui/analytics/similar?incident=${encodeURIComponent(incident)}`)); setErr('') }
    catch (e) { setErr(e instanceof ApiError ? e.message : 'Could not load similar incidents.') }
  }, [incident])
  useEffect(() => { void load() }, [load])
  if (err) return <p className="text-sm text-muted">{err}</p>
  if (!data) return <p className="text-sm text-muted" role="status">Looking for similar incidents…</p>
  const others = data.pattern.machines.filter((m) => m.host !== '-').length
  return (
    <div className="space-y-3">
      <h4 className="font-semibold">Similar incidents <span className="font-normal text-muted">· {data.pattern.count - 1} more like this on {others} machine{others === 1 ? '' : 's'}</span></h4>
      {data.similar.length === 0 ? <p className="text-sm text-soft">Nothing like this before. The playbook below uses the usual steps for this type.</p> : (
        <div className="overflow-x-auto" role="region" aria-label="Similar incidents" tabIndex={0}>
          <table className="w-full text-left text-sm">
            <thead className="border-b border-line text-xs uppercase tracking-wide text-muted">
              <tr>{['Incident', 'Machine', 'Source', 'Status', 'Contained in', 'How it was closed', 'Why similar'].map((h) => <th key={h} className="p-2 font-medium">{h}</th>)}</tr>
            </thead>
            <tbody>{data.similar.map((s) => (
              <tr key={s.id} className="border-b border-line-soft last:border-0">
                <td className="p-2 font-mono text-xs">{s.id}</td><td className="p-2">{s.host}</td><td className="p-2 font-mono text-xs">{s.attacker}</td>
                <td className="p-2 capitalize">{s.status}</td><td className="p-2 whitespace-nowrap">{s.contain}</td>
                <td className="p-2 text-soft">{s.note || '-'}</td><td className="p-2 text-xs text-muted">{s.why.join(', ')}</td>
              </tr>))}</tbody>
          </table>
        </div>)}
      <PlaybookCard p={data.pattern} ai={data.ai} changed={() => void load()} />
    </div>
  )
}

/** On a machine page: each kind of incident this machine has had, how often elsewhere, and its playbook. */
export function MachineFixes({ host }: { host: string }) {
  const [data, setData] = useState<{ patterns: Pattern[]; ai: boolean } | null>(null)
  const load = useCallback(async () => {
    try { setData(await api(`/ui/analytics?host=${encodeURIComponent(host)}`)) } catch { setData({ patterns: [], ai: false }) }
  }, [host])
  useEffect(() => { void load() }, [load])
  if (!data || data.patterns.length === 0) return null
  return (
    <div className="space-y-3 pt-2">
      <h3 className="font-semibold">Fixes for this machine <span className="font-normal text-muted">· learned from similar incidents here and on other machines</span></h3>
      {data.patterns.map((p) => (
        <details key={p.id} className="rounded-lg border border-line bg-surface-2 p-3" open={p.open > 0}>
          <summary className="cursor-pointer text-sm"><b>{p.label}</b> <span className="text-muted">· {p.here} here, {p.elsewhere} on other machines{p.open ? `, ${p.open} open` : ''}</span></summary>
          <div className="mt-3"><PlaybookCard p={p} ai={data.ai} changed={() => void load()} /></div>
        </details>
      ))}
    </div>
  )
}
