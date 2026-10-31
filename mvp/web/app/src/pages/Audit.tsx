import { useCallback, useEffect, useState } from 'react'
import { CheckCircle2, ShieldAlert } from 'lucide-react'
import { api, ApiError } from '../lib/api'

type Entry = { seq: number | null; time: string; agent: string; type: string; summary: string; hash: string }
type AgentRow = { agent: string; role: string; can_act: string; records: number; last: string }
type Page = {
  chain_valid: boolean | null; first_invalid_seq: number | null; count: number; head_hash: string
  feed: Entry[]; agents: AgentRow[]
}

export default function Audit() {
  const [page, setPage] = useState<Page | null>(null)
  const [error, setError] = useState('')
  const load = useCallback(async () => {
    try { setPage(await api<Page>('/ui/audit?limit=60')); setError('') }
    catch (e) { setError(e instanceof ApiError ? `Could not load audit log: ${e.message}` : 'Could not load audit log.') }
  }, [])
  useEffect(() => { void load(); const t = setInterval(() => void load(), 10000); return () => clearInterval(t) }, [load])

  return (
    <section className="space-y-4">
      <header>
        <h1 className="text-2xl font-semibold">Audit trail</h1>
        <p className="text-sm text-muted">every step by every agent and person, hash-chained</p>
      </header>
      {error && <p role="alert" className="rounded-md border border-line bg-surface p-3 text-bad">{error}</p>}
      {page && (
        <div className="grid gap-4 lg:grid-cols-[7fr_5fr]">
          <div className="min-w-0 space-y-3 rounded-lg border border-line bg-surface p-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <h2 className="font-semibold">Agent activity <span className="font-normal text-muted">· latest {page.feed.length} of {page.count} records</span></h2>
              {page.chain_valid === false
                ? <span className="inline-flex items-center gap-1 text-crit"><ShieldAlert size={16} aria-hidden /> Chain broken at #{page.first_invalid_seq}</span>
                : <span className="inline-flex items-center gap-1 text-ok"><CheckCircle2 size={16} aria-hidden /> Chain intact</span>}
            </div>
            {page.feed.length === 0 ? <p className="text-soft">No audit records yet.</p> : (
              <div role="region" aria-label="Agent activity" tabIndex={0} className="max-h-[32rem] overflow-y-auto">
                <ol>
                  {page.feed.map((e) => (
                    <li key={`${e.seq}-${e.hash}`} className="flex gap-3 border-b border-line-soft py-2 last:border-0">
                      <div className="w-20 shrink-0 text-xs text-muted">{e.time}<br /><span className="font-mono">#{e.seq ?? '-'}</span></div>
                      <div className="min-w-0 text-sm">
                        <p><b>{e.agent}</b> <span className="text-muted">·</span> <span className="text-soft">{e.type}</span></p>
                        <p className="break-words">{e.summary} <span className="font-mono text-xs text-muted">{e.hash}</span></p>
                      </div>
                    </li>
                  ))}
                </ol>
              </div>
            )}
          </div>
          <div className="min-w-0 space-y-3 rounded-lg border border-line bg-surface p-4">
            <h2 className="font-semibold">Agents <span className="font-normal text-muted">· who does what</span></h2>
            {page.agents.length === 0 ? <p className="text-soft">No agents yet.</p> : (
              <div className="overflow-x-auto" role="region" aria-label="Agents" tabIndex={0}>
                <table className="w-full text-left text-sm">
                  <thead className="border-b border-line text-xs uppercase tracking-wide text-muted">
                    <tr>{['Agent', 'Role', 'Can act', 'Records', 'Last'].map((h) => <th key={h} className="p-2 font-medium">{h}</th>)}</tr>
                  </thead>
                  <tbody>
                    {page.agents.map((a) => (
                      <tr key={a.agent} className="border-b border-line-soft last:border-0">
                        <td className="p-2">{a.agent}</td><td className="p-2 text-soft">{a.role}</td><td className="p-2">{a.can_act}</td>
                        <td className="p-2">{a.records}</td><td className="p-2 font-mono text-xs">{a.last}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}
    </section>
  )
}
