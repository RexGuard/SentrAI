import { useCallback, useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { ArrowLeft, DatabaseBackup, ShieldCheck } from 'lucide-react'
import { api, ApiError } from '../lib/api'
import { btn } from '../lib/ui'
import { useSession } from '../lib/session'
import { useFilters, type Filter } from '../lib/Filters'
import { MachineFixes } from '../lib/Fixes'
import { PackagesTab, ServicesTab, SignedInTab, type Details } from './MachineDetails'
import { ask } from '../lib/notice'

type Machine = {
  name: string; host: string; place: string; online: boolean; waiting: boolean; index: number | null; band: string; threshold: number
  monitor_only: boolean; open: number; contained: number; blocked: number; last_seen: string; services: string[]
  hardware: { cpu: number | null; memory: number | null; disk: number | null }; sessions: number | null
}
type Overview = { machines: Machine[]; band_words: Record<string, string> }
type Inc = { id: string; category?: string; severity?: string; status?: string; opened_at?: string; summary?: string }
type Agent = { agent_id: string; host: string; joined_at?: string; invited_by?: string; last_seen?: string; revoked_at?: string; revoked_by?: string }
type Job = { id: string; kind: string; status: string; created_at?: string; requested_by?: string }
type Hw = { latest: { at?: string; cpu?: { percent?: number; cores?: number; load?: number[] }; memory?: { percent?: number; used?: number; total?: number }
  disks?: { mount?: string; percent?: number }[]; uptime_s?: number } | null; limits?: Record<string, number> }

const TABS = ['Overview', 'Hardware', 'Incidents', 'Blocks', 'Signed in', 'Services', 'Jobs', 'Packages', 'Agent'] as const
type Tab = (typeof TABS)[number]
const bandColor: Record<string, string> = { green: 'var(--green)', amber: 'var(--amber)', red: 'var(--red)', critical: 'var(--critical)' }
const pct = (v?: number | null) => (v == null ? '-' : `${Math.round(v)}%`)
const gb = (b?: number) => (b ? `${(b / 1073741824).toFixed(1)} GB` : '-')
const dt = (v?: string) => (v ? new Date(v).toLocaleString() : '-')

const INC: Filter<Inc>[] = [
  { key: 'severity', label: 'Severity', get: (i) => i.severity }, { key: 'status', label: 'Status', get: (i) => i.status },
  { key: 'category', label: 'Type', get: (i) => (i.category ?? '').replace(/_/g, ' ') }, { key: 'opened', label: 'Opened', get: (i) => i.opened_at, kind: 'date' },
]

function MachineIncidents({ incs }: { incs: Inc[] }) {
  const f = useFilters(incs, INC, (i) => [i.id, i.category, i.summary, i.status], 'incidents')
  if (incs.length === 0) return <p className="text-soft">No incidents on this machine.</p>
  return (
    <>
      {f.bar}
      {f.rows.length === 0 ? <p className="text-soft">No incidents match these filters.</p> : (
        <div className="overflow-x-auto" role="region" aria-label="Incidents on this machine" tabIndex={0}>
          <table className="w-full text-left text-sm"><thead className="border-b border-line text-xs uppercase tracking-wide text-muted"><tr>{['Incident', 'What', 'Severity', 'Status', 'Opened'].map((h) => <th key={h} className="p-2 font-medium">{h}</th>)}</tr></thead>
            <tbody>{f.rows.map((i) => <tr key={i.id} className="border-b border-line-soft last:border-0"><td className="p-2 font-mono text-xs">{i.id}</td><td className="p-2">{(i.category ?? '').replace(/_/g, ' ')}</td>
              <td className="p-2 capitalize">{i.severity}</td><td className="p-2 capitalize">{i.status}</td><td className="p-2">{dt(i.opened_at)}</td></tr>)}</tbody></table>
        </div>)}
    </>
  )
}

function Bar({ label, value, limit }: { label: string; value?: number | null; limit?: number }) {
  const hot = value != null && limit != null && value >= limit
  return (
    <div>
      <div className="flex justify-between text-sm"><span>{label}</span><span className={hot ? 'text-warn' : 'text-soft'}>{pct(value)}</span></div>
      <div className="mt-1 h-2 rounded bg-surface-3" role="img" aria-label={`${label} ${pct(value)}`}><div className="h-full rounded" style={{ width: `${Math.min(100, value ?? 0)}%`, background: hot ? 'var(--amber)' : 'var(--ink-soft)' }} /></div>
    </div>
  )
}

export default function MachinePage() {
  const { host = '' } = useParams()
  const { me, can } = useSession()
  const op = me?.email ?? 'dashboard'
  const [tab, setTab] = useState<Tab>('Overview')
  const [m, setM] = useState<Machine | null | undefined>(undefined)
  const [words, setWords] = useState<Record<string, string>>({})
  const [incs, setIncs] = useState<Inc[]>([])
  const [blocks, setBlocks] = useState<{ ips?: string[]; users?: string[] }>({})
  const [hw, setHw] = useState<Hw | null>(null)
  const [jobs, setJobs] = useState<Job[]>([])
  const [agents, setAgents] = useState<Agent[]>([])
  const [details, setDetails] = useState<Details | null>(null)
  const [note, setNote] = useState('')
  const [error, setError] = useState('')
  const q = encodeURIComponent(host)

  const load = useCallback(async () => {
    try {
      const o = await api<Overview>('/ui/machines')
      setM(o.machines.find((x) => x.host === host) ?? null); setWords(o.band_words)
      const [i, b, h, j, a, d] = await Promise.all([
        api<Inc[]>(`/incidents?host=${q}`), api<{ ips?: string[]; users?: string[] }>(`/blocklist?host=${q}`),
        api<Hw>(`/fleet/hardware?host=${q}`), api<Job[]>(`/fleet/jobs?host=${q}`), api<Agent[]>('/fleet/agents'),
        api<Details>(`/ui/machines/${q}/details`).catch(() => null)])
      setIncs(i); setBlocks(b); setHw(h); setJobs(j); setAgents(a.filter((x) => x.host === host)); setDetails(d); setError('')
    } catch (e) { setError(e instanceof ApiError ? e.message : 'Could not load this machine.') }
  }, [host, q])
  useEffect(() => { void load(); const t = setInterval(() => void load(), 10000); return () => clearInterval(t) }, [load])

  const agent = agents.find((a) => !a.revoked_at)
  const run = async (fn: () => Promise<unknown>, msg: string) => {
    setNote('')
    try { await fn(); setNote(msg); await load() } catch (e) { setNote(e instanceof ApiError ? e.message : 'That did not go through.') }
  }
  const queue = (kind: string, msg: string) => run(() => api('/fleet/jobs', { body: { host, kind, operator: op } }), msg)
  const off = !can('act') || !agent
  const offWhy = !agent ? "Scans and backups run through SentrAI's agent, and this machine has none." : !can('act') ? 'Your role can read everything but change nothing.' : undefined

  if (m === undefined) return <p className="text-muted" role="status">Loading…</p>
  return (
    <section className="space-y-4">
      <Link to="/machines" className="inline-flex items-center gap-1 text-sm text-soft hover:text-ink"><ArrowLeft size={14} aria-hidden /> All machines</Link>
      <header>
        <h1 className="text-2xl font-semibold">{m?.name ?? host}</h1>
        <p className="text-sm text-muted">{m ? `${m.place} · last seen ${m.last_seen}` : ''}</p>
      </header>
      {error && <p role="alert" className="rounded-md border border-line bg-surface p-3 text-bad">{error}</p>}
      {note && <p role="status" className="rounded-md border border-line bg-surface p-3">{note}</p>}
      {m === null ? <p className="rounded-lg border border-line bg-surface p-4 text-soft">No machine called {host} reports to this panel. It may have been revoked, or the link is out of date. Machine pages need central panel mode (SENTRAI_RISK_SCOPE=host).</p> : (
        <>
          <div className="flex flex-wrap items-center gap-4 rounded-lg border border-line bg-surface p-4">
            <p className="text-4xl font-semibold" style={{ color: m.online ? bandColor[m.band] : undefined }}>{m.waiting ? '-' : !m.online ? '0' : m.index == null ? '-' : Math.round(m.index)}</p>
            <div className="min-w-0 flex-1">
              <p className="font-medium">{m.waiting ? 'Waiting for its first data' : !m.online ? 'Offline' : m.monitor_only ? 'Protection off' : 'Protecting'} · {m.waiting ? 'Waiting' : words[m.band] ?? 'Unknown'}</p>
              <p className="text-sm text-muted">threshold {Math.round(m.threshold)}{m.services.length ? ` · ${m.services.join(', ')}` : ''}</p>
            </div>
            <button className={btn} disabled={off} title={offWhy} onClick={() => void queue('threat_scan', `Asked ${host} to scan for threats`)}><ShieldCheck size={14} aria-hidden /> Scan for threats</button>
            <button className={btn} disabled={off} title={offWhy} onClick={() => void queue('backup', `Asked ${host} to back up`)}><DatabaseBackup size={14} aria-hidden /> Back up now</button>
          </div>
          <div role="tablist" aria-label="Machine" className="flex flex-wrap gap-2">
            {TABS.map((t) => <button key={t} role="tab" aria-selected={tab === t} onClick={() => setTab(t)}
              className={'rounded-md px-3 py-1.5 text-sm ' + (tab === t ? 'bg-surface-3 text-ink' : 'text-soft hover:bg-surface-2')}>{t}{t === 'Incidents' && incs.length ? ` (${incs.length})` : ''}</button>)}
          </div>
          <div className="space-y-3 rounded-lg border border-line bg-surface p-4">
            {tab === 'Overview' && (
              <dl className="grid grid-cols-2 gap-4 text-sm lg:grid-cols-4">
                {([['Incidents', m.open || m.contained ? [m.open && `${m.open} open`, m.contained && `${m.contained} contained`].filter(Boolean).join(' · ') : 'None'],
                  ['Blocks in force', m.blocked ? String(m.blocked) : 'None'], ['Signed in', m.sessions == null ? '-' : m.sessions ? String(m.sessions) : 'Nobody'], ['Last seen', m.last_seen],
                  ['CPU', pct(m.hardware.cpu)], ['Memory', pct(m.hardware.memory)], ['Disk', pct(m.hardware.disk)]] as [string, string][]).map(([k, v]) => (
                  <div key={k}><dt className="text-xs uppercase tracking-wide text-muted">{k}</dt><dd className="text-lg font-medium">{v}</dd></div>))}
              </dl>
            )}
            {tab === 'Hardware' && (hw?.latest ? (
              <div className="grid gap-4 lg:grid-cols-2">
                <Bar label="CPU" value={hw.latest.cpu?.percent} limit={hw.limits?.cpu} />
                <Bar label={`Memory (${gb(hw.latest.memory?.used)} of ${gb(hw.latest.memory?.total)})`} value={hw.latest.memory?.percent} limit={hw.limits?.memory} />
                {(hw.latest.disks ?? []).map((d) => <Bar key={d.mount} label={`Disk ${d.mount}`} value={d.percent} limit={hw.limits?.disk} />)}
                <p className="text-xs text-muted lg:col-span-2">{hw.latest.cpu?.cores ? `${hw.latest.cpu.cores} cores` : ''}{hw.latest.cpu?.load ? ` · load ${hw.latest.cpu.load[0]?.toFixed(2)}` : ''}{hw.latest.uptime_s ? ` · up ${Math.round(hw.latest.uptime_s / 3600)} h` : ''} · its agent reports every 30 s</p>
              </div>
            ) : <p className="text-soft">No hardware reading yet. Its agent sends one every 30 seconds once it is running.</p>)}
            {tab === 'Incidents' && <><MachineIncidents incs={incs} /><MachineFixes host={host} /></>}
            {tab === 'Blocks' && (
              <div className="grid gap-4 lg:grid-cols-2">
                <div><h2 className="font-semibold">Addresses</h2>{blocks.ips?.length ? <ul className="font-mono text-sm">{blocks.ips.map((x) => <li key={x}>{x}</li>)}</ul> : <p className="text-soft">None blocked here.</p>}</div>
                <div><h2 className="font-semibold">Accounts</h2>{blocks.users?.length ? <ul className="font-mono text-sm">{blocks.users.map((x) => <li key={x}>{x}</li>)}</ul> : <p className="text-soft">None locked here.</p>}</div>
              </div>
            )}
            {tab === 'Signed in' && (details ? <SignedInTab d={details} host={host} canAct={can('act')} why={can('act') ? undefined : 'Your role can read everything but change nothing.'} run={run}
              asking={incs.filter((i) => i.category === 'unauthorised_admin' && ['open', 'acknowledged'].includes(i.status ?? '')).length} onAnswer={() => setTab('Incidents')} /> : <p className="text-muted" role="status">Loading…</p>)}
            {tab === 'Services' && (details ? <ServicesTab d={details} hasAgent={!!agent} /> : <p className="text-muted" role="status">Loading…</p>)}
            {tab === 'Packages' && (details ? <PackagesTab d={details} host={host} hasAgent={!!agent} canAct={can('act')} why={offWhy} run={run} /> : <p className="text-muted" role="status">Loading…</p>)}
            {tab === 'Jobs' && (jobs.length === 0 ? <p className="text-soft">Nothing has been asked of this machine's agent yet.</p> : (
              <ul className="divide-y divide-line-soft">{jobs.map((j) => (
                <li key={j.id} className="grid items-center gap-x-4 gap-y-1 py-2 text-sm sm:grid-cols-[10rem_6rem_minmax(0,1fr)_6rem]">
                  <b>{j.kind.replace(/_/g, ' ')}</b><span className="capitalize text-soft">{j.status}</span><span className="truncate text-muted">{dt(j.created_at)} · {j.requested_by}</span>
                  {j.status !== 'queued' ? <span /> : <button className={btn + ' justify-self-end'} disabled={!can('act')} onClick={() => void run(() => api(`/fleet/jobs/${encodeURIComponent(j.id)}/cancel`, { body: { operator: op } }), `${j.id} cancelled`)}>Cancel</button>}
                </li>))}</ul>))}
            {tab === 'Agent' && (agent ? (
              <div className="space-y-3">
                <dl className="grid grid-cols-2 gap-3 text-sm lg:grid-cols-4">
                  {([['Id', agent.agent_id], ['Joined', dt(agent.joined_at)], ['Invited by', agent.invited_by || '-'], ['Last call-in', dt(agent.last_seen)]] as [string, string][]).map(([k, v]) => (
                    <div key={k}><dt className="text-xs uppercase tracking-wide text-muted">{k}</dt><dd className="break-all font-medium">{v}</dd></div>))}
                </dl>
                <button className={btn} disabled={!can('configure')} title={can('configure') ? 'Stop accepting this machine’s key; it has to join again' : 'Your role can read everything but change nothing.'}
                  onClick={async () => { if (await ask({ title: `Revoke ${host}'s key?`, body: 'It has to join again to report.', confirm: 'Revoke key', danger: true }) !== null) void run(() => api(`/fleet/agents/${encodeURIComponent(agent.agent_id)}/revoke`, { body: { operator: op } }), `${host}'s key was revoked`) }}>Revoke key</button>
              </div>
            ) : <p className="text-soft">This machine has no agent: it is only seen in the logs.</p>)}
          </div>
        </>
      )}
    </section>
  )
}
