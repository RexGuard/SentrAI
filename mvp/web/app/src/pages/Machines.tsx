import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { Copy, Hourglass, KeyRound, Plus, ShieldCheck, ShieldOff, Unplug } from 'lucide-react'
import { api, ApiError } from '../lib/api'
import { btn, btnPrimary } from '../lib/ui'
import { useSession } from '../lib/session'

type Machine = {
  name: string; host: string; place: string; online: boolean; waiting: boolean; index: number | null; band: string
  threshold: number; monitor_only: boolean; open: number; contained: number; blocked: number; last_seen: string
  services: string[]; hardware: { cpu: number | null; memory: number | null; disk: number | null }; sessions: number | null
}
type Joined = { host: string; agent_id: string; joined_at: string; invited_by: string; last_seen: string; status: string }
type Page = {
  panel: boolean; machines: Machine[]; joined: Joined[]; panel_info: { panel_url: string; pin: string }
  stats: { machines: number; online: number; offline: number; need_a_look: number; blocks: number }
  band_words: Record<string, string>
}
type Made = { code: string; expires_at: string; https: boolean; pin: string | null; commands: { linux: string; windows: string } }

const bandColor: Record<string, string> = { green: 'var(--green)', amber: 'var(--amber)', red: 'var(--red)', critical: 'var(--critical)' }
const pct = (v: number | null | undefined) => (v == null ? '-' : `${Math.round(v)}%`)

function State({ m }: { m: Machine }) {
  if (m.waiting) return <span className="inline-flex items-center gap-1 text-muted"><Hourglass size={14} aria-hidden /> Waiting for its first data</span>
  if (!m.online) return <span className="inline-flex items-center gap-1 text-crit"><Unplug size={14} aria-hidden /> Offline</span>
  if (m.monitor_only) return <span className="inline-flex items-center gap-1 text-warn"><ShieldOff size={14} aria-hidden /> Protection off</span>
  return <span className="inline-flex items-center gap-1 text-ok"><ShieldCheck size={14} aria-hidden /> Protecting</span>
}

function Stat({ label, value, note, hot }: { label: string; value: number; note: string; hot?: boolean }) {
  return (
    <div className="rounded-lg border border-line bg-surface p-4">
      <p className="text-xs uppercase tracking-wide text-muted">{label}</p>
      <p className={'text-2xl font-semibold ' + (hot ? 'text-bad' : '')}>{value}</p>
      <p className="text-xs text-muted">{note}</p>
    </div>
  )
}

function AddMachine({ page, onMade }: { page: Page; onMade: () => void }) {
  const { can } = useSession()
  const [name, setName] = useState('')
  const [url, setUrl] = useState(page.panel_info.panel_url || (location.protocol === 'https:' ? location.origin : ''))
  const [made, setMade] = useState<Made | null>(null)
  const [err, setErr] = useState('')
  const field = 'mt-1 block w-full rounded-md border border-line bg-surface-2 px-3 py-1.5 text-ink'
  const make = async () => {
    setErr('')
    try { setMade(await api<Made>('/ui/machines/join-code', { body: { name, panel_url: url } })); onMade() }
    catch (e) { setErr(e instanceof ApiError ? e.message : 'Could not make a join code.') }
  }
  if (!page.panel) return <p className="rounded-md border border-line bg-surface-2 p-3 text-soft">Turn on central panel mode first (see the note above).</p>
  const copy = (t: string) => void navigator.clipboard?.writeText(t)
  return (
    <div className="space-y-3 rounded-lg border border-line bg-surface-2 p-4">
      <h3 className="font-semibold">Add machine <span className="font-normal text-muted">· a one-time join code, valid for 24 hours</span></h3>
      <label className="block text-sm text-soft">Machine name (optional)
        <input className={field} value={name} onChange={(e) => setName(e.target.value)} placeholder="web-01" /></label>
      <label className="block text-sm text-soft">Panel address the machine will use
        <input className={field} value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://…" /></label>
      <button className={btnPrimary} disabled={!can('configure')} onClick={() => void make()}
        title={can('configure') ? undefined : 'Your role can read everything but change nothing.'}><KeyRound size={14} aria-hidden /> Make join code</button>
      {err && <p role="alert" className="text-bad">{err}</p>}
      {made && (
        <div className="space-y-2" role="status">
          <p>Join code <b className="font-mono">{made.code}</b> · works once, until {new Date(made.expires_at).toLocaleString()}</p>
          {(['linux', 'windows'] as const).map((os) => (
            <div key={os}>
              <p className="text-sm text-soft">{os === 'linux' ? 'On a Linux server, from a SentrAI checkout:' : 'On Windows, from a SentrAI checkout in an Administrator PowerShell:'}</p>
              <div className="flex items-start gap-2 rounded-md border border-line bg-bg p-2">
                <code className="min-w-0 flex-1 break-all font-mono text-xs">{made.commands[os]}</code>
                <button className="text-soft" aria-label={`Copy the ${os} command`} onClick={() => copy(made.commands[os])}><Copy size={14} aria-hidden /></button>
              </div>
            </div>
          ))}
          {!made.https && <p className="text-warn">Other machines refuse a plain http:// panel. Install the panel with sudo ./deploy/install.sh --panel to open its HTTPS port for agents.</p>}
        </div>
      )}
    </div>
  )
}

export default function Machines() {
  const [page, setPage] = useState<Page | null>(null)
  const [error, setError] = useState('')
  const [adding, setAdding] = useState(false)
  const load = useCallback(async () => {
    try { setPage(await api<Page>('/ui/machines')); setError('') } catch (e) { setError(e instanceof ApiError ? e.message : 'Could not load machines.') }
  }, [])
  useEffect(() => { void load(); const t = setInterval(() => void load(), 10000); return () => clearInterval(t) }, [load])
  const s = page?.stats
  return (
    <section className="space-y-4">
      <header>
        <h1 className="text-2xl font-semibold">Machines</h1>
        <p className="text-sm text-muted">every computer that reports to this panel, and adding a new one</p>
      </header>
      {error && <p role="alert" className="rounded-md border border-line bg-surface p-3 text-bad">{error}</p>}
      {page && s && (
        <>
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            <Stat label="Machines" value={s.machines} note={page.panel ? 'joined this panel' : 'this computer'} />
            <Stat label="Online" value={s.online} note={`${s.offline} offline or waiting`} hot={s.offline > 0} />
            <Stat label="Need a look" value={s.need_a_look} note="open incidents or red and above" hot={s.need_a_look > 0} />
            <Stat label="Blocks in force" value={s.blocks} note="each on its own machine" />
          </div>
          {!page.panel && <p className="rounded-md border border-line bg-surface p-3 text-soft">This core adds every machine into one score. To run it as a central panel, set SENTRAI_RISK_SCOPE=host (and SENTRAI_FIREWALL=off) on it and restart the core: each machine is then scored and blocked on its own.</p>}
          <div className="space-y-3 rounded-lg border border-line bg-surface p-4">
            <div className="flex items-center justify-between gap-3">
              <h2 className="font-semibold">Machine list <span className="font-normal text-muted">· worst first</span></h2>
              <button className={btn} aria-expanded={adding} onClick={() => setAdding(!adding)}><Plus size={14} aria-hidden /> Add machine</button>
            </div>
            {adding && <AddMachine page={page} onMade={() => void load()} />}
            <ul className="divide-y divide-line-soft">
              {page.machines.map((m) => (
                <li key={m.name} className="flex flex-wrap items-center gap-x-6 gap-y-2 py-3">
                  <div className="min-w-40 flex-1">
                    <p className="font-medium">{m.host ? <Link to={`/machines/${encodeURIComponent(m.host)}`} className="underline-offset-2 hover:underline">{m.name}</Link> : m.name}</p>
                    <p className="text-xs text-muted">{m.place}{!m.waiting && m.online ? ` · threshold ${Math.round(m.threshold)}` : ''}{m.services.length ? ` · ${m.services.join(', ')}` : ''}</p>
                    <div className="mt-1 h-1.5 w-40 rounded bg-surface-3" aria-hidden>
                      <div className="h-full rounded" style={{ width: `${m.online && m.index ? m.index : 0}%`, background: bandColor[m.band] ?? 'var(--ink-muted)' }} />
                    </div>
                  </div>
                  <div className="w-48 text-sm"><State m={m} /></div>
                  {m.online && !m.waiting && (
                    <dl className="grid min-w-0 grid-cols-3 gap-x-4 gap-y-1 text-xs text-soft">
                      {([['CPU', pct(m.hardware.cpu)], ['Memory', pct(m.hardware.memory)], ['Disk', pct(m.hardware.disk)],
                        ['Incidents', m.open || m.contained ? [m.open && `${m.open} open`, m.contained && `${m.contained} contained`].filter(Boolean).join(' · ') : 'None'],
                        ['Blocks', m.blocked ? `${m.blocked} in force` : 'None'], ['Last seen', m.last_seen]] as [string, string][]).map(([k, v]) => (
                        <div key={k}><dt className="text-muted">{k}</dt><dd>{v}</dd></div>
                      ))}
                    </dl>
                  )}
                  <div className="ml-auto w-24 text-right">
                    <p className="text-2xl font-semibold" style={{ color: m.online && !m.waiting ? bandColor[m.band] : undefined }}>
                      {m.waiting ? '-' : !m.online ? '0' : m.index == null ? '-' : Math.round(m.index)}
                    </p>
                    <p className="text-xs text-muted">{m.waiting ? 'Waiting' : !m.online ? 'Offline' : page.band_words[m.band] ?? 'Unknown'}</p>
                  </div>
                </li>
              ))}
            </ul>
          </div>
          {page.panel && (
            <div className="space-y-3 rounded-lg border border-line bg-surface p-4">
              <h2 className="font-semibold">Joined machines <span className="font-normal text-muted">· each has its own key; revoking one never touches the others</span></h2>
              {page.joined.length === 0 ? <p className="text-soft">No machine has joined yet. Make a join code above.</p> : (
                <div className="overflow-x-auto" role="region" aria-label="Joined machines" tabIndex={0}>
                  <table className="w-full text-left text-sm">
                    <thead className="border-b border-line text-xs uppercase tracking-wide text-muted">
                      <tr>{['Machine', 'Id', 'Joined', 'Invited by', 'Last seen', 'Status'].map((h) => <th key={h} className="p-2 font-medium">{h}</th>)}</tr>
                    </thead>
                    <tbody>
                      {page.joined.map((a) => (
                        <tr key={a.agent_id} className="border-b border-line-soft last:border-0">
                          <td className="p-2">{a.host}</td><td className="p-2 font-mono text-xs">{a.agent_id}</td>
                          <td className="p-2">{a.joined_at ? new Date(a.joined_at).toLocaleString() : '-'}</td><td className="p-2">{a.invited_by}</td>
                          <td className="p-2">{a.last_seen ? new Date(a.last_seen).toLocaleTimeString() : 'never'}</td><td className="p-2">{a.status}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </>
      )}
    </section>
  )
}
