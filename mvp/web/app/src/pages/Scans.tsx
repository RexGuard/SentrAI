// Scout's proposals and the three scans (process, threat, package) on the Collector page. All endpoints already
// exist on the core (/log-sources/pending, /system/scan, /threats, /quarantine, /deps).
import { useCallback, useEffect, useState, type ReactNode } from 'react'
import { ArrowUp, Ban, Eye, Radar, Search, ShieldAlert, Undo2, X } from 'lucide-react'
import { api, ApiError } from '../lib/api'
import { btn } from '../lib/ui'
import { useSession } from '../lib/session'

type Proposal = { id: string; name?: string; path?: string; layer?: string; why?: string }
type LogFile = { id: string; name?: string; size?: number; modified?: string; watched?: boolean }
type Suggestion = { program?: string; path?: string; layer?: string; reasons?: string[]; files?: LogFile[]; already_watched?: boolean; recognised?: boolean }
type ProcScan = { scanned_at?: string | null; scanned?: number; recognised?: number; skipped_protected?: number; error?: string
  threats?: { label?: string; name?: string; pid?: number; account?: string; severity?: string }[]; suggestions?: Suggestion[]; notes?: string[] }
type Finding = { id: string; label?: string; kind?: string; path?: string; entry?: string; line?: number; severity?: string; snippet?: string }
type ThreatScan = { scanned_at?: string | null; note?: string; files_checked?: number; roots?: string[]; missing?: string[]; counts?: Record<string, number>; findings?: Finding[] }
type Held = { id: string; name?: string; original?: string; finding?: { label?: string }; operator?: string; at?: string }
type DepFinding = { id: string; name: string; version: string; fixed?: string; severity?: string; kind?: string; path?: string }
type DepScan = { scanned_at?: string | null; note?: string; packages_checked?: number; sources?: string[]; missing?: string[]; counts?: Record<string, number>; findings?: DepFinding[] }

const dt = (v?: string | null) => (v ? new Date(v).toLocaleString() : '-')
const plural = (n: number, one: string, many = one + 's') => `${n} ${n === 1 ? one : many}`
const sevColor: Record<string, string> = { critical: 'var(--critical)', high: 'var(--red)', medium: 'var(--amber)' }
const Dot = ({ s }: { s?: string }) => <><span className="mr-1 inline-block h-2 w-2 rounded-full" style={{ background: sevColor[s ?? ''] ?? 'var(--ink-soft)' }} aria-hidden /><span className="sr-only">{s} </span></>

function Card({ title, note, children }: { title: string; note: string; children: ReactNode }) {
  return (
    <div className="min-w-0 space-y-3 rounded-lg border border-line bg-surface p-4">
      <h2 className="font-semibold">{title} <span className="font-normal text-muted">· {note}</span></h2>
      {children}
    </div>
  )
}

function useLoad<T>(path: string, fallback: T): [T, () => Promise<void>, string] {
  const [data, setData] = useState<T>(fallback)
  const [err, setErr] = useState('')
  const load = useCallback(async () => { try { setData(await api<T>(path)); setErr('') } catch (e) { setErr(e instanceof ApiError ? e.message : 'Could not load.') } }, [path])
  useEffect(() => { void load() }, [load])
  return [data, load, err]
}

export default function Scans() {
  const { me, can } = useSession()
  const op = me?.email ?? 'dashboard'
  const act = can('act')
  const why = act ? undefined : 'Your role can read everything but change nothing.'
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState('')
  const [pending, loadPending] = useLoad<Proposal[]>('/log-sources/pending', [])
  const [proc, loadProc] = useLoad<ProcScan>('/system/scan', {})
  const [threat, loadThreat, threatErr] = useLoad<ThreatScan>('/threats', {})
  const [held, loadHeld] = useLoad<Held[]>('/quarantine', [])
  const [deps, loadDeps, depsErr] = useLoad<DepScan>('/deps', {})
  const [, loadSources] = useLoad<unknown[]>('/log-sources', [])
  const run = async (what: string, fn: () => Promise<unknown>, msg: string, reload: (() => Promise<void>)[]) => {
    setNote(''); setBusy(what)
    try { await fn(); setNote(msg) } catch (e) { setNote(e instanceof ApiError ? e.message : 'That did not go through.') }
    setBusy(''); await Promise.all([...reload, loadSources()])
  }
  const watch = (id: string, name?: string) => run(`w${id}`, () => api('/log-sources', { body: { file_id: id, operator: op } }), `Collector now watches ${name}`, [loadProc])
  const c = threat.counts ?? {}, dc = deps.counts ?? {}
  const suggestions = proc.suggestions ?? []
  const known = suggestions.filter((s) => s.recognised !== false), other = suggestions.filter((s) => s.recognised === false)
  const Suggest = ({ s }: { s: Suggestion }) => (
    <div className="space-y-1 py-2">
      <p className="text-sm"><b>{s.program}</b> · <code className="text-xs">{s.path}</code> · {s.layer} · {s.already_watched ? 'already watched' : plural((s.files ?? []).length, 'log file')}</p>
      <p className="text-xs text-muted">{(s.reasons ?? []).join(', ')}</p>
      {(s.files ?? []).map((f) => (
        <div key={f.id} className="flex flex-wrap items-center gap-2 text-xs text-soft">
          <span className="min-w-0 flex-1">{f.name} · {((f.size ?? 0) / 1024).toFixed(1)} KB · changed {dt(f.modified)}</span>
          {f.watched ? <span>watched</span> : <button className={btn} disabled={!act || busy === `w${f.id}`} title={why} onClick={() => void watch(f.id, f.name)}><Eye size={14} aria-hidden /> Watch</button>}
        </div>))}
    </div>
  )
  return (
    <div className="space-y-4">
      {note && <p role="status" className="rounded-md border border-line bg-surface p-3">{note}</p>}
      {pending.length > 0 && (
        <Card title="Scout proposals" note="log files Scout found · nothing is watched until you press Watch">
          <ul className="divide-y divide-line-soft">{pending.map((p) => (
            <li key={p.id} className="flex flex-wrap items-center gap-2 py-2 text-sm">
              <span className="min-w-0 flex-1"><b>{p.name}</b> · <code className="text-xs">{p.path}</code> · {p.layer}<br /><span className="text-xs text-muted">{p.why}</span></span>
              <button className={btn} disabled={!act} title={why} onClick={() => void run(`p${p.id}`, () => api(`/log-sources/pending/${encodeURIComponent(p.id)}`, { body: { operator: op, approve: true } }), `Collector now watches ${p.name}`, [loadPending])}><Eye size={14} aria-hidden /> Watch</button>
              <button className={btn} disabled={!act} title={why} onClick={() => void run(`p${p.id}`, () => api(`/log-sources/pending/${encodeURIComponent(p.id)}`, { body: { operator: op, approve: false } }), `Dismissed ${p.name}`, [loadPending])}><X size={14} aria-hidden /> Dismiss</button>
            </li>))}</ul>
        </Card>)}
      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Find logs on this computer" note="read-only scan of running programs · nothing is watched until you press Watch">
          <button className={btn} disabled={!act || busy === 'proc'} title={why} onClick={() => void run('proc', () => api('/system/scan', { body: { operator: op } }), 'Scan finished', [loadProc])}><Radar size={14} aria-hidden /> {busy === 'proc' ? 'Scanning…' : 'Scan running programs'}</button>
          {!proc.scanned_at ? <p className="text-sm text-muted">No scan yet. Cyanide can also run one when you ask it in Chat.</p> : (
            <div className="space-y-1">
              <p className="text-sm text-muted">Last scan {dt(proc.scanned_at)}: {proc.scanned ?? 0} processes, {proc.recognised ?? 0} recognised, {proc.skipped_protected ?? 0} protected ones skipped.</p>
              {proc.error && <p className="text-sm text-warn">The scan hit a problem: {proc.error}</p>}
              {(proc.threats ?? []).map((t, i) => <p key={i} role="alert" className="rounded-md border border-line p-2 text-sm text-bad"><Dot s={t.severity} />Suspicious program: {t.label} · {t.name} (pid {t.pid}, account {t.account || 'unknown'})</p>)}
              {known.length === 0 ? <p className="text-soft">No log files found for the programs SentrAI recognises.</p> : <div className="divide-y divide-line-soft">{known.slice(0, 10).map((s, i) => <Suggest key={i} s={s} />)}</div>}
              {other.length > 0 && <details><summary className="cursor-pointer text-sm">Other log files open by programs SentrAI doesn't recognise ({other.length})</summary><div className="divide-y divide-line-soft">{other.slice(0, 10).map((s, i) => <Suggest key={i} s={s} />)}</div></details>}
              {(proc.notes ?? []).map((n, i) => <p key={i} className="text-xs text-muted">{n}</p>)}
            </div>)}
        </Card>
        <Card title="Check for threats" note="read-only look inside your chosen folders · files move to quarantine only when you press it">
          <button className={btn} disabled={!act || busy === 'threat'} title={why} onClick={() => void run('threat', () => api('/threats/scan', { body: { operator: op } }), 'Threat scan finished', [loadThreat, loadHeld])}><ShieldAlert size={14} aria-hidden /> {busy === 'threat' ? 'Checking…' : 'Scan for threats'}</button>
          {threatErr && <p className="text-sm text-muted">Threat scanning is not available on this core.</p>}
          {threat.note && <p className="text-sm text-muted">{threat.note}</p>}
          {!threat.scanned_at ? <p className="text-sm text-muted">No threat scan yet. Set the folders under threat_scan.paths in the system profile (or SENTRAI_THREAT_PATHS); Cyanide can also run one when you ask in Chat.</p> : (
            <div className="space-y-1">
              <p className="text-sm text-muted">Last scan {dt(threat.scanned_at)}: {threat.files_checked ?? 0} files in {(threat.roots ?? []).join(', ')} · {c.critical ?? 0} critical, {c.high ?? 0} high, {c.medium ?? 0} worth a look</p>
              {threat.missing?.length ? <p className="text-sm text-warn">Folders not found: {threat.missing.join(', ')}</p> : null}
              {(threat.findings ?? []).length === 0 ? <p className="text-ok">Nothing suspicious found.</p> : (
                <ul className="divide-y divide-line-soft">{(threat.findings ?? []).slice(0, 25).map((f) => (
                  <li key={f.id} className="flex flex-wrap items-start gap-2 py-2 text-sm">
                    <div className="min-w-0 flex-1"><p><Dot s={f.severity} /><b>{f.label}</b> · {(f.kind ?? '').replace(/_/g, ' ')} · <code className="break-all text-xs">{f.path}{f.entry ? ` → ${f.entry}` : ''}{f.line ? ` line ${f.line}` : ''}</code></p>
                      {f.snippet && <pre className="mt-1 overflow-x-auto rounded bg-surface-2 p-2 text-xs">{f.snippet}</pre>}</div>
                    <button className={btn} disabled={!act} title={why} onClick={() => void run(`q${f.id}`, () => api(`/threats/${encodeURIComponent(f.id)}/quarantine`, { body: { operator: op } }), `Quarantined ${f.path}`, [loadThreat, loadHeld])}><Ban size={14} aria-hidden /> Quarantine</button>
                  </li>))}</ul>)}
            </div>)}
          {held.length > 0 && (
            <details className="rounded-md border border-line p-2"><summary className="cursor-pointer text-sm font-medium">In quarantine ({held.length})</summary>
              <ul className="mt-2 divide-y divide-line-soft">{held.map((q) => (
                <li key={q.id} className="flex flex-wrap items-center gap-2 py-1.5 text-sm">
                  <span className="min-w-0 flex-1 text-soft">{q.name} · from <code className="text-xs">{q.original}</code> · {q.finding?.label} · by {q.operator} {dt(q.at)}</span>
                  <button className={btn} disabled={!act} title={why} onClick={() => void run(`r${q.id}`, () => api(`/quarantine/${encodeURIComponent(q.id)}/restore`, { body: { operator: op } }), `Restored ${q.name}`, [loadThreat, loadHeld])}><Undo2 size={14} aria-hidden /> Restore</button>
                </li>))}</ul></details>)}
        </Card>
      </div>
      <Card title="Check packages for known vulnerabilities" note="read-only · names and versions are looked up in OSV · joined machines get one-press updates on their Packages tab">
        <button className={btn} disabled={!act || busy === 'deps'} title={why} onClick={() => void run('deps', () => api('/deps/scan', { body: { operator: op } }), 'Package check finished', [loadDeps])}><Search size={14} aria-hidden /> {busy === 'deps' ? 'Looking up every package…' : 'Check packages'}</button>
        {depsErr ? <p className="text-sm text-muted">Package checks are not available on this core.</p> : !deps.scanned_at ? <p className="text-sm text-muted">Not checked yet. SentrAI's own environment is always checked; add folders with virtualenvs, npm projects or requirements files under dep_scan.paths (or SENTRAI_DEP_PATHS).</p> : deps.note ? <p className="text-warn">{deps.note}</p> : (
          <div className="space-y-1">
            <p className="text-sm text-muted">Checked {plural(deps.packages_checked ?? 0, 'package')} in {plural((deps.sources ?? []).length, 'place')} {dt(deps.scanned_at)} · {dc.critical ?? 0} critical, {dc.high ?? 0} high, {dc.medium ?? 0} medium, {dc.low ?? 0} low</p>
            {deps.missing?.length ? <p className="text-sm text-warn">Folders not found: {deps.missing.join(', ')}</p> : null}
            {(deps.findings ?? []).length === 0 ? <p className="text-ok">No known vulnerabilities in the installed packages.</p> : (
              <ul className="divide-y divide-line-soft">{(deps.findings ?? []).slice(0, 40).map((f) => (
                <li key={f.id} className="py-1.5 text-sm"><Dot s={f.severity} /><b>{f.name} {f.version}</b> {f.fixed ? <><ArrowUp size={12} className="inline" aria-hidden /> {f.fixed}</> : 'no fix yet'} · {f.kind} · <code className="text-xs">{f.path}</code></li>))}</ul>)}
          </div>)}
      </Card>
    </div>
  )
}
