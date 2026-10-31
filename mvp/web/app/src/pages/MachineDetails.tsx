// The single-machine page's Signed in, Services and Packages tabs (GET /ui/machines/{host}/details).
import { useState, type FormEvent, type ReactNode } from 'react'
import { ArrowUp, Plus, Search, Trash2, Undo2 } from 'lucide-react'
import { api, ApiError } from '../lib/api'
import { btn, btnPrimary } from '../lib/ui'

type Known = { how: string; by: string; at?: string | null; last_seen?: string | null }
type Entry = { kind: 'account' | 'address' | 'key'; value: string; host: string | null; headline: string; known: Known; note: string; forget: boolean }
type Session = { user: string; how: string; from: string; trust: string; trust_words: string; since?: string; preexisting: boolean; actions: number; why: string }
type Activity = { at?: string; user: string; how: string; what: string; would_have_been: string; why: string }
type Service = { name: string; port: number | null; proto: string; process: string; open_incidents: number }
type Finding = { id: string; name: string; version: string; fixed?: string; severity?: string; kind?: string; path?: string; how?: string; update?: string; line: string }
type Scan = { note?: string; counts?: Record<string, number>; packages_checked?: number; sources?: string[]; scanned_at?: string; missing?: string[]; findings: Finding[] }
type Update = { id: string; name: string; from: string; to: string; path: string }
export type Details = {
  host: string; services: Service[]; services_at?: string | null
  admins: { on: boolean; sessions: Session[]; suspect: { address: string; why?: string; until?: string }[]; activity: Activity[]; entries: Entry[] }
  packages: { latest: Scan | null; updates: Update[]; busy: { kind: string; status: string } | null }
  admin_kinds: Record<string, string>
}
type Run = (fn: () => Promise<unknown>, msg: string) => Promise<void>

const dt = (v?: string | null) => (v ? new Date(v).toLocaleString() : '-')
const plural = (n: number, one: string, many = one + 's') => `${n} ${n === 1 ? one : many}`
const sevColor: Record<string, string> = { critical: 'var(--critical)', high: 'var(--red)', medium: 'var(--amber)', low: 'var(--ink-soft)' }

function knownText(k: Known): string {
  const when = k.at ? ` on ${dt(k.at)}` : ''
  const seen = k.last_seen ? ` · last seen ${dt(k.last_seen)}` : ''
  if (k.how === 'setting') return (k.by ? `from the settings (${k.by})` : 'from the settings') + seen
  if (k.how === 'taught') return (k.by ? `taught by ${k.by}${when}` : `taught${when}`) + seen
  if (k.how === 'learned') return `learned from ${k.by && k.by !== 'a trusted sign-in' ? k.by : 'a trusted sign-in'}${when}${seen}`
  if (k.how === 'sign_in') return `until ${dt(k.at)}`
  return (k.how || 'known') + when + seen
}

function Card({ title, sub, children }: { title: string; sub?: string; children: ReactNode }) {
  return (
    <div className="space-y-2 border-t border-line-soft pt-4 first:border-0 first:pt-0">
      <div><h2 className="font-semibold">{title}</h2>{sub && <p className="text-sm text-muted">{sub}</p>}</div>
      {children}
    </div>
  )
}

function Table({ label, head, rows, empty }: { label: string; head: string[]; rows: ReactNode[][]; empty: string }) {
  if (!rows.length) return <p className="text-soft">{empty}</p>
  return (
    <div className="overflow-x-auto" role="region" aria-label={label} tabIndex={0}>
      <table className="w-full text-left text-sm">
        <thead className="border-b border-line text-xs uppercase tracking-wide text-muted"><tr>{head.map((h) => <th key={h} className="p-2 font-medium">{h}</th>)}</tr></thead>
        <tbody>{rows.map((r, i) => <tr key={i} className="border-b border-line-soft align-top last:border-0">{r.map((c, j) => <td key={j} className="p-2">{c}</td>)}</tr>)}</tbody>
      </table>
    </div>
  )
}

export function SignedInTab({ d, host, canAct, why, run, asking, onAnswer }: { d: Details; host: string; canAct: boolean; why?: string; run: Run; asking: number; onAnswer: () => void }) {
  const a = d.admins
  const [kind, setKind] = useState('address')
  const [value, setValue] = useState('')
  const [label, setLabel] = useState('')
  const [everywhere, setEverywhere] = useState(false)
  const [err, setErr] = useState('')
  const add = async (e: FormEvent) => {
    e.preventDefault(); setErr('')
    if (!value.trim()) { setErr('Type the address, key fingerprint or account first. Nothing was changed.'); return }
    try {
      await api('/admins', { body: { operator: 'dashboard', action: 'add', kind, value: value.trim(), label: label.trim(), host: kind !== 'account' || everywhere ? null : host } })
      await run(async () => undefined, `Added ${(d.admin_kinds[kind] ?? kind).toLowerCase()} ${value.trim()}`)
      setValue(''); setLabel(''); setEverywhere(false)
    } catch (x) { setErr(`Not added: ${x instanceof ApiError ? x.message : 'that did not go through.'}`) }
  }
  const forget = (e: Entry) => run(() => api('/admins', { body: { operator: 'dashboard', action: 'forget', kind: e.kind, value: e.value, host: e.kind === 'account' && e.host !== '*' ? e.host : null } }), `Forgot ${e.headline}`)
  return (
    <div className="space-y-4">
      {!a.on && <p className="rounded-md border border-line bg-surface-2 p-3 text-sm">SentrAI is not keeping track of who is signed in (ADMIN_SESSIONS is off on the core), so every root command is judged on its own.</p>}
      {asking > 0 && (
        <div className="flex flex-wrap items-center gap-3 rounded-md border border-line bg-surface-2 p-3">
          <span className="flex-1">{plural(asking, 'root-access alert')} on this machine {asking === 1 ? 'asks' : 'ask'}: was this you?</span>
          <button className={btn} onClick={onAnswer}>Answer it</button>
        </div>
      )}
      <Card title="Signed in now" sub="who is on this machine, how they got in, and whether SentrAI knows them as an administrator">
        <Table label="Signed in now" head={['User', 'How', 'From', 'Trust', 'Since', 'Root commands', 'Why']} empty={`Nobody SentrAI has seen is signed in on ${host} right now.`}
          rows={a.sessions.map((s) => [<b>{s.user}</b>, s.how, <span className="font-mono text-xs">{s.from}</span>,
            <span className={s.trust === 'suspect' ? 'text-bad' : s.trust === 'trusted' ? 'text-ok' : 'text-warn'}>{s.trust_words}</span>,
            dt(s.since) + (s.preexisting ? ' (before SentrAI started watching)' : ''), s.actions, <span className="text-soft">{s.why || '-'}</span>])} />
        {a.suspect.length > 0 && <p className="text-xs text-muted">Distrusted for now: {a.suspect.map((s) => `${s.address} (${s.why || 'suspect'}) until ${dt(s.until)}`).join(' · ')}</p>}
      </Card>
      <Card title="Recent admin work" sub="root commands by known administrators, newest first · recorded, never an incident">
        <Table label="Recent admin work" head={['When', 'Who', 'How', 'What', 'Would have been', 'Why']} empty={`No root work by a known administrator on ${host} yet.`}
          rows={a.activity.map((x) => [dt(x.at), x.user, x.how, <span className="font-mono text-xs">{x.what}</span>, x.would_have_been || '-', <span className="text-soft">{x.why || '-'}</span>])} />
      </Card>
      <Card title="Known administrators" sub="whose root work SentrAI records instead of raising · from the settings, taught with This was me or here, or learned from a trusted sign-in">
        {(['account', 'address', 'key'] as const).map((k) => {
          const rows = a.entries.filter((e) => e.kind === k)
          return (
            <div key={k} className="space-y-1">
              <h3 className="text-sm font-semibold">{{ account: 'Accounts', address: 'Addresses', key: 'SSH keys' }[k]} <span className="font-normal text-muted">· {rows.length || 'none yet'}</span></h3>
              <ul className="divide-y divide-line-soft">{rows.map((e, i) => (
                <li key={`${e.value}-${e.host}-${i}`} className="flex flex-wrap items-center gap-2 py-1.5 text-sm">
                  <span className="min-w-0 flex-1 break-all"><span className={k === 'key' ? 'font-mono text-xs' : 'font-medium'}>{e.headline}</span>
                    <span className="text-muted"> · {[e.note, knownText(e.known)].filter(Boolean).join(' · ')}</span></span>
                  {e.forget && <button className={btn} disabled={!canAct} title={canAct ? 'SentrAI stops trusting it; the next sign-in with it asks again' : why} onClick={() => void forget(e)}><Trash2 size={14} aria-hidden /> Forget</button>}
                </li>))}</ul>
            </div>
          )
        })}
        <form onSubmit={(e) => void add(e)} className="space-y-2 rounded-md border border-line p-3">
          <h3 className="flex items-center gap-1 text-sm font-semibold"><Plus size={14} aria-hidden /> Add a known administrator</h3>
          <div className="grid gap-2 sm:grid-cols-[1fr_2fr_1fr]">
            <label className="text-sm">What<select value={kind} onChange={(e) => setKind(e.target.value)} className="mt-1 w-full rounded-md border border-line bg-bg p-1.5">
              {Object.entries(d.admin_kinds).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label>
            <label className="text-sm">Value<input value={value} onChange={(e) => setValue(e.target.value)} placeholder="203.0.113.5, 203.0.113.0/24, SHA256:… or erick" className="mt-1 w-full rounded-md border border-line bg-bg p-1.5" /></label>
            <label className="text-sm">Label (optional)<input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="e.g. Erick's home" className="mt-1 w-full rounded-md border border-line bg-bg p-1.5" /></label>
          </div>
          {kind === 'account' && <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={everywhere} onChange={(e) => setEverywhere(e.target.checked)} /> An account counts on every machine, not only {host}</label>}
          <p className="text-xs text-muted">A key's fingerprint: <code>ssh-keygen -lf ~/.ssh/id_ed25519.pub</code> prints it.</p>
          {err && <p role="alert" className="text-sm text-bad">{err}</p>}
          <button type="submit" className={btnPrimary} disabled={!canAct} title={why}><Plus size={14} aria-hidden /> Add</button>
        </form>
      </Card>
    </div>
  )
}

export function ServicesTab({ d, hasAgent }: { d: Details; hasAgent: boolean }) {
  return (
    <Card title="Services" sub={'what listens on it, reported by its agent every minute' + (d.services_at ? ` · last report ${dt(d.services_at)}` : '')}>
      <Table label="Services" head={['Service', 'Port', 'Protocol', 'Process', 'Open incidents']} empty={hasAgent ? 'No services reported yet.' : 'No agent on this machine reports its services.'}
        rows={d.services.map((s) => [<b>{s.name}</b>, s.port ?? '-', s.proto, <span className="font-mono text-xs">{s.process}</span>,
          s.open_incidents ? <span className="text-bad">{s.open_incidents}</span> : '0'])} />
    </Card>
  )
}

export function PackagesTab({ d, host, hasAgent, canAct, why, run }: { d: Details; host: string; hasAgent: boolean; canAct: boolean; why?: string; run: Run }) {
  const p = d.packages
  const r = p.latest
  const job = (kind: string, msg: string, params?: Record<string, string>) =>
    run(() => api('/fleet/jobs', { body: { host, kind, operator: 'dashboard', ...(params ? { params } : {}) } }), msg)
  if (!hasAgent) return <Card title="Packages with known vulnerabilities"><p className="text-soft">Package checks run through SentrAI's agent, and this machine has none.</p></Card>
  const c = r?.counts ?? {}
  return (
    <Card title="Packages with known vulnerabilities" sub="its agent checks the virtualenvs, npm projects and requirements files under SENTRAI_DEP_PATHS there, plus Debian or Ubuntu packages · nothing changes until you press Update, and each update can be undone">
      <div className="flex flex-wrap items-center gap-3">
        <button className={btn} disabled={!canAct} title={canAct ? 'Its agent looks every package up in OSV' : why} onClick={() => void job('dep_scan', `Asked ${host} to check its packages`)}><Search size={14} aria-hidden /> Check packages</button>
        {p.busy && <span className="text-sm text-soft" role="status">{p.busy.kind === 'dep_scan' ? 'A package check' : p.busy.kind === 'dep_update' ? 'An update' : 'An undo'} is {p.busy.status === 'queued' ? 'waiting for the machine' : 'running'}…</span>}
      </div>
      {!r ? <p className="text-sm text-muted">Not checked yet.</p> : r.note ? <p className="rounded-md border border-line bg-surface-2 p-3 text-warn">{r.note}</p> : (
        <div className="space-y-2">
          <p className="text-sm text-muted">Checked {plural(r.packages_checked ?? 0, 'package')} in {plural((r.sources ?? []).length, 'place')}{r.scanned_at ? ` ${dt(r.scanned_at)}` : ''} · {c.critical ?? 0} critical, {c.high ?? 0} high, {c.medium ?? 0} medium, {c.low ?? 0} low{c.no_fix_os ? ` · ${c.no_fix_os} OS packages wait on a fix from the distribution` : ''}</p>
          {r.missing?.length ? <p className="text-sm text-warn">Folders not found: {r.missing.join(', ')}</p> : null}
          {r.findings.length === 0 ? <p className="text-ok">No known vulnerabilities in the installed packages.</p> : (
            <ul className="divide-y divide-line-soft">{r.findings.slice(0, 40).map((f) => (
              <li key={f.id} className="flex flex-wrap items-start gap-2 py-2 text-sm">
                <span className="mt-1.5 inline-block h-2 w-2 shrink-0 rounded-full" style={{ background: sevColor[f.severity ?? ''] ?? 'var(--ink-soft)' }} aria-hidden />
                <div className="min-w-0 flex-1">
                  <p><span className="sr-only">{f.severity} </span><b>{f.line}</b> · {f.kind} · <code className="text-xs">{f.path}</code></p>
                  {f.how && <p className="text-xs text-muted">{f.how}</p>}
                </div>
                {f.update === 'safe' && <button className={btn} disabled={!canAct} title={canAct ? `Asks ${host} to install ${f.fixed}; you can undo it below` : why}
                  onClick={() => void job('dep_update', `Asked ${host} to update ${f.name} to ${f.fixed}`, { finding: String(f.id) })}><ArrowUp size={14} aria-hidden /> Update</button>}
              </li>))}</ul>)}
          {r.findings.length > 40 && <p className="text-xs text-muted">… and {r.findings.length - 40} more.</p>}
        </div>
      )}
      {p.updates.length > 0 && (
        <details className="rounded-md border border-line p-2">
          <summary className="cursor-pointer text-sm font-medium">Updates made ({p.updates.length})</summary>
          <ul className="mt-2 divide-y divide-line-soft">{p.updates.map((u) => (
            <li key={u.id} className="flex flex-wrap items-center gap-2 py-1.5 text-sm">
              <span className="min-w-0 flex-1 text-soft">{u.name} {u.from} → {u.to} · <code className="text-xs">{u.path}</code></span>
              <button className={btn} disabled={!canAct} title={canAct ? `Puts ${u.name} ${u.from} back` : why} onClick={() => void job('dep_rollback', `Asked ${host} to put ${u.name} ${u.from} back`, { update: String(u.id) })}><Undo2 size={14} aria-hidden /> Undo</button>
            </li>))}</ul>
        </details>
      )}
    </Card>
  )
}
