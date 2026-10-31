import { useCallback, useEffect, useState, type ReactNode } from 'react'
import { api, ApiError } from '../lib/api'

type Rec = { seq?: number; ts?: string; type?: string; data?: Record<string, unknown> }
type Action = {
  action_id?: string; type?: string; target?: string; mode?: string; approved_by?: string; status?: string
  expires_at?: string; incident?: string; check?: { worked?: boolean | null; disruption?: boolean | null }
}
type Inc = { id: string; actions?: Action[] }
type Ext = { name: string; added?: boolean; configured?: boolean; error?: string | null; last_error?: string | null }
type Agent = { name?: string; status?: string }

const CATEGORY: Record<string, string> = {
  benign: 'Benign', brute_force: 'Brute force', sql_injection: 'SQL injection', xss: 'Cross-site scripting', port_scan: 'Port or web scan',
  privilege_escalation: 'Privilege escalation', data_exfiltration: 'Data exfiltration', misconfiguration: 'Misconfiguration',
  log_tampering: 'Log tampering', malware: 'Malware found', prompt_injection: 'Prompt injection',
}
const CLASSIFIER: Record<string, string> = { rules: 'Rules', jev: 'Jev (AI)', fallback: 'Fallback' }
const ACTION: Record<string, string> = { block_ip: 'Block IP', lock_user: 'Lock account', rate_limit: 'Rate limit', waf_rule: 'Web firewall rule', kill_process: 'Stop process', revoke_public_acl: 'Make private again' }
const MODE: Record<string, string> = { autonomous: 'Automatic', operator: 'By a person' }
const label = (m: Record<string, string>, k?: string) => (k ? m[k] ?? k.replace(/_/g, ' ') : '-')
const time = (v?: string) => (v ? new Date(v).toLocaleTimeString() : '-')

function Stat({ label: l, value, note, hot }: { label: string; value: string; note: string; hot?: boolean }) {
  return (
    <div className="rounded-lg border border-line bg-surface p-4">
      <p className="text-xs uppercase tracking-wide text-muted">{l}</p>
      <p className={'text-2xl font-semibold ' + (hot ? 'text-warn' : '')}>{value}</p>
      <p className="text-xs text-muted">{note}</p>
    </div>
  )
}

function Card({ title, note, children }: { title: string; note?: string; children: ReactNode }) {
  return (
    <div className="min-w-0 space-y-3 rounded-lg border border-line bg-surface p-4">
      <h2 className="font-semibold">{title} {note && <span className="font-normal text-muted">· {note}</span>}</h2>
      {children}
    </div>
  )
}

function Table({ head, rows, empty, name }: { head: string[]; rows: ReactNode[][]; empty: string; name: string }) {
  if (!rows.length) return <p className="text-soft">{empty}</p>
  return (
    <div className="overflow-x-auto" role="region" aria-label={name} tabIndex={0}>
      <table className="w-full text-left text-sm">
        <thead className="border-b border-line text-xs uppercase tracking-wide text-muted"><tr>{head.map((h) => <th key={h} className="p-2 font-medium">{h}</th>)}</tr></thead>
        <tbody>{rows.map((r, i) => <tr key={i} className="border-b border-line-soft last:border-0">{r.map((c, j) => <td key={j} className="p-2 align-top">{c}</td>)}</tr>)}</tbody>
      </table>
    </div>
  )
}

function usePolled<T>(path: string, fallback: T): [T, string] {
  const [data, setData] = useState<T>(fallback)
  const [err, setErr] = useState('')
  const load = useCallback(async () => { try { setData(await api<T>(path)); setErr('') } catch (e) { setErr(e instanceof ApiError ? e.message : 'Could not load.') } }, [path])
  useEffect(() => { void load(); const t = setInterval(() => void load(), 10000); return () => clearInterval(t) }, [load])
  return [data, err]
}

const byType = (recs: Rec[], ...types: string[]) => recs.filter((r) => types.includes(String(r.type)))

export function Classifier() {
  const [audit, e1] = usePolled<{ records: Rec[] }>('/audit?limit=2000', { records: [] })
  const [agents] = usePolled<Agent[]>('/agents', [])
  const [exts] = usePolled<Ext[]>('/extensions', [])
  const recs = audit.records
  const rows = byType(recs, 'event_classified').reverse()
  const opened = byType(recs, 'incident_opened')
  const byRules = rows.filter((r) => r.data?.classified_by === 'rules').length
  const jev = agents.find((a) => a.name === 'Jev')
  const ty = exts.find((e) => e.name === 'typesafe')
  const status = String(jev?.status ?? '')
  const [ai, aiNote] = status.startsWith('enabled') ? ['On', 'asked when the rules are unsure']
    : status.startsWith('disabled') ? ['Off', status.includes(':') ? status.split(':')[1].split('(')[0].trim() : 'keyword fallback in use']
    : ty ? (!ty.added ? ['Off', 'TypeSafe extension not added'] : ty.error || ty.last_error || !ty.configured ? ['Off', String(ty.error || ty.last_error || 'no TypeSafe key saved')] : ['On', 'asked when the rules are unsure'])
    : ['Unknown', 'the core did not report it']
  return (
    <section className="space-y-4">
      <header>
        <h1 className="text-2xl font-semibold">Classifier</h1>
        <p className="text-sm text-muted">Step 2 of 3 · decides which events are attacks: rules first, then AI, then keywords</p>
      </header>
      {e1 && <p role="alert" className="rounded-md border border-line bg-surface p-3 text-bad">{e1}</p>}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Stat label="Attacks identified" value={String(opened.length)} note="incidents opened" hot={opened.length > 0} />
        <Stat label="Malicious events" value={String(rows.length)} note="classified as an attack" />
        <Stat label="Settled by rules" value={String(byRules)} note="certain, no AI needed" />
        <Stat label="AI classifier" value={ai} note={aiNote.slice(0, 48)} />
      </div>
      <Card title="Classifications" note="newest first · 40-60% sure goes to a person and is never blocked on its own">
        <Table name="Classifications" empty="No malicious classifications yet."
          head={['Time', 'Event', 'Category', 'Confidence', 'Classified by', 'Layer agent', 'Incident', 'Raw log line']}
          rows={rows.slice(0, 100).map((r) => { const d = r.data ?? {}; return [time(r.ts), <span key="e" className="font-mono text-xs">{String(d.event_id ?? '-')}</span>,
            label(CATEGORY, d.category as string), typeof d.confidence === 'number' ? d.confidence.toFixed(2) : '-', label(CLASSIFIER, d.classified_by as string),
            String(d.agent ?? '-'), String(d.incident ?? '-'), <span key="r" className="break-all font-mono text-xs">{String(d.raw ?? '')}</span>] })} />
      </Card>
    </section>
  )
}

export function Responder() {
  const [incs, e1] = usePolled<Inc[]>('/incidents', [])
  const [block] = usePolled<{ ips?: string[]; users?: string[] }>('/blocklist', {})
  const [audit] = usePolled<{ records: Rec[] }>('/audit?limit=2000', { records: [] })
  const all = incs.flatMap((i) => (i.actions ?? []).map((a) => ({ ...a, incident: i.id })))
  const context = new Map(all.filter((a) => a.status === 'active' || a.status === 'permanent').map((a) => [String(a.target), a]))
  const contain: { kind: string; target: string; a?: Action }[] = [
    ...(block.ips ?? []).map((t) => ({ kind: 'IP', target: t, a: context.get(t) })),
    ...(block.users ?? []).map((t) => ({ kind: 'User', target: t, a: context.get(t) })),
  ]
  const seen = new Set(contain.map((c) => c.target))
  for (const [t, a] of context) if (!seen.has(t) && a.status === 'active') contain.push({ kind: 'Rule', target: t, a })
  const reviews = byType(audit.records, 'needle_review', 'action_applied', 'auto_rollback', 'action_rolled_back').reverse().slice(0, 15)
  const exp = (a?: Action) => (a?.status === 'permanent' ? 'permanent' : a?.expires_at ? new Date(a.expires_at).toLocaleTimeString() : '-')
  const check = (a: Action) => { const c = a.check; if (!c) return a.status === 'active' || a.status === 'permanent' ? 'pending' : '-'; const w = c.worked === true ? 'worked' : c.worked === false ? 'did not work' : "can't see"; return c.disruption === true ? `${w}, possible disruption` : w + (c.disruption === false ? ', no harm seen' : '') }
  return (
    <section className="space-y-4">
      <header>
        <h1 className="text-2xl font-semibold">Action taker</h1>
        <p className="text-sm text-muted">Step 3 of 3 · temporary blocks that undo themselves unless a person keeps them</p>
      </header>
      {e1 && <p role="alert" className="rounded-md border border-line bg-surface p-3 text-bad">{e1}</p>}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Stat label="Active containment" value={String(contain.length)} note="in force now" hot={contain.length > 0} />
        <Stat label="Blocked IPs" value={String(block.ips?.length ?? 0)} note="blocked right now" />
        <Stat label="Locked accounts" value={String(block.users?.length ?? 0)} note="locked right now" />
        <Stat label="Actions taken" value={String(all.length)} note="each expires unless a person keeps it" />
      </div>
      <Card title="Active containment" note="blocked or locked right now">
        <Table name="Active containment" empty="Nothing contained right now." head={['Kind', 'Target', 'Action', 'Incident', 'Mode', 'Approved by', 'Expires']}
          rows={contain.map((c) => [c.kind, <span key="t" className="font-mono text-xs">{c.target}</span>, label(ACTION, c.a?.type ?? (c.kind === 'IP' ? 'block_ip' : 'lock_user')), c.a?.incident ?? '-', label(MODE, c.a?.mode), c.a?.approved_by ?? '-', exp(c.a)])} />
      </Card>
      <div className="grid gap-4 lg:grid-cols-[7fr_5fr]">
        <Card title="Action history" note="every action is reversible and expires unless a person keeps it">
          <Table name="Action history" empty="No actions taken yet." head={['Incident', 'Type', 'Target', 'Mode', 'Status', 'Expires', 'Checked']}
            rows={all.map((a) => [a.incident, label(ACTION, a.type), <span key="t" className="font-mono text-xs">{a.target}</span>, label(MODE, a.mode), String(a.status ?? '-').replace(/_/g, ' '), time(a.expires_at), check(a)])} />
        </Card>
        <Card title="Countersign reviews" note="two-key check before any autonomous action">
          {reviews.length === 0 ? <p className="text-soft">No audit records yet.</p> : (
            <ol className="max-h-96 overflow-y-auto" role="region" aria-label="Countersign reviews" tabIndex={0}>
              {reviews.map((r, i) => <li key={i} className="border-b border-line-soft py-2 text-sm last:border-0"><span className="text-xs text-muted">{time(r.ts)} #{r.seq} · {String(r.type).replace(/_/g, ' ')}</span><br />{String(r.data?.summary ?? r.data?.incident ?? r.data?.target ?? '')}</li>)}
            </ol>)}
        </Card>
      </div>
    </section>
  )
}

type Collector = { collector?: string; silent?: boolean; last_seen_ts?: number }
type LogAgent = { name?: string; analyzed?: number; collectors?: Collector[] }
type Source = { layer?: string; found_by?: string; path?: string }
type SettingsData = { sections: { key: string; fields: { env: string; prompt: string; value: string }[] }[] }
const LOG_ENVS = ['SENTRAI_LOG_ACCESS', 'SENTRAI_LOG_AUTH', 'SENTRAI_LOG_DB', 'SENTRAI_LOG_OS']

export function Collector() {
  const [audit, e1] = usePolled<{ records: Rec[] }>('/audit?limit=2000', { records: [] })
  const [agents] = usePolled<LogAgent[]>('/agents', [])
  const [extra] = usePolled<Source[]>('/log-sources', [])
  const [cfg] = usePolled<SettingsData>('/ui/settings', { sections: [] })
  const fields = cfg.sections.flatMap((s) => s.fields)
  const dir = fields.find((f) => f.env === 'SENTRAI_LAB_LOGS')?.value ?? ''
  const layer = agents.filter((a) => a.analyzed !== undefined)
  const collectors = agents.find((a) => a.name === 'Watchdog')?.collectors ?? []
  const malicious = byType(audit.records, 'event_classified').reverse()
  const silent = byType(audit.records, 'collector_silent')
  const logs = LOG_ENVS.map((e) => fields.find((f) => f.env === e)).filter((f): f is NonNullable<typeof f> => !!f)
  return (
    <section className="space-y-4">
      <header>
        <h1 className="text-2xl font-semibold">Collector</h1>
        <p className="text-sm text-muted">Step 1 of 3 · reads your logs and turns each line into an event</p>
      </header>
      {e1 && <p role="alert" className="rounded-md border border-line bg-surface p-3 text-bad">{e1}</p>}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Stat label="Events analysed" value={String(layer.reduce((a, x) => a + Number(x.analyzed ?? 0), 0))} note="by the layer agents" />
        <Stat label="Malicious events" value={String(malicious.length)} note="attached to incidents" hot={malicious.length > 0} />
        <Stat label="Collectors" value={String(collectors.length)} note="sending heartbeats" />
        <Stat label="Silent alerts" value={String(silent.length)} note="a collector stopped reporting" hot={silent.length > 0} />
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Log sources" note="from the settings file">
          {dir && <p className="break-all text-xs text-muted">Folder: {dir}</p>}
          <Table name="Log sources" empty="No log sources." head={['Log', 'File']}
            rows={[...logs.map((f) => [f.prompt.replace(' file name', ''), <span key={f.env} className="font-mono text-xs">{f.value}</span>]),
              ...extra.map((x, i) => [`${x.layer ?? '?'} · ${x.found_by ?? 'Scout'}`, <span key={i} className="break-all font-mono text-xs">{x.path}</span>])]} />
        </Card>
        <Card title="Heartbeats" note="Watchdog flags a collector that goes quiet">
          <Table name="Heartbeats" empty="No heartbeat received yet. Start the collector." head={['Collector', 'State', 'Last seen']}
            rows={collectors.map((c) => [c.collector ?? '-', c.silent ? 'Silent' : 'Alive', c.last_seen_ts ? new Date(c.last_seen_ts * 1000).toLocaleTimeString() : '-'])} />
          <h2 className="pt-2 font-semibold">Events per layer agent</h2>
          <Table name="Events per layer agent" empty="No agent data." head={['Agent', 'Events analysed']} rows={layer.map((a) => [a.name ?? '-', String(a.analyzed ?? 0)])} />
        </Card>
      </div>
      <Card title="Malicious events collected" note="newest first">
        <Table name="Malicious events" empty="No malicious events yet." head={['Time', 'Event', 'Category', 'Layer agent', 'Incident', 'Raw log line']}
          rows={malicious.slice(0, 50).map((r) => { const d = r.data ?? {}; return [time(r.ts), <span key="e" className="font-mono text-xs">{String(d.event_id ?? '-')}</span>, label(CATEGORY, d.category as string), String(d.agent ?? '-'), String(d.incident ?? '-'), <span key="r" className="break-all font-mono text-xs">{String(d.raw ?? '')}</span>] })} />
      </Card>
      <p className="text-xs text-muted">Scout's proposed log files, the process and threat scans and the package scan are still on the current console.</p>
    </section>
  )
}
