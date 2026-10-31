import { useCallback, useEffect, useState } from 'react'
import Stat from '../lib/Stat'
import { ExternalLink, Minus, Plug, Plus } from 'lucide-react'
import { api, ApiError } from '../lib/api'
import { btn, btnPrimary } from '../lib/ui'
import { useSession } from '../lib/session'

type Ext = {
  name: string; title?: string; kind?: string; what?: string; detail?: string; docs?: string; settings?: string[]
  built_in?: boolean; added?: boolean; added_by?: string; configured?: boolean; testable?: boolean
  error?: string | null; last_error?: string | null; changed_by?: string | null; changed_at?: string | null
}
type TestResult = { ok?: boolean; detail?: string; error?: string }

const NOTE: Record<string, (t: string) => string> = {
  Blocking: (t) => `Blocks it added at ${t} are taken out there again; SentrAI's own blocks stay.`,
  Alerts: (t) => `Alerts stop going to ${t} within 15 seconds; the console and email still get them.`,
  Classifier: (t) => `Events are classified by the rules and the keyword fallback, without ${t}.`,
  Lookups: (t) => `New incidents get no ${t} lookups; what earlier ones show stays.`,
}
const GROUPS: [string, string, string][] = [
  ['added', 'Added', 'on now: each one works while SentrAI runs'],
  ['available', 'Available', 'installed but not added: add one to use it'],
  ['built_in', 'Built in', 'part of SentrAI itself, so always there'],
]

function Card({ r, managed, done }: { r: Ext; managed: boolean; done: (msg: string) => void }) {
  const { me, can } = useSession()
  const op = me?.email ?? 'dashboard'
  const title = r.title || r.name
  const trouble = r.error || r.last_error
  const [confirm, setConfirm] = useState(false)
  const [result, setResult] = useState<TestResult | null>(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const off = managed || !can('configure')
  const why = managed ? "The server's SENTRAI_EXTENSIONS decides which extensions are on." : !can('configure') ? 'Your role can read everything but change nothing.' : undefined
  const run = async (fn: () => Promise<unknown>, msg: (out: any) => string) => { // eslint-disable-line @typescript-eslint/no-explicit-any
    setBusy(true); setErr('')
    try { done(msg(await fn())) } catch (e) { setErr(e instanceof ApiError ? e.message : 'That did not go through.') }
    setBusy(false); setConfirm(false)
  }
  const n = encodeURIComponent(r.name)
  const chip = r.built_in ? 'Built in' : !r.added ? 'Available' : trouble ? 'Problem' : r.configured ? 'Added' : 'Not set up'
  const chipColor = chip === 'Problem' || chip === 'Not set up' ? 'text-warn' : chip === 'Added' || (chip === 'Built in' && r.configured) ? 'text-ok' : 'text-muted'
  return (
    <div className="space-y-2 rounded-lg border border-line bg-surface p-4">
      <h3 className="font-semibold">{title} <span className={'text-sm font-normal ' + chipColor}>{chip}</span> <span className="text-xs font-normal text-muted">{r.kind}</span></h3>
      <p className="text-sm">{r.what}</p>
      <p className="text-xs text-muted">{r.detail}</p>
      {trouble && (r.added || r.built_in) && <p className="text-xs text-warn">{trouble}</p>}
      {r.changed_by && r.added_by === 'dashboard' && <p className="text-xs text-muted">{r.added ? 'Added' : 'Removed'} by {r.changed_by}, {r.changed_at ? new Date(r.changed_at).toLocaleString() : ''}</p>}
      <div className="flex flex-wrap gap-2">
        {!r.built_in && !r.added && <button className={btnPrimary} disabled={off || busy} title={why}
          onClick={() => void run(() => api(`/extensions/${n}/add`, { body: { operator: op } }), (o) => `Added ${title}${o?.configured ? '' : '. Save its settings on the Configuration page to set it up.'}`)}><Plus size={14} aria-hidden /> Add</button>}
        {!r.built_in && r.added && <button className={btn} disabled={off || busy} title={why} aria-expanded={confirm} onClick={() => setConfirm(!confirm)}><Minus size={14} aria-hidden /> Remove</button>}
        {r.testable && r.added && <button className={btn} disabled={!can('configure') || busy} onClick={() => { setBusy(true); api<TestResult>(`/extensions/${n}/test`, { body: {} }).then(setResult).catch((e) => setResult({ ok: false, error: e instanceof ApiError ? e.message : 'failed' })).finally(() => setBusy(false)) }}><Plug size={14} aria-hidden /> Test</button>}
        {r.docs && <a className={btn + ' no-underline'} href={r.docs} target="_blank" rel="noreferrer"><ExternalLink size={14} aria-hidden /> How to set up<span className="sr-only"> (opens in a new tab)</span></a>}
      </div>
      {!r.built_in && !!r.settings?.length && <p className="text-xs text-muted">Settings: {r.settings.join(', ')}</p>}
      {confirm && (
        <div className="space-y-2 rounded-md border border-line bg-surface-2 p-3">
          <p className="text-sm"><b>Remove {title}?</b> {`${NOTE[r.kind ?? '']?.(title) ?? ''} Its settings are kept, so adding it back restores it.`.trim()}</p>
          <div className="flex gap-2">
            <button className={btnPrimary} disabled={off || busy} onClick={() => void run(() => api(`/extensions/${n}/remove`, { body: { operator: op } }), () => `Removed ${title}.`)}>Remove {title}</button>
            <button className={btn} onClick={() => setConfirm(false)}>Keep it</button>
          </div>
        </div>
      )}
      {err && <p role="alert" className="text-sm text-bad">{err}</p>}
      {result && (result.ok ? <p role="status" className="text-sm text-ok">{result.detail || 'Connected.'}</p> : <p role="alert" className="text-sm text-bad">Test failed: {result.error}</p>)}
    </div>
  )
}

export default function Extensions() {
  const [rows, setRows] = useState<Ext[] | null>(null)
  const [error, setError] = useState('')
  const [note, setNote] = useState('')
  const load = useCallback(async () => {
    try { setRows(await api<Ext[]>('/extensions')); setError('') } catch (e) { setError(e instanceof ApiError ? `Could not ask the core which extensions are added: ${e.message}` : 'Could not load extensions.') }
  }, [])
  useEffect(() => { void load() }, [load])
  const ext = (rows ?? []).filter((r) => !r.built_in)
  const added = ext.filter((r) => r.added)
  const problems = (rows ?? []).filter((r) => r.added && (r.last_error || r.error))
  const edge = ext.find((r) => r.name === 'cloudflare')
  const managed = ext.some((r) => r.added_by === 'SENTRAI_EXTENSIONS')
  const groups: Record<string, Ext[]> = { added, available: ext.filter((r) => !r.added), built_in: (rows ?? []).filter((r) => r.built_in) }
  return (
    <section className="space-y-4">
      <header>
        <h1 className="text-2xl font-semibold">Extensions</h1>
        <p className="text-sm text-muted">Outside services SentrAI works with · add or remove each one while SentrAI runs</p>
      </header>
      {error && <p role="alert" className="rounded-md border border-line bg-surface p-3 text-bad">{error}</p>}
      {note && <p role="status" className="rounded-md border border-line bg-surface p-3">{note}</p>}
      {rows && (
        <>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <Stat label="Added" value={`${added.length} of ${ext.length}`} note="extensions on" />
            <Stat label="Edge blocking" value={edge?.added && edge.configured ? 'On' : 'Off'} note="Cloudflare blocks what SentrAI blocks" />
            <Stat label="Problems" value={String(problems.length)} note={problems.length ? 'last call failed' : 'none'} hot={problems.length > 0} />
          </div>
          {managed && <p className="rounded-md border border-line bg-surface p-3 text-soft">The server's SENTRAI_EXTENSIONS setting decides which extensions are on, so they cannot be added or removed here. Change it where SentrAI is started, then restart it.</p>}
          {GROUPS.filter(([k]) => groups[k]?.length).map(([k, title, about]) => (
            <div key={k} className="space-y-2">
              <h2 className="font-semibold">{title} <span className="font-normal text-muted">· {about}</span></h2>
              <div className="grid gap-3 lg:grid-cols-2">{groups[k].map((r) => <Card key={r.name} r={r} managed={managed} done={(m) => { setNote(m); void load() }} />)}</div>
            </div>
          ))}
          <p className="text-xs text-muted">Removing an extension keeps its settings, so adding it back restores it. Each extension's settings are on the Configuration page, still on the current console.</p>
        </>
      )}
    </section>
  )
}
