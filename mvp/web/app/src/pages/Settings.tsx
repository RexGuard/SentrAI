import { useCallback, useEffect, useMemo, useState } from 'react'
import { ExternalLink, Info, Lock, Plug, Save, Search, Terminal } from 'lucide-react'
import { api, ApiError } from '../lib/api'
import { btn, btnPrimary } from '../lib/ui'
import { useSession } from '../lib/session'

type Field = {
  env: string; prompt: string; kind: string; secret: boolean; generated: boolean; choices: string[]; preset_field: boolean; advanced?: boolean
  value: string; is_set: boolean; default: string
}
type Section = { key: string; title: string; about: string; extension: boolean; feature?: boolean; name?: string; fields: Field[] }
// The core's view of each integration (GET /extensions): whether it is on and working.
type Ext = {
  name: string; title?: string; docs?: string; built_in?: boolean; feature?: boolean; added?: boolean; added_by?: string
  configured?: boolean; testable?: boolean; error?: string | null; last_error?: string | null
}
type TestResult = { ok?: boolean; detail?: string; error?: string }
type Data = {
  sections: Section[]; presets: Record<string, { label: string; about: string; values: Record<string, string> }>
  advanced: string; advanced_about: string
}

const PRESET_ENV = 'SENTRAI_PRESET'
const input = 'mt-1 block w-full rounded-md border border-line bg-surface-2 px-3 py-1.5 text-ink'

function Row({ f, value, onChange, disabled }: { f: Field; value: string; onChange: (v: string) => void; disabled: boolean }) {
  const id = `f-${f.env}`
  return (
    <div>
      <label htmlFor={id} className="block text-sm text-soft">{f.prompt}</label>
      {f.generated ? (
        <input id={id} className={input} value={f.is_set ? 'Set by setup' : 'Not set'} disabled readOnly aria-describedby={`${id}-d`} />
      ) : f.choices.length ? (
        <select id={id} className={input} value={value} disabled={disabled} onChange={(e) => onChange(e.target.value)} aria-describedby={`${id}-d`}>
          {f.choices.map((c) => <option key={c} value={c}>{c}</option>)}
        </select>
      ) : (
        <input id={id} className={input} type={f.secret ? 'password' : 'text'} autoComplete="off" value={value} disabled={disabled}
          placeholder={f.secret ? (f.is_set ? 'Set. Leave blank to keep it.' : 'Not set') : ''} onChange={(e) => onChange(e.target.value)} aria-describedby={`${id}-d`} />
      )}
      <p id={`${id}-d`} className="mt-0.5 text-xs text-muted">Environment variable {f.env}</p>
    </div>
  )
}

/** An advanced setting: shown as plain text, never a box or a menu. Only the SentrAI team changes it, in the terminal. */
function ReadOnly({ f }: { f: Field }) {
  const shown = f.secret || f.generated ? (f.is_set ? 'Set' : 'Not set') : f.value || 'Not set'
  return (
    <div>
      <p className="text-sm text-soft">{f.prompt}</p>
      <p className={'mt-1 break-words text-sm ' + (f.value || f.is_set ? 'font-medium text-ink' : 'text-muted')}>{shown}</p>
      <p className="mt-0.5 text-xs text-muted">Environment variable {f.env}</p>
    </div>
  )
}

/** The top of an integration's or a built-in feature's card: is it on, a switch (integrations only), Test, set-up help. */
function Status({ s, x, reload }: { s: Section; x?: Ext; reload: () => void }) {
  const { me, can } = useSession()
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState<TestResult | null>(null)
  if (!x) return null
  const trouble = x.error || x.last_error
  const on = !!x.added
  const state = !on ? 'Off' : trouble ? 'Problem' : x.configured ? 'On' : 'Needs its key'
  const color = state === 'On' ? 'text-ok' : state === 'Off' ? 'text-muted' : 'text-warn'
  const managed = x.added_by === 'SENTRAI_EXTENSIONS'
  const off = managed || !can('configure') || busy
  const why = managed ? "The server's SENTRAI_EXTENSIONS setting decides which integrations are on." : !can('configure') ? 'Your role can read the settings but not change them.' : undefined
  const n = encodeURIComponent(x.name)
  const flip = async () => {
    setBusy(true); setMsg(null)
    try { await api(`/extensions/${n}/${on ? 'remove' : 'add'}`, { body: { operator: me?.email ?? 'dashboard' } }); reload() }
    catch (e) { setMsg({ ok: false, error: e instanceof ApiError ? e.message : 'That did not go through.' }) }
    setBusy(false)
  }
  const test = async () => {
    setBusy(true)
    try { setMsg(await api<TestResult>(`/extensions/${n}/test`, { body: {} })) } catch (e) { setMsg({ ok: false, error: e instanceof ApiError ? e.message : 'failed' }) }
    setBusy(false)
  }
  return (
    <div className="space-y-2 px-4 pb-3">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <span className={'font-medium ' + color}>{state}</span>
        {s.feature && <span className="text-muted">· built into SentrAI, on whenever its key is saved</span>}
        {!s.feature && <button role="switch" aria-checked={on} aria-label={`${s.title} on`} onClick={() => void flip()} disabled={off} title={why}
          className="inline-flex items-center gap-2 rounded-full border border-line bg-surface px-2 py-1 disabled:opacity-60">
          <span className={'relative h-5 w-9 rounded-full transition-colors ' + (on ? 'bg-ok' : 'bg-surface-3')} aria-hidden>
            <span className={'absolute top-0.5 h-4 w-4 rounded-full bg-bg shadow transition-all ' + (on ? 'left-[1.125rem]' : 'left-0.5')} />
          </span>
          <span className="text-xs text-soft">{on ? 'Turn off' : 'Turn on'}</span>
        </button>}
        {x.testable && on && <button className={btn} disabled={!can('configure') || busy} onClick={() => void test()}><Plug size={14} aria-hidden /> Test</button>}
        {x.docs && <a className={btn + ' no-underline'} href={x.docs} target="_blank" rel="noreferrer"><ExternalLink size={14} aria-hidden /> How to get a key<span className="sr-only"> (opens in a new tab)</span></a>}
      </div>
      {trouble && on && <p className="text-xs text-warn">{trouble}</p>}
      {!s.feature && !on && <p className="text-xs text-muted">Turning it off keeps its settings, so turning it back on restores it.</p>}
      {msg && (msg.ok ? <p role="status" className="text-sm text-ok">{msg.detail || 'Connected.'}</p> : <p role="alert" className="text-sm text-bad">{msg.error}</p>)}
    </div>
  )
}

export default function Settings() {
  const { can } = useSession()
  const [data, setData] = useState<Data | null>(null)
  const [error, setError] = useState('')
  const [note, setNote] = useState('')
  const [draft, setDraft] = useState<Record<string, string>>({})
  const [query, setQuery] = useState('')
  const [details, setDetails] = useState(false)  // the i button: what the chosen preset sets
  const [exts, setExts] = useState<Ext[]>([])
  const loadExts = useCallback(() => { api<Ext[]>('/extensions').then(setExts).catch(() => setExts([])) }, [])
  const load = useCallback(async () => {
    try { setData(await api<Data>('/ui/settings')); setError('') } catch (e) { setError(e instanceof ApiError ? e.message : 'Could not load settings.') }
    loadExts()
  }, [loadExts])
  useEffect(() => { void load() }, [load])

  const current = useMemo(() => {
    const out: Record<string, string> = {}
    data?.sections.forEach((s) => s.fields.forEach((f) => { out[f.env] = f.value }))
    return out
  }, [data])
  const val = (f: Field) => draft[f.env] ?? current[f.env] ?? ''
  const set = (f: Field, v: string) => setDraft((d) => {
    const next = { ...d }
    if (v === current[f.env]) delete next[f.env]; else next[f.env] = v
    return next
  })
  const pickPreset = (name: string) => setDraft((d) => {
    const next: Record<string, string> = { ...d, [PRESET_ENV]: name }
    if (data && name !== data.advanced) Object.entries(data.presets[name].values).forEach(([env, v]) => { if (v === current[env]) delete next[env]; else next[env] = v })
    return next
  })
  const save = async () => {
    setNote('')
    try { const r = await api<{ message: string }>('/ui/settings', { body: { values: draft } }); setNote(r.message); setDraft({}); await load() }
    catch (e) { setNote(e instanceof ApiError ? e.message : 'Could not save.') }
  }

  const q = query.trim().toLowerCase()
  const match = (...t: string[]) => !q || t.some((x) => x.toLowerCase().includes(q))
  const preset = data?.sections[0]?.fields.find((f) => f.env === PRESET_ENV)
  const presetName = preset ? draft[PRESET_ENV] ?? current[PRESET_ENV] : ''
  const off = !can('configure')
  const dirty = Object.keys(draft).length

  return (
    <section className="space-y-4">
      <header>
        <h1 className="text-2xl font-semibold">Setup</h1>
        <p className="text-sm text-muted">Saved to the settings file · read by every part when it starts</p>
      </header>
      {error && <p role="alert" className="rounded-md border border-line bg-surface p-3 text-bad">{error}</p>}
      {note && <p role="status" className="rounded-md border border-line bg-surface p-3">{note}</p>}
      {data && (
        <>
          <div className="relative">
            <Search size={16} className="pointer-events-none absolute left-3 top-2.5 text-muted" aria-hidden />
            <label htmlFor="cfg-search" className="sr-only">Search settings</label>
            <input id="cfg-search" className={input + ' mt-0 pl-9'} placeholder="Search settings: telegram, threshold, password…" value={query} onChange={(e) => setQuery(e.target.value)} />
          </div>
          {preset && match('preset', 'security', ...Object.values(data.presets).map((p) => p.label)) && (() => {
            // Only the three presets: no Advanced. The values each one sets stay hidden until the i button is pressed.
            const choices = preset.choices.filter((c) => c !== data.advanced)
            const shown = data.presets[presetName] ? presetName : ''
            const label = (env: string) => data.sections.flatMap((x) => x.fields).find((f) => f.env === env)?.prompt ?? env
            return (
              <div className="space-y-3 rounded-lg border border-line bg-surface p-4">
                <h2 className="font-semibold">Security Preset <span className="font-normal text-muted">· one choice sets how quickly SentrAI acts</span></h2>
                <div className="flex flex-wrap items-center gap-2">
                  <div role="radiogroup" aria-label="Preset" className="flex flex-wrap gap-2">
                    {choices.map((c) => (
                      <button key={c} role="radio" aria-checked={presetName === c} disabled={off} onClick={() => pickPreset(c)}
                        className={'rounded-md px-3 py-1.5 text-sm ' + (presetName === c ? 'bg-surface-3 text-ink' : 'text-soft hover:bg-surface-2')}>{data.presets[c]?.label ?? c}</button>
                    ))}
                  </div>
                  <button aria-expanded={details} aria-controls="preset-details" onClick={() => setDetails(!details)} title={details ? 'Hide what this preset sets' : 'Show what this preset sets'}
                    className={'inline-flex h-7 w-7 items-center justify-center rounded-full border border-line ' + (details ? 'bg-surface-3 text-ink' : 'text-soft hover:bg-surface-2')}>
                    <Info size={14} aria-hidden /><span className="sr-only">Preset details</span>
                  </button>
                </div>
                <p className="text-sm text-soft">{shown ? data.presets[shown].about : 'Your values were set by hand. Pick a preset to use its values.'}</p>
                {details && (
                  <div id="preset-details" className="overflow-x-auto rounded-md border border-line-soft">
                    <table className="w-full text-left text-sm">
                      <thead className="border-b border-line text-xs uppercase tracking-wide text-muted">
                        <tr><th className="p-2 font-medium">Setting</th>{choices.map((c) => <th key={c} className={'p-2 font-medium ' + (c === shown ? 'text-ink' : '')}>{data.presets[c]?.label ?? c}</th>)}</tr>
                      </thead>
                      <tbody>
                        {Object.keys(data.presets[choices[0]]?.values ?? {}).map((env) => (
                          <tr key={env} className="border-b border-line-soft last:border-0">
                            <td className="p-2 text-soft">{label(env)}</td>
                            {choices.map((c) => <td key={c} className={'p-2 tabular-nums ' + (c === shown ? 'font-semibold text-ink' : 'text-muted')}>{data.presets[c].values[env]}</td>)}
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )
          })()}
          {data.sections.filter((s) => s.key !== 'preset').map((s) => {
            const fields = s.fields.filter((f) => f.env !== PRESET_ENV && !f.preset_field)  // the preset sets these
            const whole = match(s.title, s.about)
            const hits = whole ? fields : fields.filter((f) => match(f.prompt, f.env))
            if (!hits.length) return null
            const x = (s.extension || s.feature) ? exts.find((e) => e.name === s.name) : undefined
            const tag = s.feature ? 'Built in' : s.extension ? 'Integration' : ''
            return (
              <details key={s.key} className="rounded-lg border border-line bg-surface" open={!!q}>
                <summary className="cursor-pointer p-4 font-semibold">{s.title.replace(/^\d+\.\s*/, '')}{tag && <span className="ml-2 rounded-full border border-line px-2 py-0.5 text-xs font-normal text-soft">{tag}</span>} <span className="font-normal text-muted">· {s.about}</span></summary>
                <Status s={s} x={x} reload={loadExts} />
                {hits.some((f) => !f.advanced) && <div className="grid gap-4 p-4 pt-0 lg:grid-cols-2">{hits.filter((f) => !f.advanced).map((f) => <Row key={f.env} f={f} value={val(f)} onChange={(v) => set(f, v)} disabled={off} />)}</div>}
                {hits.some((f) => f.advanced) && (
                  <div className="mx-4 mb-4 rounded-md border border-line-soft bg-surface-2 p-3">
                    <p className="mb-3 flex flex-wrap items-center gap-1.5 text-xs text-muted">
                      <Lock size={12} aria-hidden /> <b className="font-semibold text-soft">Advanced · read only.</b> Your SentrAI team changes these in the terminal
                      <span className="inline-flex items-center gap-1 rounded bg-surface px-1.5 py-0.5 font-mono"><Terminal size={11} aria-hidden />sudo sentrai settings set</span>
                    </p>
                    <div className="grid gap-4 lg:grid-cols-2">{hits.filter((f) => f.advanced).map((f) => <ReadOnly key={f.env} f={f} />)}</div>
                  </div>
                )}
              </details>
            )
          })}
          <div className="sticky bottom-0 flex items-center gap-3 border-t border-line bg-bg py-3">
            <button className={btnPrimary} disabled={off || !dirty} onClick={() => void save()} title={off ? 'Auditors can read the settings but not change them.' : undefined}><Save size={14} aria-hidden /> Save settings</button>
            <span className="text-sm text-muted">{dirty ? `${dirty} unsaved change${dirty > 1 ? 's' : ''}` : 'No unsaved changes'}</span>
          </div>
        </>
      )}
    </section>
  )
}
