import { useCallback, useEffect, useMemo, useState } from 'react'
import { Save, Search } from 'lucide-react'
import { api, ApiError } from '../lib/api'
import { btnPrimary } from '../lib/ui'
import { useSession } from '../lib/session'

type Field = {
  env: string; prompt: string; kind: string; secret: boolean; generated: boolean; choices: string[]; preset_field: boolean
  value: string; is_set: boolean; default: string
}
type Section = { key: string; title: string; about: string; extension: boolean; fields: Field[] }
type Data = {
  sections: Section[]; presets: Record<string, { label: string; about: string; values: Record<string, string> }>
  advanced: string; advanced_about: string
}

const PRESET_ENV = 'SENTRAI_PRESET'
const GUARDRAILS = ['AUTO_ACTIONS', 'NEEDLE_MIN_CONFIDENCE', 'RISK_THRESHOLD', 'MAX_AUTO_ACTIONS_PER_HOUR', 'HOTPATCH_TTL_HOURS', 'MAX_TTL_HOURS', 'PROTECTED_IPS', 'PROTECTED_USERS']
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

export default function Settings({ only }: { only?: string[] }) {
  const { can } = useSession()
  const [data, setData] = useState<Data | null>(null)
  const [error, setError] = useState('')
  const [note, setNote] = useState('')
  const [draft, setDraft] = useState<Record<string, string>>({})
  const [query, setQuery] = useState('')
  const guard = !!only
  const load = useCallback(async () => {
    try { setData(await api<Data>('/ui/settings')); setError('') } catch (e) { setError(e instanceof ApiError ? e.message : 'Could not load settings.') }
  }, [])
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
    if (f.preset_field && data && (draft[PRESET_ENV] ?? current[PRESET_ENV]) !== data.advanced) next[PRESET_ENV] = data.advanced // a value changed by hand: Advanced
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
        <h1 className="text-2xl font-semibold">{guard ? 'Automation guardrails' : 'Configuration'}</h1>
        <p className="text-sm text-muted">{guard ? 'what SentrAI may do on its own, how often, and what it never touches' : `Saved to ${'settings file'} · read by every part when it starts`}</p>
      </header>
      {error && <p role="alert" className="rounded-md border border-line bg-surface p-3 text-bad">{error}</p>}
      {note && <p role="status" className="rounded-md border border-line bg-surface p-3">{note}</p>}
      {data && (
        <>
          {!guard && (
            <div className="relative">
              <Search size={16} className="pointer-events-none absolute left-3 top-2.5 text-muted" aria-hidden />
              <label htmlFor="cfg-search" className="sr-only">Search settings</label>
              <input id="cfg-search" className={input + ' mt-0 pl-9'} placeholder="Search settings: telegram, threshold, password…" value={query} onChange={(e) => setQuery(e.target.value)} />
            </div>
          )}
          {!guard && preset && match('preset', 'security', ...Object.values(data.presets).map((p) => p.label)) && (
            <div className="space-y-3 rounded-lg border border-line bg-surface p-4">
              <h2 className="font-semibold">Security preset <span className="font-normal text-muted">· one choice sets the detection and response values below</span></h2>
              <div role="radiogroup" aria-label="Preset" className="flex flex-wrap gap-2">
                {preset.choices.map((c) => (
                  <button key={c} role="radio" aria-checked={presetName === c} disabled={off} onClick={() => pickPreset(c)}
                    className={'rounded-md px-3 py-1.5 text-sm ' + (presetName === c ? 'bg-surface-3 text-ink' : 'text-soft hover:bg-surface-2')}>{c === data.advanced ? 'Advanced' : data.presets[c]?.label ?? c}</button>
                ))}
              </div>
              <p className="text-sm text-soft">{presetName === data.advanced ? data.advanced_about + ' Pick a preset to go back to its values.' : data.presets[presetName]?.about}</p>
            </div>
          )}
          {data.sections.filter((s) => (guard ? s.fields.some((f) => GUARDRAILS.includes(f.env)) : s.key !== 'preset')).map((s) => {
            const fields = s.fields.filter((f) => f.env !== PRESET_ENV && (guard ? GUARDRAILS.includes(f.env) : true))
            const whole = match(s.title, s.about)
            const hits = whole ? fields : fields.filter((f) => match(f.prompt, f.env))
            if (!hits.length) return null
            return (
              <details key={s.key} className="rounded-lg border border-line bg-surface" open={guard || !!q}>
                <summary className="cursor-pointer p-4 font-semibold">{s.title} <span className="font-normal text-muted">· {s.about}</span></summary>
                <div className="grid gap-4 p-4 pt-0 lg:grid-cols-2">{hits.map((f) => <Row key={f.env} f={f} value={val(f)} onChange={(v) => set(f, v)} disabled={off} />)}</div>
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
