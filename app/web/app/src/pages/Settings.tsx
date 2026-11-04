import { useCallback, useEffect, useState } from 'react'
import { Info, Save } from 'lucide-react'
import { api, ApiError } from '../lib/api'
import { btnPrimary } from '../lib/ui'
import { useSession } from '../lib/session'

// Setup for the business owner: only the security preset. Everything else (log sources, AI keys, integrations,
// contacts, advanced values) is set up by the SentrAI team in the terminal (sudo sentrai settings, docs/cli.md).
type Field = { env: string; prompt: string; choices: string[]; value: string }
type Data = {
  sections: { key: string; fields: Field[] }[]
  presets: Record<string, { label: string; about: string; values: Record<string, string> }>
  advanced: string
}

const PRESET_ENV = 'SENTRAI_PRESET'

export default function Settings() {
  const { can } = useSession()
  const [data, setData] = useState<Data | null>(null)
  const [error, setError] = useState('')
  const [note, setNote] = useState('')
  const [picked, setPicked] = useState('')
  const [details, setDetails] = useState(false)  // the i button: what each preset sets
  const load = useCallback(async () => {
    try { setData(await api<Data>('/ui/settings')); setError('') } catch (e) { setError(e instanceof ApiError ? e.message : 'Could not load settings.') }
  }, [])
  useEffect(() => { void load() }, [load])

  const fields = data?.sections.flatMap((s) => s.fields) ?? []
  const preset = fields.find((f) => f.env === PRESET_ENV)
  const saved = preset?.value ?? ''
  const name = picked || saved
  const off = !can('configure')

  const save = async () => {
    if (!data || !picked || picked === saved) return
    setNote('')
    // The preset and the values it sets, changed ones only (the same as picking it on the command line).
    const values: Record<string, string> = { [PRESET_ENV]: picked }
    Object.entries(data.presets[picked]?.values ?? {}).forEach(([env, v]) => { if (fields.find((f) => f.env === env)?.value !== v) values[env] = v })
    try { const r = await api<{ message: string }>('/ui/settings', { body: { values } }); setNote(r.message); setPicked(''); await load() }
    catch (e) { setNote(e instanceof ApiError ? e.message : 'Could not save.') }
  }

  const choices = preset ? preset.choices.filter((c) => c !== data?.advanced) : []
  const shown = data?.presets[name] ? name : ''
  const label = (env: string) => fields.find((f) => f.env === env)?.prompt ?? env

  return (
    <section className="space-y-4">
      <header>
        <h1 className="text-2xl font-semibold">Setup</h1>
        <p className="text-sm text-muted">How quickly SentrAI acts on its own. Your SentrAI team looks after everything else.</p>
      </header>
      {error && <p role="alert" className="rounded-md border border-line bg-surface p-3 text-bad">{error}</p>}
      {note && <p role="status" className="rounded-md border border-line bg-surface p-3">{note}</p>}
      {data && preset && (
        <div className="space-y-3 rounded-lg border border-line bg-surface p-4">
          <h2 className="font-semibold">Security Preset <span className="font-normal text-muted">· one choice sets how quickly SentrAI acts</span></h2>
          <div className="flex flex-wrap items-center gap-2">
            <div role="radiogroup" aria-label="Preset" className="flex flex-wrap gap-2">
              {choices.map((c) => (
                <button key={c} role="radio" aria-checked={name === c} disabled={off} onClick={() => setPicked(c === saved ? '' : c)}
                  className={'rounded-md px-3 py-1.5 text-sm ' + (name === c ? 'bg-surface-3 text-ink' : 'text-soft hover:bg-surface-2')}>{data.presets[c]?.label ?? c}</button>
              ))}
            </div>
            <button aria-expanded={details} aria-controls="preset-details" onClick={() => setDetails(!details)} title={details ? 'Hide what each preset sets' : 'Show what each preset sets'}
              className={'inline-flex h-7 w-7 items-center justify-center rounded-full border border-line ' + (details ? 'bg-surface-3 text-ink' : 'text-soft hover:bg-surface-2')}>
              <Info size={14} aria-hidden /><span className="sr-only">Preset details</span>
            </button>
          </div>
          <p className="text-sm text-soft">{shown ? data.presets[shown].about : 'Your SentrAI team set these values by hand. Pick a preset to use its values.'}</p>
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
          <div className="flex items-center gap-3 border-t border-line-soft pt-3">
            <button className={btnPrimary} disabled={off || !picked} onClick={() => void save()} title={off ? 'Your role can read the settings but not change them.' : undefined}><Save size={14} aria-hidden /> Save</button>
            <span className="text-sm text-muted">{picked ? `Switch to ${data.presets[picked]?.label ?? picked}` : 'No unsaved changes'}</span>
          </div>
        </div>
      )}
    </section>
  )
}
