import { useCallback, useEffect, useRef, useState } from 'react'
import mount from '../canvas/limits_map.mjs'
import css from '../canvas/limits_map.css?raw'
import { api, ApiError } from '../lib/api'

type Data = Record<string, unknown> & { changed?: { at?: string; by?: string } }
type Save = { id?: string; settings?: unknown }
type Result = { id: string; ok: boolean; message: string }

// The limits map is the Streamlit console's own limits_map.mjs, unchanged, drawn in a shadow root. The page does
// not refresh itself, so nothing redraws while someone types an address or drags an action.
export default function Guardrails() {
  const hostEl = useRef<HTMLDivElement>(null)
  const [data, setData] = useState<Data | null>(null)
  const [result, setResult] = useState<Result>()
  const [error, setError] = useState('')
  const seen = useRef(new Set<string>())

  const load = useCallback(async () => {
    try { setData(await api<Data>('/ui/limits')); setError('') } catch (e) { setError(e instanceof ApiError ? e.message : 'Could not load the guardrails.') }
  }, [])
  useEffect(() => { void load() }, [load])

  const handle = useCallback((name: string, value: unknown) => {
    if (name !== 'save') return
    const ev = (value ?? {}) as Save
    if (!ev.id || seen.current.has(ev.id)) return // each save is handled once
    seen.current.add(ev.id)
    const id = ev.id
    api<{ message: string }>('/ui/limits', { body: { settings: ev.settings } })
      .then((r) => { setResult({ id, ok: true, message: r.message }); return load() })
      .catch((e) => setResult({ id, ok: false, message: e instanceof ApiError ? e.message : 'That did not go through.' }))
  }, [load])

  useEffect(() => {
    const el = hostEl.current
    if (!el || !data) return
    const root = el.shadowRoot ?? el.attachShadow({ mode: 'open' })
    if (!root.querySelector('style')) { const st = document.createElement('style'); st.textContent = css; root.prepend(st) }
    mount({ parentElement: root, data: { ...data, result }, setTriggerValue: handle })
  }, [data, result, handle])

  const c = data?.changed
  return (
    <section className="space-y-3">
      <header>
        <h1 className="text-2xl font-semibold">Automation guardrails</h1>
        <p className="text-sm text-muted">what SentrAI may do without asking, and what it never touches
          · {c?.at ? `changed ${new Date(c.at).toLocaleString()}${c.by ? ` by ${c.by}` : ''}` : 'never changed'}</p>
      </header>
      {error && <p role="alert" className="rounded-md border border-line bg-surface p-3 text-bad">{error}</p>}
      <div ref={hostEl} />
    </section>
  )
}
