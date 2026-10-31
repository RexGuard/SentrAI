import { useCallback, useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import mount from '../canvas/flow_canvas.mjs'
import css from '../canvas/flow_canvas.css?raw'
import { api, ApiError } from '../lib/api'

type Result = { id: string; ok: boolean; message: string }
type Data = Record<string, unknown> & { results?: Result[] }
type Ev = { id?: string; doc?: unknown; block?: string; changes?: unknown; name?: string; on?: boolean; title?: string; page?: string; host?: string }

const ROUTES = new Set(['approvals', 'incidents', 'collector', 'classifier', 'responder', 'guardrails', 'review', 'machines', 'extensions', 'audit', 'config', 'chat', 'reports', 'backups', 'staff', 'team'])

export default function Overview() {
  const navigate = useNavigate()
  const hostEl = useRef<HTMLDivElement>(null)
  const [data, setData] = useState<Data | null>(null)
  const [results, setResults] = useState<Result[]>([])
  const [error, setError] = useState('')
  const busy = useRef(false)
  const seen = useRef(new Set<string>())

  const load = useCallback(async () => {
    if (busy.current) return
    try { setData(await api<Data>('/ui/overview')); setError('') } catch (e) { setError(e instanceof ApiError ? e.message : 'Could not load the overview.') }
  }, [])
  useEffect(() => { void load(); const t = setInterval(() => void load(), 5000); return () => clearInterval(t) }, [load])

  const answer = useCallback((id: string, ok: boolean, message: string) => setResults((r) => [...r.filter((x) => x.id !== id), { id, ok, message }].slice(-12)), [])
  const handle = useCallback((name: string, value: unknown) => {
    const ev = (value ?? {}) as Ev
    if (name === 'open') {
      if (ev.host) navigate(`/machines/${encodeURIComponent(ev.host)}`)
      else if (ev.page && ROUTES.has(ev.page)) navigate(`/${ev.page}`)
      return
    }
    if (name === 'add_machine') { navigate('/machines'); return }
    if (!ev.id || seen.current.has(ev.id)) return // each request is handled once
    seen.current.add(ev.id)
    const id = ev.id
    const path = name === 'save_layout' ? '/ui/overview/layout' : name === 'save_settings' ? '/ui/overview/settings' : name === 'toggle' ? '/ui/overview/toggle' : ''
    if (!path) return
    const body = name === 'save_layout' ? { doc: ev.doc } : name === 'save_settings' ? { block: ev.block, changes: ev.changes } : { name: ev.name, on: ev.on, title: ev.title }
    busy.current = true
    api<{ message: string }>(path, { body })
      .then((r) => answer(id, true, r.message))
      .catch((e) => answer(id, false, e instanceof ApiError ? e.message : 'That did not go through.'))
      .finally(() => { busy.current = false; if (name !== 'save_layout') void load() })
  }, [navigate, answer, load])

  useEffect(() => {
    const el = hostEl.current
    if (!el || !data) return
    const root = el.shadowRoot ?? el.attachShadow({ mode: 'open' })
    if (!root.querySelector('style')) { const st = document.createElement('style'); st.textContent = css; root.prepend(st) }
    mount({ parentElement: root, data: { ...data, results }, setTriggerValue: handle })
  }, [data, results, handle])

  return (
    <section className="space-y-3">
      <header>
        <h1 className="text-2xl font-semibold">Pipeline overview</h1>
        <p className="text-sm text-muted">every step, machine and extension as a block · click one for its numbers and settings, drag it anywhere, + Add for more</p>
      </header>
      {error && <p role="alert" className="rounded-md border border-line bg-surface p-3 text-bad">{error}</p>}
      <div ref={hostEl} />
    </section>
  )
}
