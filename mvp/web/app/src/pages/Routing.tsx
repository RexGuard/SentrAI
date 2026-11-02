import { useCallback, useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { ArrowLeft } from 'lucide-react'
import mount from '../canvas/routing_editor.mjs'
import css from '../canvas/routing_editor.css?raw'
import { api, ApiError } from '../lib/api'

type Editor = Record<string, unknown> & { result?: { id: string; ok: boolean; message: string } }
type Page = { source?: string; escalate_after?: number; editor: Editor }
type Save = { id?: string; routing?: unknown; summary?: string }

export default function Routing() {
  const hostEl = useRef<HTMLDivElement>(null)
  const [page, setPage] = useState<Page | null>(null)
  const [result, setResult] = useState<Editor['result']>()
  const [error, setError] = useState('')
  const editing = useRef(false)
  const seen = useRef(new Set<string>())

  const load = useCallback(async () => {
    if (editing.current) return
    try { setPage(await api<Page>('/ui/routing')); setError('') } catch (e) { setError(e instanceof ApiError ? e.message : 'Could not load who gets what.') }
  }, [])
  useEffect(() => { void load() }, [load])

  const handle = useCallback((name: string, value: unknown) => {
    if (name !== 'save') return
    const ev = (value ?? {}) as Save
    if (!ev.id || seen.current.has(ev.id)) return // each save is handled once
    seen.current.add(ev.id)
    const id = ev.id
    editing.current = true
    api<{ message: string }>('/ui/routing', { body: { routing: ev.routing, summary: ev.summary } })
      .then((r) => setResult({ id, ok: true, message: r.message }))
      .catch((e) => setResult({ id, ok: false, message: e instanceof ApiError ? e.message : 'That did not go through.' }))
      .finally(() => { editing.current = false })
  }, [])

  useEffect(() => {
    const el = hostEl.current
    if (!el || !page) return
    const root = el.shadowRoot ?? el.attachShadow({ mode: 'open' })
    if (!root.querySelector('style')) { const st = document.createElement('style'); st.textContent = css; root.prepend(st) }
    mount({ parentElement: root, data: { ...page.editor, result }, setTriggerValue: handle })
  }, [page, result, handle])

  return (
    <section className="space-y-3">
      <Link to="/command?tab=incidents" className="inline-flex items-center gap-1 text-sm text-soft hover:text-ink"><ArrowLeft size={14} aria-hidden /> All incidents</Link>
      <header>
        <h1 className="text-2xl font-semibold">Who gets what</h1>
        <p className="text-sm text-muted">routing rules: the first match owns the incident
          {page?.source ? ` · from ${page.source}` : ''}{page?.escalate_after ? ` · unanswered alerts go to the owner's backup after ${page.escalate_after} reminders` : ''}</p>
      </header>
      {error && <p role="alert" className="rounded-md border border-line bg-surface p-3 text-bad">{error}</p>}
      <div ref={hostEl} />
    </section>
  )
}
