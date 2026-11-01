// In-app notifications that ask before a risky step, in place of the browser's own confirm() and prompt() boxes.
// `ask()` shows a card in the top-right corner, styled like the rest of the dashboard, and resolves with the typed
// text (or '' when there is no field) on confirm, or null on cancel / Escape. <Notices /> renders the cards once.
import { useEffect, useRef, useState, useSyncExternalStore } from 'react'
import { AlertTriangle, Info, X } from 'lucide-react'
import { btn, btnPrimary } from './ui'

export type Ask = {
  title: string
  body?: string | string[]
  confirm?: string
  cancel?: string
  danger?: boolean
  input?: { label: string; value?: string; placeholder?: string; required?: boolean }
}
type Open = Ask & { id: number; done: (v: string | null) => void }

let open: Open[] = []
let seq = 0
const subs = new Set<() => void>()
const emit = () => subs.forEach((f) => f())

/** Show a notification asking for a decision. Resolves with the text typed ('' if no field) or null when cancelled. */
export function ask(a: Ask): Promise<string | null> {
  return new Promise((resolve) => {
    const id = ++seq
    open = [...open, { ...a, id, done: (v) => { open = open.filter((o) => o.id !== id); emit(); resolve(v) } }]
    emit()
  })
}

function Card({ n }: { n: Open }) {
  const [text, setText] = useState(n.input?.value ?? '')
  const first = useRef<HTMLInputElement | HTMLButtonElement>(null)
  useEffect(() => { first.current?.focus() }, [])
  const blocked = !!n.input?.required && !text.trim()
  const ok = () => { if (!blocked) n.done(n.input ? text : '') }
  const lines = Array.isArray(n.body) ? n.body : n.body ? [n.body] : []
  return (
    <div role="alertdialog" aria-labelledby={`n${n.id}`} className="notice pointer-events-auto w-[24rem] max-w-[calc(100vw-2rem)] rounded-xl border border-line bg-surface p-4 shadow-2xl"
      onKeyDown={(e) => { if (e.key === 'Escape') n.done(null) }}>
      <div className="flex items-start gap-3">
        {n.danger ? <AlertTriangle size={18} className="mt-0.5 shrink-0 text-warn" aria-hidden /> : <Info size={18} className="mt-0.5 shrink-0 text-soft" aria-hidden />}
        <div className="min-w-0 flex-1 space-y-2">
          <p id={`n${n.id}`} className="font-semibold">{n.title}</p>
          {lines.map((l, i) => <p key={i} className="text-sm text-soft">{l}</p>)}
          {n.input && (
            <label className="block text-sm text-soft">{n.input.label}
              <input ref={first as React.RefObject<HTMLInputElement>} value={text} placeholder={n.input.placeholder}
                onChange={(e) => setText(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter') ok() }}
                className="mt-1 block w-full rounded-md border border-line bg-surface-2 px-3 py-1.5 text-ink" /></label>)}
          <div className="flex justify-end gap-2 pt-1">
            <button className={btn} onClick={() => n.done(null)}>{n.cancel ?? 'Cancel'}</button>
            <button ref={n.input ? undefined : first as React.RefObject<HTMLButtonElement>} className={btnPrimary} disabled={blocked} onClick={ok}>{n.confirm ?? 'OK'}</button>
          </div>
        </div>
        <button className="text-muted hover:text-ink" aria-label="Close" onClick={() => n.done(null)}><X size={16} aria-hidden /></button>
      </div>
    </div>
  )
}

/** Renders the open notifications; mount once near the root. */
export function Notices() {
  const list = useSyncExternalStore((f) => { subs.add(f); return () => { subs.delete(f) } }, () => open)
  if (!list.length) return null
  return (
    <div className="pointer-events-none fixed right-4 top-4 z-50 flex flex-col items-end gap-3" aria-live="assertive">
      {list.map((n) => <Card key={n.id} n={n} />)}
    </div>
  )
}
