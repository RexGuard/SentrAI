// The ? button at the bottom right of every page. It opens a chat with Sentry docked on the right, and the page
// beside it stays usable. (Questions for the SentrAI team go through Contact Us in the side menu.)
import { lazy, Suspense, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { transition } from '../lib/motion'
import { CircleHelp, Maximize2, MessageSquare, X } from 'lucide-react'

// Fetched when the dock is first opened, not with every page.
const Chat = lazy(() => import('./Chat'))

export type DockTab = 'chat'
const KEY = 'sentrai.dock'

function remembered(): { open: boolean; tab: DockTab } {
  try {
    const v = JSON.parse(localStorage.getItem(KEY) ?? '{}')
    return { open: v.open === true, tab: 'chat' as DockTab }
  } catch { return { open: false, tab: 'chat' as DockTab } }
}

/** Open state for the dock, kept across page loads in this browser. */
export function useDock() {
  const [state, setState] = useState(remembered)
  useEffect(() => { try { localStorage.setItem(KEY, JSON.stringify(state)) } catch { /* private window: nothing to keep */ } }, [state])
  return {
    ...state,
    // The ? button grows into the panel and the panel shrinks back into it (both are named "dock").
    show: (tab: DockTab) => transition(() => setState({ open: true, tab })),
    close: () => transition(() => setState((s) => ({ ...s, open: false }))),
  }
}

export default function HelpDock({ dock }: { dock: ReturnType<typeof useDock> }) {
  useEffect(() => {
    if (!dock.open) return
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') dock.close() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [dock])

  if (!dock.open) {
    return (
      <button onClick={() => dock.show(dock.tab)} aria-label="Help: chat with Sentry" title="Chat with Sentry" style={{ viewTransitionName: 'dock' }}
        className="fixed bottom-5 right-5 z-40 flex h-12 w-12 items-center justify-center rounded-full border border-accent bg-accent text-on-accent shadow-lg hover:opacity-90">
        <CircleHelp size={22} aria-hidden />
      </button>
    )
  }

  return (
    <aside aria-label="Help panel" style={{ viewTransitionName: 'dock' }} className="fixed inset-y-0 right-0 z-40 flex w-full flex-col gap-3 border-l border-line bg-bg p-3 shadow-xl sm:w-[26rem]">
      <div className="flex items-center gap-1">
        <p className="inline-flex flex-1 items-center gap-1.5 px-2.5 py-1.5 text-sm font-medium"><MessageSquare size={14} aria-hidden /> Chat with Sentry</p>
        <Link to="/chat" onClick={dock.close} className="rounded-md p-1.5 text-soft hover:bg-surface-2" aria-label="Open as a full page" title="Open as a full page">
          <Maximize2 size={16} aria-hidden />
        </Link>
        <button onClick={dock.close} className="rounded-md p-1.5 text-soft hover:bg-surface-2" aria-label="Close the help panel" title="Close (Esc)"><X size={16} aria-hidden /></button>
      </div>
      <div className="min-h-0 flex-1 overflow-y-auto">
        <Suspense fallback={<p className="text-muted" role="status">Loading…</p>}><Chat compact /></Suspense>
      </div>
    </aside>
  )
}
