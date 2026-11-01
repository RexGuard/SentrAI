// The ? button at the bottom right of every page. It opens a panel docked on the right with two tabs:
// chat with Cyanide, and report something suspicious. The page beside it stays usable.
import { lazy, Suspense, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { CircleHelp, Maximize2, MessageSquare, MessageSquareWarning, X } from 'lucide-react'

// Fetched when the dock is first opened, not with every page.
const Chat = lazy(() => import('./Chat'))
const Report = lazy(() => import('./Report'))

export type DockTab = 'chat' | 'report'
const KEY = 'sentrai.dock'

function remembered(): { open: boolean; tab: DockTab } {
  try {
    const v = JSON.parse(localStorage.getItem(KEY) ?? '{}')
    return { open: v.open === true, tab: v.tab === 'report' ? 'report' : 'chat' }
  } catch { return { open: false, tab: 'chat' } }
}

/** Open state for the dock, kept across page loads in this browser. */
export function useDock() {
  const [state, setState] = useState(remembered)
  useEffect(() => { try { localStorage.setItem(KEY, JSON.stringify(state)) } catch { /* private window: nothing to keep */ } }, [state])
  return {
    ...state,
    show: (tab: DockTab) => setState({ open: true, tab }),
    close: () => setState((s) => ({ ...s, open: false })),
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
      <button onClick={() => dock.show(dock.tab)} aria-label="Help: chat with Cyanide or report something" title="Chat with Cyanide or report something"
        className="fixed bottom-5 right-5 z-40 flex h-12 w-12 items-center justify-center rounded-full border border-line bg-ink text-bg shadow-lg hover:opacity-90">
        <CircleHelp size={22} aria-hidden />
      </button>
    )
  }

  const tabs: [DockTab, string, typeof MessageSquare][] = [['chat', 'Chat with Cyanide', MessageSquare], ['report', 'Report something', MessageSquareWarning]]
  return (
    <aside aria-label="Help panel" className="fixed inset-y-0 right-0 z-40 flex w-full flex-col gap-3 border-l border-line bg-bg p-3 shadow-xl sm:w-[26rem]">
      <div className="flex items-center gap-1">
        <div role="tablist" aria-label="Help" className="flex flex-1 gap-1">
          {tabs.map(([t, label, Icon]) => (
            <button key={t} role="tab" aria-selected={dock.tab === t} onClick={() => dock.show(t)}
              className={'inline-flex items-center gap-1.5 rounded-md px-2.5 py-1.5 text-sm ' + (dock.tab === t ? 'bg-surface-3 text-ink' : 'text-soft hover:bg-surface-2')}>
              <Icon size={14} aria-hidden /> {label}
            </button>
          ))}
        </div>
        <Link to={dock.tab === 'chat' ? '/chat' : '/report'} onClick={dock.close} className="rounded-md p-1.5 text-soft hover:bg-surface-2" aria-label="Open as a full page" title="Open as a full page">
          <Maximize2 size={16} aria-hidden />
        </Link>
        <button onClick={dock.close} className="rounded-md p-1.5 text-soft hover:bg-surface-2" aria-label="Close the help panel" title="Close (Esc)"><X size={16} aria-hidden /></button>
      </div>
      <div className="min-h-0 flex-1 overflow-y-auto">
        <Suspense fallback={<p className="text-muted" role="status">Loading…</p>}>{dock.tab === 'chat' ? <Chat compact /> : <Report compact />}</Suspense>
      </div>
    </aside>
  )
}
