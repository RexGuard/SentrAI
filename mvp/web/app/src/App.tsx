import { createElement, lazy, Suspense, useEffect, useState, type ComponentType } from 'react'
import { BrowserRouter, HashRouter, Navigate, Route, Routes } from 'react-router-dom'
import { X } from 'lucide-react'
import { DEMO } from './lib/demo'
import { SessionProvider, useSession } from './lib/session'
import { SimpleProvider, useSimple } from './lib/simple'
import { Notices } from './lib/notice'
import { holdTransition } from './lib/motion'
import Layout from './pages/Layout'
import SignIn from './pages/SignIn'

// Each page is its own small file, fetched when it is first opened (and all of them in the background once the
// console is up), so the first load only waits for the shell and the page asked for.
const pages: Array<() => Promise<unknown>> = []
// A page already downloaded is drawn straight away: going through Suspense again would hold it back (React waits
// up to 300 ms before swapping a fallback for content).
function page(load: () => Promise<{ default: ComponentType }>) {
  let ready: ComponentType | undefined
  const get = () => load().then((m) => { ready = m.default; return m })
  pages.push(get)
  const Lazy = lazy(get)
  // Opened before its file arrived (the background fetch had not reached it yet): a page change in progress waits
  // briefly for the file, so the page slides in drawn rather than as a loading placeholder.
  const Page = (props: object) => { if (!ready) void holdTransition(get()); return createElement(ready ?? Lazy, props) }
  return Object.assign(Page, { preload: get })
}
const Analytics = page(() => import('./pages/Analytics'))
page(() => import('./pages/Approvals'))  // drawn in the Command center's tabs; fetched early with the rest
const Audit = page(() => import('./pages/Audit'))
const Chat = page(() => import('./pages/Chat'))
const Command = page(() => import('./pages/Command'))
const Guardrails = page(() => import('./pages/Guardrails'))
page(() => import('./pages/Incidents'))  // drawn in the Command center's tabs; fetched early with the rest
const Manager = page(() => import('./pages/Manager'))
const MachinePage = page(() => import('./pages/Machine'))
const Machines = page(() => import('./pages/Machines'))
const Backups = page(() => import('./pages/Backups'))
const pipeline = () => import('./pages/Pipeline')
const Classifier = page(() => pipeline().then((m) => ({ default: m.Classifier })))
const Collector = page(() => pipeline().then((m) => ({ default: m.Collector })))
const Responder = page(() => pipeline().then((m) => ({ default: m.Responder })))
const Tuning = page(() => import('./pages/Tuning'))
const Privacy = page(() => import('./pages/Privacy'))
const Overview = page(() => import('./pages/Overview'))
const Report = page(() => import('./pages/Report'))
const Reports = page(() => import('./pages/Reports'))
const Routing = page(() => import('./pages/Routing'))
page(() => import('./pages/Review'))  // drawn in the Command center's tabs; fetched early with the rest
const RiskList = page(() => import('./pages/RiskList'))
const Settings = page(() => import('./pages/Settings'))
const Staff = page(() => import('./pages/Staff'))
const Team = page(() => import('./pages/Team'))

/** Once signed in and the first page has its data, fetch the other pages while the browser is idle, so opening
 *  one later is instant. Waits a few seconds first so it never queues in front of the page's own calls. */
function usePrefetch(on: boolean) {
  useEffect(() => {
    if (!on) return
    const go = () => { for (const load of pages) void load().catch(() => {}) }
    const w = window as Window & { requestIdleCallback?: (cb: () => void, o?: { timeout: number }) => number }
    const t = setTimeout(() => (w.requestIdleCallback ? w.requestIdleCallback(go, { timeout: 5000 }) : go()), 4000)
    return () => clearTimeout(t)
  }, [on])
}

// The page asked for starts downloading now, alongside the sign-in check, not after it.
const first: Record<string, () => Promise<unknown>> = {
  '': Command.preload, command: Command.preload, risks: RiskList.preload, incidents: Command.preload, approvals: Command.preload,
  machines: Machines.preload, manager: Manager.preload,
}
const firstPage = (first[location.pathname.split('/')[1] ?? '']?.() ?? Promise.resolve()).catch(() => {})

function Gate() {
  const { me, loading } = useSession()
  const { simple } = useSimple()
  const [pageReady, setPageReady] = useState(false)
  useEffect(() => { void firstPage.then(() => setPageReady(true)) }, [])
  usePrefetch(!!me)
  if (loading || (me && !pageReady)) return <p className="p-6 text-muted" role="status">Loading…</p>
  if (!me) return <SignIn />
  if (new URLSearchParams(location.search).has('report') && location.pathname === '/') return <Navigate to="/report" replace />  // the old /?report address
  return (
    <Suspense fallback={<p className="p-6 text-muted" role="status">Loading…</p>}>
    <Routes>
      <Route element={<Layout />}>
        <Route path="/manager" element={<Manager />} />
        <Route index element={<Navigate to={simple ? '/manager' : '/command'} replace />} />
        <Route path="/command" element={<Command />} />
        <Route path="/risks/:severity" element={<RiskList />} />
        <Route path="/approvals" element={<Navigate to="/command?tab=approvals" replace />} />
        <Route path="/machines" element={<Machines />} />
        <Route path="/machines/:host" element={<MachinePage />} />
        <Route path="/chat" element={<Chat />} />
        <Route path="/audit" element={<Audit />} />
        <Route path="/team" element={<Team />} />
        <Route path="/staff" element={<Staff />} />
        <Route path="/report" element={<Report />} />
        <Route path="/routing" element={<Routing />} />
        <Route path="/overview" element={<Overview />} />
        <Route path="/config" element={<Settings />} />
        <Route path="/guardrails" element={<Guardrails />} />
        <Route path="/review" element={<Navigate to="/command?tab=review" replace />} />
        <Route path="/collector" element={<Collector />} />
        <Route path="/classifier" element={<Classifier />} />
        <Route path="/responder" element={<Responder />} />
        <Route path="/extensions" element={<Navigate to="/config" replace />} />
        <Route path="/reports" element={<Reports />} />
        <Route path="/backups" element={<Backups />} />
        <Route path="/incidents" element={<Navigate to="/command?tab=incidents" replace />} />
        <Route path="/analytics" element={<Analytics />} />
        <Route path="/tuning" element={<Tuning />} />
        <Route path="/privacy" element={<Privacy />} />
        <Route path="*" element={<Navigate to="/command" replace />} />
      </Route>
    </Routes>
    </Suspense>
  )
}

/** The demo copy's note that nothing on it is real. Small, and can be closed for a clean screen recording. */
function DemoNote() {
  const [shown, setShown] = useState(true)
  if (!shown) return null
  return (
    <div role="note" className="fixed bottom-3 left-1/2 z-50 flex -translate-x-1/2 max-w-[calc(100vw-1.5rem)] items-center gap-2 rounded-lg border border-line bg-surface px-3 py-1.5 text-xs text-soft shadow-lg">
      <span>Demo copy: made-up data, nothing is saved.</span>
      <button className="text-muted hover:text-ink" aria-label="Close" onClick={() => setShown(false)}><X size={14} aria-hidden /></button>
    </div>
  )
}

export default function App() {
  // The demo copy is static files on any host, so it keeps the page address in the # part (no server routes needed).
  const Router = DEMO ? HashRouter : BrowserRouter
  // useTransitions={false}: the router otherwise wraps every page change in React's startTransition, which renders
  // in the background and can finish after the page-change animation has already taken its "after" picture, so on
  // a busy panel the animation ran between two pictures of the same page and seemed not to happen at all.
  return (
    <Router useTransitions={false}>
      <SessionProvider><SimpleProvider><Gate /><Notices />{DEMO && <DemoNote />}</SimpleProvider></SessionProvider>
    </Router>
  )
}
