import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { SessionProvider, useSession } from './lib/session'
import Layout, { MENU } from './pages/Layout'
import SignIn from './pages/SignIn'
import Approvals from './pages/Approvals'
import Audit from './pages/Audit'
import Chat from './pages/Chat'
import Guardrails from './pages/Guardrails'
import Extensions from './pages/Extensions'
import Incidents from './pages/Incidents'
import MachinePage from './pages/Machine'
import Machines from './pages/Machines'
import Backups from './pages/Backups'
import { Classifier, Collector, Responder } from './pages/Pipeline'
import Overview from './pages/Overview'
import Report from './pages/Report'
import Reports from './pages/Reports'
import Routing from './pages/Routing'
import Review from './pages/Review'
import Soon from './pages/Soon'
import Settings from './pages/Settings'
import Staff from './pages/Staff'
import Team from './pages/Team'

function Gate() {
  const { me, loading } = useSession()
  if (loading) return <p className="p-6 text-muted" role="status">Loading…</p>
  if (!me) return <SignIn />
  if (new URLSearchParams(location.search).has('report') && location.pathname === '/') return <Navigate to="/report" replace />  // the old /?report address
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Navigate to="/approvals" replace />} />
        <Route path="/approvals" element={<Approvals />} />
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
        <Route path="/review" element={<Review />} />
        <Route path="/collector" element={<Collector />} />
        <Route path="/classifier" element={<Classifier />} />
        <Route path="/responder" element={<Responder />} />
        <Route path="/extensions" element={<Extensions />} />
        <Route path="/reports" element={<Reports />} />
        <Route path="/backups" element={<Backups />} />
        <Route path="/incidents" element={<Incidents />} />
        {MENU.flatMap((g) => g.items).filter((i) => !['/approvals', '/report', '/machines', '/chat', '/audit', '/team', '/incidents', '/staff', '/reports', '/backups', '/extensions', '/overview', '/collector', '/classifier', '/responder', '/review', '/config', '/guardrails'].includes(i.to)).map((i) => <Route key={i.to} path={i.to} element={<Soon />} />)}
        <Route path="*" element={<Navigate to="/approvals" replace />} />
      </Route>
    </Routes>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <SessionProvider><Gate /></SessionProvider>
    </BrowserRouter>
  )
}
