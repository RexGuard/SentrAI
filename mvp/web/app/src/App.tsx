import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { SessionProvider, useSession } from './lib/session'
import { SimpleProvider, useSimple } from './lib/simple'
import Layout from './pages/Layout'
import SignIn from './pages/SignIn'
import Analytics from './pages/Analytics'
import Approvals from './pages/Approvals'
import Audit from './pages/Audit'
import Chat from './pages/Chat'
import Command from './pages/Command'
import Guardrails from './pages/Guardrails'
import Extensions from './pages/Extensions'
import Incidents from './pages/Incidents'
import Manager from './pages/Manager'
import MachinePage from './pages/Machine'
import Machines from './pages/Machines'
import Backups from './pages/Backups'
import { Classifier, Collector, Responder } from './pages/Pipeline'
import Overview from './pages/Overview'
import Report from './pages/Report'
import Reports from './pages/Reports'
import Routing from './pages/Routing'
import Review from './pages/Review'
import Settings from './pages/Settings'
import Staff from './pages/Staff'
import Team from './pages/Team'

function Gate() {
  const { me, loading } = useSession()
  const { simple } = useSimple()
  if (loading) return <p className="p-6 text-muted" role="status">Loading…</p>
  if (!me) return <SignIn />
  if (new URLSearchParams(location.search).has('report') && location.pathname === '/') return <Navigate to="/report" replace />  // the old /?report address
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Navigate to={simple ? '/manager' : '/command'} replace />} />
        <Route path="/manager" element={<Manager />} />
        <Route path="/command" element={<Command />} />
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
        <Route path="/analytics" element={<Analytics />} />
        <Route path="*" element={<Navigate to="/command" replace />} />
      </Route>
    </Routes>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <SessionProvider><SimpleProvider><Gate /></SimpleProvider></SessionProvider>
    </BrowserRouter>
  )
}
