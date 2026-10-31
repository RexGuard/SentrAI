import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { SessionProvider, useSession } from './lib/session'
import Layout, { MENU } from './pages/Layout'
import SignIn from './pages/SignIn'
import Approvals from './pages/Approvals'
import Soon from './pages/Soon'

function Gate() {
  const { me, loading } = useSession()
  if (loading) return <p className="p-6 text-muted" role="status">Loading…</p>
  if (!me) return <SignIn />
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Navigate to="/approvals" replace />} />
        <Route path="/approvals" element={<Approvals />} />
        {MENU.flatMap((g) => g.items).filter((i) => i.to !== '/approvals').map((i) => <Route key={i.to} path={i.to} element={<Soon />} />)}
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
