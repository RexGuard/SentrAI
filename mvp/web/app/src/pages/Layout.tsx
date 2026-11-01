import { NavLink, Outlet } from 'react-router-dom'
import {
  BarChart3, Boxes, Briefcase, Eye, ClipboardCheck, LayoutDashboard, DatabaseBackup, FileText, Flag, Gauge, Link2, LogOut, Moon, Network,
  Puzzle, ScrollText, Server, Settings2, ShieldCheck, Siren, SlidersHorizontal, Sun, Users, Workflow, type LucideIcon,
} from 'lucide-react'
import { useSession } from '../lib/session'
import { useTheme } from '../lib/theme'
import { useSimple } from '../lib/simple'
import HelpDock, { useDock } from './HelpDock'
import AutoMode from './AutoMode'

type Item = { to: string; label: string; icon: LucideIcon; needs?: string }

export const MENU: { group: string; items: Item[] }[] = [
  { group: 'Decide', items: [
    { to: '/manager', label: 'Manager view', icon: Briefcase },
    { to: '/command', label: 'Command center', icon: LayoutDashboard },
    { to: '/approvals', label: 'Approvals', icon: ClipboardCheck },
    { to: '/incidents', label: 'Incidents', icon: Siren },
    { to: '/staff', label: 'Staff reports', icon: Flag },
  ] },
  { group: 'Pipeline', items: [
    { to: '/overview', label: 'Overview', icon: Network },
    { to: '/collector', label: 'Collector', icon: Workflow },
    { to: '/classifier', label: 'Classifier', icon: Boxes },
    { to: '/responder', label: 'Action taker', icon: ShieldCheck },
    { to: '/guardrails', label: 'Automation guardrails', icon: Settings2 },
    { to: '/tuning', label: 'Tuning', icon: SlidersHorizontal },
  ] },
  { group: 'Oversight', items: [
    { to: '/machines', label: 'Machines', icon: Server },
    { to: '/review', label: 'Review', icon: Gauge },
    { to: '/analytics', label: 'Analytics', icon: BarChart3 },
    { to: '/reports', label: 'Reports', icon: FileText },
    { to: '/audit', label: 'Audit trail', icon: Link2 },
    { to: '/backups', label: 'Backups', icon: DatabaseBackup },
    { to: '/team', label: 'Team', icon: Users, needs: 'people' },
  ] },
  { group: 'Settings', items: [
    { to: '/extensions', label: 'Extensions', icon: Puzzle },
    { to: '/config', label: 'Configuration', icon: ScrollText },
  ] },
]

// Simple view: the pages a non-technical person needs, in everyday words. Same pages, same permissions.
export const SIMPLE_MENU: { group: string; items: Item[] }[] = [
  { group: 'At a glance', items: [
    { to: '/manager', label: 'Are we safe?', icon: Briefcase },
    { to: '/approvals', label: 'Waiting for my OK', icon: ClipboardCheck },
    { to: '/incidents', label: 'Problems found', icon: Siren },
  ] },
  { group: 'Records', items: [
    { to: '/machines', label: 'Our computers', icon: Server },
    { to: '/reports', label: 'Reports to share', icon: FileText },
    { to: '/backups', label: 'Backups', icon: DatabaseBackup },
    { to: '/team', label: 'Who has access', icon: Users, needs: 'people' },
  ] },
]

const side = 'flex flex-1 items-center justify-center gap-1 rounded-md border border-line px-2 py-1.5 text-soft hover:bg-surface-2'

export default function Layout() {
  const { me, signOut, can } = useSession()
  const [theme, toggle] = useTheme()
  const dock = useDock()
  const { simple, toggle: toggleSimple } = useSimple()
  return (
    <div className="flex min-h-screen">
      <aside className="sticky top-0 flex h-screen w-60 shrink-0 flex-col gap-4 overflow-y-auto border-r border-line bg-sidebar p-3">
        <div className="flex items-center gap-2 px-2 py-1">
          <img src="/mark.svg" alt="" width={24} height={24} />
          <span className="font-semibold">SentrAI</span>
        </div>
        <nav aria-label="Main" className="flex flex-1 flex-col gap-4">
          {(simple ? SIMPLE_MENU : MENU).map((g) => (
            <div key={g.group}>
              <p className="px-2 pb-1 text-xs uppercase tracking-wide text-muted">{g.group}</p>
              {g.items.filter((i) => !i.needs || can(i.needs)).map(({ to, label, icon: Icon }) => (
                <NavLink
                  key={to}
                  to={to}
                  className={({ isActive }) =>
                    'flex items-center gap-2 rounded-md px-2 py-1.5 text-sm ' +
                    (isActive ? 'bg-surface-3 text-ink' : 'text-soft hover:bg-surface-2')}
                >
                  <Icon size={16} aria-hidden /> {label}
                </NavLink>
              ))}
            </div>
          ))}
        </nav>
        <div className="space-y-2 border-t border-line pt-3 text-sm">
          <p className="truncate px-2 text-soft">
            {me?.name || me?.email}
            <span className="block text-xs text-muted">{me?.role_label}</span>
          </p>
          <button onClick={toggleSimple} className={side + ' w-full'} aria-pressed={simple}
            title={simple ? 'Show every page, with the technical names' : 'Fewer pages, everyday words: for people who are not in IT'}>
            <Eye size={14} aria-hidden /> {simple ? 'Full view' : 'Simple view'}
          </button>
          <div className="flex gap-2">
            <button onClick={toggle} className={side}>
              {theme === 'dark' ? <Sun size={14} aria-hidden /> : <Moon size={14} aria-hidden />}
              {theme === 'dark' ? 'White' : 'Black'}
            </button>
            <button onClick={() => void signOut()} className={side}>
              <LogOut size={14} aria-hidden /> Sign out
            </button>
          </div>
        </div>
      </aside>
      <main className={'min-w-0 flex-1 p-6 pb-20' + (dock.open ? ' lg:mr-[26rem]' : '')}><div className="mb-3"><AutoMode /></div><Outlet /></main>
      <HelpDock dock={dock} />
    </div>
  )
}
