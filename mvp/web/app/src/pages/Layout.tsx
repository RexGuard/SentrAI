import { Suspense, useState } from 'react'
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom'
import {
  BarChart3, Boxes, Briefcase, Eye, Gavel, LayoutDashboard, Library, DatabaseBackup, FileText, Flag, Link2, Lock, LogOut, Moon, Network,
  Puzzle, ScrollText, Server, Settings2, ShieldCheck, Siren, SlidersHorizontal, Sun, Users, Workflow, type LucideIcon,
} from 'lucide-react'
import { useSession } from '../lib/session'
import { useTheme } from '../lib/theme'
import { useSimple } from '../lib/simple'
import HelpDock, { useDock } from './HelpDock'
import AutoMode from './AutoMode'

type Item = { to: string; label: string; icon: LucideIcon; needs?: string }
type Group = { group: string; icon: LucideIcon; items: Item[] }

export const MENU: Group[] = [
  { group: 'Decide', icon: Gavel, items: [
    { to: '/manager', label: 'Manager view', icon: Briefcase },
    { to: '/command', label: 'Command center', icon: LayoutDashboard },
    { to: '/staff', label: 'Staff reports', icon: Flag },
  ] },
  { group: 'Pipeline', icon: Workflow, items: [
    { to: '/overview', label: 'Overview', icon: Network },
    { to: '/collector', label: 'Collector', icon: Workflow },
    { to: '/classifier', label: 'Classifier', icon: Boxes },
    { to: '/responder', label: 'Action taker', icon: ShieldCheck },
    { to: '/guardrails', label: 'Automation guardrails', icon: Settings2 },
    { to: '/tuning', label: 'Tuning', icon: SlidersHorizontal },
  ] },
  { group: 'Oversight', icon: Eye, items: [
    { to: '/machines', label: 'Machines', icon: Server },
    { to: '/analytics', label: 'Analytics', icon: BarChart3 },
    { to: '/reports', label: 'Reports', icon: FileText },
    { to: '/audit', label: 'Audit trail', icon: Link2 },
    { to: '/backups', label: 'Backups', icon: DatabaseBackup },
    { to: '/privacy', label: 'Privacy and data', icon: Lock },
    { to: '/team', label: 'Team', icon: Users, needs: 'people' },
  ] },
  { group: 'Settings', icon: Settings2, items: [
    { to: '/extensions', label: 'Extensions', icon: Puzzle },
    { to: '/config', label: 'Configuration', icon: ScrollText },
  ] },
]

// Simple view: the pages a non-technical person needs, in everyday words. Same pages, same permissions.
export const SIMPLE_MENU: Group[] = [
  { group: 'At a glance', icon: Briefcase, items: [
    { to: '/manager', label: 'Are we safe?', icon: Briefcase },
    { to: '/command', label: 'What needs me', icon: Siren },
  ] },
  { group: 'Records', icon: Library, items: [
    { to: '/machines', label: 'Our computers', icon: Server },
    { to: '/reports', label: 'Reports to share', icon: FileText },
    { to: '/backups', label: 'Backups', icon: DatabaseBackup },
    { to: '/privacy', label: 'Privacy and staff data', icon: Lock },
    { to: '/team', label: 'Who has access', icon: Users, needs: 'people' },
  ] },
]

// Pages reached from inside another page belong to the group of the page that leads there.
const HOME: [string, string][] = [['/risks', '/command'], ['/machines/', '/machines'], ['/routing', '/command']]

/** The group the current page is in: the sidebar marks it and the top bar shows its pages as tabs. */
function groupOf(menu: Group[], path: string): Group | undefined {
  const base = HOME.find(([p]) => path.startsWith(p))?.[1] ?? path
  return menu.find((g) => g.items.some((i) => base === i.to || base.startsWith(i.to + '/')))
}

const side = 'flex flex-1 items-center justify-center gap-1 rounded-md border border-line px-2 py-1.5 text-soft hover:bg-surface-2'

export default function Layout() {
  const { me, signOut, can } = useSession()
  const [theme, toggle] = useTheme()
  const dock = useDock()
  const { simple, toggle: toggleSimple } = useSimple()
  const { pathname } = useLocation()
  const go = useNavigate()
  const menu = simple ? SIMPLE_MENU : MENU
  const items = (g: Group) => g.items.filter((i) => !i.needs || can(i.needs))
  // A page outside every group (Chat, Report) keeps the last group picked on top.
  const [picked, setPicked] = useState(menu[0].group)
  const current = groupOf(menu, pathname) ?? menu.find((g) => g.group === picked) ?? menu[0]
  return (
    <div className="flex min-h-screen">
      <aside className="sticky top-0 flex h-screen w-60 shrink-0 flex-col gap-4 overflow-y-auto border-r border-line bg-sidebar p-3">
        <div className="flex items-center gap-2 px-2 py-1">
          <img src="/mark.svg" alt="" width={24} height={24} />
          <span className="font-semibold">SentrAI</span>
        </div>
        <nav aria-label="Sections" className="flex flex-1 flex-col gap-1">
          {menu.map((g) => {
            const on = g.group === current?.group
            return (
              <button key={g.group} aria-current={on ? 'true' : undefined} onClick={() => { setPicked(g.group); const first = items(g)[0]; if (first) go(first.to) }}
                className={'flex items-center gap-2.5 rounded-lg px-3 py-2.5 text-left text-sm font-medium ' + (on ? 'side-on' : 'text-soft hover:bg-surface-2')}>
                <g.icon size={18} aria-hidden /> {g.group}
              </button>)
          })}
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
      <main className={'min-w-0 flex-1 p-6 pb-20' + (dock.open ? ' lg:mr-[26rem]' : '')}>
        <div className="mb-4 flex flex-wrap items-center gap-3 border-b border-line pb-3">
          <nav aria-label={current.group} className="flex min-w-0 flex-1 flex-wrap gap-1">
            {items(current).map(({ to, label, icon: Icon }) => (
              <NavLink key={to} to={to}
                className={({ isActive }) => 'topnav flex items-center gap-2 rounded-xl px-3 py-2 text-sm ' + (isActive || groupOf([{ ...current, items: [{ to, label, icon: Icon }] }], pathname) ? 'topnav-on text-ink' : 'text-soft hover:bg-surface-2 hover:text-ink')}>
                <Icon size={16} aria-hidden /> {label}
              </NavLink>))}
          </nav>
          <AutoMode />
        </div><Suspense fallback={<p className="text-muted" role="status">Loading…</p>}><Outlet /></Suspense></main>
      <HelpDock dock={dock} />
    </div>
  )
}
