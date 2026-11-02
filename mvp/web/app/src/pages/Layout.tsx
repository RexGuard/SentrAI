import { Suspense, useEffect, useRef, useState } from 'react'
import { Link, NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom'
import {
  BarChart3, Boxes, Briefcase, Eye, Gavel, LayoutDashboard, Library, DatabaseBackup, FileText, Flag, Link2, Lock, LogOut, Moon, Network,
  Puzzle, ScrollText, Search, Server, Settings2, ShieldCheck, Siren, SlidersHorizontal, Sun, UserRound, Users, Workflow, Bell as BellIcon, type LucideIcon,
} from 'lucide-react'
import { api } from '../lib/api'
import { useSession } from '../lib/session'
import { useTheme } from '../lib/theme'
import Waves from '../lib/Waves'
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

// The account menu behind the avatar (top right): who is signed in, Simple view, Black/White, sign out.
function Account({ simple, toggleSimple }: { simple: boolean; toggleSimple: () => void }) {
  const { me, signOut } = useSession()
  const [theme, toggle] = useTheme()
  const [open, setOpen] = useState(false)
  const box = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!open) return
    const off = (e: MouseEvent) => { if (!box.current?.contains(e.target as Node)) setOpen(false) }
    const esc = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(false) }
    document.addEventListener('mousedown', off); document.addEventListener('keydown', esc)
    return () => { document.removeEventListener('mousedown', off); document.removeEventListener('keydown', esc) }
  }, [open])
  const row = 'flex w-full items-center gap-2.5 rounded-xl px-3 py-2 text-left text-sm text-soft hover:bg-surface-3 hover:text-ink'
  return (
    <div ref={box} className="relative">
      <button className="console-avatar" aria-haspopup="menu" aria-expanded={open} aria-label={`Account: ${me?.name || me?.email || 'you'}`} onClick={() => setOpen(!open)}>
        <UserRound size={22} aria-hidden />
      </button>
      {open && (
        <div role="menu" className="console-pop right-0 w-64">
          <p className="truncate px-3 pb-2 pt-1 font-medium">{me?.name || me?.email}<span className="block text-xs font-normal text-muted">{me?.role_label}</span></p>
          <button role="menuitem" className={row} onClick={() => { toggleSimple(); setOpen(false) }}
            title={simple ? 'Show every page, with the technical names' : 'Fewer pages, everyday words: for people who are not in IT'}>
            <Eye size={16} aria-hidden /> {simple ? 'Full view' : 'Simple view'}
          </button>
          <button role="menuitem" className={row} onClick={() => toggle()}>
            {theme === 'dark' ? <Sun size={16} aria-hidden /> : <Moon size={16} aria-hidden />} {theme === 'dark' ? 'White theme' : 'Black theme'}
          </button>
          <button role="menuitem" className={row} onClick={() => void signOut()}><LogOut size={16} aria-hidden /> Sign out</button>
        </div>)}
    </div>
  )
}

// The magnifier (top right): find any page by name.
function Find({ menu }: { menu: Group[] }) {
  const [open, setOpen] = useState(false)
  const [q, setQ] = useState('')
  const go = useNavigate()
  const box = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!open) return
    const off = (e: MouseEvent) => { if (!box.current?.contains(e.target as Node)) setOpen(false) }
    document.addEventListener('mousedown', off)
    return () => document.removeEventListener('mousedown', off)
  }, [open])
  const all = menu.flatMap((g) => g.items.map((i) => ({ ...i, group: g.group })))
  const hits = all.filter((i) => (i.label + ' ' + i.group).toLowerCase().includes(q.trim().toLowerCase())).slice(0, 8)
  const pick = (to: string) => { setOpen(false); setQ(''); go(to) }
  return (
    <div ref={box} className="relative">
      <button className="console-icon" aria-label="Find a page" aria-expanded={open} onClick={() => setOpen(!open)}><Search size={22} aria-hidden /></button>
      {open && (
        <div className="console-pop right-0 w-72">
          <input autoFocus value={q} onChange={(e) => setQ(e.target.value)} placeholder="Find a page…" aria-label="Find a page"
            onKeyDown={(e) => { if (e.key === 'Enter' && hits[0]) pick(hits[0].to); if (e.key === 'Escape') setOpen(false) }}
            className="mb-1 w-full rounded-xl border border-line bg-surface-2 px-3 py-2 text-sm outline-none focus:border-[var(--accent-2)]" />
          {hits.length === 0 ? <p className="px-3 py-2 text-sm text-muted">No page by that name.</p> : hits.map((i) => (
            <button key={i.to} className="flex w-full items-center gap-2.5 rounded-xl px-3 py-2 text-left text-sm text-soft hover:bg-surface-3 hover:text-ink" onClick={() => pick(i.to)}>
              <i.icon size={16} aria-hidden /> {i.label} <span className="ml-auto text-xs text-muted">{i.group}</span>
            </button>))}
        </div>)}
    </div>
  )
}

// The bell (top right): opens the Command center; the dot means something Critical or High needs a person.
function Bell() {
  const [hot, setHot] = useState(0)
  useEffect(() => {
    const load = async () => {
      try {
        const r = await api<{ levels: { severity: string; count: number }[] }>('/ui/risks')
        setHot(r.levels.filter((l) => l.severity === 'critical' || l.severity === 'high').reduce((n, l) => n + l.count, 0))
      } catch { /* the pages show core errors */ }
    }
    void load(); const t = setInterval(() => void load(), 30000); return () => clearInterval(t)
  }, [])
  return (
    <Link to="/command" className="console-icon relative" aria-label={hot ? `${hot} critical or high risks need a person` : 'Nothing urgent'}>
      <BellIcon size={22} aria-hidden />{hot > 0 && <span className="console-dot" aria-hidden />}
    </Link>
  )
}

export default function Layout() {
  const { can } = useSession()
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
    <>
    <Waves />
    <div className="console-shell min-h-screen">
      <header className="console-top">
        <Link to="/" className="console-logo" aria-label="SentrAI home">
          <img src="/mark.svg" alt="" width={52} height={52} className="console-brand-mark" />
          <span className="leading-tight"><span className="console-brand block">SentrAI</span><span className="block text-[0.8125rem] text-soft">Cybersecurity Console</span></span>
        </Link>
        <nav aria-label={current.group} className={'console-topnav' + (items(current).length > 4 ? ' is-many' : '')}>
          {items(current).map(({ to, label, icon: Icon }) => (
            <NavLink key={to} to={to}
              className={({ isActive }) => 'topnav flex shrink-0 items-center gap-2.5 rounded-2xl px-5 py-2.5 text-base font-medium ' + (isActive || groupOf([{ ...current, items: [{ to, label, icon: Icon }] }], pathname) ? 'topnav-on' : 'text-soft hover:text-ink')}>
              <Icon size={20} aria-hidden /> {label}
            </NavLink>))}
        </nav>
        <div className="flex shrink-0 items-center gap-4 pr-2">
          <Find menu={menu} />
          <Bell />
          <Account simple={simple} toggleSimple={toggleSimple} />
        </div>
      </header>
      <div className="flex">
        <aside className="console-side">
          <nav aria-label="Sections" className="flex flex-col gap-3">
            {menu.map((g) => {
              const on = g.group === current?.group
              return (
                <button key={g.group} aria-current={on ? 'true' : undefined} onClick={() => { setPicked(g.group); const first = items(g)[0]; if (first) go(first.to) }}
                  className={'flex items-center gap-3.5 rounded-2xl px-4 py-3 text-left text-[0.9375rem] font-medium ' + (on ? 'side-on' : 'text-soft hover:text-ink')}>
                  <g.icon size={20} aria-hidden /> {g.group}
                </button>)
            })}
          </nav>
          <div className="console-auto"><AutoMode /></div>
        </aside>
        <main className={'console-main min-w-0 flex-1' + (dock.open ? ' lg:mr-[26rem]' : '')}>
          <Suspense fallback={<p className="text-muted" role="status">Loading…</p>}><Outlet /></Suspense>
        </main>
      </div>
      <HelpDock dock={dock} />
    </div>
    </>
  )
}
