import { Suspense, useEffect, useRef, useState } from 'react'
import { Outlet, useLocation } from 'react-router-dom'
import {
  BarChart3, Boxes, Briefcase, Eye, Gavel, LayoutDashboard, Library, DatabaseBackup, FileText, Flag, Link2, Lock, LogOut, Moon, Network,
  ScrollText, Search, Server, Settings2, ShieldCheck, Siren, Sparkles, SlidersHorizontal, Sun, UserRound, Users, Workflow, Bell as BellIcon, PanelLeftClose, PanelLeftOpen, type LucideIcon,
} from 'lucide-react'
import { api } from '../lib/api'
import { useSession } from '../lib/session'
import { useTheme } from '../lib/theme'
import Waves from '../lib/Waves'
import { transition, usePresence, useGo, VLink, VNavLink } from '../lib/motion'
import { ask } from '../lib/notice'
import { useSimple } from '../lib/simple'
import HelpDock, { useDock } from './HelpDock'
import AutoMode from './AutoMode'

type Item = { to: string; label: string; icon: LucideIcon; needs?: string }
type Group = { group: string; icon: LucideIcon; items: Item[] }

export const MENU: Group[] = [
  { group: 'Respond', icon: Gavel, items: [
    { to: '/command', label: 'Command Center', icon: LayoutDashboard },
    { to: '/staff', label: 'Staff Reports', icon: Flag },
  ] },
  { group: 'How It Works', icon: Workflow, items: [
    { to: '/overview', label: 'Overview', icon: Network },
    { to: '/collector', label: 'Log Reading', icon: Workflow },
    { to: '/classifier', label: 'Threat Detection', icon: Boxes },
    { to: '/responder', label: 'Automatic Responses', icon: ShieldCheck },
    { to: '/guardrails', label: 'Safety Limits', icon: Settings2 },
    { to: '/tuning', label: 'Fewer False Alarms', icon: SlidersHorizontal },
  ] },
  { group: 'Monitoring', icon: Eye, items: [
    { to: '/machines', label: 'Computers', icon: Server },
    { to: '/analytics', label: 'Trends', icon: BarChart3 },
    { to: '/reports', label: 'Reports', icon: FileText },
    { to: '/audit', label: 'Activity Log', icon: Link2 },
    { to: '/backups', label: 'Backups', icon: DatabaseBackup },
    { to: '/privacy', label: 'Privacy and Data', icon: Lock },
    { to: '/team', label: 'People and Access', icon: Users, needs: 'people' },
  ] },
  { group: 'Settings', icon: Settings2, items: [
    { to: '/config', label: 'Setup', icon: ScrollText },
  ] },
]

// Simple view: the pages a non-technical person needs, in everyday words. Same pages, same permissions.
export const SIMPLE_MENU: Group[] = [
  { group: 'At a Glance', icon: Briefcase, items: [
    { to: '/command', label: 'What Needs Me', icon: Siren },
  ] },
  { group: 'Records', icon: Library, items: [
    { to: '/machines', label: 'Our Computers', icon: Server },
    { to: '/reports', label: 'Reports to Share', icon: FileText },
    { to: '/backups', label: 'Backups', icon: DatabaseBackup },
    { to: '/privacy', label: 'Privacy and Staff Data', icon: Lock },
    { to: '/team', label: 'Who Has Access', icon: Users, needs: 'people' },
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
  const pop = usePresence(open)
  const out = async () => {
    setOpen(false)
    const ok = await ask({ title: 'Sign out?', body: 'Are you sure you want to sign out? You will need your password and authenticator code to come back in.', confirm: 'Sign Out', danger: true })
    if (ok !== null) void signOut()
  }
  const row = 'flex w-full items-center gap-2.5 rounded-xl px-3 py-2 text-left text-sm text-soft hover:bg-surface-3 hover:text-ink'
  return (
    <div ref={box} className="relative">
      <button className="console-avatar" aria-haspopup="menu" aria-expanded={open} aria-label={`Account: ${me?.name || me?.email || 'you'}`} onClick={() => setOpen(!open)}>
        <UserRound size={22} aria-hidden />
      </button>
      {pop.mounted && (
        <div role="menu" data-state={pop.state} className="console-pop right-0 w-64">
          <p className="truncate px-3 pb-2 pt-1 font-medium">{me?.name || me?.email}<span className="block text-xs font-normal text-muted">{me?.role_label}</span></p>
          <button role="menuitem" className={row} onClick={() => { toggleSimple(); setOpen(false) }}
            title={simple ? 'Show every page, with the technical names' : 'Fewer pages, everyday words: for people who are not in IT'}>
            <Eye size={16} aria-hidden /> {simple ? 'Full View' : 'Simple View'}
          </button>
          <button role="menuitem" className={row} onClick={() => transition(() => toggle())}>
            {theme === 'dark' ? <Sun size={16} aria-hidden /> : <Moon size={16} aria-hidden />} {theme === 'dark' ? 'White Theme' : 'Black Theme'}
          </button>
          <button role="menuitem" className={row} onClick={() => void out()}><LogOut size={16} aria-hidden /> Sign Out</button>
        </div>)}
    </div>
  )
}

// The magnifier (top right): find any page by name.
function Find({ menu }: { menu: Group[] }) {
  const [open, setOpen] = useState(false)
  const [q, setQ] = useState('')
  const go = useGo()
  const box = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!open) return
    const off = (e: MouseEvent) => { if (!box.current?.contains(e.target as Node)) setOpen(false) }
    document.addEventListener('mousedown', off)
    return () => document.removeEventListener('mousedown', off)
  }, [open])
  const pop = usePresence(open)
  const all = [{ to: '/manager', label: 'Sentry', icon: Sparkles, group: 'Sentry' }, ...menu.flatMap((g) => g.items.map((i) => ({ ...i, group: g.group })))]
  const hits = all.filter((i) => (i.label + ' ' + i.group).toLowerCase().includes(q.trim().toLowerCase())).slice(0, 8)
  const pick = (to: string) => { setOpen(false); setQ(''); go(to) }
  return (
    <div ref={box} className="relative">
      <button className="console-icon" aria-label="Find a page" aria-expanded={open} onClick={() => setOpen(!open)}><Search size={22} aria-hidden /></button>
      {pop.mounted && (
        <div data-state={pop.state} className="console-pop right-0 w-72">
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

// The bell (top right): a notification list like any website's. Every risk waiting on a person, newest first, with
// its severity and age; unread ones have a dot. "Read" is remembered in this browser only.
type Note = { id: string; incident: string; title: string; severity: 'critical' | 'high' | 'medium' | 'low'; host: string; open_for: string; overdue: boolean }
const SEEN_KEY = 'sentrai-seen-risks'
const SEV_COLOR = { critical: 'var(--card-critical)', high: 'var(--card-high)', medium: 'var(--card-medium)', low: 'var(--card-low)' }
const SEV_NAME = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' }
function readSeen(): Set<string> {
  try { return new Set(JSON.parse(localStorage.getItem(SEEN_KEY) || '[]') as string[]) } catch { return new Set() }
}
function Bell() {
  const [rows, setRows] = useState<Note[]>([])
  const [seen, setSeen] = useState<Set<string>>(readSeen)
  const [open, setOpen] = useState(false)
  const box = useRef<HTMLDivElement>(null)
  const go = useGo()
  const pop = usePresence(open)
  useEffect(() => {
    const load = async () => {
      try { setRows((await api<{ rows: Note[] }>('/ui/risks?severity=all')).rows) } catch { /* the pages show core errors */ }
    }
    void load(); const t = setInterval(() => void load(), 30000); return () => clearInterval(t)
  }, [])
  useEffect(() => {
    if (!open) return
    const off = (e: MouseEvent) => { if (!box.current?.contains(e.target as Node)) setOpen(false) }
    const esc = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(false) }
    document.addEventListener('mousedown', off); document.addEventListener('keydown', esc)
    return () => { document.removeEventListener('mousedown', off); document.removeEventListener('keydown', esc) }
  }, [open])
  const save = (next: Set<string>) => {
    // Keep only ids still on the list, so the stored set never grows without end.
    const keep = new Set([...next].filter((id) => rows.some((r) => r.id === id)))
    setSeen(keep)
    try { localStorage.setItem(SEEN_KEY, JSON.stringify([...keep])) } catch { /* private window */ }
  }
  const unread = rows.filter((r) => !seen.has(r.id)).length
  const openOne = (r: Note) => { save(new Set([...seen, r.id])); setOpen(false); go(`/risks/${r.severity}?open=${encodeURIComponent(r.id)}`) }
  return (
    <div ref={box} className="relative">
      <button className="console-icon relative" aria-haspopup="true" aria-expanded={open}
        aria-label={unread ? `Notifications: ${unread} unread` : 'Notifications'} onClick={() => setOpen(!open)}>
        <BellIcon size={22} aria-hidden />{unread > 0 && <span className="console-badge" aria-hidden>{unread > 9 ? '9+' : unread}</span>}
      </button>
      {pop.mounted && (
        <div data-state={pop.state} className="console-pop right-0 w-[23rem] max-w-[calc(100vw-2rem)] p-0">
          <div className="flex items-center justify-between gap-2 border-b border-line px-4 py-3">
            <p className="font-semibold">Notifications</p>
            <button className="text-sm text-[var(--accent-2)] hover:underline disabled:opacity-40 disabled:no-underline" disabled={!unread}
              onClick={() => save(new Set([...seen, ...rows.map((r) => r.id)]))}>Mark all as read</button>
          </div>
          {rows.length === 0 ? <p className="px-4 py-6 text-center text-sm text-muted">Nothing needs you right now.</p> : (
            <ul className="max-h-[26rem] overflow-y-auto p-1.5">
              {rows.slice(0, 30).map((r) => {
                const isNew = !seen.has(r.id)
                return (
                  <li key={r.id}>
                    <button onClick={() => openOne(r)} className={'flex w-full items-start gap-3 rounded-xl px-3 py-2.5 text-left hover:bg-surface-3' + (isNew ? '' : ' opacity-70')}>
                      <span className="mt-1.5 h-2.5 w-2.5 shrink-0 rounded-full" style={{ background: SEV_COLOR[r.severity], boxShadow: `0 0 8px ${SEV_COLOR[r.severity]}` }} aria-hidden />
                      <span className="min-w-0 flex-1">
                        <span className={'block truncate text-sm ' + (isNew ? 'font-semibold' : '')}>{r.title} on {r.host}</span>
                        <span className="block text-xs text-muted">
                          <span style={{ color: SEV_COLOR[r.severity] }}>{SEV_NAME[r.severity]}</span> · {r.overdue ? 'overdue · ' : ''}{r.open_for} ago
                        </span>
                      </span>
                      {isNew && <span className="mt-2 h-2 w-2 shrink-0 rounded-full bg-[var(--accent-2)]" aria-label="Unread" />}
                    </button>
                  </li>)
              })}
            </ul>)}
          <button className="block w-full border-t border-line px-4 py-2.5 text-center text-sm text-soft hover:text-ink" onClick={() => { setOpen(false); go('/command') }}>
            Open Command Center
          </button>
        </div>)}
    </div>
  )
}

/** Shown while a page's code loads: the shape of a page, gently shimmering. */
function PageSkeleton() {
  return (
    <div role="status" aria-label="Loading" className="space-y-6">
      <div className="skeleton h-10 w-72 rounded-xl" />
      <div className="skeleton h-5 w-[28rem] max-w-full rounded-lg" />
      <div className="grid max-w-[64rem] gap-8 sm:grid-cols-2">{[0, 1, 2, 3].map((i) => <div key={i} className="skeleton h-40 rounded-[1.25rem]" />)}</div>
    </div>
  )
}

export default function Layout() {
  const { can } = useSession()
  const dock = useDock()
  const { simple, toggle: toggleSimple } = useSimple()
  const { pathname } = useLocation()
  const go = useGo()
  const menu = simple ? SIMPLE_MENU : MENU
  const items = (g: Group) => g.items.filter((i) => !i.needs || can(i.needs))
  // A page outside every group (Chat, Report) keeps the last group picked on top.
  const [picked, setPicked] = useState(menu[0].group)
  // The side menu can be hidden for more room (the button left of the logo); remembered in this browser.
  const [sideHidden, setSideHidden] = useState(() => { try { return localStorage.getItem('sentrai-side-hidden') === '1' } catch { return false } })
  const toggleSide = () => setSideHidden((h) => { try { localStorage.setItem('sentrai-side-hidden', h ? '0' : '1') } catch { /* private window */ } return !h })
  const current = groupOf(menu, pathname) ?? menu.find((g) => g.group === picked) ?? menu[0]
  // Where we are, for the direction of the slide: Sentry sits above the groups (-1).
  const onSentry = pathname.startsWith('/manager')
  const groupIndex = onSentry ? -1 : menu.indexOf(current)
  const tabIndex = items(current).findIndex((i) => pathname === i.to || pathname.startsWith(i.to + '/'))
  const tabSlide = (i: number) => (tabIndex < 0 || i === tabIndex ? undefined : { dir: i > tabIndex ? 'left' : 'right', steps: Math.abs(i - tabIndex) } as const)
  return (
    <>
    <Waves />
    <div className={'console-shell min-h-screen' + (sideHidden ? ' side-hidden' : '')}>
      <header className="console-top">
        <button className="console-icon side-toggle" onClick={toggleSide} aria-expanded={!sideHidden} aria-controls="console-side"
          aria-label={sideHidden ? 'Show the side menu' : 'Hide the side menu'} title={sideHidden ? 'Show the side menu' : 'Hide the side menu'}>
          {sideHidden ? <PanelLeftOpen size={20} aria-hidden /> : <PanelLeftClose size={20} aria-hidden />}
        </button>
        <VLink to="/" className="console-logo" aria-label="SentrAI home">
          <img src={import.meta.env.BASE_URL + "mark.svg"} alt="" width={52} height={52} className="console-brand-mark" />
          <span className="leading-tight"><span className="console-brand block">SentrAI</span><span className="block text-[0.8125rem] text-soft">Cybersecurity Console</span></span>
        </VLink>
        <nav aria-label={current.group} className={'console-topnav' + (items(current).length > 4 ? ' is-many' : '')}>
          {!onSentry && items(current).map(({ to, label, icon: Icon }, i) => (
            <VNavLink key={to} to={to} slide={tabSlide(i)}
              className={({ isActive }) => 'topnav flex shrink-0 items-center gap-2.5 rounded-2xl px-5 py-2.5 text-base font-medium ' + (isActive || groupOf([{ ...current, items: [{ to, label, icon: Icon }] }], pathname) ? 'topnav-on' : 'text-soft hover:text-ink')}>
              <Icon size={20} aria-hidden /> {label}
            </VNavLink>))}
        </nav>
        <div className="flex shrink-0 items-center gap-4 pr-2">
          <Find menu={menu} />
          <Bell />
          <Account simple={simple} toggleSimple={toggleSimple} />
        </div>
      </header>
      <div className="flex">
        <aside id="console-side" className="console-side" inert={sideHidden}>
          <nav aria-label="Sections" className="flex flex-col gap-3">
            <VNavLink to="/manager" slide={{ dir: 'down', steps: groupIndex + 1 }} className={({ isActive }) => 'flex items-center gap-3.5 rounded-2xl px-4 py-3 text-left text-[0.9375rem] font-medium ' + (isActive ? 'side-on' : 'text-soft hover:text-ink')}>
              <Sparkles size={20} aria-hidden /> Sentry
            </VNavLink>
            {menu.map((g) => {
              const on = !onSentry && g.group === current?.group
              const gi = menu.indexOf(g)
              return (
                <button key={g.group} aria-current={on ? 'true' : undefined} onClick={() => {
                  setPicked(g.group); const first = items(g)[0]
                  // Further down the menu the new page rises from below; further up, it drops in from above.
                  if (first) go(first.to, { slide: { dir: gi > groupIndex ? 'up' : 'down', steps: Math.abs(gi - groupIndex) } })
                }}
                  className={'flex items-center gap-3.5 rounded-2xl px-4 py-3 text-left text-[0.9375rem] font-medium ' + (on ? 'side-on' : 'text-soft hover:text-ink')}>
                  <g.icon size={20} aria-hidden /> {g.group}
                </button>)
            })}
          </nav>
          <div className="console-auto"><AutoMode /></div>
        </aside>
        <main className={'console-main min-w-0 flex-1' + (dock.open ? ' lg:mr-[26rem]' : '')}>
          {/* A new page rises in (keyed by path); a menu slide moves it instead. */}
          <div key={pathname} className={document.documentElement.dataset.slide ? undefined : 'page-in'}><Suspense fallback={<PageSkeleton />}><Outlet /></Suspense></div>
        </main>
      </div>
      <HelpDock dock={dock} />
    </div>
    </>
  )
}
