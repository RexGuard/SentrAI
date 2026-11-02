// Motion helpers. Most movement uses the browser's View Transitions: the page is snapshotted, the change is made,
// and elements that share a `view-transition-name` morph from the old place to the new one (a severity card grows
// into its page and shrinks back; the ? button grows into the help panel). Browsers without it, and people who ask
// for reduced motion, get the change straight away. Popovers that open and close in place use usePresence().
import { useEffect, useState } from 'react'
import { flushSync } from 'react-dom'
import { Link, NavLink, useNavigate } from 'react-router-dom'

export const reducedMotion = () => typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches

type VT = { startViewTransition?: (cb: () => void) => unknown }

/** Run a state change inside a view transition when the browser has them. */
export function transition(update: () => void) {
  const d = document as Document & VT
  if (!d.startViewTransition || reducedMotion()) { update(); return }
  d.startViewTransition(() => flushSync(update))
}

/** A CSS-safe view-transition-name for an id such as "RSK-2026-085". */
export const vtName = (prefix: string, id: string) => `${prefix}-${id.replace(/[^a-zA-Z0-9_-]/g, '_')}`

/** Keeps a popover mounted while it closes, so it can play its closing animation. */
export function usePresence(open: boolean, ms = 160): { mounted: boolean; state: 'open' | 'closed' } {
  const [mounted, setMounted] = useState(open)
  useEffect(() => {
    if (open) { setMounted(true); return }
    if (reducedMotion()) { setMounted(false); return }
    const t = setTimeout(() => setMounted(false), ms)
    return () => clearTimeout(t)
  }, [open, ms])
  return { mounted: mounted || open, state: open ? 'open' : 'closed' }
}

const plainClick = (e: React.MouseEvent) => e.button === 0 && !e.metaKey && !e.ctrlKey && !e.shiftKey && !e.altKey

/** navigate() that animates the change of page (a view transition). */
export function useGo() {
  const navigate = useNavigate()
  return (to: string, opts?: { replace?: boolean }) => transition(() => navigate(to, opts))
}

/** <Link> that animates the change of page. Elements with the same view-transition-name morph across it. */
export function VLink({ to, onClick, ...rest }: React.ComponentProps<typeof Link> & { to: string }) {
  const go = useGo()
  return <Link to={to} {...rest} onClick={(e) => { onClick?.(e); if (!e.defaultPrevented && plainClick(e)) { e.preventDefault(); go(to) } }} />
}

/** <NavLink> that animates the change of page. */
export function VNavLink({ to, onClick, ...rest }: React.ComponentProps<typeof NavLink> & { to: string }) {
  const go = useGo()
  return <NavLink to={to} {...rest} onClick={(e) => { onClick?.(e); if (!e.defaultPrevented && plainClick(e)) { e.preventDefault(); go(to) } }} />
}
