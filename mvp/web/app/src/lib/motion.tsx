// Motion helpers. Most movement uses the browser's View Transitions: the page is snapshotted, the change is made,
// and elements that share a `view-transition-name` morph from the old place to the new one (a severity card grows
// into its page and shrinks back; the ? button grows into the help panel). Browsers without it, and people who ask
// for reduced motion, get the change straight away. Popovers that open and close in place use usePresence().
import { useEffect, useState } from 'react'
import { flushSync } from 'react-dom'
import { Link, NavLink, useNavigate } from 'react-router-dom'

export const reducedMotion = () => typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches

type VT = { startViewTransition?: (cb: () => void) => { finished: Promise<void> } }

/** Which way the page moves through the menus: sidebar "stack" (up = new page rises from below, down = from above), top tabs "push" (left = new page comes from the right). */
export type Slide = { dir: 'up' | 'down' | 'left' | 'right'; steps: number }

/** Run a state change inside a view transition when the browser has them. With `slide`, the content panel
 *  (named "page" only for the length of the transition) moves that way; steps 0 (the same place) means no slide. */
export function transition(update: () => void, slide?: Slide) {
  const d = document as Document & VT
  if (!d.startViewTransition || reducedMotion()) { update(); return }
  const root = document.documentElement
  if (slide && slide.steps > 0) {
    root.dataset.slide = slide.dir
    root.style.setProperty('--slide-steps', String(Math.min(slide.steps, 4)))
  }
  const vt = d.startViewTransition(async () => {
    flushSync(update)
    // Let the new page's first effects run, then give any data it asked to wait for (holdTransition) a moment
    // to arrive, so the page slides in already filled instead of sliding in empty and then popping its content.
    await tick()
    const waits = held.splice(0)
    if (waits.length) {
      await Promise.race([Promise.allSettled(waits), new Promise((r) => setTimeout(r, 450))])
      await tick(); await tick()
    }
  })
  if (slide) void vt.finished.finally(() => { delete root.dataset.slide; root.style.removeProperty('--slide-steps') })
}

const held: Promise<unknown>[] = []
const tick = () => new Promise((r) => setTimeout(r, 0))

/** Called by a page while it loads what it shows first: a page change in progress waits (briefly) for it. */
export function holdTransition<T>(p: Promise<T>): Promise<T> { held.push(p); return p }

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
  return (to: string, opts?: { replace?: boolean; slide?: Slide }) => transition(() => navigate(to, { replace: opts?.replace }), opts?.slide)
}

/** <Link> that animates the change of page. Elements with the same view-transition-name morph across it. */
export function VLink({ to, onClick, ...rest }: React.ComponentProps<typeof Link> & { to: string }) {
  const go = useGo()
  return <Link to={to} {...rest} onClick={(e) => { onClick?.(e); if (!e.defaultPrevented && plainClick(e)) { e.preventDefault(); go(to) } }} />
}

/** <NavLink> that animates the change of page. */
export function VNavLink({ to, onClick, slide, ...rest }: React.ComponentProps<typeof NavLink> & { to: string; slide?: Slide }) {
  const go = useGo()
  return <NavLink to={to} {...rest} onClick={(e) => { onClick?.(e); if (!e.defaultPrevented && plainClick(e)) { e.preventDefault(); go(to, { slide }) } }} />
}
