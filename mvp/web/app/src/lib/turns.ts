// A chat as turns: each question with the answers that follow it. Each turn is its own block, so the question can
// stick to the top of the chat while its answer scrolls by (CSS .chat-stick), and the next question takes its place.
import type { MouseEvent } from 'react'

export function turns<T extends { role: string }>(list: T[]): { m: T; n: number }[][] {
  const out: { m: T; n: number }[][] = []
  list.forEach((m, n) => {
    if (m.role === 'operator' || !out.length) out.push([])
    out[out.length - 1].push({ m, n })
  })
  return out
}

/** Clicking a stuck question scrolls back to where it was asked. */
export function backToQuestion(e: MouseEvent<HTMLElement>) {
  if ((e.target as HTMLElement).closest('button, a, input, textarea')) return
  e.currentTarget.closest('[data-turn]')?.scrollIntoView({ block: 'start', behavior: 'smooth' })
}
