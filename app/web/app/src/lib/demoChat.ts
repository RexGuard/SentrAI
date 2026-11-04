// Sentry's pregenerated answers for the demo copy (VITE_DEMO_COPY=1). The demo copy has no core and no AI key, so the
// Sentry chat plays a ready-made answer instead: a few "looking at" steps, then the text typed out word by word, just
// like a streamed answer. The answer about the live attack follows what happened (open, fixed by you, closed).
import { LIVE_ID, liveState } from './demo'

type Msg = { id: string; role: string; text: string; ts: string; operator?: string; incident?: string | null; source?: string; looked_at?: string[] }
const log: Msg[] = []
let n = 0

/** The demo chat history: only what was asked in this page (a reload starts clean). */
export const demoChatLog = () => log.slice()

function answer(question: string, incident: string | null): { text: string; looked: string[] } {
  const q = question.toLowerCase()
  const s = liveState()
  const mins = s.minutes < 2 ? 'last minute' : `last ${s.minutes} minutes`
  const aboutLive = incident === LIVE_ID || /brute|password|203\.0\.113\.45|attack|risk/.test(q)
  if (s.phase === 'open' && (aboutLive || !incident)) {
    return { looked: ['the open Critical risk', 'sign-ins on aegis-web'], text:
      `**Someone is trying to guess the admin password on your student portal (aegis-web) right now.**\n\n` +
      `In the ${mins} the address 203.0.113.45 has tried **${s.tries} wrong passwords** on the admin sign-in. None has worked yet, but it keeps going.\n\n` +
      `**How serious:** Critical. One right guess would give them the portal's admin account.\n\n` +
      `**What to do:** open the risk and press **Do the suggested fix**. That stops sign-ins from 203.0.113.45 for 2 hours, and you can undo it. ` +
      `Then ask whoever owns the admin account to change its password and turn on two-step sign-in.\n\n` +
      `I haven't blocked it myself, because your settings leave this one for a person to decide.` }
  }
  if (s.phase === 'fixed' && aboutLive) {
    return { looked: ['the Brute Force risk', 'blocked addresses'], text:
      `**It's handled.** You blocked 203.0.113.45, so it can no longer reach your student portal. It tried ${s.tries} passwords and none of them worked.\n\n` +
      `Sign-ins from that IP address stay stopped for 2 hours. If it comes back after that, I'll raise it again.\n\n` +
      `**One thing left:** ask the admin account's owner to change the password and turn on two-step sign-in, just to be safe.` }
  }
  if (s.phase === 'dismissed' && aboutLive) {
    return { looked: ['the Brute Force risk'], text:
      `You closed it as **not a threat**, so nothing was blocked. If 203.0.113.45 keeps failing to sign in, I'll raise it again so you can look twice.` }
  }
  if (s.phase === 'attacking') {
    return { looked: ['sign-ins on aegis-web'], text:
      `I'm seeing a burst of failed sign-ins on your student portal from 203.0.113.45. It isn't a risk yet, but I'm watching it. If it keeps going, it will show up as a risk for you in a few seconds.` }
  }
  if (/summar|week/.test(q)) {
    return { looked: ['this week\'s risks'], text:
      `**A quiet week.** Nothing needs a person right now. I handled the usual background noise on my own (scans and a few bad sign-ins), and every one of those blocks can be undone from the risk list.\n\nYour computers are online and protected.` }
  }
  return { looked: ['open risks', 'your computers'], text:
    `**You're safe right now.** Nothing needs a person: every risk card is at 0 and all your computers are online and protected.\n\nIf something comes up, it will appear in the Command Center and I'll explain it in plain words.` }
}

const wait = (ms: number, signal?: AbortSignal) => new Promise<void>((ok, no) => {
  const t = setTimeout(ok, ms)
  signal?.addEventListener('abort', () => { clearTimeout(t); no(new DOMException('Stopped', 'AbortError')) }, { once: true })
})

/** Plays the pregenerated answer as a stream: the same events the core sends (step, text). */
export async function demoChat(body: unknown, onEvent: (e: Record<string, unknown>) => void, signal?: AbortSignal, quick = false): Promise<void> {
  const b = (body ?? {}) as { message?: string; incident?: string | null; operator?: string }
  const question = String(b.message ?? '').trim()
  const incident = b.incident ?? null
  const ts = new Date().toISOString()
  log.push({ id: `demo-${++n}`, role: 'operator', text: question, ts, operator: b.operator ?? 'owner@example.com', incident })
  const { text, looked } = answer(question, incident)
  let sent = ''
  try {
    for (const step of ['Looking at ' + looked.join(' and '), 'Writing the answer']) { await wait(quick ? 400 : 450, signal); onEvent({ type: 'step', text: step }) }
    for (const part of text.split(/(\s+)/)) { if (!quick) await wait(part.trim() ? 28 : 0, signal); sent += part; onEvent({ type: 'text', delta: part }) }
  } finally {
    log.push({ id: `demo-${++n}`, role: 'assistant', text: signal?.aborted ? sent : text, ts: new Date().toISOString(), incident, source: 'demo', looked_at: looked })
  }
}
