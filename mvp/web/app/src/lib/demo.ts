// The "demo copy" build (VITE_DEMO_COPY=1, see mvp/web/demo-copy/README.md): the whole console runs in the browser
// from a snapshot of made-up demo data, with no core, no sign-in and nothing saved. Its only job is to let people
// (and tools that record the screen) look around every page. A normal build never sets the flag, so none of this runs.
export const DEMO = import.meta.env.VITE_DEMO_COPY === '1'
export const DEMO_READ_ONLY = 'This is a demo copy with made-up data, so changes are not saved.'

type Snapshot = Record<string, unknown>
let snap: Promise<Snapshot> | null = null
const load = () => (snap ??= fetch(import.meta.env.BASE_URL + 'snapshot.json').then((r) => r.json() as Promise<Snapshot>))

const bare = (p: string) => p.split('?')[0]

/** The recorded answer for a GET: the exact address, else the same address with other query values, else null. */
export async function demoGet(path: string): Promise<unknown> {
  const s = await load()
  if (path in s) return s[path]
  const base = bare(path)
  if (base in s) return s[base]
  const near = Object.keys(s).find((k) => bare(k) === base)
  return near ? s[near] : null
}

// ---- Live attack (demo copy only) -------------------------------------------------------------------------------
// The attacker window of the one-button demo (RexGuard/SentrAI-demo, demo-site/attack.html) sends "launch" over a
// BroadcastChannel (with a localStorage fallback) in the same browser. The demo copy then plays a password-guessing
// attack on aegis-web: a Critical "Brute Force" risk appears that SentrAI does NOT block on its own, so the manager
// can press "Do the suggested fix" themselves. Addresses are documentation-only. The pages also talk through a small
// public relay (see relaySend) so the attacker can be on another device.
export const LIVE_ID = 'RSK-2026-099'
const ATTACKER = '203.0.113.45'
const WORDS = ['password', 'admin123', 'letmein', 'qwerty', 'P@ssw0rd', 'welcome1', 'aegis2024', 'changeme', 'root', '12345678', 'student', 'admin']
type Phase = 'idle' | 'attacking' | 'open' | 'fixed' | 'dismissed'
let phase: Phase = 'idle'
let tries = 0
let openedAt = 0
let timers: ReturnType<typeof setTimeout>[] = []
const listeners = new Set<() => void>()
const seen = new Set<string>()
let bc: BroadcastChannel | null = null

/** Calls `fn` whenever the live attack changes what the pages should show; returns the unsubscribe. */
export function onDemoChange(fn: () => void): () => void {
  if (!DEMO) return () => {}
  listeners.add(fn)
  return () => { listeners.delete(fn) }
}
const changed = () => listeners.forEach((fn) => fn())

// Cross-device relay: the attacker page and this panel can be on different devices. Both subscribe to the same
// public ntfy.sh topic, named by a room code (?room=... on either page, default below). Only a handful of small
// state messages go over it per run (no attempts: the attacker page plays those itself), so the free rate limits hold.
const RELAY = 'https://ntfy.sh/'
const DEFAULT_ROOM = 'solid10'
function roomCode(): string {
  const pick = (q: string) => new URLSearchParams(q).get('room')
  const fromUrl = pick(window.location.search) ?? pick(window.location.hash.split('?')[1] ?? '')
  const clean = (v: string | null) => (v ?? '').toLowerCase().replace(/[^a-z0-9-]/g, '').slice(0, 32)
  if (clean(fromUrl)) { try { localStorage.setItem('sentrai-demo-room', clean(fromUrl)) } catch { /* private window */ } return clean(fromUrl) }
  try { return clean(localStorage.getItem('sentrai-demo-room')) || DEFAULT_ROOM } catch { return DEFAULT_ROOM }
}
let topic = ''
function relaySend(m: Record<string, unknown>) {
  if (!topic || m.type === 'attempt') return
  fetch(RELAY + topic, { method: 'POST', body: JSON.stringify(m) }).catch(() => { /* offline: same-browser path still works */ })
}
function relayListen() {
  if (typeof EventSource === 'undefined') return
  try {
    const es = new EventSource(`${RELAY}${topic}/sse`)
    es.onmessage = (e) => {
      try {
        const n = JSON.parse(e.data) as { event?: string; message?: string }
        if (n.event === 'message' && n.message) onMsg(JSON.parse(n.message))
      } catch { /* not ours */ }
    }
  } catch { /* blocked */ }
}

function send(msg: Record<string, unknown>) {
  const m = { ...msg, id: `${Date.now()}-${Math.random()}` }
  seen.add(m.id)
  try { bc?.postMessage(m) } catch { /* closed */ }
  try { localStorage.setItem('sentrai-demo-msg', JSON.stringify(m)) } catch { /* private window */ }
  relaySend(m)
}
function stopTimers() { timers.forEach(clearTimeout); timers = [] }
function after(ms: number, fn: () => void) { timers.push(setTimeout(fn, ms)) }

function attempt() {
  if (phase !== 'attacking' && phase !== 'open') return
  tries += 1
  send({ type: 'attempt', n: tries, pw: WORDS[(tries - 1) % WORDS.length] })
  if (tries === 12) { phase = 'open'; openedAt = Date.now(); changed() }
  if (tries < 80) after(tries < 12 ? 450 : 1500, attempt)  // a burst, then it keeps trying until someone stops it
}
function launch() {
  stopTimers(); phase = 'attacking'; tries = 0; changed()
  send({ type: 'started' })
  after(600, attempt)
}
function reset() { stopTimers(); phase = 'idle'; tries = 0; changed(); send({ type: 'reset-done' }) }

function onMsg(m: { type?: string; id?: string } | null) {
  if (!m || !m.type || !m.id || seen.has(m.id)) return
  seen.add(m.id)
  if (m.type === 'launch' && phase !== 'attacking' && phase !== 'open') launch()
  if (m.type === 'reset') reset()
  if (m.type === 'hello') send({ type: 'here', running: phase === 'attacking' || phase === 'open', target: 'panel' })
}
if (DEMO && typeof window !== 'undefined') {
  try { bc = new BroadcastChannel('sentrai-demo'); bc.onmessage = (e) => onMsg(e.data) } catch { bc = null }
  window.addEventListener('storage', (e) => {
    if (e.key !== 'sentrai-demo-msg' || !e.newValue) return
    try { onMsg(JSON.parse(e.newValue)) } catch { /* not ours */ }
  })
  topic = `sentrai-demo-${roomCode()}`
  relayListen()
}

function liveRisk() {
  const mins = Math.max(1, Math.round((Date.now() - openedAt) / 60000))
  return {
    id: LIVE_ID, ids: [LIVE_ID], wave: '', incident: LIVE_ID, title: 'Brute Force', category: 'brute_force', severity: 'critical',
    host: 'aegis-web', source: ATTACKER, owner: 'On-duty responder', open_for: mins < 2 ? 'just now' : `${mins} min`, hours: 0,
    overdue: false, status: 'open', acked: false, needs: ['Decide what to do'],
    what_happened: `${ATTACKER} kept trying wrong passwords for the 'admin' account on aegis-web, ${tries} times so far, and is still trying.`,
    meaning: 'Someone is guessing passwords to get into an account. If they guess right, they are in.',
    fix: 'Block the IP address mentioned above and stop sign-ins from that IP address for 2 hours, so that they cannot keep guessing ' +
      'passwords. Then ask the account owner to change their password.',
    steps: [], unsure: false,
    actions: [
      { verb: 'approve', label: 'Do the suggested fix', hint: 'Blocks the address and stops sign-ins from it for 2 hours. Written to the audit log.' },
      { verb: 'reject', label: 'Not a threat', hint: 'Closes it without acting. You say why.' },
    ],
    inc: { id: LIVE_ID, status: 'open', category: 'brute_force', acked: false, actions: [] },
  }
}
export const isLiveRisk = (id: string) => id === LIVE_ID
/** Where the live attack is, for Sentry's pregenerated answers (lib/demoChat.ts). */
export const liveState = () => ({ phase, tries, minutes: openedAt ? Math.max(1, Math.round((Date.now() - openedAt) / 60000)) : 0 })

type Lvl = { severity: string; count: number; bubbles: number; overdue: number; oldest: string }
/** The risk lists as the live demo shows them: the recorded active risks are left out (every card starts at 0, as
 *  Erick asked, so only the live attack shows up), and the live risk is added while it is open. Risks SentrAI
 *  already handled stay under "Already handled". */
function withLive(path: string, body: unknown): unknown {
  if (!body || typeof body !== 'object' || !bare(path).startsWith('/ui/risks')) return body
  const b = body as { levels?: Lvl[]; rows?: unknown[]; headline?: string }
  const sev = new URLSearchParams(path.split('?')[1] ?? '').get('severity')
  const on = phase === 'open'
  const levels = (b.levels ?? []).map((l) => (on && l.severity === 'critical'
    ? { ...l, count: 1, bubbles: 1, overdue: 0, oldest: 'just now' } : { ...l, count: 0, bubbles: 0, overdue: 0, oldest: '' }))
  const out: Record<string, unknown> = { ...b, levels, headline: on ? '1 thing needs a person. Start with Critical.' : 'Nothing needs a person right now.' }
  if ('rows' in b || sev) out.rows = on && (sev === 'critical' || sev === 'all') ? [liveRisk()] : []
  return out
}
export async function demoGetLive(path: string): Promise<unknown> {
  const body = await demoGet(path)
  if (bare(path) === '/chat' && body && typeof body === 'object') {  // Sentry's answers come from lib/demoChat.ts
    const { demoChatLog } = await import('./demoChat')
    return { ...(body as object), model: 'demo answers (pregenerated)', messages: demoChatLog() }
  }
  return withLive(path, body)
}

/** The only writes the demo copy accepts: the manager's answer to the live risk. Anything else stays read-only. */
export function demoWrite(path: string, body: unknown): { message: string; done: string[] } | null {
  if (bare(path) !== '/ui/approvals/bulk' || phase !== 'open') return null
  const b = (body ?? {}) as { verb?: string; ids?: string[] }
  if (!b.ids?.includes(LIVE_ID)) return null
  stopTimers()
  if (b.verb === 'approve') {
    phase = 'fixed'
    send({ type: 'blocked', by: 'manager' })
    after(900, () => send({ type: 'refused', wait: 4 }))
    after(1700, () => send({ type: 'refused', wait: 8 }))
    after(2400, () => send({ type: 'done', tries, by: 'manager' }))
    changed()
    return { message: `Done. ${ATTACKER} is blocked: no sign-ins from that IP address for 2 hours. Ask the account owner to change their password.`, done: [LIVE_ID] }
  }
  if (b.verb === 'reject') {
    phase = 'dismissed'
    send({ type: 'done', tries, by: 'nobody' })
    changed()
    return { message: 'Closed as not a threat. Nothing was blocked.', done: [LIVE_ID] }
  }
  return null
}
