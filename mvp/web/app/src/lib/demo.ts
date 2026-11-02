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
// can press "Do the suggested fix" themselves. Nothing leaves the browser; addresses are documentation-only.
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

function send(msg: Record<string, unknown>) {
  const m = { ...msg, id: `${Date.now()}-${Math.random()}` }
  try { bc?.postMessage(m) } catch { /* closed */ }
  try { localStorage.setItem('sentrai-demo-msg', JSON.stringify(m)) } catch { /* private window */ }
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
}

function liveRisk() {
  const mins = Math.max(1, Math.round((Date.now() - openedAt) / 60000))
  return {
    id: LIVE_ID, ids: [LIVE_ID], wave: '', incident: LIVE_ID, title: 'Brute Force', category: 'brute_force', severity: 'critical',
    host: 'aegis-web', source: ATTACKER, owner: 'On-duty responder', open_for: mins < 2 ? 'just now' : `${mins} min`, hours: 0,
    overdue: false, status: 'open', acked: false, needs: ['Decide what to do'],
    what_happened: `${ATTACKER} kept trying wrong passwords for the 'admin' account on aegis-web, ${tries} times so far, and is still trying.`,
    meaning: 'Someone is guessing passwords to get into an account. If they guess right, they are in.',
    fix: 'Block the IP address mentioned above and slow down sign-ins for 2 hours, so that they cannot keep guessing ' +
      'passwords. Then ask the account owner to change their password.',
    steps: [], unsure: false,
    actions: [
      { verb: 'approve', label: 'Do the suggested fix', hint: 'Blocks the address and slows down sign-ins. Written to the audit log.' },
      { verb: 'reject', label: 'Not a threat', hint: 'Closes it without acting. You say why.' },
    ],
    inc: { id: LIVE_ID, status: 'open', category: 'brute_force', acked: false, actions: [] },
  }
}
export const isLiveRisk = (id: string) => id === LIVE_ID

type Lvl = { severity: string; count: number; bubbles: number; overdue: number; oldest: string }
/** Adds the live risk (while it is open) to a recorded /ui/risks answer. */
function withLive(path: string, body: unknown): unknown {
  if (phase !== 'open' || !body || typeof body !== 'object' || !bare(path).startsWith('/ui/risks')) return body
  const b = body as { levels?: Lvl[]; rows?: unknown[]; headline?: string }
  const sev = new URLSearchParams(path.split('?')[1] ?? '').get('severity')
  const levels = (b.levels ?? []).map((l) => l.severity === 'critical'
    ? { ...l, count: l.count + 1, bubbles: l.bubbles + 1, oldest: l.oldest || 'just now' } : l)
  const total = levels.reduce((n, l) => n + l.count, 0)
  const out: Record<string, unknown> = { ...b, levels, headline: `${total} thing${total === 1 ? ' needs' : 's need'} a person. Start with Critical.` }
  if (sev === 'critical' || sev === 'all') out.rows = [liveRisk(), ...((b.rows as unknown[]) ?? [])]
  return out
}
export async function demoGetLive(path: string): Promise<unknown> {
  return withLive(path, await demoGet(path))
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
    return { message: `Done. ${ATTACKER} is blocked for 2 hours and sign-ins are slowed down. Ask the account owner to change their password.`, done: [LIVE_ID] }
  }
  if (b.verb === 'reject') {
    phase = 'dismissed'
    send({ type: 'done', tries, by: 'nobody' })
    changed()
    return { message: 'Closed as not a threat. Nothing was blocked.', done: [LIVE_ID] }
  }
  return null
}
