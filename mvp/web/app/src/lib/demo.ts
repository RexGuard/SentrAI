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
