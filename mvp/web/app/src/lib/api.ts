// Every call goes through /api (the core), with the session cookie. A write also sends X-SentrAI-Web,
// which another website cannot add to a request.
export class ApiError extends Error {
  status: number
  constructor(message: string, status: number) { super(message); this.status = status }
}

// The last answer to each GET and its ETag, in memory only (gone on reload or sign-out). A page that refreshes
// every few seconds sends If-None-Match, and when nothing changed the server answers 304 with no body.
const lastGet = new Map<string, { etag: string; body: unknown }>()
export function forgetCache() { lastGet.clear() }

export async function api<T = unknown>(path: string, init: { method?: string; body?: unknown } = {}): Promise<T> {
  const method = init.method ?? (init.body === undefined ? 'GET' : 'POST')
  const headers: Record<string, string> = {}
  if (init.body !== undefined) headers['Content-Type'] = 'application/json'
  if (method !== 'GET') headers['X-SentrAI-Web'] = '1'
  const seen = method === 'GET' ? lastGet.get(path) : undefined
  if (seen) headers['If-None-Match'] = seen.etag
  const res = await fetch('/api' + path, {
    method, headers, credentials: 'same-origin', cache: 'no-store',
    body: init.body === undefined ? undefined : JSON.stringify(init.body),
  })
  if (res.status === 304 && seen) return seen.body as T
  if (!res.ok) {
    if (method === 'GET') lastGet.delete(path)
    let detail = res.statusText
    try { const j = await res.json(); if (typeof j.detail === 'string') detail = j.detail } catch { /* not JSON */ }
    throw new ApiError(detail, res.status)
  }
  const body = await (res.headers.get('content-type')?.includes('json') ? res.json() : res.text())
  const etag = res.headers.get('etag')
  if (method === 'GET' && etag) lastGet.set(path, { etag, body })
  else if (method !== 'GET') lastGet.clear()  // a change may show up on any page: ask afresh
  return body as T
}

export type Me = { email: string; name: string; role: string; role_label: string; permissions: string[] }

/** A streamed answer: POSTs `body` and calls `onEvent` with each JSON line as it arrives. Aborting `signal` closes the
 *  connection, which the core takes as Stop. */
export async function stream(path: string, body: unknown, onEvent: (e: Record<string, unknown>) => void, signal?: AbortSignal): Promise<void> {
  const res = await fetch('/api' + path, {
    method: 'POST', credentials: 'same-origin', signal,
    headers: { 'Content-Type': 'application/json', 'X-SentrAI-Web': '1' }, body: JSON.stringify(body),
  })
  if (!res.ok || !res.body) {
    let detail = res.statusText
    try { const j = await res.json(); if (typeof j.detail === 'string') detail = j.detail } catch { /* not JSON */ }
    throw new ApiError(detail, res.status)
  }
  const reader = res.body.getReader()
  const dec = new TextDecoder()
  let buf = ''
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    buf += dec.decode(value, { stream: true })
    let nl
    while ((nl = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, nl).trim(); buf = buf.slice(nl + 1)
      if (line) onEvent(JSON.parse(line))
    }
  }
  if (buf.trim()) onEvent(JSON.parse(buf))
}
