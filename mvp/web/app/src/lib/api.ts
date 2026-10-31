// Every call goes through /api (the core), with the session cookie. A write also sends X-SentrAI-Web,
// which another website cannot add to a request.
export class ApiError extends Error {
  status: number
  constructor(message: string, status: number) { super(message); this.status = status }
}

export async function api<T = unknown>(path: string, init: { method?: string; body?: unknown } = {}): Promise<T> {
  const method = init.method ?? (init.body === undefined ? 'GET' : 'POST')
  const headers: Record<string, string> = {}
  if (init.body !== undefined) headers['Content-Type'] = 'application/json'
  if (method !== 'GET') headers['X-SentrAI-Web'] = '1'
  const res = await fetch('/api' + path, {
    method, headers, credentials: 'same-origin',
    body: init.body === undefined ? undefined : JSON.stringify(init.body),
  })
  if (!res.ok) {
    let detail = res.statusText
    try { const j = await res.json(); if (typeof j.detail === 'string') detail = j.detail } catch { /* not JSON */ }
    throw new ApiError(detail, res.status)
  }
  return (res.headers.get('content-type')?.includes('json') ? res.json() : res.text()) as Promise<T>
}

export type Me = { email: string; name: string; role: string; role_label: string; permissions: string[] }
