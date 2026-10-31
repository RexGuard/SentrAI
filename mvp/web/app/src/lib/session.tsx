import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react'
import { api, ApiError, type Me } from './api'

type Session = { me: Me | null; loading: boolean; refresh: () => Promise<void>; signOut: () => Promise<void>; can: (p: string) => boolean }
const Ctx = createContext<Session | null>(null)

export function SessionProvider({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<Me | null>(null)
  const [loading, setLoading] = useState(true)
  const refresh = useCallback(async () => {
    try { setMe(await api<Me>('/auth/me')) } catch (e) { if (e instanceof ApiError) setMe(null) }
    setLoading(false)
  }, [])
  useEffect(() => { void refresh() }, [refresh])
  const signOut = async () => { await api('/auth/logout', { method: 'POST', body: {} }).catch(() => {}); setMe(null) }
  const can = (p: string) => !!me?.permissions.includes(p)
  return <Ctx.Provider value={{ me, loading, refresh, signOut, can }}>{children}</Ctx.Provider>
}

export function useSession() {
  const s = useContext(Ctx)
  if (!s) throw new Error('SessionProvider missing')
  return s
}
