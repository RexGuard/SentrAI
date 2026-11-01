// Simple view: a switch for people who are not in IT (owners, managers, office staff). It keeps the menu to the
// pages a non-technical person needs, with everyday names, and opens on the Manager view. The full dashboard is one
// click away and nothing is hidden from the API: this only changes what the menu shows. Kept per browser.
import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'

const KEY = 'sentrai.simple'
type Simple = { simple: boolean; toggle: () => void }
const Ctx = createContext<Simple>({ simple: false, toggle: () => {} })

function remembered(): boolean {
  try { return localStorage.getItem(KEY) === '1' } catch { return false }
}

export function SimpleProvider({ children }: { children: ReactNode }) {
  const [simple, setSimple] = useState(remembered)
  useEffect(() => { try { localStorage.setItem(KEY, simple ? '1' : '0') } catch { /* private window */ } }, [simple])
  return <Ctx.Provider value={{ simple, toggle: () => setSimple((s) => !s) }}>{children}</Ctx.Provider>
}

export const useSimple = () => useContext(Ctx)
