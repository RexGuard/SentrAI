import { useLocation } from 'react-router-dom'
import { MENU } from './Layout'

// Pages still on the Streamlit console during the rebuild.
export default function Soon() {
  const { pathname } = useLocation()
  const label = MENU.flatMap((g) => g.items).find((i) => i.to === pathname)?.label ?? 'This page'
  return (
    <section>
      <h1 className="text-2xl font-semibold">{label}</h1>
      <p className="mt-2 max-w-prose text-soft">
        This page has not moved to the new console yet. Open it in the current console.
      </p>
    </section>
  )
}
