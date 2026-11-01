import { useCallback, useEffect, useState } from 'react'
import { Copy, KeyRound, Trash2, UserPlus } from 'lucide-react'
import { useFilters, type Filter } from '../lib/Filters'
import { api, ApiError } from '../lib/api'
import { btn, btnPrimary } from '../lib/ui'

type Person = { email: string; name: string; role: string; role_label: string; authenticator: boolean; last_sign_in: number | null; last_ip: string }
type Invite = { email: string; role: string; by: string; expires: number; reset: boolean }
type Page = { me: string; my_role: string; roles: Record<string, string>; invite_hours: number; people: Person[]; invites: Invite[] }
type Made = { code: string; path: string; message: string }

const when = (t: number | null) => (t ? new Date(t * 1000).toLocaleString() : 'never')
const field = 'mt-1 block rounded-md border border-line bg-surface-2 px-3 py-1.5 text-ink'

const PICK: Filter<Person>[] = [
  { key: 'role', label: 'Role', get: (p) => p.role_label }, { key: 'auth', label: 'Authenticator', get: (p) => (p.authenticator ? 'Yes' : 'Not yet') },
  { key: 'seen', label: 'Signed in', get: (p) => (p.last_sign_in ? 'Has signed in' : 'Never') },
]
const NOBODY: Person[] = []

export default function Team() {
  const [page, setPage] = useState<Page | null>(null)
  const [error, setError] = useState('')
  const [note, setNote] = useState('')
  const [link, setLink] = useState<Made | null>(null)
  const [who, setWho] = useState('')
  const [role, setRole] = useState('')
  const [sure, setSure] = useState(false)
  const [inviteEmail, setInviteEmail] = useState('')
  const [inviteRole, setInviteRole] = useState('admin')

  const load = useCallback(async () => {
    try { setPage(await api<Page>('/ui/team')); setError('') }
    catch (e) { setError(e instanceof ApiError ? e.message : 'Could not load the team.') }
  }, [])
  useEffect(() => { void load() }, [load])
  const people = useFilters(page?.people ?? NOBODY, PICK, (p) => [p.name, p.email, p.role_label, p.last_ip], 'people')

  const others = page?.people.filter((p) => p.email !== page.me) ?? []
  const person = others.find((p) => p.email === who) ?? others[0]
  useEffect(() => { if (person) { setWho(person.email); setRole(person.role) } }, [person?.email]) // eslint-disable-line react-hooks/exhaustive-deps
  const roles = page ? Object.entries(page.roles).filter(([r]) => r !== 'owner' || page.my_role === 'owner') : []
  const link_url = (path: string) => location.origin + path

  const act = async (path: string, body: unknown, keepLink = false) => {
    setNote(''); if (!keepLink) setLink(null)
    try {
      const r = await api<Made>(path, { body })
      setNote(r.message); if (r.code) setLink(r); setSure(false); await load()
    } catch (e) { setNote(e instanceof ApiError ? e.message : 'That did not go through.') }
  }

  return (
    <section className="space-y-4">
      <header>
        <h1 className="text-2xl font-semibold">Team</h1>
        <p className="text-sm text-muted">Who may sign in to this console, and what each role may do</p>
      </header>
      {error && <p role="alert" className="rounded-md border border-line bg-surface p-3 text-bad">{error}</p>}
      {note && <p role="status" className="rounded-md border border-line bg-surface p-3">{note}</p>}
      {link && (
        <div className="space-y-2 rounded-lg border border-line bg-surface p-4">
          <p className="font-medium">{link.message}</p>
          <div className="flex items-start gap-2 rounded-md border border-line bg-bg p-2">
            <code className="min-w-0 flex-1 break-all font-mono text-xs">{link_url(link.path)}</code>
            <button className="text-soft" aria-label="Copy the link" onClick={() => void navigator.clipboard?.writeText(link_url(link.path))}><Copy size={14} aria-hidden /></button>
          </div>
          <p className="text-xs text-muted">Send this link to them yourself. It works once, for {page?.invite_hours} hours.</p>
        </div>
      )}
      {page && (
        <>
          <div className="space-y-3 rounded-lg border border-line bg-surface p-4">
            <h2 className="font-semibold">People <span className="font-normal text-muted">· {page.people.length} with access</span></h2>
            {people.bar}
            <div className="overflow-x-auto" role="region" aria-label="People" tabIndex={0}>
              <table className="w-full text-left text-sm">
                <thead className="border-b border-line text-xs uppercase tracking-wide text-muted">
                  <tr>{['Name', 'Email', 'Role', 'Authenticator', 'Last sign-in'].map((h) => <th key={h} className="p-2 font-medium">{h}</th>)}</tr>
                </thead>
                <tbody>
                  {people.rows.map((p) => (
                    <tr key={p.email} className="border-b border-line-soft last:border-0">
                      <td className="p-2">{p.name}</td><td className="p-2">{p.email}</td><td className="p-2">{p.role_label}</td>
                      <td className="p-2">{p.authenticator ? 'Yes' : 'Not yet'}</td>
                      <td className="p-2 whitespace-nowrap">{when(p.last_sign_in)}{p.last_ip ? ` from ${p.last_ip}` : ''}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="text-xs text-muted">Owner and Admin run SentrAI. An Auditor sees every page and can export reports, but changes nothing.</p>
          </div>

          {others.length > 0 && person && (
            <div className="space-y-3 rounded-lg border border-line bg-surface p-4">
              <h2 className="font-semibold">Change someone's access</h2>
              <div className="flex flex-wrap items-end gap-3">
                <label className="text-sm text-soft">Person
                  <select className={field} value={who} onChange={(e) => { setWho(e.target.value); setRole(others.find((p) => p.email === e.target.value)?.role ?? '') }}>
                    {others.map((p) => <option key={p.email} value={p.email}>{p.email}</option>)}
                  </select></label>
                <label className="text-sm text-soft">Role
                  <select className={field} value={role} onChange={(e) => setRole(e.target.value)}>
                    {roles.map(([r, label]) => <option key={r} value={r}>{label}</option>)}
                  </select></label>
                <button className={btn} disabled={role === person.role} onClick={() => void act('/ui/team/role', { email: who, role })}>Change role</button>
                <button className={btn} title="Forgot the password or lost the phone: their old password stops working and a link lets them set both again."
                  onClick={() => void act('/ui/team/reset', { email: who })}><KeyRound size={14} aria-hidden /> Reset sign-in</button>
                <label className="flex items-center gap-1 pb-2 text-sm text-soft"><input type="checkbox" checked={sure} onChange={(e) => setSure(e.target.checked)} /> I'm sure</label>
                <button className={btn} disabled={!sure} onClick={() => void act('/ui/team/remove', { email: who })}><Trash2 size={14} aria-hidden /> Remove</button>
              </div>
            </div>
          )}

          <div className="space-y-3 rounded-lg border border-line bg-surface p-4">
            <h2 className="font-semibold">Invite someone <span className="font-normal text-muted">· they set their own password and authenticator</span></h2>
            <form className="flex flex-wrap items-end gap-3" onSubmit={(e) => { e.preventDefault(); void act('/ui/team/invite', { email: inviteEmail, role: inviteRole }).then(() => setInviteEmail('')) }}>
              <label className="text-sm text-soft">Their email
                <input type="email" required className={field + ' w-72 max-w-full'} value={inviteEmail} onChange={(e) => setInviteEmail(e.target.value)} /></label>
              <label className="text-sm text-soft">Role
                <select className={field} value={inviteRole} onChange={(e) => setInviteRole(e.target.value)}>
                  {roles.map(([r, label]) => <option key={r} value={r}>{label}</option>)}
                </select></label>
              <button className={btnPrimary}><UserPlus size={14} aria-hidden /> Make invite link</button>
            </form>
            {page.invites.length > 0 && (
              <div>
                <h3 className="text-sm font-semibold">Waiting to be used</h3>
                <ul className="mt-1 space-y-1">
                  {page.invites.map((i) => (
                    <li key={i.email} className="flex flex-wrap items-center gap-3 text-sm text-soft">
                      <span>{i.email} · {i.reset ? 'reset' : page.roles[i.role]} · by {i.by} · until {when(i.expires)}</span>
                      <button className={btn} onClick={() => void act('/ui/team/withdraw', { email: i.email })}>Withdraw</button>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </>
      )}
    </section>
  )
}
