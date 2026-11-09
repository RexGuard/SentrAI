// Security Coach: SentrAI teaches each member of staff right after a risky action in a work app (Google Workspace,
// Microsoft 365, ...). This page is the owner's view: turn it on (regions' checklists and the staff notice first),
// pick the apps, see team totals and open moments, and browse the lessons. Names stay hidden unless a moment is
// urgent or the admin turns names on. The core enforces all of this (core/app/coach.py); the page only shows it.
import { useCallback, useEffect, useState } from 'react'
import { AlertTriangle, BookOpen, CheckCircle2, Download, FlaskConical, GraduationCap, Smartphone, Trash2 } from 'lucide-react'
import { api, ApiError } from '../lib/api'
import { btn } from '../lib/ui'
import { useSession } from '../lib/session'
import Stat from '../lib/Stat'

type App = { key: string; name: string; covers: string; wave: number; sees: string; needs: string; status: 'sample' | 'planned' }
type Region = { key: string; name: string; law: string; consent: boolean; checks: string[] }
type Moment = { id: string; app: string; kind: string; group: string; level: 'tip' | 'fix_soon' | 'urgent'; level_word: string; at: string; lesson: string; times: number; status: string; title: string; fix: string | null; who: string; sample: boolean }
type Settings = { apps_on: string[]; kinds_on: string[]; regions: string[]; region_checks: Record<string, number[]>; show_names: boolean; file_names: boolean; notice_shared: boolean; notice_shared_at?: string }
type Team = { people: number; notice_confirmed: number; moments_30d: number; urgent_open: number; fixed_30d: number; lessons_done: number; notes_ready: number; notes_held: number; by_group: Record<string, number>; top: { kind: string; count: number; lesson: string; title: string }[] }
type Person = { email: string; name: string; group: string; notice_confirmed: boolean; level: { name: string; step: number; of: number }; lessons_done: number }
type Page = { settings: Settings; ready: boolean; why_not_ready: string; apps: App[]; regions: Region[]; team: Team; moments: Moment[]; people: Person[] | null; kept: { activity: string; notes: string }; has_sample: boolean }
type Lesson = { id: string; title: string; card: string; steps: string[]; questions: { q: string; options: string[] }[]; deeper: string | null }

const card = 'rounded-lg border border-line bg-surface p-4'
const pill: Record<Moment['level'], string> = { urgent: 'border-bad text-bad', fix_soon: 'border-warn text-warn', tip: 'border-line text-soft' }
const appName = (apps: App[], key: string) => apps.find((a) => a.key === key)?.name ?? key

type Phones = { phones: { id: string; email: string; kind: string; device: string; last_at: string }[]; team: { phones_checked: number; all_good: number; by_problem: Record<string, number> } }
type Invite = { code: string; email: string; expires_at: string; steps: string[] }

export default function Coach() {
  const { can } = useSession()
  const off = !can('configure')
  const [page, setPage] = useState<Page | null>(null)
  const [lessons, setLessons] = useState<Lesson[]>([])
  const [error, setError] = useState('')
  const [note, setNote] = useState('')
  const [phones, setPhones] = useState<Phones | null>(null)
  const [inviteFor, setInviteFor] = useState('')
  const [invite, setInvite] = useState<Invite | null>(null)
  const load = useCallback(async () => {
    try {
      const [p, l, ph] = await Promise.all([api<Page>('/ui/coach'), api<{ lessons: Lesson[] }>('/ui/coach/lessons'), api<Phones>('/ui/mobile')])
      setPage(p); setLessons(l.lessons); setPhones(ph); setError('')
    } catch (e) { setError(e instanceof ApiError ? e.message : 'Could not reach SentrAI.') }
  }, [])
  useEffect(() => { void load() }, [load])

  const save = async (body: Partial<Settings>, done?: string) => {
    setError(''); setNote('')
    try { setPage(await api<Page>('/ui/coach/settings', { body })); if (done) setNote(done) }
    catch (e) { setError(e instanceof ApiError ? e.message : 'Could not save.') }
  }
  const sample = async (clear: boolean) => {
    setError(''); setNote('')
    try {
      setPage(await api<Page>('/ui/coach/sample', { body: { clear } }))
      setNote(clear ? 'Sample people and activity removed.' : 'Added three made-up people and a day of made-up activity. Remove them any time.')
    } catch (e) { setError(e instanceof ApiError ? e.message : 'Could not add sample data.') }
  }
  const makeInvite = async () => {
    setError(''); setNote(''); setInvite(null)
    try { setInvite(await api<Invite>('/ui/mobile/invites', { body: { email: inviteFor.trim() } })) }
    catch (e) { setError(e instanceof ApiError ? e.message : 'Could not make the invite.') }
  }
  const answer = async (m: Moment, a: string) => {
    try { await api(`/ui/coach/moments/${m.id}`, { body: { answer: a } }); await load() }
    catch (e) { setError(e instanceof ApiError ? e.message : 'Could not save.') }
  }

  if (!page) return <section className="space-y-4"><h1 className="text-2xl font-semibold">Security Coach</h1>{error ? <p role="alert" className="text-bad">{error}</p> : <p className="text-muted" role="status">Loading…</p>}</section>
  const s = page.settings
  const toggle = (list: string[], key: string) => (list.includes(key) ? list.filter((k) => k !== key) : [...list, key])
  const ticked = (r: string, i: number) => (s.region_checks[r] ?? []).includes(i)
  const tick = (r: string, i: number) => save({ region_checks: { ...s.region_checks, [r]: ticked(r, i) ? (s.region_checks[r] ?? []).filter((x) => x !== i) : [...(s.region_checks[r] ?? []), i] } })
  const t = page.team

  return (
    <section className="space-y-5">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-semibold"><GraduationCap size={22} aria-hidden /> Security Coach</h1>
          <p className="text-sm text-muted">Teaches your team to stay safe in the work apps they use every day, right when it matters</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <a className={btn + ' no-underline'} href="/api/ui/coach/notice.md" download><Download size={14} aria-hidden /> Staff notice</a>
          {page.ready && (page.has_sample
            ? <button className={btn} disabled={off} onClick={() => void sample(true)}><Trash2 size={14} aria-hidden /> Remove sample data</button>
            : <button className={btn} disabled={off} onClick={() => void sample(false)}><FlaskConical size={14} aria-hidden /> Try with sample data</button>)}
        </div>
      </header>
      {error && <p role="alert" className="rounded-md border border-line bg-surface p-3 text-bad">{error}</p>}
      {note && <p role="status" className="rounded-md border border-line bg-surface p-3">{note}</p>}

      <p className={'flex items-start gap-2 rounded-md border border-line bg-surface p-3 text-sm ' + (page.ready ? '' : 'text-warn')}>
        {page.ready ? <CheckCircle2 size={16} className="mt-0.5 shrink-0 text-ok" aria-hidden /> : <AlertTriangle size={16} className="mt-0.5 shrink-0" aria-hidden />}
        {page.ready
          ? `The coach is on. Activity is kept for ${page.kept.activity} and coaching notes for ${page.kept.notes}, then deleted (change this on the Privacy page).`
          : `The coach is off, and nothing is recorded until it is on. Next step: ${page.why_not_ready}`}
      </p>

      {page.ready && (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <Stat label="Risky moments" value={t.moments_30d} note="in the last 30 days" />
          <Stat label="Fixed" value={t.fixed_30d} note="by the person, after a note" />
          <Stat label="Lessons finished" value={t.lessons_done} note={`by ${t.people} ${t.people === 1 ? 'person' : 'people'}`} />
          <Stat label="Urgent" value={t.urgent_open} note="someone may be using a staff account" hot={t.urgent_open > 0} tone="bad" />
        </div>)}

      {page.ready && (
        <div className="grid gap-4 lg:grid-cols-[2fr_1fr]">
          <div className={card}>
            <h2 className="mb-2 font-semibold">Needs a look</h2>
            {!page.moments.length ? <p className="text-sm text-muted">Nothing open. Nice.</p> : (
              <ul className="divide-y divide-line-soft">
                {page.moments.map((m) => (
                  <li key={m.id} className="flex flex-wrap items-start justify-between gap-2 py-2.5 text-sm">
                    <div className="min-w-0">
                      <span className={'mr-2 inline-block rounded-full border px-2 py-0.5 text-xs ' + pill[m.level]}>{m.level_word}</span>
                      <b>{m.who}</b> {m.title}
                      <span className="block text-xs text-muted">{appName(page.apps, m.app)} · {m.at.slice(0, 16).replace('T', ' ')}{m.times > 1 ? ` · ${m.times} times recently` : ''}{m.status === 'needs help' ? ' · said it wasn’t them' : ''}{m.sample ? ' · sample' : ''}</span>
                      <span className="block text-xs text-soft">Lesson sent: {lessons.find((l) => l.id === m.lesson)?.title ?? m.lesson}</span>
                    </div>
                    <div className="flex gap-2">
                      <button className={btn} disabled={off} onClick={() => void answer(m, 'fixed')}>Mark fixed</button>
                      <button className={btn} disabled={off} onClick={() => void answer(m, 'dismissed')}>Dismiss</button>
                    </div>
                  </li>))}
              </ul>)}
          </div>
          <div className={card}>
            <h2 className="mb-2 font-semibold">What the team is learning</h2>
            {!t.top.length ? <p className="text-sm text-muted">No risky moments yet.</p> : (
              <ol className="space-y-2 text-sm">
                {t.top.map((r) => <li key={r.kind}><b>{r.title}</b><span className="block text-xs text-muted">{r.count} {r.count === 1 ? 'time' : 'times'} this month</span></li>)}
              </ol>)}
            <p className="mt-3 text-xs text-muted">{t.notes_ready} notes ready to send, {t.notes_held} waiting for the person to read the staff notice. Sending by email, Slack and Teams comes in the next update.</p>
          </div>
        </div>)}

      <div className={card}>
        <h2 className="font-semibold">1. Where your staff work</h2>
        <p className="mb-3 text-sm text-muted">Pick each region, then tick its checklist. These are starting points to check with your lawyer, not legal advice.</p>
        <div className="flex flex-wrap gap-2">
          {page.regions.map((r) => (
            <label key={r.key} className="flex items-center gap-1.5 rounded-full border border-line px-3 py-1 text-sm">
              <input type="checkbox" className="accent-[var(--accent)]" disabled={off} checked={s.regions.includes(r.key)} onChange={() => void save({ regions: toggle(s.regions, r.key) })} /> {r.name}
            </label>))}
        </div>
        {page.regions.filter((r) => s.regions.includes(r.key)).map((r) => (
          <fieldset key={r.key} className="mt-3 rounded-md border border-line-soft p-3">
            <legend className="px-1 text-sm font-medium">{r.name} · {r.law}{r.consent ? ' · each person must agree first' : ''}</legend>
            {r.checks.map((c, i) => (
              <label key={i} className="flex items-start gap-2 py-0.5 text-sm text-soft">
                <input type="checkbox" className="mt-1 accent-[var(--accent)]" disabled={off} checked={ticked(r.key, i)} onChange={() => void tick(r.key, i)} /> {c}
              </label>))}
          </fieldset>))}
      </div>

      <div className={card}>
        <h2 className="font-semibold">2. Tell your staff</h2>
        <p className="mb-3 text-sm text-muted">Download the staff notice, check it, and share it. It says exactly what the coach looks at, what it never reads, who sees what, and how long it is kept.</p>
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" className="accent-[var(--accent)]" disabled={off} checked={s.notice_shared} onChange={() => void save({ notice_shared: !s.notice_shared })} />
          Staff have been given the notice{s.notice_shared_at ? ` (marked ${s.notice_shared_at.slice(0, 10)})` : ''}
        </label>
      </div>

      <div className={card}>
        <h2 className="font-semibold">3. Work apps</h2>
        <p className="mb-3 text-sm text-muted">SentrAI reads each app’s own activity log with a read-only admin connection. It never reads the text of emails, chats or files.</p>
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {page.apps.map((a) => (
            <label key={a.key} className="flex gap-3 rounded-md border border-line-soft p-3 text-sm">
              <input type="checkbox" className="mt-1 accent-[var(--accent)]" disabled={off} checked={s.apps_on.includes(a.key)} onChange={() => void save({ apps_on: toggle(s.apps_on, a.key) })} />
              <span className="min-w-0">
                <b>{a.name}</b> <span className="text-xs text-muted">{a.covers}</span>
                <span className="block text-soft">{a.sees}</span>
                <span className="block text-xs text-muted">{a.needs}</span>
                <span className="mt-1 inline-block rounded-full border border-line px-2 py-0.5 text-xs text-muted">{a.status === 'sample' ? 'Live connection coming next' : `Planned, wave ${a.wave}`}</span>
              </span>
            </label>))}
        </div>
      </div>

      <div className={card}>
        <h2 className="mb-2 font-semibold">4. What owners can see</h2>
        <label className="flex items-start gap-2 py-1 text-sm">
          <input type="checkbox" className="mt-1 accent-[var(--accent)]" disabled={off} checked={s.show_names} onChange={() => void save({ show_names: !s.show_names })} />
          <span>Show people’s names<span className="block text-xs text-muted">Off: you see team totals, and names only when a moment is urgent (an account may be in the wrong hands). The staff notice changes to match.</span></span>
        </label>
        <label className="flex items-start gap-2 py-1 text-sm">
          <input type="checkbox" className="mt-1 accent-[var(--accent)]" disabled={off} checked={s.file_names} onChange={() => void save({ file_names: !s.file_names })} />
          <span>Keep file names<span className="block text-xs text-muted">Off: a file shows only as “a spreadsheet” or “a document”.</span></span>
        </label>
        {page.people && (
          <div className="mt-3 overflow-x-auto" tabIndex={0}>
            <table className="w-full min-w-[36rem] text-left text-sm">
              <thead className="text-xs text-muted"><tr className="border-b border-line"><th className="p-2 font-medium">Person</th><th className="p-2 font-medium">Group</th><th className="p-2 font-medium">Read the notice</th><th className="p-2 font-medium">Safe habits</th></tr></thead>
              <tbody>
                {page.people.map((p) => (
                  <tr key={p.email} className="border-b border-line-soft">
                    <td className="p-2">{p.name || p.email}</td><td className="p-2 text-soft">{p.group}</td>
                    <td className="p-2 text-soft">{p.notice_confirmed ? 'Yes' : 'Not yet'}</td>
                    <td className="p-2 text-soft">{p.level.name} ({p.level.step} of {p.level.of}) · {p.lessons_done} lessons</td>
                  </tr>))}
              </tbody>
            </table>
          </div>)}
      </div>

      <div className={card}>
        <h2 className="mb-2 flex items-center gap-2 font-semibold"><Smartphone size={16} aria-hidden /> 5. Phone app</h2>
        <p className="mb-2 text-sm text-muted">Staff get their notes and lessons on their Android phone, and the app checks the phone itself (screen lock, updates, risky apps). Only yes or no answers leave the phone. Tick “SentrAI phone app” under Work apps to turn its findings into notes.</p>
        {phones && <p className="mb-2 text-sm text-soft">{phones.phones.length} {phones.phones.length === 1 ? 'phone is' : 'phones are'} signed in · {phones.team.phones_checked} checked, {phones.team.all_good} with nothing to fix.</p>}
        <div className="flex flex-wrap items-end gap-2">
          <label className="text-sm">Work email of someone on the list<input type="email" value={inviteFor} disabled={off} onChange={(e) => setInviteFor(e.target.value)} className="mt-1 block w-72 max-w-full rounded-md border border-line bg-transparent px-2 py-1" placeholder="name@yourcompany.com" /></label>
          <button className={btn} disabled={off || !inviteFor.includes('@')} onClick={() => void makeInvite()}>Make an app invite</button>
        </div>
        {invite && (
          <div className="mt-3 rounded-md border border-line-soft p-3 text-sm" role="status">
            <p>Invite for {invite.email}: <code className="text-base font-semibold">{invite.code}</code> <span className="text-xs text-muted">(works once, until {new Date(invite.expires_at).toLocaleString()}; shown only now)</span></p>
            <ol className="mt-2 list-decimal pl-5 text-soft">{invite.steps.map((x) => <li key={x}>{x}</li>)}</ol>
            <p className="mt-1 text-xs text-muted">The panel address is the one you use for this website. Owners and admins sign in to the app with their usual email, password and authenticator code, no invite needed.</p>
          </div>)}
      </div>

      <div className={card}>
        <h2 className="mb-2 flex items-center gap-2 font-semibold"><BookOpen size={16} aria-hidden /> Lessons</h2>
        <p className="mb-2 text-sm text-muted">Each note comes with one of these. If the same slip happens again, the next note goes a step deeper.</p>
        <div className="grid gap-2 md:grid-cols-2">
          {lessons.map((l) => (
            <details key={l.id} className="rounded-md border border-line-soft p-3 text-sm">
              <summary className="cursor-pointer font-medium">{l.title}</summary>
              <p className="mt-2 text-soft">{l.card}</p>
              <ul className="mt-2 list-disc pl-5 text-soft">{l.steps.map((x) => <li key={x}>{x}</li>)}</ul>
              <p className="mt-2 text-xs text-muted">Quick check: {l.questions.map((q) => q.q).join(' · ')}</p>
            </details>))}
        </div>
      </div>
    </section>
  )
}
