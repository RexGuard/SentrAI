import { useCallback, useEffect, useState } from 'react'
import Stat from '../lib/Stat'
import { CheckCircle2, CircleHelp, DatabaseBackup, ShieldAlert } from 'lucide-react'
import { api, ApiError } from '../lib/api'
import { btn, btnPrimary } from '../lib/ui'
import { useSession } from '../lib/session'
import { useFilters, type Filter } from '../lib/Filters'

type Backup = {
  id: string; created?: string; reason?: string; by?: string; files?: number; bytes?: number
  verified?: { ok?: boolean | null; at?: string; problems?: string[] }
  held_on?: string[]
}
type CopyItem = { id: string; created?: string; bytes?: number; on_panel?: boolean; held_on?: string[] }
type CopyMachine = { owner: string; name: string; key_kept?: boolean; should_hold?: string[]; copies: CopyItem[] }
type Copies = { replicas?: number; machines_available?: number; recovery_code_shown?: boolean; machines: CopyMachine[] }
type Data = {
  backups: Backup[]; keep?: number; every_hours?: number; next_due?: string; overdue?: boolean; folders?: string[]
  include_sentrai?: boolean; stored_in?: string; copy_to?: string; last_error?: { at?: string; error?: string }
  copies?: Copies
}

const REASON: Record<string, string> = { schedule: 'on schedule', manual: 'by hand', before_restore: 'safety copy before a restore' }
const PICK: Filter<Backup>[] = [
  { key: 'reason', label: 'Made', get: (b) => REASON[b.reason ?? ''] ?? b.reason }, { key: 'by', label: 'By', get: (b) => b.by },
  { key: 'check', label: 'Check', get: (b) => (b.verified?.ok ? 'Intact' : b.verified?.ok === false ? 'Problem' : 'Not checked') },
  { key: 'created', label: 'Made on', get: (b) => b.created, kind: 'date' },
]
const when = (v?: string) => (v ? new Date(v).toLocaleString([], { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' }) : '-')
const mb = (b?: number) => ((b ?? 0) / 1048576).toFixed(1)
const field = 'mt-1 block rounded-md border border-line bg-surface-2 px-3 py-1.5 text-ink'

function CopyRow({ m, done }: { m: CopyMachine; done: (msg: string) => void }) {
  const { me, can } = useSession()
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const newest = m.copies[0]
  const lost = async () => {
    setBusy(true); setErr('')
    try {
      const r = await api<{ unlocked_to: string }>('/backups/copies/unlock', { body: { owner: m.owner, id: newest.id, operator: me?.email ?? 'dashboard' } })
      done(`The newest backup of ${m.name} was unlocked into ${r.unlocked_to}`)
    } catch (e) { setErr(e instanceof ApiError ? e.message : 'That did not go through.') }
    setBusy(false)
  }
  const places = [...(newest?.on_panel ? ['this panel'] : []), ...(newest?.held_on ?? [])]
  return (
    <li className="grid items-center gap-x-4 gap-y-1 py-3 text-sm sm:grid-cols-[10rem_minmax(0,1fr)_auto]">
      <b className="truncate">{m.name}</b>
      <span className="min-w-0">
        Newest copy {when(newest?.created)} · {mb(newest?.bytes)} MB · kept on {places.length ? places.join(', ') : 'no other machine yet'}
        {places.length < 2 && <span className="block text-xs text-warn">Fewer than two places hold it yet. Machines pick copies up within about 10 minutes.</span>}
        {err && <span role="alert" className="block text-bad">{err}</span>}
      </span>
      {m.owner !== '_panel' && m.key_kept ? (
        <button className={btn} disabled={busy || !can('configure')} onClick={() => void lost()}
          title={can('configure') ? 'Use this when the machine is lost or broken: its newest backup is unlocked into the restores folder on this panel' : 'Your role can read everything but change nothing.'}>
          Machine lost? Unlock
        </button>
      ) : <span />}
    </li>
  )
}

function Row({ b, done }: { b: Backup; done: (m: string) => void }) {
  const { me, can } = useSession()
  const op = me?.email ?? 'dashboard'
  const v = b.verified ?? {}
  const [open, setOpen] = useState(false)
  const [where, setWhere] = useState<'new' | 'in_place'>('new')
  const [confirm, setConfirm] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const run = async (fn: () => Promise<unknown>, msg: string) => {
    setBusy(true); setErr('')
    try { await fn(); done(msg) } catch (e) { setErr(e instanceof ApiError ? e.message : 'That did not go through.') }
    setBusy(false)
  }
  const id = encodeURIComponent(b.id)
  return (
    <li className="space-y-2 py-3">
      <div className="grid items-center gap-x-4 gap-y-1 text-sm sm:grid-cols-[9rem_minmax(0,1fr)_7.5rem_auto]">
        <b className="truncate font-mono text-xs">{b.id}</b>
        <span className="min-w-0">{when(b.created)} · {REASON[String(b.reason)] ?? b.reason} by {b.by} · {b.files ?? 0} files, {mb(b.bytes)} MB
          {b.reason !== 'before_restore' && <span className="block text-xs text-muted">{b.held_on?.length ? `Also kept on ${b.held_on.join(', ')}` : 'Only on this panel so far'}</span>}</span>
        {v.ok ? <span className="inline-flex items-center gap-1 text-ok"><CheckCircle2 size={14} aria-hidden /> intact</span>
          : v.ok === false ? <span className="inline-flex items-center gap-1 text-crit"><ShieldAlert size={14} aria-hidden /> problem</span>
          : <span className="inline-flex items-center gap-1 text-muted"><CircleHelp size={14} aria-hidden /> not checked</span>}
        <div className="flex justify-end gap-2">
          <button className={btn} disabled={busy} onClick={() => void run(() => api(`/backups/${id}/verify`, { body: { operator: op } }), `Backup ${b.id} checked`)}>Check</button>
          <button className={btn} aria-expanded={open} onClick={() => setOpen(!open)}>Restore</button>
        </div>
      </div>
      {v.ok === false && <p className="text-sm text-bad">{(v.problems ?? []).join('; ')}</p>}
      {open && (
        <form className="space-y-2 rounded-md border border-line bg-surface-2 p-3" onSubmit={(e) => { e.preventDefault()
          void run(() => api(`/backups/${id}/restore`, { body: { operator: op, in_place: where === 'in_place', confirm: confirm.trim() } }),
            `Restored ${b.id}${where === 'in_place' ? ' in place' : ' into a new folder'}`) }}>
          <fieldset className="space-y-1"><legend className="text-sm text-soft">Where to put the files</legend>
            <label className="flex items-center gap-2 text-sm"><input type="radio" checked={where === 'new'} onChange={() => setWhere('new')} /> Into a new folder (nothing live changes)</label>
            <label className="flex items-center gap-2 text-sm"><input type="radio" checked={where === 'in_place'} onChange={() => setWhere('in_place')} /> Back where they came from (overwrites live files)</label>
          </fieldset>
          {where === 'in_place' && <label className="block text-sm text-soft">Type {b.id} to confirm<input className={field} value={confirm} onChange={(e) => setConfirm(e.target.value)} /></label>}
          <p className="text-xs text-muted">Back in place first takes a safety backup of the current files, so it can be undone. SentrAI's own data is only ever restored into a new folder.</p>
          {err && <p role="alert" className="text-bad">{err}</p>}
          <button className={btnPrimary} disabled={busy || !can('configure') || (where === 'in_place' && confirm.trim() !== b.id)}
            title={can('configure') ? undefined : 'Your role can read everything but change nothing.'}>Restore</button>
        </form>
      )}
      {!open && err && <p role="alert" className="text-sm text-bad">{err}</p>}
    </li>
  )
}

export default function Backups() {
  const { me, can } = useSession()
  const [data, setData] = useState<Data | null>(null)
  const [error, setError] = useState('')
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)
  const load = useCallback(async () => {
    try { setData(await api<Data>('/backups')); setError('') } catch (e) { setError(e instanceof ApiError ? `Backups are not available on this core. ${e.message}` : 'Could not load backups.') }
  }, [])
  useEffect(() => { void load(); const t = setInterval(() => void load(), 15000); return () => clearInterval(t) }, [load])
  const done = (m: string) => { setNote(m); void load() }
  const backupNow = async () => {
    setBusy(true); setNote('')
    try { await api('/backups', { body: { operator: me?.email ?? 'dashboard' } }); done('Backup made') }
    catch (e) { setNote(e instanceof ApiError ? e.message : 'The backup failed.') }
    setBusy(false)
  }
  const kept = data?.backups ?? []
  const f = useFilters(kept, PICK, (b) => [b.id, b.reason, b.by], 'backups')
  const last = kept.find((b) => b.reason !== 'before_restore')
  const check = last?.verified ?? {}
  return (
    <section className="space-y-4">
      <header>
        <h1 className="text-2xl font-semibold">Backups</h1>
        <p className="text-sm text-muted">Copies of your folders and SentrAI's own records, ready to put back</p>
      </header>
      {error && <p role="alert" className="rounded-md border border-line bg-surface p-3 text-bad">{error}</p>}
      {note && <p role="status" className="rounded-md border border-line bg-surface p-3">{note}</p>}
      {data && (
        <>
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            <Stat label="Last backup" value={last ? when(last.created) : 'Never'} note={last ? `${last.files ?? 0} files · ${mb(last.bytes)} MB` : 'take one below'} hot={!last || !!data.overdue} />
            <Stat label="Next due" value={!data.every_hours ? 'Off' : data.next_due === 'now' ? 'Now' : when(data.next_due)} note={data.every_hours ? `every ${data.every_hours} h` : 'no schedule'} />
            <Stat label="Kept" value={`${kept.length} of ${data.keep}`} note="oldest removed first" />
            <Stat label="Last check" value={check.ok ? 'Intact' : check.ok === false ? 'Problem' : 'Not checked'} note={check.at ? when(check.at) : 'press Check on a backup'} hot={check.ok === false} />
          </div>
          {data.last_error ? <p role="alert" className="text-bad">The last backup failed ({when(data.last_error.at)}): {data.last_error.error}</p>
            : data.overdue ? <p role="alert" className="text-warn">The last backup is more than two schedule periods old. Is SentrAI's core running?</p> : null}
          <div className="space-y-2 rounded-lg border border-line bg-surface p-4">
            <h2 className="font-semibold">What Is Backed Up</h2>
            <p className="text-sm text-soft">
              {data.folders?.length ? <>Folders: {data.folders.map((f) => <code key={f} className="mr-2 font-mono text-xs">{f}</code>)}</> : "No folders chosen yet, so only SentrAI's own data is copied."}
              {data.include_sentrai ? " SentrAI's own settings, signing key and audit records are always included." : ''}
              {data.stored_in ? <> Stored in <code className="font-mono text-xs">{data.stored_in}</code></> : null}
              {data.copy_to ? <>, with a second copy in <code className="font-mono text-xs">{data.copy_to}</code></> : null}
            </p>
            <button className={btnPrimary} disabled={busy || !can('act')} onClick={() => void backupNow()} title={can('act') ? undefined : 'Your role can read everything but change nothing.'}>
              <DatabaseBackup size={14} aria-hidden /> {busy ? 'Backing up…' : 'Back up now'}
            </button>
          </div>
          <div className="space-y-2 rounded-lg border border-line bg-surface p-4">
            <h2 className="font-semibold">Copies On Other Machines <span className="font-normal text-muted">· locked, so the machine keeping a copy cannot read it</span></h2>
            {!data.copies?.machines_available ? (
              <p className="text-sm text-soft">Backups stay on one machine until other machines join this panel. Then each backup is also kept on {data.copies?.replicas ?? 2} other machines, so losing one machine does not lose its backups.</p>
            ) : !data.copies.machines.length ? (
              <p className="text-sm text-soft">No copies yet. The next backup is copied to {data.copies.replicas ?? 2} other machines.</p>
            ) : <ul className="divide-y divide-line-soft">{data.copies.machines.map((m) => <CopyRow key={m.owner} m={m} done={done} />)}</ul>}
            {data.copies?.machines_available ? (
              <p className="text-xs text-muted">{data.copies.recovery_code_shown ? 'The recovery code for this panel was shown to your SentrAI team. It unlocks these copies if this panel itself is lost.' : 'Ask your SentrAI team to write down this panel\'s recovery code. Without it, the copies cannot be unlocked if this panel itself is lost.'}</p>
            ) : null}
          </div>
          <div className="space-y-2 rounded-lg border border-line bg-surface p-4">
            <h2 className="font-semibold">Backups Kept <span className="font-normal text-muted">· newest first · a restore always checks the backup first</span></h2>
            {f.bar}
            {kept.length === 0 ? <p className="text-soft">No backups yet.</p> : f.rows.length === 0 ? <p className="text-soft">No backups match these filters.</p> : <ul className="divide-y divide-line-soft">{f.rows.map((b) => <Row key={b.id} b={b} done={done} />)}</ul>}
          </div>
        </>
      )}
    </section>
  )
}
