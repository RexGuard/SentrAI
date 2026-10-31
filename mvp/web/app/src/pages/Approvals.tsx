import { Fragment, useCallback, useEffect, useMemo, useState } from 'react'
import { Check, ChevronDown, ChevronRight, FolderPlus, Pin, Undo2, UserCheck, X } from 'lucide-react'
import { api, ApiError } from '../lib/api'
import { btn, btnPrimary } from '../lib/ui'
import { useSession } from '../lib/session'

type Row = {
  id: string; what: string; host: string; severity: string; status: string; owner: string; open_for: string
  needs: string[]; target: string; points: number; attacker: string; summary: string
  can: { decide: boolean; ack: boolean; contain_controls: boolean; mine: boolean }
}
type Page = {
  headline: string; total: number; rows: Row[]; groups: { name: string; rows: Row[] }[]
  grouped: { name: string; rows: Row[] }[]; protection_on: boolean
}
type Verb = 'approve' | 'reject' | 'rollback' | 'keep' | 'mine'

const READ_ONLY = 'Your role can read everything but change nothing.'
const sevColor: Record<string, string> = { critical: 'text-crit', high: 'text-bad', medium: 'text-warn', low: 'text-ok' }

function Actions({ rows, page, onRun, onGroup, extra }: {
  rows: Row[]; page: Page; extra?: React.ReactNode
  onRun: (verb: Verb, ids: string[], why: string) => Promise<void>
  onGroup?: (ids: string[]) => void
}) {
  const { can } = useSession()
  const [why, setWhy] = useState('')
  const [asking, setAsking] = useState<'reject' | 'keep' | null>(null)
  const decide = rows.filter((r) => r.can.decide && !r.can.mine)
  const mine = rows.filter((r) => r.can.mine)
  const contain = rows.filter((r) => !r.can.decide && r.can.contain_controls)
  const off = !can('act')
  const ids = (xs: Row[]) => xs.map((r) => r.id)
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap gap-2">
        {mine.length > 0 && <button className={btn} disabled={off} title={off ? READ_ONLY : undefined} onClick={() => void onRun('mine', ids(mine), '')}><UserCheck size={14} aria-hidden /> This was me {mine.length}</button>}
        {decide.length > 0 && <>
          <button className={btnPrimary} disabled={off || !page.protection_on}
            title={off ? READ_ONLY : !page.protection_on ? 'Protection is off (monitor only): turn it on in Configuration to apply a hotpatch.' : undefined}
            onClick={() => void onRun('approve', ids(decide), '')}><Check size={14} aria-hidden /> Approve {decide.length}</button>
          <button className={btn} disabled={off} title={off ? READ_ONLY : undefined} onClick={() => setAsking(asking === 'reject' ? null : 'reject')}><X size={14} aria-hidden /> Reject {decide.length}</button>
        </>}
        {contain.length > 0 && <>
          <button className={btn} disabled={off} title={off ? READ_ONLY : undefined} onClick={() => void onRun('rollback', ids(contain), '')}><Undo2 size={14} aria-hidden /> Roll back {contain.length}</button>
          <button className={btn} disabled={off} title={off ? READ_ONLY : undefined} onClick={() => setAsking(asking === 'keep' ? null : 'keep')}><Pin size={14} aria-hidden /> Keep {contain.length}</button>
        </>}
        {onGroup && <button className={btn} disabled={off} title={off ? READ_ONLY : undefined} onClick={() => onGroup(ids(rows))}><FolderPlus size={14} aria-hidden /> Group {rows.length}</button>}
        {extra}
      </div>
      {asking && (
        <form className="flex flex-wrap items-end gap-2" onSubmit={(e) => { e.preventDefault(); void onRun(asking, ids(asking === 'reject' ? decide : contain), why).then(() => { setAsking(null); setWhy('') }) }}>
          <label className="text-sm text-soft">
            {asking === 'reject' ? 'Why (required, written to the audit log for each one)' : 'Why (optional, written to the audit log)'}
            <input value={why} onChange={(e) => setWhy(e.target.value)} required={asking === 'reject'} autoFocus
              className="mt-1 block w-80 max-w-full rounded-md border border-line bg-surface-2 px-3 py-1.5 text-ink" />
          </label>
          <button className={btnPrimary} disabled={asking === 'reject' && !why.trim()}>
            {asking === 'reject' ? `Reject all ${decide.length}` : `Keep all ${contain.length} forever`}
          </button>
        </form>
      )}
    </div>
  )
}

function Table({ rows, picking, picked, toggle, page, run, empty }: {
  rows: Row[]; picking: boolean; picked: Set<string>; toggle: (id: string) => void; page: Page; empty: string
  run: (verb: Verb, ids: string[], why: string) => Promise<void>
}) {
  const [open, setOpen] = useState<string | null>(null)
  if (!rows.length) return <p className="rounded-lg border border-line bg-surface p-4 text-soft">{empty}</p>
  return (
    <div className="overflow-x-auto rounded-lg border border-line bg-surface">
      <table className="w-full text-left text-sm">
        <thead className="border-b border-line text-xs uppercase tracking-wide text-muted">
          <tr>
            {picking && <th className="w-8 p-2"><span className="sr-only">Pick</span></th>}
            <th className="w-8 p-2"><span className="sr-only">Details</span></th>
            {['Incident', 'What', 'Host', 'Severity', 'Status', 'Owner', 'Open for', 'Needs'].map((h) => <th key={h} className="p-2 font-medium">{h}</th>)}
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <Fragment key={r.id}>
              <tr className="border-b border-line-soft last:border-0 hover:bg-surface-2">
                {picking && <td className="p-2"><input type="checkbox" checked={picked.has(r.id)} onChange={() => toggle(r.id)} aria-label={`Pick ${r.id}`} /></td>}
                <td className="p-2">
                  <button aria-expanded={open === r.id} aria-label={`Details of ${r.id}`} onClick={() => setOpen(open === r.id ? null : r.id)} className="text-soft">
                    {open === r.id ? <ChevronDown size={16} aria-hidden /> : <ChevronRight size={16} aria-hidden />}
                  </button>
                </td>
                <td className="p-2 font-mono text-xs">{r.id}</td>
                <td className="p-2">{r.what}</td>
                <td className="p-2">{r.host}</td>
                <td className={'p-2 font-medium capitalize ' + (sevColor[r.severity] ?? '')}>{r.severity}</td>
                <td className="p-2">{r.status}</td>
                <td className="p-2">{r.owner}</td>
                <td className="p-2 whitespace-nowrap">{r.open_for}</td>
                <td className="p-2 text-soft">{r.needs.join('; ') || 'In hand'}</td>
              </tr>
              {open === r.id && (
                <tr className="border-b border-line-soft bg-surface-2">
                  <td colSpan={picking ? 10 : 9} className="space-y-3 p-4">
                    <p className="text-soft">{r.summary || `${r.what} on ${r.host}${r.target ? ` · ${r.target}` : ''}.`}</p>
                    <p className="text-xs text-muted">Source: {r.attacker} · Points: {r.points}</p>
                    <Actions rows={[r]} page={page} onRun={run} />
                  </td>
                </tr>
              )}
            </Fragment>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export default function Approvals() {
  const { can } = useSession()
  const [page, setPage] = useState<Page | null>(null)
  const [error, setError] = useState('')
  const [note, setNote] = useState('')
  const [tab, setTab] = useState<'waiting' | 'groups'>('waiting')
  const [by, setBy] = useState('')
  const [picked, setPicked] = useState<Set<string>>(new Set())

  const load = useCallback(async () => {
    try { setPage(await api<Page>('/ui/approvals' + (by ? `?by=${by}` : ''))); setError('') }
    catch (e) { setError(e instanceof ApiError ? e.message : 'Could not load approvals.') }
  }, [by])
  useEffect(() => { void load(); const t = setInterval(() => void load(), 10000); return () => clearInterval(t) }, [load])

  const run = async (verb: Verb, ids: string[], justification: string) => {
    try {
      const r = await api<{ message: string }>('/ui/approvals/bulk', { body: { verb, ids, justification } })
      setNote(r.message); setPicked(new Set()); await load()
    } catch (e) { setNote(e instanceof ApiError ? e.message : 'That did not go through.') }
  }
  const group = async (ids: string[]) => {
    const suggested = (await api<{ name: string }>('/ui/approvals/group-name', { body: { ids } })).name
    const name = window.prompt('Group name (an existing name adds to that group)', suggested)
    if (!name?.trim()) return
    const r = await api<{ message: string }>('/ui/approvals/groups', { body: { name: name.trim(), ids } })
    setNote(r.message); setPicked(new Set()); await load()
  }
  const ungroup = async (name: string) => {
    const r = await api<{ message: string }>('/ui/approvals/groups', { body: { ungroup: name } })
    setNote(r.message); await load()
  }

  const rows = page?.rows ?? []
  const picking = can('act') && rows.length > 1
  const pickedRows = useMemo(() => rows.filter((r) => picked.has(r.id)), [rows, picked])
  const toggle = (id: string) => setPicked((s) => { const n = new Set(s); if (n.has(id)) n.delete(id); else n.add(id); return n })

  return (
    <section className="space-y-4">
      <header>
        <h1 className="text-2xl font-semibold">Approvals</h1>
        <p className="text-sm text-muted">requests waiting on a person · nothing permanent happens without one</p>
      </header>
      {error && <p role="alert" className="rounded-md border border-line bg-surface p-3 text-bad">{error}</p>}
      {note && <p role="status" className="rounded-md border border-line bg-surface p-3">{note}</p>}
      {page && page.total === 0 && <p className="rounded-lg border border-line bg-surface p-4 text-ok">Nothing waiting for a decision. All quiet at the gate.</p>}
      {page && page.total > 0 && (
        <>
          <p className="font-medium">{page.headline}</p>
          <div role="tablist" aria-label="Part of the Approvals page" className="flex gap-2">
            {(['waiting', ...(page.groups.length ? ['groups'] : [])] as ('waiting' | 'groups')[]).map((t) => (
              <button key={t} role="tab" aria-selected={tab === t} onClick={() => setTab(t)}
                className={'rounded-md px-3 py-1.5 text-sm ' + (tab === t ? 'bg-surface-3 text-ink' : 'text-soft hover:bg-surface-2')}>
                {t === 'waiting' ? `Waiting (${rows.length})` : `Your groups (${page.groups.length})`}
              </button>
            ))}
          </div>
          {tab === 'groups' ? page.groups.map((g) => (
            <div key={g.name} className="space-y-3 rounded-lg border border-line bg-surface p-4">
              <h2 className="font-semibold">{g.name} · {g.rows.length}</h2>
              <Actions rows={g.rows} page={page} onRun={run}
                extra={<button className={btn} disabled={!can('act')} onClick={() => void ungroup(g.name)}>Ungroup</button>} />
              <Table rows={g.rows} picking={false} picked={picked} toggle={toggle} page={page} run={run} empty="" />
            </div>
          )) : (
            <>
              {pickedRows.length > 0 && (
                <div className="space-y-3 rounded-lg border border-line bg-surface p-4">
                  <h2 className="font-semibold">{pickedRows.length} picked</h2>
                  <Actions rows={pickedRows} page={page} onRun={run} onGroup={group}
                    extra={<button className={btn} onClick={() => setPicked(new Set())}>Clear</button>} />
                </div>
              )}
              <label className="inline-flex items-center gap-2 text-sm text-soft">
                Group by
                <select value={by} onChange={(e) => setBy(e.target.value)} className="rounded-md border border-line bg-surface-2 px-2 py-1 text-ink">
                  <option value="">Nothing</option><option value="attacker">Attacker</option><option value="machine">Machine</option><option value="type">Type</option>
                </select>
              </label>
              {by && page.grouped.length ? page.grouped.map((g) => (
                <div key={g.name} className="space-y-2">
                  <h2 className="text-sm font-semibold text-soft">{g.name} · {g.rows.length}</h2>
                  <Table rows={g.rows} picking={picking} picked={picked} toggle={toggle} page={page} run={run} empty="" />
                </div>
              )) : <Table rows={rows} picking={picking} picked={picked} toggle={toggle} page={page} run={run}
                empty={page.groups.length ? 'Everything waiting is in one of your groups.' : 'Nothing waiting for a decision.'} />}
            </>
          )}
        </>
      )}
    </section>
  )
}
