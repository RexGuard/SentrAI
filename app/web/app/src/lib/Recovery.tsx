// After an attack: the recovery checklist under one incident. Five phases, ticked off by people; each tick goes on
// the audit record. Points to the backup made just before the incident and flags when personal data may be involved.
import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { LifeBuoy, ShieldAlert } from 'lucide-react'
import { api, ApiError } from './api'
import { useSession } from './session'

type Step = { id: string; text: string; done: { by: string; at: string } | null }
type Phase = { key: string; title: string; about: string; steps: Step[] }
type Plan = { incident: string; what: string; machine: string; phases: Phase[]; done: number; total: number; personal_data: boolean
  backup: { id: string; created: string; checked: boolean | null } | null }

export function RecoveryPlan({ incident }: { incident: string }) {
  const { can } = useSession()
  const [plan, setPlan] = useState<Plan | null>(null)
  const [err, setErr] = useState('')
  const load = useCallback(async () => {
    try { setPlan(await api<Plan>(`/ui/recovery?incident=${encodeURIComponent(incident)}`)) } catch (e) { setErr(e instanceof ApiError ? e.message : 'Could not load the plan.') }
  }, [incident])
  useEffect(() => { void load() }, [load])
  const off = !can('act')
  const tick = async (step: Step) => {
    setErr('')
    try { setPlan(await api<Plan>('/ui/recovery/check', { body: { incident, step: step.id, done: !step.done } })) }
    catch (e) { setErr(e instanceof ApiError ? e.message : 'That did not go through.') }
  }
  if (!plan) return err ? <p className="text-sm text-bad">{err}</p> : null
  const pct = plan.total ? Math.round((plan.done / plan.total) * 100) : 0
  return (
    <div className="space-y-3 rounded-lg border border-line bg-surface p-4">
      <div className="flex flex-wrap items-center gap-3">
        <h3 className="flex items-center gap-2 font-semibold"><LifeBuoy size={16} aria-hidden /> After the attack: recovery plan</h3>
        <span className="text-sm text-muted">{plan.done} of {plan.total} done</span>
        <div className="h-1.5 w-32 rounded bg-surface-2" role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100} aria-label="Recovery progress">
          <div className="h-1.5 rounded bg-ok" style={{ width: `${pct}%` }} /></div>
      </div>
      {err && <p role="alert" className="text-sm text-bad">{err}</p>}
      {plan.personal_data && (
        <p className="flex gap-2 text-sm text-warn"><ShieldAlert size={16} className="mt-0.5 shrink-0" aria-hidden />
          This kind of attack can reach personal data. Check with your data protection officer whether it must be reported.</p>)}
      <p className="text-sm text-soft">
        {plan.backup ? <>Backup to restore from: <Link to="/backups" className="underline">{plan.backup.id}</Link>, made {new Date(plan.backup.created).toLocaleString([], { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' })}, before the attack
          {plan.backup.checked ? ', checked and intact.' : ' (not checked yet: check it first).'}</>
          : 'No backup from before this attack. Set up backups on the Backups page so the next recovery has one.'}
      </p>
      <ol className="grid gap-3 md:grid-cols-2 xl:grid-cols-5">
        {plan.phases.map((ph, i) => (
          <li key={ph.key} className="space-y-1.5 rounded-md border border-line-soft p-3">
            <p className="text-sm font-semibold">{i + 1}. {ph.title}</p>
            <p className="text-xs text-muted">{ph.about}</p>
            <ul className="space-y-1.5">
              {ph.steps.map((s) => (
                <li key={s.id}>
                  <label className="flex items-start gap-2 text-sm">
                    <input type="checkbox" className="mt-1" checked={!!s.done} disabled={off} onChange={() => void tick(s)} />
                    <span className={s.done ? 'text-muted line-through' : ''}>{s.text}
                      {s.done && <span className="block text-xs text-muted no-underline">done by {s.done.by}</span>}</span>
                  </label>
                </li>))}
            </ul>
          </li>))}
      </ol>
    </div>
  )
}
