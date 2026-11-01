// The Auto mode switch at the top of every page. On: SentrAI contains incidents over the threshold by itself,
// within the Automation guardrails. Off: every protective action waits for a person on Approvals.
import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { Bot, Hand, ShieldOff } from 'lucide-react'
import { api, ApiError } from '../lib/api'
import { useSession } from '../lib/session'
import { ask } from '../lib/notice'

type Protection = { protection: 'on' | 'off'; auto_mode: boolean; auto_mode_meta?: { changed_by?: string; changed_at?: string; reason?: string | null } }

export default function AutoMode() {
  const { can } = useSession()
  const [p, setP] = useState<Protection | null>(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const load = useCallback(async () => { try { setP(await api<Protection>('/protection')) } catch { /* the page itself shows core errors */ } }, [])
  useEffect(() => { void load(); const t = setInterval(() => void load(), 15000); return () => clearInterval(t) }, [load])
  if (!p) return null

  const on = p.auto_mode
  const allowed = can('configure')
  const flip = async () => {
    const turnOn = !on
    const reason = await ask(turnOn
      ? { title: 'Turn Auto mode on?', confirm: 'Turn on', body: 'SentrAI will contain incidents over the risk threshold by itself, within the Automation guardrails (which actions, how long, how many per hour). Everything it does is in the audit trail and can be rolled back.' }
      : { title: 'Turn Auto mode off?', confirm: 'Turn off', danger: true,
          body: 'SentrAI keeps watching and scoring, but nothing is contained on its own: every protective action waits for a person on Approvals. Actions already in force stay until they expire or are rolled back.',
          input: { label: 'Why? (written to the audit log, optional)' } })
    if (reason === null) return
    setBusy(true); setErr('')
    try { setP(await api<Protection>('/ui/auto-mode', { body: { on: turnOn, reason } })) }
    catch (e) { setErr(e instanceof ApiError ? e.message : 'Auto mode could not be changed.') }
    setBusy(false)
  }
  const who = p.auto_mode_meta?.changed_by ? ` · changed by ${p.auto_mode_meta.changed_by}` : ''
  return (
    <div className="flex flex-wrap items-center justify-end gap-3 text-sm">
      {err && <span role="alert" className="text-bad">{err}</span>}
      {p.protection === 'off' && <Link to="/guardrails" className="inline-flex items-center gap-1 text-warn"><ShieldOff size={14} aria-hidden /> Protection off: nothing is applied</Link>}
      <span className="text-muted" title={on ? 'SentrAI acts on its own above the threshold, within the guardrails' + who : 'Every action waits for a person' + who}>
        {on ? <Bot size={14} className="mr-1 inline" aria-hidden /> : <Hand size={14} className="mr-1 inline" aria-hidden />}
        {on ? 'Acts on its own' : 'Waits for you'}
      </span>
      <button role="switch" aria-checked={on} onClick={() => void flip()} disabled={busy || !allowed}
        title={allowed ? undefined : 'Only an Owner or Admin can change Auto mode.'}
        className="inline-flex items-center gap-2 rounded-full border border-line bg-surface px-2 py-1 disabled:opacity-60">
        <span className="font-medium">Auto mode</span>
        <span className={'relative h-5 w-9 rounded-full transition-colors ' + (on ? 'bg-ok' : 'bg-surface-3')} aria-hidden>
          <span className={'absolute top-0.5 h-4 w-4 rounded-full bg-bg shadow transition-all ' + (on ? 'left-[1.125rem]' : 'left-0.5')} />
        </span>
        <span className="w-6 text-left text-xs text-soft">{on ? 'On' : 'Off'}</span>
      </button>
    </div>
  )
}
