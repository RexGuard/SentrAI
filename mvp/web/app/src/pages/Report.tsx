// The open staff report page: /report (and the old /?report). No sign-in. It shows nothing from SentrAI; it only
// sends the report and tells the reporter what to do now (core ui_public.py).
import { useEffect, useState, type FormEvent } from 'react'
import { CheckCircle2, Plus, Send } from 'lucide-react'
import { api, ApiError } from '../lib/api'

type Info = { on: boolean; code_needed: boolean; machines: string[] }
type Sent = { id: string; kind_label?: string; urgency?: string; advice?: string[] }

const input = 'mt-1 block w-full rounded-md border border-line bg-surface-2 px-3 py-2 text-ink placeholder:text-muted'

export function isReportPage(): boolean {
  return location.pathname.replace(/\/+$/, '') === '/report' || new URLSearchParams(location.search).has('report')
}

export default function Report() {
  const [info, setInfo] = useState<Info | null>(null)
  const [sent, setSent] = useState<Sent | null>(null)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const [f, setF] = useState({ text: '', reporter: '', where: '', contact: '', host: '', code: '' })
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => setF((x) => ({ ...x, [k]: e.target.value }))
  useEffect(() => { api<Info>('/public/report').then(setInfo).catch(() => setErr('The report page cannot reach SentrAI right now. Please tell your IT contact directly.')) }, [])

  const submit = async (e: FormEvent) => {
    e.preventDefault(); setErr('')
    if (f.text.trim().length < 10) return setErr('Please describe what you saw in a sentence or two.')
    setBusy(true)
    try { setSent(await api<Sent>('/public/report', { body: f })) }
    catch (x) { setErr(x instanceof ApiError && [400, 404, 429].includes(x.status) ? x.message : 'The report could not be sent right now. Please tell your IT contact directly.') }
    setBusy(false)
  }

  return (
    <main className="mx-auto max-w-xl space-y-4 p-4 sm:p-8">
      <h1 className="text-2xl font-semibold">SentrAI</h1>
      {info && !info.on ? <p className="rounded-md border border-line bg-surface p-4">Reporting from this page is turned off. Please tell your IT contact directly.</p>
        : sent ? (
          <div className="space-y-3 rounded-lg border border-line bg-surface p-4">
            <p role="status" className="flex items-start gap-2"><CheckCircle2 size={18} className="mt-0.5 shrink-0 text-ok" aria-hidden /> Thank you. Your report {sent.id} reached the security team.</p>
            <p><b>It sounds like:</b> {sent.kind_label || 'something to check'}{sent.urgency === 'high' ? <> · <b>treated as urgent</b></> : null}</p>
            <div><p className="font-semibold">What to do now</p><ol className="list-decimal space-y-1 pl-5">{(sent.advice ?? []).map((a, i) => <li key={i}>{a}</li>)}</ol></div>
            <p className="text-sm text-muted">Someone will look at it and may contact you. If it gets worse, tell your manager or IT contact.</p>
            <button className="inline-flex items-center gap-1 rounded-md border border-line px-3 py-1.5 text-sm hover:bg-surface-2" onClick={() => { setSent(null); setF({ text: '', reporter: '', where: '', contact: '', host: '', code: '' }) }}><Plus size={14} aria-hidden /> Report something else</button>
          </div>
        ) : (
          <form onSubmit={(e) => void submit(e)} className="space-y-3 rounded-lg border border-line bg-surface p-4">
            <div><h2 className="text-lg font-semibold">Report something suspicious</h2>
              <p className="text-sm text-muted">Seen a strange email, a pop-up, a login you didn't make, or a stranger near the computers? Tell us in your own words. You don't need to be sure; it is always fine to report.</p></div>
            <label className="block text-sm text-soft">What did you notice?
              <textarea className={input} rows={6} maxLength={4000} value={f.text} onChange={set('text')} required
                placeholder="e.g. I got an email from 'IT support' asking me to confirm my password. I clicked the link but did not type anything." /></label>
            <div className="grid gap-3 sm:grid-cols-2">
              <label className="block text-sm text-soft">Your name (optional)<input className={input} maxLength={120} value={f.reporter} onChange={set('reporter')} /></label>
              <label className="block text-sm text-soft">Where? (computer, room or account)<input className={input} maxLength={120} value={f.where} onChange={set('where')} placeholder="e.g. front desk PC" /></label>
            </div>
            <label className="block text-sm text-soft">How can we reach you? (optional)<input className={input} maxLength={120} value={f.contact} onChange={set('contact')} placeholder="phone, email or extension" /></label>
            {info?.machines.length ? (
              <label className="block text-sm text-soft">Which computer is it about?
                <select className={input} value={f.host} onChange={set('host')}><option value="">Not sure</option>{info.machines.map((m) => <option key={m} value={m}>{m}</option>)}</select></label>) : null}
            {info?.code_needed && <label className="block text-sm text-soft">Report code (on the staff noticeboard)<input className={input} type="password" autoComplete="off" value={f.code} onChange={set('code')} /></label>}
            {err && <p role="alert" className="text-sm text-bad">{err}</p>}
            <button disabled={busy || !info} className="inline-flex w-full items-center justify-center gap-1 rounded-md bg-ink px-3 py-2 font-medium text-bg disabled:opacity-50"><Send size={14} aria-hidden /> {busy ? 'Sending…' : 'Send report'}</button>
          </form>
        )}
    </main>
  )
}
