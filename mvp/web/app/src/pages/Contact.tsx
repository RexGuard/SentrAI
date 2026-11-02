// Contact Us (bottom of the side menu): a short form that sends a question, feedback or bug report to the SentrAI
// team (POST /ui/feedback). The team reads them with `sudo sentrai feedback`.
import { useState } from 'react'
import { CheckCircle2, Send } from 'lucide-react'
import { api, ApiError } from '../lib/api'
import { btnPrimary } from '../lib/ui'
import { useSession } from '../lib/session'

const input = 'mt-1 block w-full rounded-md border border-line bg-surface-2 px-3 py-2 text-ink'

export default function Contact() {
  const { me } = useSession()
  const [name, setName] = useState(me?.name ?? '')
  const [contact, setContact] = useState(me?.email ?? '')
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [sent, setSent] = useState('')

  const send = async () => {
    setBusy(true); setErr('')
    try { setSent((await api<{ message: string }>('/ui/feedback', { body: { name, contact, message } })).message); setMessage('') }
    catch (e) { setErr(e instanceof ApiError ? e.message : 'That did not go through. Please try again.') }
    setBusy(false)
  }
  const ready = name.trim() && contact.trim() && message.trim()

  return (
    <section className="max-w-2xl space-y-4">
      <header>
        <h1 className="text-2xl font-semibold">Contact Us</h1>
        <p className="text-sm text-muted">A question, some feedback or a bug? Send it to the SentrAI team and we will get back to you.</p>
      </header>
      {sent ? (
        <div role="status" className="space-y-3 rounded-lg border border-line bg-surface p-5">
          <p className="flex items-center gap-2 font-medium text-ok"><CheckCircle2 size={18} aria-hidden /> Message sent</p>
          <p className="text-soft">{sent}</p>
          <button className={btnPrimary} onClick={() => setSent('')}>Send another</button>
        </div>
      ) : (
        <form className="space-y-4 rounded-lg border border-line bg-surface p-5" onSubmit={(e) => { e.preventDefault(); if (ready) void send() }}>
          <label className="block text-sm text-soft">Name
            <input className={input} value={name} onChange={(e) => setName(e.target.value)} maxLength={120} autoComplete="name" required />
          </label>
          <label className="block text-sm text-soft">Email or company
            <input className={input} value={contact} onChange={(e) => setContact(e.target.value)} maxLength={200} autoComplete="email" required />
          </label>
          <label className="block text-sm text-soft">Your question, feedback or bug report
            <textarea className={input + ' min-h-40'} value={message} onChange={(e) => setMessage(e.target.value)} maxLength={5000} required
              placeholder="Tell us what you need, or what went wrong and on which page." />
          </label>
          {err && <p role="alert" className="text-sm text-bad">{err}</p>}
          <button className={btnPrimary} disabled={busy || !ready}><Send size={14} aria-hidden /> {busy ? 'Sending…' : 'Send'}</button>
        </form>
      )}
    </section>
  )
}
