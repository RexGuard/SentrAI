import { useEffect, useState, type FormEvent, type ReactNode } from 'react'
import QRCode from 'qrcode'
import { api, ApiError } from '../lib/api'
import { useSession } from '../lib/session'

type Step = 'loading' | 'blocked' | 'register' | 'invite' | 'login' | 'code' | 'add' | 'recovery'

const input = 'w-full rounded-md border border-line bg-surface-2 px-3 py-2 text-ink placeholder:text-muted'
const button = 'w-full rounded-md bg-ink px-3 py-2 font-medium text-bg disabled:opacity-50'

function Field({ label, ...p }: { label: string } & React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <label className="block text-sm text-soft">
      {label}
      <input className={input + ' mt-1'} {...p} />
    </label>
  )
}

export default function SignIn() {
  const { refresh } = useSession()
  const invite = new URLSearchParams(location.search).get('invite') ?? ''
  const [step, setStep] = useState<Step>('loading')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const [email, setEmail] = useState('')
  const [secret, setSecret] = useState('')
  const [qr, setQr] = useState('')
  const [codes, setCodes] = useState<string[]>([])

  useEffect(() => {
    (async () => {
      try {
        if (invite) { await api(`/auth/invite?code=${encodeURIComponent(invite)}`); return setStep('invite') }
      } catch { setErr('This invite link is wrong or has expired. Ask whoever invited you for a new one.') }
      const s = await api<{ has_accounts: boolean; setup_code_waiting: boolean }>('/auth/state').catch(() => null)
      if (!s) { setErr('Cannot reach the core.'); return setStep('blocked') }
      setStep(s.has_accounts ? 'login' : s.setup_code_waiting ? 'register' : 'blocked')
    })()
  }, [invite])

  async function run(fn: () => Promise<void>) {
    setBusy(true); setErr('')
    try { await fn() } catch (e) { setErr(e instanceof ApiError ? e.message : 'Something went wrong.') }
    setBusy(false)
  }
  const form = (e: FormEvent<HTMLFormElement>) => Object.fromEntries(new FormData(e.currentTarget)) as Record<string, string>

  async function next(n: string) {
    if (n === 'code') return setStep('code')
    const r = await api<{ secret: string; uri: string }>('/auth/authenticator/start', { body: {} })
    setSecret(r.secret); setQr(await QRCode.toDataURL(r.uri, { margin: 1, width: 200 })); setStep('add')
  }

  let body: ReactNode = null
  if (step === 'blocked') {
    body = <p className="text-soft">No one can sign in yet. On the machine running SentrAI, run <code className="font-mono">python sentrai_config.py admin</code> (on a server: <code className="font-mono">sudo sentrai-admin</code>) for a one-time setup code, then reload this page.</p>
  } else if (step === 'register' || step === 'invite') {
    const isInvite = step === 'invite'
    body = (
      <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); const f = form(e); void run(async () => {
        setEmail(f.email ?? '')
        const r = await api<{ next: string }>(isInvite ? '/auth/invite/accept' : '/auth/register-owner',
          { body: isInvite ? { code: invite, name: f.name, password: f.password } : { code: f.code, name: f.name, email: f.email, password: f.password } })
        await next(r.next)
      }) }}>
        <h2 className="text-lg font-semibold">{isInvite ? 'Join SentrAI' : 'Create the Owner account'}</h2>
        {!isInvite && <Field label="Setup code" name="code" required autoComplete="off" />}
        <Field label="Your name" name="name" required autoComplete="name" />
        {!isInvite && <Field label="Email" name="email" type="email" required autoComplete="email" />}
        <Field label="Password (at least 12 characters)" name="password" type="password" minLength={12} required autoComplete="new-password" />
        <button className={button} disabled={busy}>Continue</button>
      </form>
    )
  } else if (step === 'login') {
    body = (
      <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); const f = form(e); void run(async () => {
        setEmail(f.email ?? '')
        await next((await api<{ next: string }>('/auth/login', { body: { email: f.email, password: f.password } })).next)
      }) }}>
        <h2 className="text-lg font-semibold">Sign in</h2>
        <Field label="Email" name="email" type="email" required autoComplete="username" />
        <Field label="Password" name="password" type="password" required autoComplete="current-password" />
        <button className={button} disabled={busy}>Continue</button>
      </form>
    )
  } else if (step === 'code') {
    body = (
      <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); const f = form(e); void run(async () => {
        await api('/auth/totp', { body: { code: f.code } }); await refresh()
      }) }}>
        <h2 className="text-lg font-semibold">Authenticator code</h2>
        <p className="text-sm text-muted">Signing in as {email}. Type the 6-digit code from your app, or a recovery code.</p>
        <Field label="Code" name="code" required autoComplete="one-time-code" inputMode="text" autoFocus />
        <button className={button} disabled={busy}>Sign in</button>
      </form>
    )
  } else if (step === 'add') {
    body = (
      <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); const f = form(e); void run(async () => {
        const r = await api<{ recovery_codes: string[] }>('/auth/authenticator/confirm', { body: { code: f.code } })
        setCodes(r.recovery_codes); setStep('recovery')
      }) }}>
        <h2 className="text-lg font-semibold">Add an authenticator</h2>
        <p className="text-sm text-muted">Scan this with an authenticator app, then type the code it shows.</p>
        {qr && <img src={qr} width={200} height={200} alt={`QR code for the authenticator secret ${secret}`} className="rounded bg-white" />}
        <p className="break-all font-mono text-xs text-muted">{secret}</p>
        <Field label="Code from the app" name="code" required autoComplete="one-time-code" inputMode="numeric" />
        <button className={button} disabled={busy}>Confirm</button>
      </form>
    )
  } else if (step === 'recovery') {
    body = (
      <div className="space-y-3">
        <h2 className="text-lg font-semibold">Save your recovery codes</h2>
        <p className="text-sm text-muted">Each works once if you lose your phone. They are shown only now.</p>
        <ul className="grid grid-cols-2 gap-1 rounded-md border border-line bg-surface-2 p-3 font-mono text-sm">{codes.map((c) => <li key={c}>{c}</li>)}</ul>
        <button className={button} onClick={() => void refresh()}>I saved them, continue</button>
      </div>
    )
  } else {
    body = <p className="text-muted" role="status">Loading…</p>
  }

  return (
    <main className="grid min-h-screen place-items-center px-4">
      <div className="w-full max-w-sm space-y-4 rounded-xl border border-line bg-surface p-6">
        <div className="flex items-center gap-2"><img src="/mark.svg" alt="" width={28} height={28} /><span className="text-xl font-semibold">SentrAI</span></div>
        {err && <p role="alert" className="rounded-md border border-line bg-surface-2 p-2 text-sm text-bad">{err}</p>}
        <div key={step}>{body}</div> {/* a new step is a new form: React must not carry the password into the code box */}
      </div>
    </main>
  )
}
