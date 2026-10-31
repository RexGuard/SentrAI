const { chromium } = require('playwright')
// node pages.js <authenticator code>   (needs: SIGNIN_EMAIL, SIGNIN_PASSWORD, optional WEB=http://127.0.0.1:5173)
const code = process.argv[2]
const WEB = process.env.WEB || 'http://127.0.0.1:5173'
const EMAIL = process.env.SIGNIN_EMAIL, PASS = process.env.SIGNIN_PASSWORD
const routes = ['/overview','/approvals','/incidents','/machines','/machines/srv-01','/chat','/audit','/team','/staff','/report','/routing','/config','/guardrails','/review','/collector','/classifier','/responder','/extensions','/reports','/backups']
;(async () => {
  const b = await chromium.launch(); const ctx = await b.newContext({ viewport: { width: 1440, height: 900 } }); const p = await ctx.newPage()
  const errs = []; let reqs = 0, bytes = 0, slow = []
  p.on('console', m => { if (m.type() === 'error') errs.push(m.text().slice(0, 140)) })
  p.on('pageerror', e => errs.push('PAGEERROR ' + String(e).slice(0, 140)))
  const t0 = Date.now()
  await p.goto(WEB + '/'); await p.waitForSelector('input[name=email]')
  console.log('cold login page ready ms', Date.now() - t0)
  await p.fill('input[name=email]', EMAIL); await p.fill('input[name=password]', PASS); await p.click('button:has-text("Continue")')
  await p.waitForSelector('input[name=code]'); await p.fill('input[name=code]', code); await p.click('button:has-text("Sign in")')
  await p.waitForSelector('nav', { timeout: 8000 })
  console.log('signed in ok after ms', Date.now() - t0)
  for (const r of routes) {
    errs.length = 0; const s = Date.now(); let n = 0
    const on = (res) => { if (res.url().includes('/api/')) n++ }
    p.on('response', on)
    await p.goto(WEB + r, { waitUntil: 'networkidle' })
    const load = Date.now() - s
    const txt = (await p.innerText('main').catch(() => '')).replace(/\s+/g, ' ').slice(0, 60)
    const nav = await p.evaluate(() => { const e = performance.getEntriesByType('navigation')[0]; return Math.round(e.domContentLoadedEventEnd) })
    p.off('response', on)
    console.log(`${r.padEnd(18)} idle ${String(load).padStart(5)}ms dcl ${String(nav).padStart(4)}ms api ${String(n).padStart(2)} err ${errs.length} | ${txt}`)
    for (const e of errs.slice(0, 2)) console.log('     !', e)
  }
  await b.close()
})()
