import { createRequire } from 'module'; const { chromium } = createRequire(import.meta.url)('playwright')
import fs from 'fs'
const acct = JSON.parse(fs.readFileSync('acct.json'))
const B = 'http://127.0.0.1:5173'
const snap = {}
const browser = await chromium.launch()
const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } })
await ctx.addCookies(Object.entries(acct.cookies).map(([name, value]) => ({ name, value, url: B })))
const page = await ctx.newPage()
page.on('response', async (r) => {
  const u = new URL(r.url())
  if (!u.pathname.startsWith('/api/') || r.request().method() !== 'GET' || r.status() !== 200) return
  const key = u.pathname.slice(4) + u.search
  try { const ct = r.headers()['content-type'] || ''; snap[key] = ct.includes('json') ? await r.json() : await r.text() } catch {}
})
const visited = new Set()
async function visit(path, clickTabs = true) {
  if (visited.has(path)) return; visited.add(path)
  await page.goto(B + path, { waitUntil: 'networkidle' }).catch(() => {})
  await page.waitForTimeout(800)
  if (!clickTabs) return
  for (const list of await page.locator('[role=tablist]').all()) {
    const tabs = await list.locator('[role=tab], button').all()
    for (const t of tabs) { await t.click({ timeout: 2000 }).catch(() => {}); await page.waitForLoadState('networkidle').catch(() => {}); await page.waitForTimeout(400) }
  }
}
const routes = ['/command','/command?tab=approvals','/command?tab=incidents','/command?tab=review','/risks/critical','/risks/high','/risks/medium','/risks/low',
 '/machines','/chat','/audit','/team','/staff','/report','/routing','/overview','/config','/guardrails','/collector','/classifier','/responder',
 '/extensions','/reports','/backups','/analytics','/tuning','/privacy','/manager']
for (const r of routes) await visit(r)
// every machine page, and the links found on pages (incident details etc.)
const hosts = (snap['/ui/machines']?.machines ?? snap['/ui/machines']?.rows ?? []).map((m) => m.host).filter(Boolean)
for (const h of hosts) await visit('/machines/' + encodeURIComponent(h))
for (const r of ['/command', '/risks/critical', '/risks/high', '/risks/medium', '/machines', '/command?tab=incidents']) {
  await page.goto(B + r, { waitUntil: 'networkidle' })
  const hrefs = await page.$$eval('a[href^="/"]', (as) => as.map((a) => a.getAttribute('href')))
  for (const h of hrefs) if (!h.startsWith('/api')) await visit(h)
}
// open each incident's detail rows on the incidents list (buttons that expand a row)
await page.goto(B + '/command?tab=incidents', { waitUntil: 'networkidle' })
for (const b of await page.locator('table tbody tr').all()) { await b.click({ timeout: 1500 }).catch(() => {}); await page.waitForLoadState('networkidle').catch(() => {}) }
fs.writeFileSync('snapshot.json', JSON.stringify(snap))
console.log(Object.keys(snap).length, 'answers;', [...visited].length, 'pages'); console.log(Object.keys(snap).join('\n'))
await browser.close()
