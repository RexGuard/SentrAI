// Times the Command center's first load and its 10 s refresh in Chromium, on a local and a slower network.
// Needs the throwaway core from README.md (token t) and serve.py in front of it: node load.js [port] [port ...]
// Signs nobody in: the API token goes with every call and /auth/me is answered by the script.
const { chromium } = require('playwright');
const me = { email: 'erick@example.com', name: 'Erick', role: 'owner', role_label: 'Owner', permissions: ['read','act','admin','configure','team'] };
async function run(port, label, net) {
  const b = await chromium.launch(); const ctx = await b.newContext({ extraHTTPHeaders: { Authorization: 'Bearer t' } });
  const page = await ctx.newPage();
  await page.route('**/api/auth/me', r => r.fulfill({ json: me }));
  const cdp = await ctx.newCDPSession(page);
  await cdp.send('Network.enable');
  if (net) await cdp.send('Network.emulateNetworkConditions', { offline: false, latency: net.rtt, downloadThroughput: net.down / 8, uploadThroughput: net.up / 8 });
  let bytes = 0; cdp.on('Network.loadingFinished', e => bytes += e.encodedDataLength);
  const t0 = Date.now();
  await page.goto(`http://127.0.0.1:${port}/command`);
  await page.waitForFunction(() => document.body.innerText.includes('Waiting for a decision') && !document.body.innerText.includes('Loading…'), null, { timeout: 120000 });
  const ready = Date.now() - t0; const firstBytes = bytes; bytes = 0;
  await page.waitForTimeout(12000); bytes = 0; await page.waitForTimeout(10000); const refresh = bytes;
  // open another page
  const t1 = Date.now(); await page.click('a[href="/incidents"]'); await page.waitForFunction(() => location.pathname === '/incidents' && !document.body.innerText.includes('Loading…'), null, { timeout: 120000 });
  const nav = Date.now() - t1;
  console.log(`${label}: Command center ready ${ready} ms, ${Math.round(firstBytes/1024)} KB downloaded; one 10 s refresh ${Math.round(refresh/1024)} KB; open Incidents ${nav} ms`);
  await b.close();
}
(async () => {
  const net = { rtt: 60, down: 20e6, up: 5e6 };
  const ports = process.argv.slice(2).length ? process.argv.slice(2) : ["5173"]
  for (const n of [null, net]) for (const p of ports) await run(Number(p), `port ${p}` + (n ? " (20 Mbit/s, 60 ms)" : " (local)"), n)
})();
