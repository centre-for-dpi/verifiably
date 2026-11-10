import puppeteer from 'puppeteer-core';
const BASE = process.env.BASE || 'http://172.24.0.1:8080';
// citizens-postgres's real password is CITIZENS_PG_PASSWORD from .env
// (generated on `deploy.sh setup`, defaults to the literal "citizens" only
// on deployments from before that var existed) — 'citizens' here is a
// fallback for those older hosts, not the expected value on a fresh one.
const CONN = process.env.CONN ||
  `postgres://citizens:${process.env.CITIZENS_PG_PASSWORD || 'citizens'}@citizens-postgres:5432/citizens`;
const QUERY = process.env.QUERY || "SELECT first_name || ' ' || last_name AS holder FROM citizens ORDER BY id LIMIT 5";
const br = await puppeteer.launch({ executablePath: '/usr/bin/google-chrome', headless: 'new',
  args: ['--no-sandbox', '--disable-dev-shm-usage'] });
const p = await (await br.createBrowserContext()).newPage();
await p.setViewport({ width: 1400, height: 1000 });
async function auth(role) {
  await p.goto(`${BASE}/`, { waitUntil: 'domcontentloaded' });
  await p.click(`button.role-card[value="${role}"]`);
  await p.waitForFunction(() => /\/auth/.test(location.pathname), { timeout: 15000 });
  await Promise.all([
    p.waitForNavigation({ waitUntil: 'domcontentloaded', timeout: 20000 }).catch(()=>null),
    p.evaluate(() => [...document.querySelectorAll('button.provider-btn')].find(b => (b.getAttribute('hx-vals')||'').includes('keycloak'))?.click()),
  ]);
  await p.waitForSelector('input[name="username"]', { timeout: 20000 });
  await p.type('input[name="username"]', 'admin');
  await p.type('input[name="password"]', 'admin');
  await Promise.all([
    p.waitForNavigation({ waitUntil: 'domcontentloaded', timeout: 20000 }).catch(()=>null),
    p.click('input[type="submit"], button[type="submit"]'),
  ]);
  await new Promise(r => setTimeout(r, 700));
}
await auth('issuer');
await p.goto(`${BASE}/issuer/dpg`, { waitUntil: 'domcontentloaded' });
await p.waitForSelector('.dpg-card', { timeout: 15000 });
await p.evaluate(() => [...document.querySelectorAll('.dpg-card')].find(x => x.dataset.vendor === 'Walt Community Stack')?.click());
try { await p.waitForFunction(() => { const b = document.querySelector('#issuer-dpg-continue'); return b && !b.classList.contains('btn-disabled'); }, { timeout: 10000 }); } catch {}
await p.evaluate(() => document.querySelector('#issuer-dpg-continue')?.click());
await p.waitForNavigation({ waitUntil: 'domcontentloaded', timeout: 10000 }).catch(()=>{});
await p.goto(`${BASE}/issuer/schema`, { waitUntil: 'domcontentloaded' });
await p.waitForSelector('.schema-card', { timeout: 20000 });
await p.evaluate(() => {
  const c = [...document.querySelectorAll('.schema-card')].find(x => x.dataset.name === 'Mortgage Eligibility');
  const chip = [...(c?.querySelectorAll('.chip.small') || [])].find(x => x.title === 'jwt_vc_json');
  (chip || c)?.click();
});
await p.waitForNetworkIdle({ idleTime: 500 }).catch(()=>{});
await p.goto(`${BASE}/issuer/mode`, { waitUntil: 'domcontentloaded' });
await p.evaluate(() => {
  document.querySelector('input[name="scale"][value="bulk"]').checked = true;
  document.querySelector('input[name="dest"][value="wallet"]').checked = true;
  document.getElementById('mode-form').submit();
});
await p.waitForNavigation({ waitUntil: 'domcontentloaded' }).catch(()=>{});
await p.goto(`${BASE}/issuer/issue`, { waitUntil: 'domcontentloaded' });
await new Promise(r => setTimeout(r, 600));
await p.evaluate(() => {
  const chip = [...document.querySelectorAll('*')].find(el => (el.textContent||'').trim().toLowerCase() === 'database' || (el.getAttribute('hx-vals')||'').includes('"source":"db"'));
  chip?.click();
});
await p.waitForNetworkIdle({ idleTime: 400 }).catch(()=>{});
await p.evaluate((c, q) => {
  const setVal = (sel, v) => { const e = document.querySelector(sel); if (e) { e.value = v; e.dispatchEvent(new Event('input',{bubbles:true})); } };
  setVal('input[name="db_conn"]', c);
  setVal('textarea[name="db_query"], input[name="db_query"]', q);
  (document.querySelector('input[name="db_conn"]')?.closest('form'))?.requestSubmit();
}, CONN, QUERY);
await p.waitForNetworkIdle({ idleTime: 800, timeout: 20000 }).catch(()=>{});
await new Promise(r => setTimeout(r, 1500));
const body = await p.evaluate(() => document.body.innerText);
const m = body.match(/(\d+)\s+rows?\s*·\s*(\d+)\s+accepted/i);
console.log('[d] result:', m ? `rows=${m[1]} accepted=${m[2]}` : 'no banner');
if (!m) console.log('preview:', body.slice(0, 400));
await br.close();
if (!m || m[1] !== m[2] || +m[1] < 1) process.exit(1);
console.log('[d] OK');
