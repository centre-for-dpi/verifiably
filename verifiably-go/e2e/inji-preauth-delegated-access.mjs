// E2E: inji PRE-AUTH delegated access. Issue a pre-authorized pair → claim both
// offers into the walt.id wallet → evaluate-over-wallet (AUTHORIZED) → revoke →
// DENIED. (The walt.id wallet can't build a multi-cred SD-JWT VP, so verify reads
// the held creds and runs the same evaluator.)
import { chromium } from 'playwright';
import crypto from 'crypto';

const WW = process.env.WALT_WALLET || 'https://walt-wallet.in-labs.cdpi.dev';
const HOLDER_UK = process.env.HOLDER_USERKEY || 'keycloak|ee330876-28c8-410f-8b4f-cf0ef28ae7a4';
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const BASE = process.env.BASE || 'https://verifiably.in-labs.cdpi.dev';
const KEY = process.env.API_KEY;
const DPG = 'Walt Community Stack';
const NS = 'urn:person:preauth-' + Date.now();
const log = (...a) => console.log('•', ...a);

async function api(ctx, method, path, body) {
  const res = await ctx.request.fetch(BASE + path, {
    method, headers: { Authorization: 'Bearer ' + KEY, 'Content-Type': 'application/json' },
    data: body ? JSON.stringify(body) : undefined, timeout: 90000,
  });
  let json; const t = await res.text(); try { json = JSON.parse(t); } catch {}
  return { status: res.status(), json, text: t };
}
async function form(ctx, path, fields) {
  const res = await ctx.request.post(BASE + path, { form: fields, timeout: 60000, maxRedirects: 0 }).catch(e => e);
  return { status: res.status ? res.status() : 0, text: res.text ? await res.text() : '', headers: res.headers ? res.headers() : {} };
}
const fail = (m) => { console.error('✗ FAIL:', m); process.exitCode = 1; throw new Error(m); };

async function cleanWallet(ctx) {
  const email = 'u-' + sha(HOLDER_UK).slice(0, 16) + '@verifiably-demo.local';
  const pass = 'pw-' + sha('verifiably|' + HOLDER_UK);
  const login = await ctx.request.post(WW + '/wallet-api/auth/login', { data: { email, password: pass, type: 'email' }, timeout: 30000 });
  const tok = (await login.json()).token;
  const ws = await (await ctx.request.get(WW + '/wallet-api/wallet/accounts/wallets', { headers: { Authorization: 'Bearer ' + tok } })).json();
  const wid = ws.wallets[0].id;
  const creds = await (await ctx.request.get(WW + `/wallet-api/wallet/${wid}/credentials`, { headers: { Authorization: 'Bearer ' + tok } })).json();
  for (const c of creds) await ctx.request.delete(WW + `/wallet-api/wallet/${wid}/credentials/${c.id}?permanent=true`, { headers: { Authorization: 'Bearer ' + tok } });
  log(`cleaned wallet (${creds.length} pre-existing creds removed)`);
}

(async () => {
  const browser = await chromium.launch({ args: ['--no-sandbox'] });
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await ctx.newPage();
  try {
    // ---- 0. issue the pre-auth delegation pair ----
    const issue = await api(ctx, 'POST', '/api/v1/delegation/inji/preauth/issue', {
      subjectRef: NS, givenName: 'Maria', role: 'Mother',
      allowedAction: ['present', 'consent:disclose'], validUntil: '2033-03-10T00:00:00Z',
    });
    if (issue.status !== 201) fail('issue ' + issue.status + ' ' + issue.text);
    const offer1 = issue.json.subject.offerUri, offer2 = issue.json.delegation.offerUri, statusIdx = issue.json.statusListIndex;
    log('issued pre-auth pair; statusIdx=' + statusIdx);

    // ---- 1. login as holder (Keycloak) + pick DPG = walt.id ----
    await page.goto(BASE + '/', { waitUntil: 'domcontentloaded' });
    await form(ctx, '/role', { role: 'holder' });
    const start = await form(ctx, '/auth/start', { provider: 'keycloak' });
    const authURL = start.headers['hx-redirect'] || start.headers['location'];
    if (!authURL) fail('no authorize URL');
    await page.goto(authURL, { waitUntil: 'domcontentloaded' });
    await page.fill('#username', process.env.KC_USER || 'admin@cdpi.dev');
    await page.fill('#password', process.env.KC_PASS || 'changeme');
    await Promise.all([
      page.waitForURL(u => u.toString().includes(new URL(BASE).host), { timeout: 30000 }),
      page.click('#kc-login, input[type=submit], button[type=submit]'),
    ]);
    await form(ctx, '/holder/dpg/toggle', { vendor: DPG });
    await form(ctx, '/holder/dpg', {});
    const wallet0 = await ctx.request.get(BASE + '/holder/wallet', { maxRedirects: 0 });
    if (wallet0.status() === 303) fail('holder DPG not set');
    log('holder logged in; DPG=' + DPG);

    // ---- 2. clean wallet, claim both offers ----
    await cleanWallet(ctx);
    async function claim(offer, label) {
      const p = await form(ctx, '/holder/wallet/paste', { offer_uri: offer });
      const m = p.text.match(/hx-vals='\{"id":\s*"([^"]+)"\}'/);
      if (!m) fail('no pending offer id (' + label + '): ' + p.text.slice(0, 300));
      const acc = await form(ctx, '/holder/wallet/accept', { id: m[1] });
      log('claimed ' + label + ' accept→' + acc.status);
    }
    await claim(offer1, 'subject');
    await claim(offer2, 'delegation');

    // ---- 3. evaluate-over-wallet → AUTHORIZED ----
    async function verify() { return (await ctx.request.get(BASE + '/holder/wallet/verify-delegation', { timeout: 30000 })).json(); }
    const v1 = await verify();
    log('verdict#1 ' + JSON.stringify(v1));
    const d1 = v1.delegation || {};
    if (d1.Authorized !== true) fail('expected AUTHORIZED, got ' + JSON.stringify(d1));
    log('✓ AUTHORIZED (linkage=' + d1.Linkage + ' invocation=' + d1.Invocation + ' capability=' + d1.Capability + ' notRevoked=' + d1.NotRevoked + ')');

    // ---- 4. revoke → DENIED ----
    const rev = await api(ctx, 'POST', '/api/v1/delegation/inji/revoke', { index: statusIdx });
    log('revoke → ' + rev.status);
    const v2 = await verify();
    log('verdict#2 ' + JSON.stringify(v2));
    if ((v2.delegation || {}).Authorized === true) fail('expected DENIED after revoke');
    log('✓ DENIED after revoke (reason: ' + (v2.delegation || {}).Reason + ')');

    console.log('\n✅ INJI PRE-AUTH DELEGATION E2E PASSED: issue → claim → AUTHORIZED → revoke → DENIED');
  } catch (e) {
    console.error('ERROR:', e.message);
    try { await page.screenshot({ path: '/out/preauth-fail.png', fullPage: true }); } catch {}
    process.exitCode = 1;
  } finally {
    await browser.close();
  }
})();
