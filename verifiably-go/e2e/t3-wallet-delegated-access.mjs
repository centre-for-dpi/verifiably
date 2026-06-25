// E2E: T3 walt.id SD-JWT delegated access via EVALUATE-OVER-WALLET (bypasses the
// walt.id multi-cred SD-JWT present bug). Issue the pair → claim both into the
// walt.id wallet → /holder/wallet/verify-delegation → AUTHORIZED. (Revoke→deny
// needs flat status; walt.id's nested status.status_list is dropped by the
// wallet's field flattening, so this proves AUTHORIZED only.)
import { chromium } from 'playwright';
import crypto from 'crypto';

const WW = process.env.WALT_WALLET || 'https://walt-wallet.in-labs.cdpi.dev';
const HOLDER_UK = process.env.HOLDER_USERKEY || 'keycloak|ee330876-28c8-410f-8b4f-cf0ef28ae7a4';
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const BASE = process.env.BASE || 'https://verifiably.in-labs.cdpi.dev';
const KEY = process.env.API_KEY;
const DPG = 'Walt Community Stack';
const NS = 'urn:person:t3w-' + Date.now();
const log = (...a) => console.log('•', ...a);

async function api(ctx, method, path, body) {
  const res = await ctx.request.fetch(BASE + path, { method, headers: { Authorization: 'Bearer ' + KEY, 'Content-Type': 'application/json' }, data: body ? JSON.stringify(body) : undefined, timeout: 90000 });
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
  const tok = (await (await ctx.request.post(WW + '/wallet-api/auth/login', { data: { email, password: pass, type: 'email' }, timeout: 30000 })).json()).token;
  const ws = await (await ctx.request.get(WW + '/wallet-api/wallet/accounts/wallets', { headers: { Authorization: 'Bearer ' + tok } })).json();
  const wid = ws.wallets[0].id;
  const creds = await (await ctx.request.get(WW + `/wallet-api/wallet/${wid}/credentials`, { headers: { Authorization: 'Bearer ' + tok } })).json();
  for (const c of creds) await ctx.request.delete(WW + `/wallet-api/wallet/${wid}/credentials/${c.id}?permanent=true`, { headers: { Authorization: 'Bearer ' + tok } });
  log(`cleaned wallet (${creds.length} removed)`);
}

(async () => {
  const browser = await chromium.launch({ args: ['--no-sandbox'] });
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await ctx.newPage();
  try {
    const issue = await api(ctx, 'POST', '/api/v1/delegation/issue', {
      issuerDpg: DPG, std: 'sd_jwt_vc (IETF)',
      subject: { type: 'BirthCertificate', subjectRef: NS, claims: { givenName: 'Maria' }, validUntil: '2033-03-10T00:00:00Z' },
      delegation: { type: 'DelegatedAccessCredential', role: 'Mother', allowedAction: ['present', 'consent:disclose'], validUntil: '2033-03-10T00:00:00Z' },
    });
    if (issue.status !== 201) fail('issue ' + issue.status + ' ' + issue.text);
    log('issued T3 sd-jwt pair');

    await page.goto(BASE + '/', { waitUntil: 'domcontentloaded' });
    await form(ctx, '/role', { role: 'holder' });
    const start = await form(ctx, '/auth/start', { provider: 'keycloak' });
    const authURL = start.headers['hx-redirect'] || start.headers['location'];
    await page.goto(authURL, { waitUntil: 'domcontentloaded' });
    await page.fill('#username', process.env.KC_USER || 'admin@cdpi.dev');
    await page.fill('#password', process.env.KC_PASS || 'changeme');
    await Promise.all([page.waitForURL(u => u.toString().includes(new URL(BASE).host), { timeout: 30000 }), page.click('#kc-login, input[type=submit], button[type=submit]')]);
    await form(ctx, '/holder/dpg/toggle', { vendor: DPG });
    await form(ctx, '/holder/dpg', {});
    log('holder logged in');
    await cleanWallet(ctx);
    async function claim(offer, label) {
      const p = await form(ctx, '/holder/wallet/paste', { offer_uri: offer });
      const m = p.text.match(/hx-vals='\{"id":\s*"([^"]+)"\}'/);
      if (!m) fail('no pending id (' + label + ')');
      const acc = await form(ctx, '/holder/wallet/accept', { id: m[1] });
      log('claimed ' + label + ' accept→' + acc.status);
    }
    await claim(issue.json.subject.offerUri, 'subject');
    await claim(issue.json.delegation.offerUri, 'delegation');

    const v = await (await ctx.request.get(BASE + '/holder/wallet/verify-delegation', { timeout: 30000 })).json();
    log('verdict ' + JSON.stringify(v));
    const d = v.delegation || {};
    if (d.Authorized !== true) fail('expected AUTHORIZED, got ' + JSON.stringify(d));
    console.log('\n✅ T3 walt.id SD-JWT AUTHORIZED via evaluate-over-wallet (linkage=' + d.Linkage + ' invocation=' + d.Invocation + ' capability=' + d.Capability + ')');
  } catch (e) {
    console.error('ERROR:', e.message); process.exitCode = 1;
  } finally { await browser.close(); }
})();
