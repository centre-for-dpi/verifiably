import { chromium } from 'playwright';
import crypto from 'crypto';

const WW = process.env.WALT_WALLET || 'https://walt-wallet.in-labs.cdpi.dev';
const HOLDER_UK = process.env.HOLDER_USERKEY || 'keycloak|ee330876-28c8-410f-8b4f-cf0ef28ae7a4';
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const BASE = process.env.BASE || 'https://verifiably.in-labs.cdpi.dev';
const KEY = process.env.API_KEY;
const DPG = 'Walt Community Stack';
const NS = 'urn:person:child-e2e-' + Date.now();
const log = (...a) => console.log('•', ...a);

async function api(ctx, method, path, body) {
  const res = await ctx.request.fetch(BASE + path, {
    method,
    headers: { Authorization: 'Bearer ' + KEY, 'Content-Type': 'application/json' },
    data: body ? JSON.stringify(body) : undefined,
    timeout: 90000,
  });
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch {}
  return { status: res.status(), json, text };
}

async function form(ctx, path, fields) {
  const res = await ctx.request.post(BASE + path, { form: fields, timeout: 60000, maxRedirects: 0 }).catch(e => e);
  const status = res.status ? res.status() : 0;
  let text = ''; try { text = await res.text(); } catch {}
  return { status, text, headers: res.headers ? res.headers() : {} };
}

const fail = (m) => { console.error('✗ FAIL:', m); process.exitCode = 1; throw new Error(m); };

// cleanWallet removes any accumulated credentials from the holder's walt.id
// wallet so each run starts clean (the shared wallet otherwise carries pairs
// from prior runs, which would let selectPerDescriptor pick a mismatched pair).
async function cleanWallet(ctx) {
  const email = 'u-' + sha(HOLDER_UK).slice(0, 16) + '@verifiably-demo.local';
  const pass = 'pw-' + sha('verifiably|' + HOLDER_UK);
  const login = await ctx.request.post(WW + '/wallet-api/auth/login', { data: { email, password: pass, type: 'email' }, timeout: 30000 });
  const tok = (await login.json()).token;
  const ws = await (await ctx.request.get(WW + '/wallet-api/wallet/accounts/wallets', { headers: { Authorization: 'Bearer ' + tok } })).json();
  const wid = ws.wallets[0].id;
  const creds = await (await ctx.request.get(WW + `/wallet-api/wallet/${wid}/credentials`, { headers: { Authorization: 'Bearer ' + tok } })).json();
  for (const c of creds) {
    await ctx.request.delete(WW + `/wallet-api/wallet/${wid}/credentials/${c.id}?permanent=true`, { headers: { Authorization: 'Bearer ' + tok } });
  }
  log(`cleaned wallet (${creds.length} pre-existing creds removed)`);
}

(async () => {
  const browser = await chromium.launch({ args: ['--no-sandbox'] });
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await ctx.newPage();
  try {
    // ---- 0. issue a fresh delegation pair (API) ----
    const issue = await api(ctx, 'POST', '/api/v1/delegation/issue', {
      issuerDpg: DPG,
      subject: { type: 'BirthCertificate', subjectDid: 'did:example:child-e2e', subjectRef: NS, claims: { givenName: 'Maria' }, validUntil: '2033-03-10T00:00:00Z' },
      delegation: { type: 'DelegatedAccessCredential', role: 'Mother', allowedAction: ['present', 'consent:disclose'], validUntil: '2033-03-10T00:00:00Z' },
    });
    if (issue.status !== 201) fail('issue ' + issue.status + ' ' + issue.text);
    const offer1 = issue.json.subject.offerUri, offer2 = issue.json.delegation.offerUri, delegId = issue.json.delegation.credentialId;
    log('issued pair; delegId=' + delegId + ' statusIdx=' + issue.json.statusListIndex);

    // ---- 1. login as holder via Keycloak (OIDC) ----
    await page.goto(BASE + '/', { waitUntil: 'domcontentloaded' });
    await form(ctx, '/role', { role: 'holder' });
    const start = await form(ctx, '/auth/start', { provider: 'keycloak' });
    const authURL = start.headers['hx-redirect'] || start.headers['location'];
    if (!authURL) fail('no authorize URL from /auth/start (status ' + start.status + ') ' + start.text.slice(0, 200));
    log('authorize →', authURL.slice(0, 70));
    await page.goto(authURL, { waitUntil: 'domcontentloaded' });
    await page.fill('#username', process.env.KC_USER || 'admin@cdpi.dev');
    await page.fill('#password', process.env.KC_PASS || 'changeme');
    await Promise.all([
      page.waitForURL(u => u.toString().includes(new URL(BASE).host), { timeout: 30000 }),
      page.click('#kc-login, input[type=submit], button[type=submit]'),
    ]);
    await page.waitForLoadState('domcontentloaded');
    log('back on verifiably →', page.url());

    // ---- 2. pick holder DPG = Walt Community Stack ----
    await form(ctx, '/holder/dpg/toggle', { vendor: DPG });
    await form(ctx, '/holder/dpg', {});
    const wallet0 = await ctx.request.get(BASE + '/holder/wallet', { maxRedirects: 0 });
    log('holder/wallet after DPG pick →', wallet0.status());
    if (wallet0.status() === 303) fail('holder DPG not set (still redirecting)');

    // ---- 2b. clean the shared wallet so this run is deterministic ----
    await cleanWallet(ctx);

    // ---- 3. claim both offers (paste → accept) ----
    async function claim(offer, label) {
      const p = await form(ctx, '/holder/wallet/paste', { offer_uri: offer });
      const m = p.text.match(/hx-vals='\{"id":\s*"([^"]+)"\}'/);
      if (!m) fail('no pending offer id after paste (' + label + '): ' + p.text.slice(0, 300));
      const acc = await form(ctx, '/holder/wallet/accept', { id: m[1] });
      log('claimed ' + label + ' (id=' + m[1] + ') accept→' + acc.status);
    }
    await claim(offer1, 'BirthCertificate');
    await claim(offer2, 'DelegatedAccessCredential');

    // ---- helper: create verify request, present, poll verdict ----
    async function verifyOnce() {
      const vr = await api(ctx, 'POST', '/api/v1/delegation/verify/request', { verifierDpg: DPG });
      if (vr.status !== 200) fail('verify/request ' + vr.status + ' ' + vr.text);
      const reqUri = vr.json.requestUri, state = vr.json.state;
      // credential_id must be non-empty to pass SubmitPresent's guard; the
      // multi-present logic ignores it when the PD has >1 descriptor.
      const sub = await form(ctx, '/holder/present/submit', { request_uri: reqUri, credential_id: 'pair' });
      log('present submit →', sub.status);
      let verdict = null;
      for (let i = 0; i < 10; i++) {
        const r = await api(ctx, 'GET', '/api/v1/delegation/verify/result/' + encodeURIComponent(state));
        if (r.json && (r.json.delegation || r.json.valid !== undefined) && !r.json.pending) { verdict = r.json; break; }
        await new Promise(res => setTimeout(res, 1500));
      }
      return verdict;
    }

    // ---- 4. present the pair → expect AUTHORIZED ----
    const v1 = await verifyOnce();
    log('verdict#1', JSON.stringify(v1));
    if (!v1 || !v1.delegation || v1.delegation.Authorized !== true) fail('expected delegation authorized, got ' + JSON.stringify(v1));
    log('✓ AUTHORIZED (linkage=' + v1.delegation.Linkage + ' capability=' + v1.delegation.Capability + ' notRevoked=' + v1.delegation.NotRevoked + ')');

    // ---- 5. revoke the delegation, present again → expect DENIED ----
    const rev = await api(ctx, 'POST', '/api/v1/credentials/' + delegId + '/revoke');
    log('revoke →', rev.status);
    const v2 = await verifyOnce();
    log('verdict#2', JSON.stringify(v2));
    if (!v2 || !v2.delegation) fail('no verdict after revoke: ' + JSON.stringify(v2));
    if (v2.delegation.Authorized === true) fail('expected DENIED after revoke, got authorized');
    log('✓ DENIED after revoke (reason: ' + v2.delegation.Reason + ')');

    console.log('\n✅ E2E PASSED: issue → claim → present → AUTHORIZED → revoke → present → DENIED');
  } catch (e) {
    console.error('ERROR:', e.message);
    try { await page.screenshot({ path: '/out/da-e2e-fail.png', fullPage: true }); console.error('screenshot: /out/da-e2e-fail.png'); } catch {}
    process.exitCode = 1;
  } finally {
    await browser.close();
  }
})();
