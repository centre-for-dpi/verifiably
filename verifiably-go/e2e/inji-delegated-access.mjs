// E2E: inji AUTH-CODE delegated access, full loop. Setup (configs + mock-identity
// + provision) → claim the subject + delegation creds via the in-app eSignet PIN
// flow (one session) → evaluate the held pair (AUTHORIZED) → revoke → DENIED.
import { chromium } from 'playwright';

const BASE = process.env.BASE || 'https://verifiably.in-labs.cdpi.dev';
const KEY = process.env.API_KEY;
const PIN = process.env.PIN || '123456';
const ID = process.env.INDIVIDUAL_ID || String(Date.now()).slice(-10);
const SUBJ = process.env.SUBJECT_CRED || 'BirthCertificate';
const DELEG = process.env.DELEGATION_CRED || 'DelegationCert';
const log = (...a) => console.log('•', ...a);

const browser = await chromium.launch({ headless: true, args: ['--no-sandbox', '--ignore-certificate-errors'] });
const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
const page = await ctx.newPage();
const shot = (n) => page.screenshot({ path: `/out/inji-${n}.png`, fullPage: true }).catch(() => {});

async function api(method, path, body) {
  const res = await ctx.request.fetch(BASE + path, {
    method, headers: { Authorization: 'Bearer ' + KEY, 'Content-Type': 'application/json' },
    data: body ? JSON.stringify(body) : undefined, timeout: 180000,
  });
  let json; const t = await res.text(); try { json = JSON.parse(t); } catch {}
  return { status: res.status(), json, text: t };
}

async function claim(cred) {
  await page.goto(BASE + '/holder/wallet/inji/start?cred=' + cred, { waitUntil: 'domcontentloaded', timeout: 45000 });
  await page.waitForTimeout(4000);
  const idIn = await page.$('input[type=text]:not([readonly]),input[type=tel],input[type=number]');
  if (idIn) {
    await idIn.fill(ID);
    await page.waitForTimeout(500);
    const pinIn = await page.$('input[type=password],input[placeholder*="PIN" i],input[name*="pin" i]');
    if (pinIn) await pinIn.fill(PIN);
    await page.waitForTimeout(600);
    for (let t = 0; t < 12; t++) {
      const done = await page.evaluate(() => { const b = [...document.querySelectorAll('button')].find(x => /^\s*login\s*$|verify|^submit$|continue/i.test(x.innerText || '') && !x.disabled && !/get otp|resend|sign ?up/i.test(x.innerText || '')); if (b) { b.click(); return true; } return false; });
      if (done) break;
      await page.waitForTimeout(1000);
    }
    await page.waitForTimeout(4000);
  }
  await page.evaluate(() => { const b = [...document.querySelectorAll('button')].find(x => /allow|consent|agree|authorize|proceed|accept/i.test(x.innerText || '') && !x.disabled && !/cancel|deny/i.test(x.innerText || '')); if (b) b.click(); });
  await page.waitForURL(/verifiably\.in-labs\.cdpi\.dev\/holder\/wallet\/inji/, { timeout: 45000 }).catch(() => {});
  await page.waitForTimeout(2500);
  await shot('claimed-' + cred);
  log('claimed ' + cred + ' -> ' + page.url().replace(/[?#].*/, ''));
}

async function verifyDelegation() {
  const r = await ctx.request.get(BASE + '/holder/wallet/inji/verify-delegation', { timeout: 30000 });
  return r.json();
}

let code = 0;
try {
  // ---- 0. setup: configs + mock-identity + provision (+ a revocation slot) ----
  const setup = await api('POST', '/api/v1/delegation/inji/setup', {
    individualId: ID, pin: PIN, subjectRef: 'urn:person:inji-' + ID, delegationType: DELEG,
    givenName: 'Maria', role: 'Mother', allowedAction: ['present', 'consent:disclose'], validUntil: '2033-03-10T00:00:00Z',
  });
  if (setup.status !== 201) { console.error('✗ setup', setup.status, setup.text); process.exit(1); }
  const statusIdx = setup.json.statusListIndex;
  log('setup ok; holder=' + ID + ' statusIdx=' + statusIdx);

  // ---- 1. claim both via eSignet PIN (one session) ----
  await claim(SUBJ);
  await claim(DELEG);

  // ---- 2. evaluate → AUTHORIZED ----
  const v1 = await verifyDelegation();
  log('verdict#1 ' + JSON.stringify(v1));
  const d1 = v1.delegation || {};
  if (v1.credentialCount < 2 || d1.Authorized !== true) { console.error('✗ expected AUTHORIZED with 2 creds'); code = 1; throw new Error('not authorized'); }
  log('✓ AUTHORIZED (linkage=' + d1.Linkage + ' invocation=' + d1.Invocation + ' capability=' + d1.Capability + ' notRevoked=' + d1.NotRevoked + ')');

  // ---- 3. revoke → DENIED ----
  const rev = await api('POST', '/api/v1/delegation/inji/revoke', { index: statusIdx });
  log('revoke → ' + rev.status + ' ' + (rev.text || '').slice(0, 60));
  const v2 = await verifyDelegation();
  log('verdict#2 ' + JSON.stringify(v2));
  const d2 = v2.delegation || {};
  if (d2.Authorized === true) { console.error('✗ expected DENIED after revoke'); code = 1; throw new Error('still authorized'); }
  log('✓ DENIED after revoke (reason: ' + d2.Reason + ')');

  console.log('\n✅ INJI AUTH-CODE DELEGATION E2E PASSED: setup → claim → AUTHORIZED → revoke → DENIED');
} catch (e) {
  console.error('ERROR:', e.message); await shot('error'); code = 1;
} finally {
  await browser.close();
  process.exitCode = code;
}
