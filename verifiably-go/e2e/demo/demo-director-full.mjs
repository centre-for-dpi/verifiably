// Delegated-access COMBINED presentation — full step-by-step demo (walt.id, W3C VCDM 2.0).
// Business Registration Certificate (the company) + Company Director Authority
// (delegated authority to act for that company). Issue -> hold -> present both ->
// AUTHORISED -> revoke the Director -> DENIED.
// Issuer = keycloak (adamk); Holder = WSO2 (adamw, clean wallet); Verifier = keycloak.
import { launch, newCtx, login, pickDpg, BASE } from '/pv/helpers.mjs';
import { mkdirSync } from 'fs';
const OUT = '/root/e2e-out/director-demo'; mkdirSync(OUT, { recursive: true });
const uniq = String(Date.now()).slice(-6);
const BRN = 'BRN-2024-' + uniq;
const BIZ = 'Business Registration Certificate';
const DIR = 'Company Director Authority';
const ACTIONS = process.env.ACTIONS || 'present';
const log = (...a) => console.log('[dm]', ...a);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const shot = (p, n) => p.screenshot({ path: `${OUT}/${n}.png`, fullPage: true }).catch(() => {});
const R = { bizIssued: false, dirIssued: false, held: 0, authorised: null, dirRevoked: false, denied: null };
const b = await launch();

async function saveAndUse(page) {
  await page.click('button:has-text("Save & use")').catch(() => page.click('button:has-text("Save")'));
  await page.waitForURL((u) => new URL(u).pathname === '/issuer/schema', { timeout: 90000 }).catch(() => {});
  await page.waitForTimeout(2500);
}
async function setStdName(page, name) {
  await page.selectOption('select[name="std"]', 'w3c_vcdm_2').catch(() => {});
  await page.waitForTimeout(300);
  await page.fill('input[name="name"]', name);
}
async function issueWallet(page, fields) {
  await page.goto(BASE + '/issuer/mode', { waitUntil: 'domcontentloaded' }); await page.waitForTimeout(800);
  await page.evaluate(() => { for (const [n, v] of [['scale', 'single'], ['dest', 'wallet']]) { const r = document.querySelector(`input[name="${n}"][value="${v}"]`); if (r) { r.checked = true; r.dispatchEvent(new Event('change', { bubbles: true })); const l = r.closest('label'); if (l) l.click(); } } });
  await page.waitForTimeout(400);
  await page.click('#mode-form button[type=submit], button:has-text("Continue")').catch(() => {});
  await page.waitForTimeout(1500);
  if (!/\/issuer\/issue/.test(page.url())) { await page.goto(BASE + '/issuer/issue', { waitUntil: 'domcontentloaded' }); await page.waitForTimeout(1000); }
  for (const [k, v] of Object.entries(fields)) await page.fill(`input[name="field_${k}"]`, v).catch(() => {});
  await page.click('button:has-text("Issue credential")').catch(() => {});
  await page.waitForTimeout(5000);
  return page.evaluate(() => (document.querySelector('#issue-result .link-display') || document.querySelector('.link-display') || {}).textContent?.trim() || '');
}
async function cleanWallet(hp) {
  hp.on('dialog', (d) => d.accept());
  await hp.goto(BASE + '/holder/wallet', { waitUntil: 'domcontentloaded' }); await hp.waitForTimeout(1200);
  for (let i = 0; i < 40; i++) {
    const btn = await hp.$('[data-wallet-card] .wallet-card-btn.del, [data-wallet-card] button[hx-post="/holder/wallet/delete"]');
    if (!btn) break;
    await btn.click().catch(() => {});
    await hp.waitForTimeout(1500);
  }
}
async function hold(hp, offer) {
  if (!offer) return;
  await hp.goto(BASE + '/holder/wallet', { waitUntil: 'domcontentloaded' }); await hp.waitForTimeout(1200);
  await hp.fill('#offer-paste, textarea[name="offer_uri"]', offer);
  await hp.evaluate(() => { const f = document.querySelector('form[hx-post="/holder/wallet/paste"]'); if (f && window.htmx) window.htmx.trigger(f, 'submit'); });
  await hp.waitForTimeout(3500);
  await hp.click('button[hx-post="/holder/wallet/accept"], button:has-text("Accept")').catch(() => {});
  await hp.waitForTimeout(3000);
}
async function buildRequest(vp) {
  await vp.goto(BASE + '/verifier/verify', { waitUntil: 'domcontentloaded' }); await vp.waitForTimeout(1500);
  await vp.evaluate(() => { const c = document.querySelector('input[name="delegation"][value="on"]'); if (c && !c.checked) c.click(); });
  await vp.waitForTimeout(2200);
  await vp.evaluate(() => { const c = document.querySelector('input[name="policy"][value="status-list"]'); if (c && c.checked) c.click(); });
  await vp.waitForTimeout(500);
  for (const tag of [DIR, BIZ]) {
    await vp.evaluate((t) => { const cards = [...document.querySelectorAll('.schema-card')].filter((x) => (x.textContent || '').includes(t)); const c = cards[0]; if (c) { const s = c.querySelector('[hx-post="/verifier/verify/build"]') || c.querySelector('button'); (s || c).click(); } }, tag);
    await vp.waitForTimeout(1800);
  }
  await vp.click('button:has-text("Generate request")').catch(() => {});
  await vp.waitForTimeout(3500);
  return vp.evaluate(() => (document.querySelector('#oid4vp-output .link-display') || {}).textContent?.trim() || '');
}
async function present(hp, req) {
  await hp.goto(BASE + '/holder/present', { waitUntil: 'domcontentloaded' }); await hp.waitForTimeout(1200);
  await hp.fill('textarea[name="request_uri"]', req);
  await hp.click('button:has-text("Review"), button:has-text("send")').catch(() => {});
  await hp.waitForTimeout(2500);
  await hp.click('button:has-text("Disclose")').catch(() => {});
  await hp.waitForTimeout(3500);
}
async function verdict(vp) {
  for (let i = 0; i < 10; i++) { await vp.click('#verify-poll-btn').catch(() => {}); await vp.waitForTimeout(2500); const t = await vp.evaluate(() => (document.querySelector('#verify-result') || {}).textContent || ''); if (/authoris|denied/i.test(t)) break; }
  return vp.evaluate(() => { const el = document.querySelector('#verify-result .verify-result'); const cls = el ? el.className : ''; if (/invalid/.test(cls)) return 'DENIED'; if (/valid/.test(cls)) return 'AUTHORISED'; const t = (document.querySelector('#verify-result') || {}).textContent || ''; return /authoris/i.test(t) ? 'AUTHORISED' : /denied/i.test(t) ? 'DENIED' : 'PENDING'; });
}

// ---- ISSUER (keycloak) ----
const iss = await newCtx(b); const ip = await iss.newPage();
let bizOffer = '', dirOffer = '';
try {
  await login(iss, ip, { role: 'issuer', provider: 'keycloak' });
  await pickDpg(ip, 'issuer', 'Walt Community Stack');
  // Business Registration Certificate
  await ip.goto(BASE + '/issuer/schema/build', { waitUntil: 'domcontentloaded' }); await ip.waitForTimeout(1200);
  await setStdName(ip, BIZ);
  await ip.fill('input[name="field_name_0"]', 'subjectRef').catch(() => {});
  await ip.fill('input[name="field_name_1"]', 'businessName').catch(() => {});
  await ip.waitForTimeout(400); await shot(ip, '01-biz-schema');
  await saveAndUse(ip);
  bizOffer = await issueWallet(ip, { subjectRef: BRN, businessName: 'Acme Trading Ltd' });
  R.bizIssued = !!bizOffer; log('biz issued', R.bizIssued);
  // Company Director Authority (delegation, director scenario)
  await ip.goto(BASE + '/issuer/schema/build', { waitUntil: 'domcontentloaded' }); await ip.waitForTimeout(1200);
  await ip.evaluate(() => { const c = document.querySelector('input[name="delegation"]'); if (c && !c.checked) c.click(); });
  await ip.waitForTimeout(2800);
  await ip.selectOption('select[name="scenario"]', 'director').catch(() => {});
  await ip.waitForTimeout(2800);
  await setStdName(ip, DIR);
  await ip.waitForTimeout(400); await shot(ip, '02-director-schema');
  await saveAndUse(ip);
  dirOffer = await issueWallet(ip, { onBehalfOf: BRN, role: 'Director', allowedAction: ACTIONS, companyRegistrationNumber: BRN });
  R.dirIssued = !!dirOffer; log('dir issued', R.dirIssued);
  await ip.goto(BASE + '/issuer/credentials', { waitUntil: 'domcontentloaded' }); await ip.waitForTimeout(2000);
  await shot(ip, '03-issued');
} catch (e) { log('ISSUER ERR', e.message); await shot(ip, 'zz-issuer'); }

// ---- HOLDER (WSO2, clean wallet) ----
const hol = await newCtx(b); const hp = await hol.newPage();
try {
  await login(hol, hp, { role: 'holder', provider: 'wso2is' });
  await pickDpg(hp, 'holder', 'Walt Community Stack');
  await cleanWallet(hp);
  await hold(hp, bizOffer);
  await hold(hp, dirOffer);
  await hp.goto(BASE + '/holder/wallet', { waitUntil: 'domcontentloaded' }); await hp.waitForTimeout(1500);
  R.held = await hp.$$eval('[data-wallet-card]', (e) => e.length).catch(() => 0);
  log('held', R.held); await shot(hp, '04-holding');
} catch (e) { log('HOLD ERR', e.message); await shot(hp, 'zz-hold'); }

// ---- VERIFIER (keycloak): combined presentation -> AUTHORISED ----
const ver = await newCtx(b); const vp = await ver.newPage();
try {
  await login(ver, vp, { role: 'verifier', provider: 'keycloak' });
  await pickDpg(vp, 'verifier', 'Walt Community Stack');
  let req = await buildRequest(vp); await shot(vp, '05-request');
  if (req) { await present(hp, req); await shot(hp, '06-present'); R.authorised = await verdict(vp); }
  log('verdict (both valid)', R.authorised); await shot(vp, '07-authorised');
} catch (e) { log('VERIFY1 ERR', e.message); await shot(vp, 'zz-verify1'); }

// ---- REVOKE the Director Authority -> DENIED ----
try {
  ip.on('dialog', (d) => d.accept());
  await ip.goto(BASE + '/issuer/credentials', { waitUntil: 'domcontentloaded' }); await ip.waitForTimeout(2000);
  const clicked = await ip.evaluate((name) => {
    const card = [...document.querySelectorAll('.schema-card')].find((c) => (c.querySelector('h4')?.textContent || '').includes(name));
    if (!card) return 'no-card';
    const btn = [...card.querySelectorAll('button')].find((x) => /^\s*Revoke\s*$/.test(x.textContent) && !x.disabled);
    if (!btn) return 'no-btn';
    btn.click(); return 'clicked';
  }, DIR);
  log('revoke click', clicked);
  await ip.waitForTimeout(4000);
  R.dirRevoked = await ip.evaluate((name) => { const c = [...document.querySelectorAll('.schema-card')].find((x) => (x.querySelector('h4')?.textContent || '').includes(name)); return !!c && /revoked/i.test(c.textContent || ''); }, DIR);
  await ip.goto(BASE + '/issuer/credentials', { waitUntil: 'domcontentloaded' }); await ip.waitForTimeout(1500); await shot(ip, '08-revoked');
  log('director revoked', R.dirRevoked);
  await sleep(65000); // status-list TTL
  let req = await buildRequest(vp); await shot(vp, '09-request-2');
  if (req) { await present(hp, req); R.denied = await verdict(vp); }
  log('verdict (director revoked)', R.denied); await shot(vp, '10-denied');
} catch (e) { log('REVOKE ERR', e.message); await shot(vp, 'zz-revoke'); }

log('RESULT ' + JSON.stringify(R));
await b.close();
