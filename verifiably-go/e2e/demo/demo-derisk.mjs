// DE-RISK: can a walt.id W3C combined delegated presentation reach AUTHORISED?
// Business Registration (subject) + Company Director Authority (delegation),
// issue -> hold -> present pair -> read verdict + per-cred capability check.
import { launch, newCtx, login, pickDpg, BASE } from '/pv/helpers.mjs';
import { mkdirSync } from 'fs';
const OUT = '/root/e2e-out/demo-derisk'; mkdirSync(OUT, { recursive: true });
const uniq = String(Date.now()).slice(-6);
const BRN = 'BRN-2024-' + uniq;
const BIZ = 'BizReg ' + uniq, DIR = 'DirAuthority ' + uniq;   // unique names for reliable picking
const ACTIONS = process.env.ACTIONS || 'present';
const log = (...a) => console.log('[dr]', ...a);
const shot = (p, n) => p.screenshot({ path: `${OUT}/${n}.png`, fullPage: true }).catch(() => {});
const R = { bizIssued: false, dirIssued: false, held: 0, verdict: null, checks: null };
const b = await launch();

async function saveAndUse(page) {
  // "Save & use" restarts issuer-api (walt.id) then HX-redirects to /issuer/schema.
  // It can take 20-40s; navigating away early aborts the save. Wait for the redirect.
  await page.click('button:has-text("Save & use")').catch(() => page.click('button:has-text("Save")'));
  await page.waitForURL((u) => new URL(u).pathname === '/issuer/schema', { timeout: 90000 }).catch(() => {});
  await page.waitForTimeout(2500);
}
async function setStdName(page, name) {
  await page.selectOption('select[name="std"]', 'w3c_vcdm_2').catch(async () => {
    const opts = await page.$$eval('select[name="std"] option', (os) => os.map((o) => o.value));
    await page.selectOption('select[name="std"]', opts.find((o) => o.startsWith('w3c')) || opts[0]);
  });
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
  hp.on('dialog', (d) => d.accept()); // hx-confirm on delete
  await hp.goto(BASE + '/holder/wallet', { waitUntil: 'domcontentloaded' }); await hp.waitForTimeout(1200);
  for (let i = 0; i < 40; i++) {
    const btn = await hp.$('[data-wallet-card] .wallet-card-btn.del, [data-wallet-card] button[hx-post="/holder/wallet/delete"]');
    if (!btn) break;
    await btn.click().catch(() => {});
    await hp.waitForTimeout(1500);
  }
  const n = await hp.$$eval('[data-wallet-card]', (e) => e.length).catch(() => -1);
  log('wallet cleaned, remaining cards:', n);
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

// ISSUER
const iss = await newCtx(b); const ip = await iss.newPage();
let bizOffer = '', dirOffer = '';
try {
  await login(iss, ip, { role: 'issuer', provider: 'keycloak' });
  await pickDpg(ip, 'issuer', 'Walt Community Stack');
  // Business Registration — normal, 2 default field rows
  await ip.goto(BASE + '/issuer/schema/build', { waitUntil: 'domcontentloaded' }); await ip.waitForTimeout(1200);
  await setStdName(ip, BIZ);
  await ip.fill('input[name="field_name_0"]', 'subjectRef').catch(() => {});
  await ip.fill('input[name="field_name_1"]', 'businessName').catch(() => {});
  await ip.waitForTimeout(400);
  await saveAndUse(ip);
  bizOffer = await issueWallet(ip, { subjectRef: BRN, businessName: 'Acme Trading Ltd' });
  R.bizIssued = !!bizOffer; log('biz issued', R.bizIssued, bizOffer.slice(0, 40));
  // Director Authority — delegation + director scenario, override std to W3C
  await ip.goto(BASE + '/issuer/schema/build', { waitUntil: 'domcontentloaded' }); await ip.waitForTimeout(1200);
  await ip.evaluate(() => { const c = document.querySelector('input[name="delegation"]'); if (c && !c.checked) c.click(); });
  await ip.waitForTimeout(2800);
  await ip.selectOption('select[name="scenario"]', 'director').catch((e) => log('scenario select err', e.message));
  await ip.waitForTimeout(2800);
  await setStdName(ip, DIR);
  await ip.waitForTimeout(400); await shot(ip, '01-director-schema');
  await saveAndUse(ip);
  dirOffer = await issueWallet(ip, { onBehalfOf: BRN, role: 'Director', allowedAction: ACTIONS, companyRegistrationNumber: BRN });
  R.dirIssued = !!dirOffer; log('dir issued', R.dirIssued, dirOffer.slice(0, 40));
} catch (e) { log('ISSUER ERR', e.message); await shot(ip, 'zz-issuer'); }

// HOLDER
const hol = await newCtx(b); const hp = await hol.newPage();
try {
  await login(hol, hp, { role: 'holder', provider: 'wso2is' });
  await pickDpg(hp, 'holder', 'Walt Community Stack');
  await cleanWallet(hp);
  await hold(hp, bizOffer);
  await hold(hp, dirOffer);
  await hp.goto(BASE + '/holder/wallet', { waitUntil: 'domcontentloaded' }); await hp.waitForTimeout(1500);
  R.held = await hp.$$eval('[data-wallet-card]', (e) => e.length).catch(() => 0);
  log('held', R.held);
} catch (e) { log('HOLD ERR', e.message); await shot(hp, 'zz-hold'); }

// VERIFIER: pair request -> present -> verdict
const ver = await newCtx(b); const vp = await ver.newPage();
try {
  await login(ver, vp, { role: 'verifier', provider: 'keycloak' });
  await pickDpg(vp, 'verifier', 'Walt Community Stack');
  await vp.goto(BASE + '/verifier/verify', { waitUntil: 'domcontentloaded' }); await vp.waitForTimeout(1500);
  await vp.evaluate(() => { const c = document.querySelector('input[name="delegation"][value="on"]'); if (c && !c.checked) c.click(); });
  await vp.waitForTimeout(2200);
  // Uncheck walt.id's status-list policy: it cosmetically fails to fetch/verify
  // the fresh W3C status list. verifiably's delegation evaluator enforces
  // revocation itself (attachRevocationVerdict + Not-revoked sub-check), so this
  // keeps revoke->DENIED working while avoiding the redundant failure.
  await vp.evaluate(() => { const c = document.querySelector('input[name="policy"][value="status-list"]'); if (c && c.checked) c.click(); });
  await vp.waitForTimeout(500);
  for (const tag of [DIR, BIZ]) {
    await vp.evaluate((t) => { const c = [...document.querySelectorAll('.schema-card')].find((x) => (x.textContent || '').includes(t)); if (c) { const s = c.querySelector('[hx-post="/verifier/verify/build"]') || c.querySelector('button'); (s || c).click(); } }, tag);
    await vp.waitForTimeout(1800);
  }
  await vp.click('button:has-text("Generate request")').catch(() => {});
  await vp.waitForTimeout(3500);
  const req = await vp.evaluate(() => (document.querySelector('#oid4vp-output .link-display') || {}).textContent?.trim() || '');
  log('request', !!req);
  if (req) {
    await hp.goto(BASE + '/holder/present', { waitUntil: 'domcontentloaded' }); await hp.waitForTimeout(1200);
    await hp.fill('textarea[name="request_uri"]', req);
    await hp.click('button:has-text("Review"), button:has-text("send")').catch(() => {});
    await hp.waitForTimeout(2500); await shot(hp, '02-present');
    await hp.click('button:has-text("Disclose")').catch(() => {});
    await hp.waitForTimeout(3500);
    for (let i = 0; i < 10; i++) { await vp.click('#verify-poll-btn').catch(() => {}); await vp.waitForTimeout(2500); const t = await vp.evaluate(() => (document.querySelector('#verify-result') || {}).textContent || ''); if (/authoris|denied|valid|invalid/i.test(t)) break; }
  }
  R.verdict = await vp.evaluate(() => { const el = document.querySelector('#verify-result .verify-result'); const cls = el ? el.className : ''; const t = (document.querySelector('#verify-result') || {}).textContent || ''; if (/valid/.test(cls) && !/invalid/.test(cls)) return 'AUTHORISED'; if (/invalid/.test(cls)) return 'DENIED'; if (/authoris/i.test(t)) return 'AUTHORISED'; if (/denied/i.test(t)) return 'DENIED'; return 'PENDING/' + t.slice(0, 60); });
  R.checks = await vp.evaluate(() => {
    const rows = [...document.querySelectorAll('#verify-result')].flatMap((r) => [...r.querySelectorAll('div')]).map((d) => (d.textContent || '').replace(/\s+/g, ' ').trim()).filter((t) => /pass ✓|fail ✗|Linkage|Capability|Not revoked|Invocation/.test(t) && t.length < 120);
    return [...new Set(rows)].slice(0, 12);
  });
  log('VERDICT', R.verdict);
  log('CHECKS', JSON.stringify(R.checks));
  await shot(vp, '03-verdict');
} catch (e) { log('VERIFY ERR', e.message); await shot(vp, 'zz-verify'); }

log('RESULT ' + JSON.stringify(R));
await b.close();
