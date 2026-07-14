// Inji auth-code delegated-access COMBINED presentation demo (W3C VCDM 2.0).
// Business Registration Certificate (subject) + Company Director Authority (delegation):
// build+provision -> claim via eSignet -> hold in Inji web wallet -> present pair ->
// AUTHORISED -> revoke director -> DENIED. Issuer=keycloak, eSignet UIN 5500000002/123456.
import { launch, newCtx, login, pickDpg, BASE } from '/pv/helpers.mjs';
import { mkdirSync } from 'fs';
const OUT = '/root/e2e-out/inji-director'; mkdirSync(OUT, { recursive: true });
const uniq = String(Date.now()).slice(-6);
const UIN = '5500000002', PIN = '123456', CLIENT = 'wallet-demo-client';
const API = 'vfly_prov_demo_2026';
const BRN = 'BRN-2024-' + uniq;
const BIZ_NAME = 'Business Registration Certificate', DIR_NAME = 'Company Director Authority';
const BIZ_KEY = 'BusinessRegistrationCertificate', DIR_KEY = 'DirectorAuthority';
const ACTIONS = 'present, execute-contracts, manage-assets, appoint-staff';
const log = (...a) => console.log('[ij]', ...a);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const shot = (p, n) => p.screenshot({ path: `${OUT}/${n}.png`, fullPage: true }).catch(() => {});
const reactSet = async (p, s, v) => p.evaluate(({ s, v }) => { const i = document.querySelector(s); if (!i) return false; const set = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set; set.call(i, v); i.dispatchEvent(new Event('input', { bubbles: true })); i.dispatchEvent(new Event('change', { bubbles: true })); return true; }, { s, v });
const clickText = async (p, t) => { try { for (const e of await p.$$('button')) { let x = ''; try { x = (await e.evaluate((n) => (n.innerText || n.value || '').trim())) || ''; } catch { continue; } if (x && x.toLowerCase().includes(t.toLowerCase())) { try { await e.click({ timeout: 2000 }); return x; } catch {} } } } catch {} return null; };
const R = { bizProv: false, dirProv: false, bizSubj: false, dirSubj: false, held: 0, authorised: null, revoked: false, denied: null };

async function setStdName(page, name) { await page.selectOption('select[name="std"]', 'w3c_vcdm_2').catch(() => {}); await page.waitForTimeout(300); await page.fill('input[name="name"]', name); }
async function saveAndProvision(page, key, name) {
  await page.click('button:has-text("Save & use")').catch(() => page.click('button:has-text("Save")'));
  await sleep(4000);
  for (let i = 0; i < 45; i++) {
    const r = await page.request.get(BASE + '/issuer/schema/ready?key=' + encodeURIComponent(key) + '&name=' + encodeURIComponent(name)).catch(() => null);
    if (r && r.status() === 200) { const body = (await r.text()).trim(); if (body.length < 20) { log('provisioned', key, 'after ~' + (i * 4) + 's'); return true; } }
    await sleep(4000);
  }
  log('provision TIMEOUT', key); return false;
}
async function provisionSubject(ctx, key, claims) {
  const r = await ctx.request.post(BASE + '/api/v1/subjects', { headers: { Authorization: 'Bearer ' + API, 'Content-Type': 'application/json' }, data: JSON.stringify({ individualId: UIN, clientId: CLIENT, credentialConfigKey: key, claims }) });
  const t = await r.text(); log('provision-subject', key, r.status(), t.slice(0, 80)); return r.status() === 200;
}
async function claim(p, cred) {
  await p.goto(BASE + '/holder/wallet/inji/start?cred=' + cred, { waitUntil: 'domcontentloaded' }); await sleep(8000);
  if (/esignet/.test(p.url())) {
    await shot(p, 'claim-esignet-' + cred);
    if (await p.$('#login_with_pin')) { await p.evaluate(() => document.querySelector('#login_with_pin')?.click()); await sleep(3000); }
    if (await reactSet(p, '#Pin_mosip-uin', UIN)) { await reactSet(p, '#Pin_pin', PIN); await sleep(900); await shot(p, 'claim-pin-' + cred); (await clickText(p, 'Login')) || (await clickText(p, 'Verify')); await sleep(9000); }
    (await clickText(p, 'Allow')) || (await clickText(p, 'Proceed')) || (await clickText(p, 'Authorize')) || (await clickText(p, 'Continue')) || (await clickText(p, 'Agree'));
    await p.waitForURL(/verifiably\.in-labs\.cdpi\.dev\/holder\/wallet\/inji/, { timeout: 45000 }).catch(() => {});
  }
  await sleep(2500); log('claimed', cred, p.url());
}
async function buildRequest(vp) {
  await vp.goto(BASE + '/verifier/verify', { waitUntil: 'domcontentloaded' }); await sleep(1500);
  await vp.evaluate(() => { const c = document.querySelector('input[name="delegation"][value="on"]'); if (c && !c.checked) c.click(); }); await sleep(2500);
  for (const name of [DIR_NAME, BIZ_NAME]) {
    await vp.evaluate((n) => { const c = [...document.querySelectorAll('.schema-card')].find((x) => ((x.getAttribute('data-name') || '') + ' ' + (x.textContent || '')).includes(n)); if (c) { const s = c.querySelector('[hx-post="/verifier/verify/build"]') || c.querySelector('button'); (s || c).click(); } }, name);
    await sleep(2200);
  }
  await vp.click('button:has-text("Generate request")').catch(() => {}); await sleep(3500);
  return vp.evaluate(() => { const el = document.querySelector('#oid4vp-output .link-display, #oid4vp-output textarea, #oid4vp-output code'); return el ? (el.textContent || el.value || '').trim() : ''; });
}
async function presentAndVerdict(vp, hp, openid4vp) {
  await hp.goto(BASE + '/holder/wallet/inji/credentials', { waitUntil: 'domcontentloaded' }); await sleep(2000);
  const creds = await hp.evaluate(() => { const o = []; for (const pre of document.querySelectorAll('pre')) { const t = (pre.textContent || '').trim(); if (t.startsWith('{')) { try { const j = JSON.parse(t); if (j.credentialSubject) o.push(j); } catch {} } } return o; });
  const subj = creds.find((c) => (c.type || []).some((t) => /business|subject/i.test(t))), deleg = creds.find((c) => (c.type || []).some((t) => /director|deleg/i.test(t)));
  if (!subj || !deleg) { log('present: missing cred subj?', !!subj, 'deleg?', !!deleg, 'of', creds.length); return 'NO-CREDS'; }
  const ru = new URL(openid4vp.replace(/^openid4vp:\/\//, 'https://x/')).searchParams.get('request_uri');
  const jar = JSON.parse(Buffer.from((await (await hp.request.get(ru)).text()).split('.')[1], 'base64url').toString());
  const ids = (jar.presentation_definition.input_descriptors || []).map((d) => d.id);
  const vpTok = { '@context': ['https://www.w3.org/ns/credentials/v2', 'https://w3id.org/security/suites/ed25519-2020/v1'], type: ['VerifiablePresentation'], holder: subj.credentialSubject.id, verifiableCredential: [subj, deleg] };
  const psub = { id: 'sub-ij', definition_id: jar.presentation_definition.id, descriptor_map: [
    { id: ids[0], format: 'ldp_vp', path: '$', path_nested: { format: 'ldp_vc', path: '$.verifiableCredential[0]' } },
    { id: ids[1], format: 'ldp_vp', path: '$', path_nested: { format: 'ldp_vc', path: '$.verifiableCredential[1]' } }] };
  const sub = await hp.request.post(jar.response_uri, { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, data: new URLSearchParams({ vp_token: JSON.stringify(vpTok), presentation_submission: JSON.stringify(psub), state: jar.state }).toString() });
  log('direct-post', sub.status());
  // poll via the PAGE so the verdict renders in #verify-result for the screenshot
  for (let i = 0; i < 14; i++) {
    await vp.click('#verify-poll-btn').catch(() => {});
    await sleep(2500);
    const t = await vp.evaluate(() => (document.querySelector('#verify-result') || {}).textContent || '');
    if (!/waiting for the holder/i.test(t) && /(authoris|denied)/i.test(t)) return /authoris/i.test(t) ? 'AUTHORISED' : 'DENIED';
  }
  return 'PENDING';
}

const b = await launch();
try {
  // ISSUER: build + provision two auth-code schemas
  const iss = await newCtx(b); const ip = await iss.newPage();
  await login(iss, ip, { role: 'issuer', provider: 'keycloak' }); await pickDpg(ip, 'issuer', 'Inji Certify · Auth-Code');
  if (!process.env.SKIP_BUILD) {
    await ip.goto(BASE + '/issuer/schema/build', { waitUntil: 'domcontentloaded' }); await sleep(1200);
    await setStdName(ip, BIZ_NAME);
    await ip.fill('input[name="field_name_0"]', 'subjectRef').catch(() => {});
    await ip.fill('input[name="field_name_1"]', 'businessName').catch(() => {});
    await sleep(400); await shot(ip, '01-biz-schema');
    R.bizProv = await saveAndProvision(ip, BIZ_KEY, BIZ_NAME);
    await ip.goto(BASE + '/issuer/schema/build', { waitUntil: 'domcontentloaded' }); await sleep(1200);
    await ip.evaluate(() => { const c = document.querySelector('input[name="delegation"]'); if (c && !c.checked) c.click(); }); await sleep(2800);
    await ip.selectOption('select[name="scenario"]', 'director').catch(() => {}); await sleep(2800);
    await setStdName(ip, DIR_NAME);
    await sleep(400); await shot(ip, '02-director-schema');
    R.dirProv = await saveAndProvision(ip, DIR_KEY, DIR_NAME);
  } else { R.bizProv = true; R.dirProv = true; log('SKIP_BUILD — reusing existing configs'); }
  await ip.goto(BASE + '/issuer/schema', { waitUntil: 'domcontentloaded' }); await sleep(1500); await shot(ip, '03-schema-catalog');
  log('provisioned biz', R.bizProv, 'dir', R.dirProv);

  // PROVISION subject data (linked by BRN)
  R.bizSubj = await provisionSubject(iss, BIZ_KEY, { subjectRef: BRN, businessName: 'Acme Trading Ltd' });
  R.dirSubj = await provisionSubject(iss, DIR_KEY, { onBehalfOf: BRN, role: 'Director', allowedAction: ACTIONS, companyRegistrationNumber: BRN });

  // HOLDER: claim both via eSignet
  const hc = await newCtx(b); const hp = await hc.newPage();
  await claim(hp, BIZ_KEY); await claim(hp, DIR_KEY);
  await hp.goto(BASE + '/holder/wallet/inji/credentials', { waitUntil: 'domcontentloaded' }); await sleep(2000);
  R.held = await hp.evaluate(() => document.querySelectorAll('pre').length);
  await shot(hp, '04-holding'); log('held pre-blocks', R.held);

  // VERIFIER: pair request -> present -> AUTHORISED
  const vc = await newCtx(b); const vp = await vc.newPage();
  await login(vc, vp, { role: 'verifier', provider: 'keycloak' }); await pickDpg(vp, 'verifier', 'Inji Verify');
  let req = await buildRequest(vp); await shot(vp, '05-request'); log('request?', /openid4vp/.test(req));
  if (/openid4vp/.test(req)) { R.authorised = await presentAndVerdict(vp, hp, req); await shot(vp, '06-authorised'); }
  log('verdict (valid)', R.authorised);

  // REVOKE the director -> DENIED
  ip.on('dialog', (d) => d.accept());
  await ip.goto(BASE + '/issuer/credentials', { waitUntil: 'domcontentloaded' }); await sleep(2000);
  const rev = await ip.evaluate(({ key, brn }) => { const card = [...document.querySelectorAll('.schema-card')].find((c) => (c.querySelector('h4')?.textContent || '').includes(key) && (c.textContent || '').includes(brn) && !/revoked/i.test(c.querySelector('.pill')?.textContent || '')); if (!card) return 'no-card'; const btn = [...card.querySelectorAll('button')].find((x) => /^\s*Revoke\s*$/.test(x.textContent) && !x.disabled); if (!btn) return 'no-btn'; btn.click(); return 'clicked'; }, { key: DIR_KEY, brn: BRN });
  log('revoke', rev); await sleep(4000); await shot(ip, '07-revoked');
  R.revoked = rev === 'clicked';
  log('waiting ~90s for Certify status republish + cache…'); await sleep(92000);
  let req2 = await buildRequest(vp);
  if (/openid4vp/.test(req2)) { R.denied = await presentAndVerdict(vp, hp, req2); await shot(vp, '08-denied'); }
  log('verdict (revoked)', R.denied);

  log('RESULT ' + JSON.stringify(R));
} catch (e) { log('ERR', e.message, e.stack?.split('\n').slice(0, 4).join(' | ')); }
await b.close();
