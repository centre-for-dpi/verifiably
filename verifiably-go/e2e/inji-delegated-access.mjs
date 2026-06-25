// E2E: inji AUTH-CODE delegated access. Claim the subject + delegation creds via
// the in-app eSignet OTP flow (one session), then evaluate the held pair.
import { chromium } from 'playwright';

const BASE = process.env.BASE || 'https://verifiably.in-labs.cdpi.dev';
const ID = process.env.INDIVIDUAL_ID || '9876543210';
const PIN = process.env.PIN || '123456';
const SUBJ = process.env.SUBJECT_CRED || 'BirthCertificate';
const DELEG = process.env.DELEGATION_CRED || 'DelegatedAccessCredential';
const log = (...a) => console.log('•', ...a);

const browser = await chromium.launch({ headless: true, args: ['--no-sandbox', '--ignore-certificate-errors'] });
const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
const page = await ctx.newPage();
const shot = (n) => page.screenshot({ path: `/out/inji-${n}.png`, fullPage: true }).catch(() => {});

async function claim(cred) {
  await page.goto(BASE + '/holder/wallet/inji/start?cred=' + cred, { waitUntil: 'domcontentloaded', timeout: 45000 });
  await page.waitForTimeout(4000);
  // pick the OTP login method if the method tiles are shown
  await page.evaluate(() => { const e = [...document.querySelectorAll('button,a,div,span,[role=button]')].find(x => x.offsetParent !== null && /login with otp/i.test(x.innerText || '') && !/sign ?up|inji/i.test(x.innerText || '') && (x.innerText || '').trim().length < 40); if (e) e.click(); });
  await page.waitForTimeout(4000);
  // PIN login: fill UIN/VID + PIN, click Login (skipped on eSignet SSO).
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
  // consent if shown
  await page.evaluate(() => { const b = [...document.querySelectorAll('button')].find(x => /allow|consent|agree|authorize|proceed|accept/i.test(x.innerText || '') && !x.disabled && !/cancel|deny/i.test(x.innerText || '')); if (b) b.click(); });
  await page.waitForURL(/verifiably\.in-labs\.cdpi\.dev\/holder\/wallet\/inji/, { timeout: 45000 }).catch(() => {});
  await page.waitForTimeout(2500);
  await shot('claimed-' + cred);
  log('claimed ' + cred + ' -> ' + page.url().replace(/[?#].*/, ''));
}

let code = 0;
try {
  await claim(SUBJ);
  await claim(DELEG);

  // evaluate the held pair (same session)
  const r = await ctx.request.get(BASE + '/holder/wallet/inji/verify-delegation', { timeout: 30000 });
  const verdict = await r.json();
  log('verdict ' + JSON.stringify(verdict));
  const d = verdict.delegation || {};
  if (verdict.credentialCount < 2) { console.error('✗ expected 2 claimed creds, got', verdict.credentialCount); code = 1; }
  else if (d.Authorized === true) { console.log('✅ INJI AUTH-CODE DELEGATION AUTHORIZED (linkage=' + d.Linkage + ' invocation=' + d.Invocation + ' capability=' + d.Capability + ' notRevoked=' + d.NotRevoked + ')'); }
  else { console.error('✗ NOT authorized:', JSON.stringify(d)); code = 1; }
} catch (e) {
  console.error('ERROR:', e.message); await shot('error'); code = 1;
} finally {
  await browser.close();
  process.exitCode = code;
}
