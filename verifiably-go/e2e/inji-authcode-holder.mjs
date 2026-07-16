// E2E: verifiably's OWN holder claim flow (no inji-web). Navigate the in-app
// start URL -> eSignet OTP login -> back to verifiably -> assert the claimed VC.
import { chromium } from 'playwright';
const CRED = process.env.CRED || '';
const START = 'https://verifiably.in-labs.cdpi.dev/holder/wallet/inji/start' + (CRED ? '?cred=' + CRED : '');
const ID = process.env.INDIVIDUAL_ID || '7777777777';
const OTP = process.env.OTP || '111111';
const browser = await chromium.launch({ headless: true, args: ['--no-sandbox', '--ignore-certificate-errors'] });
const page = await (await browser.newContext({ ignoreHTTPSErrors: true })).newPage();
const shot = n => page.screenshot({ path: `/e2e/shots/inji-${n}.png` }).catch(() => {});
const click = (rx, xs = '^$') => page.evaluate(({ rx, xs }) => { const re = new RegExp(rx, 'i'), xe = new RegExp(xs, 'i'); const e = [...document.querySelectorAll('button,a,div,span,[role=button]')].find(x => x.offsetParent !== null && re.test(x.innerText || '') && !xe.test(x.innerText || '') && (x.innerText || '').trim().length < 40); if (e) { e.click(); return e.innerText.slice(0, 30); } return null; }, { rx, xs });
try {
  await page.goto(START, { waitUntil: 'domcontentloaded', timeout: 45000 });
  await page.waitForTimeout(4000);
  console.log('[1] after start ->', page.url());
  console.log('method:', await click('login with otp', 'sign ?up|inji'));
  await page.waitForTimeout(4500);
  const idIn = await page.$('input[type=text]:not([readonly]),input[type=tel],input[type=number]');
  if (idIn) await idIn.fill(ID);
  await page.waitForTimeout(800);
  await page.evaluate(() => { const b = [...document.querySelectorAll('button')].find(x => /get otp|send otp/i.test(x.innerText || '') && !x.disabled); if (b) b.click(); });
  // wait for the OTP boxes to render, then fill each
  await page.waitForSelector('input[maxlength="1"]', { timeout: 14000 }).catch(() => {});
  await page.waitForTimeout(1500);
  let otps = await page.$$('input[maxlength="1"]');
  if (otps.length === 0) otps = await page.$$('input[inputmode=numeric],input[type=number],input[type=tel]');
  console.log('otp boxes:', otps.length);
  for (let i = 0; i < Math.min(otps.length, OTP.length); i++) { await otps[i].click().catch(() => {}); await otps[i].fill(OTP[i]); }
  await page.waitForTimeout(1500);
  await shot('otp-filled');
  // click Verify, retrying until it's enabled
  for (let t = 0; t < 12; t++) {
    const done = await page.evaluate(() => { const b = [...document.querySelectorAll('button')].find(x => /verify|^login$|^submit$/i.test(x.innerText || '') && !x.disabled && !/get otp|resend/i.test(x.innerText || '')); if (b) { b.click(); return true; } return false; });
    if (done) { console.log('verify clicked @', t); break; }
    await page.waitForTimeout(1000);
  }
  await page.waitForTimeout(5000);
  await shot('after-verify');
  // consent, if shown
  await page.evaluate(() => { const b = [...document.querySelectorAll('button')].find(x => /allow|consent|agree|authorize|proceed|accept/i.test(x.innerText || '') && !x.disabled && !/cancel|deny/i.test(x.innerText || '')); if (b) b.click(); });
  await page.waitForURL(/verifiably\.in-labs\.cdpi\.dev\/holder\/wallet\/inji/, { timeout: 40000 }).catch(() => {});
  await page.waitForTimeout(2000);
  // land on the result page (retry the --network host glitches); the session
  // cookie carries the claim result set by the callback.
  for (let t = 0; t < 5; t++) {
    try { await page.goto('https://verifiably.in-labs.cdpi.dev/holder/wallet/inji', { waitUntil: 'domcontentloaded', timeout: 30000 }); break; }
    catch (e) { console.log('result nav retry', t, (e.message || '').slice(0, 40)); await page.waitForTimeout(2500); }
  }
  await page.waitForTimeout(2000);
  await shot('final');
  console.log('[final] url ->', page.url());
  const txt = await page.evaluate(() => document.body.innerText).catch(() => '(no body)');
  console.log('[final] text:', txt.replace(/\s+/g, ' ').slice(0, 700));
} finally { await browser.close(); }
