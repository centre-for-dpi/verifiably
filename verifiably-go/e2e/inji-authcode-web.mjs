// Flow C e2e — Inji Web auth-code issuance, proving the issued VC carries the
// DYNAMIC claims from certify.vc_subject (Ada Lovelace). Now reaches the eSignet
// login: choose "Login with OTP" -> individualId 8267411072 -> Get OTP -> OTP
// 111111 -> Verify -> consent -> credential.
import { chromium } from 'playwright';
const INJI_WEB = process.env.INJI_WEB_URL || 'https://inji-web.in-labs.cdpi.dev';
const ID = process.env.INDIVIDUAL_ID || '8267411072';
const OTP = process.env.OTP || '111111';
const OUT = '/e2e/shots';
(await import('node:fs')).mkdirSync(OUT, { recursive: true });
let step = 0;
const snap = async (page, label) => {
  step++; const n = String(step).padStart(2, '0');
  try { await page.screenshot({ path: `${OUT}/${n}-${label}.png`, fullPage: true }); } catch {}
  let url = '', text = '';
  try { url = page.url(); } catch {}
  try { text = await page.evaluate(() => document.body ? document.body.innerText.replace(/\s+/g, ' ').slice(0, 350) : ''); } catch {}
  console.log(`\n[${n}] ${label}\n  URL: ${url.slice(0,110)}\n  TXT: ${text}`);
  return { url, text };
};
const dump = async (page) => {
  try {
    const els = await page.evaluate(() => Array.from(document.querySelectorAll('[data-testid],input,button'))
      .filter(e => e.offsetParent !== null).slice(0, 26)
      .map(e => ({ t: e.tagName, tid: e.getAttribute('data-testid'), id: e.id, type: e.getAttribute('type'), ml: e.getAttribute('maxlength'), txt: (e.innerText || e.value || '').replace(/\s+/g, ' ').slice(0, 30) })));
    console.log('  EL:', JSON.stringify(els));
  } catch (e) { console.log('  dump err', e.message); }
};
const clickTid = (page, s) => page.evaluate((s) => { const el = Array.from(document.querySelectorAll('[data-testid]')).find(e => (e.getAttribute('data-testid') || '').includes(s) && e.offsetParent !== null); if (el) { el.click(); return el.getAttribute('data-testid'); } return null; }, s);
const clickTxt = (page, rs, xs = '^$') => page.evaluate(({ rs, xs }) => { const re = new RegExp(rs, 'i'), xe = new RegExp(xs, 'i'); const el = Array.from(document.querySelectorAll('button,a,[role=button],div,span,li')).find(e => e.offsetParent !== null && re.test(e.innerText || '') && !xe.test(e.innerText || '') && (e.innerText || '').trim().length < 40); if (el) { el.click(); return (el.innerText || '').replace(/\s+/g,' ').slice(0, 35); } return null; }, { rs, xs });
// clickBtn: click the actual <button> (not a container) — eSignet renders Get OTP/Verify as buttons.
const clickBtn = (page, rs) => page.evaluate((rs) => { const re = new RegExp(rs, 'i'); const b = Array.from(document.querySelectorAll('button,[type=submit]')).find(e => e.offsetParent !== null && re.test(e.innerText || e.value || '') && !e.disabled); if (b) { b.click(); return (b.innerText || b.value || '').replace(/\s+/g, ' ').slice(0, 30); } return null; }, rs);

const browser = await chromium.launch({ headless: true, args: ['--no-sandbox', '--ignore-certificate-errors'] });
const ctx = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 1100 }, acceptDownloads: true });
const page = await ctx.newPage();
ctx.on('download', async d => { try { await d.saveAs(OUT + '/credential-' + (d.suggestedFilename() || 'cred.pdf')); console.log('DOWNLOAD saved:', d.suggestedFilename()); } catch (e) { console.log('dl err', e.message); } });
page.setDefaultTimeout(20000);
page.on('response', r => { const u = r.url(); if (/authenticate|send-otp|sendotp|oauth-details|authorization|auth-code|kyc|credential|csrf/i.test(u)) console.log(`  NET ${r.status()} ${r.request().method()} ${u.split('?')[0].slice(-70)}`); });
try {
  await page.goto(INJI_WEB, { waitUntil: 'domcontentloaded', timeout: 45000 });
  await page.waitForTimeout(3500);
  await page.evaluate(() => { const b = document.querySelector('#home-banner-guest-login'); if (b) b.click(); });
  await page.waitForTimeout(4500); await snap(page, 'issuers');
  await clickTid(page, 'ItemBox-Outer-Container'); // issuer
  await page.waitForTimeout(7000); await snap(page, 'credentials');
  await clickTid(page, 'ItemBox-Outer-Container'); // credential -> redirects to eSignet
  await page.waitForTimeout(7000);
  const r = await snap(page, 'esignet-options'); await dump(page);

  // eSignet: choose "Login with OTP" (NOT Sign Up / Login with Inji)
  if (/esignet|\/login|authorize/i.test(r.url)) {
    let m = await clickTxt(page, 'login with otp', 'sign ?up|inji|google|unified');
    console.log('METHOD:', m);
    await page.waitForTimeout(5000); await snap(page, 'esignet-otp-form'); await dump(page);
    // Fill individualId / VID
    const idIn = await page.$('input[type=text]:not([readonly]), input[type=tel], input[type=number]');
    if (idIn) { await idIn.fill(ID); console.log('filled id', ID); } else console.log('NO id input');
    await snap(page, 'esignet-id-filled');
    // Get OTP — click the actual button
    console.log('GETOTP:', await clickBtn(page, 'get otp|send otp'));
    await page.waitForTimeout(6500); await snap(page, 'after-getotp'); await dump(page);
    // Fill the OTP (6 boxes or one field)
    let otps = await page.$$('input[maxlength="1"], input[type=tel], input[type=number], input[inputmode=numeric], input[type=password]');
    console.log('otp fields:', otps.length);
    if (otps.length > 1) { for (let i = 0; i < Math.min(otps.length, OTP.length); i++) await otps[i].fill(OTP[i]); }
    else if (otps.length === 1) await otps[0].fill(OTP);
    await snap(page, 'otp-filled'); await dump(page);
    // Verify / Login button
    console.log('VERIFY:', await clickBtn(page, 'verify|^login$|^submit$|^proceed$'));
    await page.waitForTimeout(8000); await snap(page, 'after-verify'); await dump(page);
    // Consent — allow/accept button (may be a toggle + button)
    console.log('CONSENT-TOGGLE:', await clickTxt(page, 'allow all|select all', 'cancel'));
    console.log('CONSENT:', await clickBtn(page, 'allow|consent|agree|^accept$|authorize|proceed|continue'));
    await page.waitForTimeout(9000); await snap(page, 'after-consent'); await dump(page);
  }
  await page.waitForTimeout(14000); await snap(page, 'download-1');
  await page.waitForTimeout(14000);
  const final = await snap(page, 'final');
  console.log('\n===== RESULT =====\nAda/Lovelace:', /ada|lovelace/i.test(final.text), '| download/success:', /download|success|issued|added|stored|credential/i.test(final.text));
} catch (e) { console.log('FLOW ERROR:', e.message); await snap(page, 'error'); }
finally { await browser.close(); }
