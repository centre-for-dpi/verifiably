// Capture verifiably's in-app holder claim flow: step screenshots + browser
// routes + browser-visible API calls (server-side token/credential are in
// inji_holder.go, not browser-visible).
import { chromium } from 'playwright';
const ID = process.env.INDIVIDUAL_ID || '7777777777', OTP = '111111';
const OUT = '/e2e/cmp';
(await import('node:fs')).mkdirSync(OUT, { recursive: true });
const browser = await chromium.launch({ headless: true, args: ['--no-sandbox', '--ignore-certificate-errors'] });
const ctx = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 1100 } });
const page = await ctx.newPage();
const api = [];
page.on('request', r => { const u = r.url(); if (/(esignet\.in-labs|inji-certify|certify|\/holder\/wallet\/inji|\/v1\/esignet|\/v1\/certify)/.test(u) && !/\.(css|js|png|svg|woff2?|ico|map)(\?|$)/.test(u)) api.push(r.method() + ' ' + u.replace(/\?.*/, '').replace(/^https?:\/\//, '')); });
const shot = async (n, label) => { await page.waitForTimeout(1500); try { await page.screenshot({ path: `${OUT}/vfly-${n}.png`, fullPage: true }); } catch {} console.log(`[V-${n}] ${label} :: ${page.url().replace(/[?#].*/, '')}`); };
const click = (rx, xs = '^$') => page.evaluate(({ rx, xs }) => { const re = new RegExp(rx, 'i'), xe = new RegExp(xs, 'i'); const e = [...document.querySelectorAll('button,a,[role=button]')].find(x => x.offsetParent !== null && re.test(x.innerText || '') && !xe.test(x.innerText || '') && (x.innerText || '').trim().length < 45); if (e) { e.click(); return true; } return false; }, { rx, xs });
try {
  await page.goto('https://verifiably.in-labs.cdpi.dev/holder/wallet/inji', { waitUntil: 'domcontentloaded', timeout: 45000 });
  await shot('1-claim', 'Claim screen (entry)');
  await page.goto('https://verifiably.in-labs.cdpi.dev/holder/wallet/inji/start', { waitUntil: 'domcontentloaded', timeout: 45000 });
  await page.waitForTimeout(3500);
  await shot('2-esignet-login', 'eSignet login');
  await click('login with otp', 'sign ?up|inji|unified');
  await page.waitForTimeout(4000);
  const idIn = await page.$('input[type=text]:not([readonly]),input[type=tel],input[type=number]'); if (idIn) await idIn.fill(ID);
  await page.waitForTimeout(700);
  await page.evaluate(() => { const b = [...document.querySelectorAll('button')].find(x => /get otp|send otp/i.test(x.innerText || '') && !x.disabled); if (b) b.click(); });
  await page.waitForSelector('input[maxlength="1"]', { timeout: 14000 }).catch(() => {});
  await shot('3-otp', 'OTP entry');
  let otps = await page.$$('input[maxlength="1"]'); if (otps.length === 0) otps = await page.$$('input[inputmode=numeric],input[type=number]');
  for (let i = 0; i < Math.min(otps.length, OTP.length); i++) { await otps[i].click().catch(() => {}); await otps[i].fill(OTP[i]); }
  await page.waitForTimeout(1000);
  for (let t = 0; t < 12; t++) { if (await page.evaluate(() => { const b = [...document.querySelectorAll('button')].find(x => /verify|^login$|^submit$/i.test(x.innerText || '') && !x.disabled && !/get otp|resend/i.test(x.innerText || '')); if (b) { b.click(); return true; } return false; })) break; await page.waitForTimeout(1000); }
  await page.waitForTimeout(5000);
  await page.evaluate(() => { const b = [...document.querySelectorAll('button')].find(x => /allow|consent|agree|authorize|proceed|accept/i.test(x.innerText || '') && !x.disabled && !/cancel|deny/i.test(x.innerText || '')); if (b) b.click(); });
  await page.waitForURL(/holder\/wallet\/inji/, { timeout: 40000 }).catch(() => {});
  for (let t = 0; t < 5; t++) { try { await page.goto('https://verifiably.in-labs.cdpi.dev/holder/wallet/inji', { waitUntil: 'domcontentloaded', timeout: 30000 }); break; } catch { await page.waitForTimeout(2500); } }
  await shot('4-result', 'Claimed VC in verifiably');
} catch (e) { console.log('ERR', e.message); }
finally {
  console.log('--- VFLY browser-visible API calls ---');
  console.log([...new Set(api)].join('\n'));
  await browser.close();
}
