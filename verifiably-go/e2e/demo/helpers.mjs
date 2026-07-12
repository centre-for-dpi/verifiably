// Shared headless-Chromium harness for the Verifiably UI/UX e2e test.
// Every action goes through the real browser UI (no API shortcuts for flows under test).
import { chromium } from 'playwright';

export const BASE = process.env.BASE || 'https://verifiably.in-labs.cdpi.dev';
export const SHOTS = process.env.SHOTS || '/root/e2e-out/uiux';
export const USERS = {
  keycloak: { user: 'adamk', pass: 'Q!w2e3r4d' },
  wso2is: { user: 'adamw', pass: 'Q!w2e3r4d' },
};

export async function launch() {
  const browser = await chromium.launch({ args: ['--no-sandbox', '--ignore-certificate-errors'] });
  return browser;
}
export async function newCtx(browser, opts = {}) {
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 1600 }, ...opts });
  return ctx;
}

export async function postForm(ctx, path, fields) {
  const r = await ctx.request.post(BASE + path, { form: fields, maxRedirects: 0 }).catch((e) => e);
  return { headers: r.headers ? r.headers() : {}, status: r.status ? r.status() : 0, text: r.text ? await r.text().catch(() => '') : '' };
}
async function fillFirst(page, sels, val) {
  for (const s of sels) { const el = await page.$(s); if (el && (await el.isVisible().catch(() => false))) { await el.fill(val); return true; } }
  return false;
}

// login drives /role -> /auth/start -> IdP form -> back to /{role}/dpg.
export async function login(ctx, page, { role, provider = 'keycloak' }) {
  const { user, pass } = USERS[provider];
  await page.goto(BASE + '/', { waitUntil: 'domcontentloaded' });
  await postForm(ctx, '/role', { role });
  const s = await postForm(ctx, '/auth/start', { provider });
  const dest = s.headers['hx-redirect'] || s.headers['location'];
  if (!dest) throw new Error('auth/start returned no redirect: ' + s.status);
  await page.goto(dest, { waitUntil: 'domcontentloaded' });
  await page.waitForTimeout(1200);
  await page.click('button:has-text("Got it")', { timeout: 1500 }).catch(() => {});
  await fillFirst(page, ['#usernameUserInput', '#username', 'input[name="username"]', 'input[type=text]:not([type=hidden])'], user);
  await fillFirst(page, ['#password', 'input[name="password"]', 'input[type=password]'], pass);
  await Promise.all([
    page.waitForURL((u) => u.toString().includes(new URL(BASE).host), { timeout: 30000 }).catch(() => {}),
    page.click('#kc-login, input[type=submit], button[type=submit]').catch(() => {}),
  ]);
  await page.waitForTimeout(2500);
  if (!page.url().includes(new URL(BASE).host)) throw new Error('login failed, at ' + page.url());
  return page.url();
}

// pickDpg selects a DPG card by data-vendor on /{role}/dpg and clicks continue.
export async function pickDpg(page, role, vendor) {
  await page.goto(`${BASE}/${role}/dpg`, { waitUntil: 'domcontentloaded' });
  await page.waitForTimeout(1000);
  const clicked = await page.evaluate((v) => {
    const c = [...document.querySelectorAll('.dpg-card')].find((x) => (x.dataset.vendor || '') === v);
    if (c) { c.click(); return true; }
    return false;
  }, vendor);
  if (!clicked) throw new Error(`DPG card not found: ${vendor} (role ${role})`);
  await page.waitForTimeout(900);
  await page.evaluate((role) => {
    const b = document.querySelector(`#${role}-dpg-continue`) || [...document.querySelectorAll('button,a')].find((x) => /continue|proceed/i.test(x.textContent));
    if (b) b.click();
  }, role);
  await page.waitForTimeout(1500);
  return page.url();
}

export async function listDpgCards(page, role) {
  await page.goto(`${BASE}/${role}/dpg`, { waitUntil: 'domcontentloaded' });
  await page.waitForTimeout(1000);
  return page.$$eval('.dpg-card', (els) => els.map((e) => e.dataset.vendor || (e.textContent || '').trim().split('\n')[0]));
}

export async function shot(page, dir, name) {
  const path = `${SHOTS}/${dir}/${name}.png`;
  await page.screenshot({ path, fullPage: true }).catch(() => {});
  return path;
}
