// Protocol-level proof of the Inji auth-code DYNAMIC issuance — bypasses Mimoto
// and Inji Web. Drives the real OID4VCI authorization_code flow directly:
//   1. eSignet authorize + OTP login (browser, only for the human-auth step)
//   2. token exchange via private_key_jwt (wallet-demo-client key) + PKCE      [REST]
//   3. holder-proof JWT (did:jwk binding, c_nonce)                             [REST]
//   4. POST inji-certify /v1/certify/issuance/credential                       [REST]
//   5. assert the issued VC carries the DYNAMIC claims (Ada Lovelace from
//      certify.vc_subject), NOT the eSignet identity ("Demo Farmer").
import { chromium } from 'playwright';
import * as jose from 'jose';
import { readFileSync } from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';

const ESIGNET = 'https://esignet.in-labs.cdpi.dev';
const TOKEN_EP = ESIGNET + '/v1/esignet/oauth/v2/token';
const AUTHORIZE = ESIGNET + '/authorize';
const CRED_ISSUER = 'http://certify-nginx:80';
const CRED_EP = 'http://inji-certify:8090/v1/certify/issuance/credential';
const CLIENT_ID = 'wallet-demo-client';
const REDIRECT = 'https://inji-web.in-labs.cdpi.dev/redirect';
const SCOPE = process.env.INJI_SCOPE || 'mock_identity_vc_ldp';
const CRED_TYPE = process.env.CRED_TYPE || 'VerifiablePersonCredential';
const ID = process.env.INDIVIDUAL_ID || '8267411072', OTP = process.env.OTP || '111111';

const b64url = b => Buffer.from(b).toString('base64url');
const verifier = b64url(randomBytes(32));
const challenge = createHash('sha256').update(verifier).digest().toString('base64url');
const state = b64url(randomBytes(8)), nonce = b64url(randomBytes(8));

const clientKey = await jose.importPKCS8(readFileSync('/e2e/client-key.pem', 'utf8'), 'RS256');

// ---- 1. browser: authorize + OTP login, capture the auth code from the redirect ----
const authUrl = `${AUTHORIZE}?response_type=code&client_id=${CLIENT_ID}&scope=${encodeURIComponent(SCOPE)}` +
  `&redirect_uri=${encodeURIComponent(REDIRECT)}&state=${state}&nonce=${nonce}` +
  `&code_challenge=${challenge}&code_challenge_method=S256&ui_locales=en`;
const browser = await chromium.launch({ headless: true, args: ['--no-sandbox', '--ignore-certificate-errors'] });
const page = await (await browser.newContext({ ignoreHTTPSErrors: true })).newPage();
let code = null;
await page.route('**/redirect*', r => { const m = r.request().url().match(/[?&]code=([^&]+)/); if (m) code = decodeURIComponent(m[1]); r.abort(); });
const click = (rx, xs = '^$') => page.evaluate(({ rx, xs }) => { const re = new RegExp(rx, 'i'), xe = new RegExp(xs, 'i'); const e = [...document.querySelectorAll('button,a,div,span,[role=button]')].find(x => x.offsetParent !== null && re.test(x.innerText || '') && !xe.test(x.innerText || '') && (x.innerText || '').trim().length < 40); if (e) { e.click(); return e.innerText.slice(0, 30); } return null; }, { rx, xs });
try {
  await page.goto(authUrl, { waitUntil: 'domcontentloaded', timeout: 45000 });
  await page.waitForTimeout(4000);
  console.log('method:', await click('login with otp', 'sign ?up|inji'));
  await page.waitForTimeout(4500);
  const idIn = await page.$('input[type=text]:not([readonly]),input[type=tel],input[type=number]');
  if (idIn) await idIn.fill(ID);
  await page.evaluate(() => { const b = [...document.querySelectorAll('button')].find(x => /get otp|send otp/i.test(x.innerText || '') && !x.disabled); if (b) b.click(); });
  await page.waitForTimeout(5500);
  const otps = await page.$$('input[maxlength="1"],input[type=tel],input[type=number],input[inputmode=numeric]');
  if (otps.length > 1) for (let i = 0; i < Math.min(otps.length, OTP.length); i++) await otps[i].fill(OTP[i]);
  else if (otps.length === 1) await otps[0].fill(OTP);
  await page.evaluate(() => { const b = [...document.querySelectorAll('button')].find(x => /verify|^login$|^submit$/i.test(x.innerText || '') && !x.disabled && !/get otp|resend/i.test(x.innerText || '')); if (b) b.click(); });
  await page.waitForTimeout(6000);
  await page.evaluate(() => { const b = [...document.querySelectorAll('button')].find(x => /allow|consent|agree|authorize|proceed|accept/i.test(x.innerText || '') && !x.disabled && !/cancel|deny/i.test(x.innerText || '')); if (b) b.click(); });
  for (let i = 0; i < 25 && !code; i++) await page.waitForTimeout(1000);
} finally { await browser.close(); }
console.log('CODE:', code);
if (!code) throw new Error('no auth code captured');

// ---- 2. token exchange (private_key_jwt + PKCE) ----
const assertion = await new jose.SignJWT({}).setProtectedHeader({ alg: 'RS256', kid: 'wallet-demo-client-kid', typ: 'JWT' })
  .setIssuer(CLIENT_ID).setSubject(CLIENT_ID).setAudience(TOKEN_EP).setIssuedAt().setExpirationTime('5m').setJti(b64url(randomBytes(12))).sign(clientKey);
const tokRes = await fetch(TOKEN_EP, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT, code_verifier: verifier,
    client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: assertion }) });
const tok = await tokRes.json().catch(() => ({}));
console.log('TOKEN status:', tokRes.status, '| keys:', Object.keys(tok).join(','));
const accessToken = tok.access_token;
let cNonce = tok.c_nonce;
if (!accessToken) throw new Error('no access_token: ' + JSON.stringify(tok).slice(0, 400));
console.log('access_token: OK (jwt, ' + accessToken.length + ' chars) | c_nonce:', cNonce || '(none yet)');
const tokSub = jose.decodeJwt(accessToken).sub;
console.log('TOKEN sub (= the :id the data provider queries):', tokSub);

// ---- 3+4. holder proof + credential request ----
const holder = await jose.generateKeyPair('ES256', { extractable: true });
const holderJwk = await jose.exportJWK(holder.publicKey); holderJwk.alg = 'ES256';
async function credReq(n) {
  const proof = await new jose.SignJWT(n ? { nonce: n } : {}).setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: holderJwk })
    .setIssuer(CLIENT_ID).setAudience(CRED_ISSUER).setIssuedAt().sign(holder.privateKey);
  const res = await fetch(CRED_EP, { method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer ' + accessToken },
    body: JSON.stringify({ format: 'ldp_vc', credential_definition: { '@context': ['https://www.w3.org/2018/credentials/v1'], type: ['VerifiableCredential', CRED_TYPE] }, proof: { proof_type: 'jwt', jwt: proof } }) });
  const body = await res.json().catch(() => ({}));
  return { status: res.status, body };
}
let r = await credReq(cNonce);
if (r.status >= 400 && (r.body.c_nonce || r.body?.error)) {
  console.log('first cred attempt:', r.status, JSON.stringify(r.body).slice(0, 200));
  if (r.body.c_nonce) { cNonce = r.body.c_nonce; r = await credReq(cNonce); }
}
console.log('CRED status:', r.status);
const vc = r.body?.credential || r.body;
console.log('VC (first 1100):', JSON.stringify(vc).slice(0, 1100));
const subj = (vc && (vc.credentialSubject || vc?.credential?.credentialSubject)) || {};
console.log('\n===== RESULT =====');
console.log('credentialSubject.fullName :', subj.fullName);
console.log('credentialSubject.givenName:', subj.givenName, '| familyName:', subj.familyName, '| email:', subj.email);
console.log('DYNAMIC CLAIMS PROVEN (Ada Lovelace, from vc_subject):', /ada\s*lovelace/i.test(JSON.stringify(vc || {})));
