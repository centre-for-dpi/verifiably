// Headless auth-flow test — mode-aware (works for legacy host:port AND
// subdomain/TLS deployments). Verifies, for EVERY OIDC provider the running
// instance advertises:
//
//   1. /auth lists the provider as a button.
//   2. /auth/start builds a well-formed authorize redirect — proving the
//      server completed OIDC discovery against the IdP. (Catches the subdomain
//      hairpin-NAT regression where discovery times out.)
//   3. Following that authorize URL one hop does NOT bounce back with
//      error=invalid_scope / invalid_client / unauthorized_client. (Catches the
//      Keycloak credebl-client scope regression and similar IdP misconfig.)
//
// Unlike the old version this does NOT hardcode provider ids, hosts, paths, or
// client_id — it discovers providers from the page and asserts structure, so it
// passes whether the IdP is at localhost:8180 or keycloak.example.com.
//
// Full interactive login (entering credentials) is out of scope — that needs a
// seeded user per IdP and is covered by the browser e2e matrix.
//
// Usage: VERIFIABLY_URL=https://verifiably.example.com node e2e/auth-test.mjs
//   (alias BASE= also accepted; defaults to http://localhost:8089)

const BASE = (process.env.VERIFIABLY_URL || process.env.BASE || 'http://localhost:8089').replace(/\/$/, '');

const results = [];
const fail = [];
function log(ok, msg, detail) {
  console.log((ok ? 'PASS' : 'FAIL') + '  ' + msg + (detail ? ' — ' + detail : ''));
  results.push({ ok, msg, detail });
  if (!ok) fail.push({ msg, detail });
}
function expect(cond, msg, detail) { log(!!cond, msg, cond ? '' : detail); }

async function run() {
  const jar = new Map();
  const cookieHeader = () => Array.from(jar.entries()).map(([k, v]) => `${k}=${v}`).join('; ');
  async function fetchX(url, opts = {}) {
    const headers = Object.assign({}, opts.headers || {}, { Cookie: cookieHeader() });
    const res = await fetch(url, { ...opts, headers, redirect: 'manual' });
    const setCookie = res.headers.get('set-cookie');
    if (setCookie) {
      const m = setCookie.match(/^([^=]+)=([^;]*)/);
      if (m) jar.set(m[1], m[2]);
    }
    return res;
  }

  // Establish a session + pick a role (the /auth/start guard requires one).
  await fetchX(BASE + '/');
  await fetchX(BASE + '/role', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'role=issuer',
  });

  // Discover the providers the running instance actually offers, from the page.
  const authPage = await fetchX(BASE + '/auth').then((r) => r.text());
  const ids = [...authPage.matchAll(/hx-vals='\{"provider":"([^"]+)"\}'/g)].map((m) => m[1]);
  const uniqIds = [...new Set(ids)];
  expect(uniqIds.length > 0, 'auth page advertises at least one OIDC provider', `found: ${uniqIds.join(', ') || '(none)'}`);

  for (const id of uniqIds) {
    // 2) /auth/start → expect an authorize redirect (HX-Redirect or 303 Location).
    const res = await fetchX(BASE + '/auth/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'HX-Request': 'true' },
      body: `provider=${encodeURIComponent(id)}`,
    });
    const target = res.headers.get('hx-redirect') || res.headers.get('HX-Redirect') || res.headers.get('location');
    expect(!!target, `${id}: /auth/start issued a redirect (discovery succeeded)`, `status=${res.status} (no HX-Redirect/Location — likely a discovery timeout/error toast)`);
    if (!target) continue;

    let u;
    try { u = new URL(target); } catch { expect(false, `${id}: authorize URL is absolute`, target); continue; }
    expect(/^https?:$/.test(u.protocol), `${id}: authorize URL is http(s)`, u.protocol);
    expect(u.searchParams.get('response_type') === 'code', `${id}: response_type=code`, u.searchParams.get('response_type') || '(missing)');
    expect(u.searchParams.get('code_challenge_method') === 'S256', `${id}: PKCE S256`, u.searchParams.get('code_challenge_method') || '(missing)');
    expect(!!u.searchParams.get('client_id'), `${id}: client_id present`, '(missing)');
    expect(!!u.searchParams.get('state'), `${id}: state present`, '(missing)');
    expect((u.searchParams.get('scope') || '').split(/[+ ]/).includes('openid'), `${id}: requests openid scope`, u.searchParams.get('scope') || '(missing)');
    expect(!!u.searchParams.get('redirect_uri'), `${id}: redirect_uri present`, '(missing)');

    // 3) Follow the authorize URL one hop — must NOT be rejected by the IdP.
    try {
      const az = await fetch(target, { redirect: 'manual' });
      const loc = az.headers.get('location') || '';
      const rejected = /[?&]error=(invalid_scope|invalid_request|invalid_client|unauthorized_client|access_denied)/.test(loc);
      expect(!rejected, `${id}: IdP authorize accepted the request (no invalid_scope/client)`, rejected ? decodeURIComponent(loc) : '');
      // A valid authorize is a login page (200) or a non-error redirect to the IdP's own login.
      expect(az.status === 200 || (az.status >= 300 && az.status < 400 && !rejected),
        `${id}: authorize responded with a login page or login redirect`, `status=${az.status}`);
    } catch (e) {
      expect(false, `${id}: authorize URL reachable`, String(e && e.message || e));
    }
  }

  console.log('\n' + '='.repeat(60));
  console.log(`Results: ${results.filter((r) => r.ok).length}/${results.length} passed  (BASE=${BASE})`);
  if (fail.length) {
    console.log('\nFailures:');
    for (const f of fail) console.log(`  - ${f.msg}${f.detail ? ' — ' + f.detail : ''}`);
    process.exit(1);
  }
}

run().catch((e) => { console.error('test harness error:', e); process.exit(2); });
