# Architecture

A Go + HTMX server that renders HTML for every interaction and treats the
backend layer as a single `backend.Adapter` interface. No SPA, no framework,
standard library `net/http` and `html/template` only.

> **Per-DPG deep dives:** for exactly what makes each DPG work — containers, env
> vars, Caddy blocks, runtime configs, databases, APIs, gotchas — see the
> self-contained guides in [`docs/dpg/`](dpg/README.md).

## Package layout

```
vctypes/            Shared domain types (DPG, Schema, Credential, …).
                    Zero third-party deps. Everything else imports this.

backend/            Adapter interface + request/response shapes + the
                    context helper for holder-DPG routing.
                    Depends only on vctypes and stdlib.

internal/adapters/  Concrete implementations of Adapter:
    registry/       Fan-out adapter: routes to the right per-DPG
                    impl based on the DPG selected in the request.
    waltid/         Real walt.id issuer-api / wallet-api / verifier-api client.
    injicertify/    Real Inji Certify client; drives BOTH the auth-code
                    (eSignet + in-app wallet) and pre-auth (direct-to-PDF)
                    instances, plus the PixelPass QR encoder/decoder.
    injiweb/        Thin stub — the external Inji Web wallet is browser-hosted;
                    the adapter exposes the redirect URL + capability claims.
                    (The auth-code holder wallet is served IN-APP by handlers,
                    not here — see internal/handlers/inji_holder.go.)
    injiverify/     Real Inji Verify client for OID4VP + direct verify.
    credebl/        Real CREDEBL client (api-gateway auth + OID4VCI/OID4VP).
    libretranslate/ Translator client with on-disk cache.
    factory/        Builds the right adapter from a config/backends.json entry
                    (vendor `type` → adapter constructor).

internal/auth/      OIDC provider registry (Keycloak, WSO2IS) + discovery +
                    PKCE authorize URL + token exchange.

internal/delegation/ DPG-agnostic delegated-access evaluator (linkage,
                    invocation, capability, revocation) — see delegated-access.md.

internal/injidid/   Per-instance did:web kid observers (Primary = auth-code,
                    Preauth = pre-auth); feeds the patched did.json.

internal/mailer/    SMTP mailer (STARTTLS) for the real email-OTP activation.

internal/storage/pg/ Postgres access for the Inji auth-code data plane —
                    SubjectStore: vc_subject (claims), credential_config
                    (catalog), vc_credential_owner, identity_registry.

internal/handlers/  HTTP handlers. Depend on backend + vctypes. Never import
                    adapters directly — they go through the Registry. Notable:
                    inji_holder.go (the in-app auth-code wallet + OID4VCI claim),
                    inji_schema.go (Inji schema builder → credential_config),
                    inji_proxy.go (did:web + credential-forwarding endpoints
                    certify-nginx routes back to us), inji_wallet_pdf.go
                    (QR-on-PDF download), qr_decode.go (PixelPass QR decode),
                    onboard.go + otp.go (registry-gated activation), identity.go
                    (registrar bulk-enrol), bulk.go (bulk engine + data-source
                    connectors), api_subjects.go (the SubjectProvisioner API),
                    i18n_postprocess.go (post-render translation walker).

internal/httpx/     Tiny HTTP client with bearer-token context injection.

cmd/server/         main.go + adapter wiring + auth wiring + i18n wiring +
                    template loading. The only place where adapter types
                    are named explicitly.

templates/          html/template files. layout.html wraps every page;
                    fragments/ hold the HTMX-swappable pieces.

static/             CSS + a small JS file + the jsQR scanner.

e2e/                Headless Chromium tests (puppeteer-core) per DPG flow.

deploy/             compose override + per-service config overrides.
deploy.sh           Single-entrypoint orchestrator.
```

## Dependency graph

```
handlers ──→ backend ──→ vctypes
   ↑          ↑
   │          │
cmd/server ──┴──→ registry ──→ waltid / injicertify / injiweb / injiverify
                      │
                      └──→ libretranslate
```

`internal/handlers` only knows about the Adapter interface. Swapping every
concrete adapter in `cmd/server/adapter.go` doesn't move a byte of handler
code.

## The Adapter interface

One ~30-method interface in `backend/adapter.go` covers:

- List capabilities (`ListIssuerDpgs`, `ListHolderDpgs`, `ListVerifierDpgs`)
- Schema browsing + custom-schema lifecycle
- Prefill (MOSIP Identity Plugin, walt.id demo account, …)
- Issuance (`IssueToWallet`, `IssueAsPDF`, `IssueBulk`)
- Wallet operations (`ParseOffer`, `ClaimCredential`, `ListWalletCredentials`)
- Presentation (`PresentCredential`, `RequestPresentation`, `FetchPresentationResult`)
- Direct verification (`VerifyDirect`)
- Example offers (`ListExampleOffers`, `BootstrapOffers`)

Most methods carry a `...Dpg` field in the request struct. The four that
don't (`ParseOffer`, `ClaimCredential`, `ListWalletCredentials`,
`PresentCredential`'s context call path) use
`backend.WithHolderDpg(ctx, vendor)` — the Registry reads it back via
`backend.HolderDpgFromContext(ctx)` to route the call.

## Registry fan-out

`internal/adapters/registry` is the adapter the handlers actually hold. It
keeps per-role maps (`issuers`, `holders`, `verifiers`) keyed by vendor
display name, and for each request dispatches to the matching concrete
adapter. Unknown DPGs return `backend.ErrUnknownDPG`; handlers show a
toast rather than crashing.

When a scenario has a single holder registered, `currentHolder` falls
through to a shortcut — so scenario=waltid works even if a handler forgets
to wrap the context. `all` forces callers to be explicit.

## HTMX pattern

Every interactive control is `hx-get` or `hx-post` that swaps an HTML
fragment back into the page. Key conventions:

- **Page loads** render `{{template "layout" .}}` which dispatches to the
  page-specific `content_X` template via `PageData.ContentTemplate`.
- **HTMX boost** requests (`HX-Target: main`) skip the layout and render
  just the content template.
- **Fragment responses** use `H.renderFragment(w, r, name, data)` — no
  layout, just the named sub-template.
- **Toasts** are triggered via the `HX-Trigger` response header; a JS
  listener in `static/js/app.js` pops them.
- **Out-of-band swaps** (`hx-swap-oob`) let one response update a distant
  element — for example, the Continue button state outside the DPG grid.

## Session model

One in-memory store (`internal/handlers/session.go`) keyed by a cookie.
Holds the currently-picked DPG per role, wallet contents, last seen error,
expand state for DPG cards, schema-builder draft, and the auth token
returned by the OIDC provider.

Per-session locking is **not** implemented — two concurrent HTMX requests
from the same browser could race on writes. Real deployments should move
sessions to Redis or wrap each request in a per-session mutex.

## Authentication

`internal/auth` loads OIDC providers from `config/auth-providers.json`,
does discovery via `.well-known/openid-configuration`, and handles PKCE
code exchange on the `/auth/callback` route. The resulting access token
lives in the session; adapters pick it up via `httpx.WithToken(ctx, tok)`.

Inside a docker deployment the provider URL has two forms: the
browser-visible one (`http://localhost:8180`, what HX-Redirect sends the
browser to) and the container-visible one (`http://keycloak:8180`, what
the Go server uses for discovery + token exchange). `oidc.Discover`
rewrites endpoints to the internal form for server-side use and flips
them back to public for browser redirects.

## Translation

`internal/adapters/libretranslate` caches translations on disk
(`locales/<lang>.json`) so repeat renders are instant.

Two layers keep every surface translated:

1. **Template-level `{{t "string" $.Lang}}`** — static strings known at
   template-write time are wrapped explicitly. Parse-time binding means
   the helper is a single package-level function that looks up the
   translator from a request-scoped package variable.

2. **Post-render HTML walker** (`internal/handlers/i18n_postprocess.go`)
   — when Lang != "en", the render output is captured to a buffer,
   parsed with `golang.org/x/net/html`, walked node-by-node, and every
   text node (plus `title` / `placeholder` / `alt` / `aria-label`
   attributes) is translated. Skips `<script>`, `<style>`, `<code>`,
   `<pre>`, `<textarea>`, and elements with `translate="no"` or class
   `mono` / `notr` — those hold identifiers, URLs, and brand names that
   must render verbatim.

The safety-net walker means a template author can forget to wrap a string
and translation still works. Brand names that get incorrectly translated
("Keycloak" → "Clé" in French) are fixed by adding a `mono` class to the
span holding them.

## Inji-proxy (did:web resolver + credential forwarder)

Two separate Inji Certify instances run behind two separate nginx
front-ends, each publishing its OWN DID document. Before the split, both
instances signed under `did:web:certify-nginx` and collided on kid (two
different Ed25519 keypairs claiming the same kid fragment), which
stranded whichever flow's VC didn't happen to resolve to the winning
entry in the merged did.json. The per-instance DID split eliminates
that class of failure entirely:

| Flow      | Instance                          | Nginx                   | Public issuer DID                              |
|-----------|-----------------------------------|-------------------------|------------------------------------------------|
| Auth-code | `inji-certify`                    | `certify-nginx`         | `did:web:inji-certify-authcode.<domain>`       |
| Pre-auth  | `inji-certify-preauth-backend`    | `certify-preauth-nginx` | `did:web:inji-certify-preauth.<domain>`        |

Both instances are now **public issuers** — `mosip_certify_domain_url` is the
public host, so each VC's `credential_issuer` + `credentialStatus` URLs resolve
externally and the issuer DID is a publicly-resolvable `did:web` at its own
subdomain (falling back to the docker-internal `certify-nginx` /
`certify-preauth-nginx` only on a host-less dev box). See
[dpg/inji-certify-authcode.md](dpg/inji-certify-authcode.md) for the audience
decoupling this required.

Each nginx routes `GET /.well-known/did.json` back through `verifiably-go:8080`
(resolved per-request via Docker DNS — previously `host.docker.internal:8080`,
which isn't routable cross-bridge on hardened hosts) to its own verifiably-go
handler; each handler fetches ONLY its own upstream's did.json (no merge), and
each has its own `injidid.Observer` tracking the kids the corresponding instance
has signed with. Four endpoints total:

- `POST /inji-proxy/issuance/credential` — forwards to
  `inji-certify:8090`, patching `credential_definition.@context` if the
  wallet omitted it (walt.id's Kotlin wallet does; Mimoto doesn't).
  Records observed kids into `injidid.Primary`.

- `GET /inji-proxy/.well-known/did.json` — serves did:web:certify-nginx.
  Fetches `inji-certify:8090/v1/certify/.well-known/did.json`, appends
  synthetic `verificationMethod` entries for every kid `injidid.Primary`
  has seen.

- `GET /inji-proxy-preauth/.well-known/did.json` — serves
  did:web:certify-preauth-nginx. Fetches
  `inji-certify-preauth-backend:8090/v1/certify/.well-known/did.json`,
  appends entries for every kid `injidid.Preauth` has seen. Pre-auth
  kids come from the direct-to-PDF flow in
  `adapters/injicertify/pdf.go`, not through the proxy endpoints.

- `GET /inji-proxy/credentials/status-list/{id}` — forwards the
  primary status-list VC and records its `proof.verificationMethod` kid
  into `injidid.Primary`.

Observers can be pre-seeded for restarts: `INJI_PROXY_EXTRA_KIDS` feeds
primary, `INJI_PROXY_PREAUTH_EXTRA_KIDS` feeds pre-auth. Both are
comma-separated kid fragments.

The individual kid-synthesis workarounds (derived from multiple hash
paths over one Ed25519 key) stay in place within each handler because
Inji Certify v0.14.0 still publishes a kid in its did.json that
isn't the kid its signer uses. What's gone is the cross-instance merge
— Inji Verify never sees keys from a different instance while resolving
one instance's DID.

See [dpg-matrix.md](dpg-matrix.md) for the upstream bugs each of these
workarounds target.

## Data plane: databases & registries

verifiably-go is mostly stateless (one cookie-keyed session store); the DPGs and
data sources own the persistent state. The Postgres instances on the box:

| Database (container) | Owner | Holds |
|---|---|---|
| `waltid` (`postgres`) | walt.id | wallet-api accounts, keys, DIDs, held credentials |
| `verifiably` (`verifiably-pg`) | verifiably-go | optional Postgres-backed session store (else encrypted file) |
| `inji_certify` (`certify-postgres`) | Inji auth-code | `credential_config`, `vc_subject`, `vc_credential_owner`, `identity_registry`, status-list tables, key manager |
| `inji_certify` (`certify-preauth-postgres`) | Inji pre-auth | `credential_config` (isolated; pre-auth caches claims itself) |
| `inji_verify` (`inji-verify-postgres`, schema `verify`) | Inji Verify | VP tracking (schema not DDL-initialised — see the guide) |
| `mosip_mockidentitysystem` / `mosip_esignet` / `inji_mimoto` (`injiweb-postgres`) | eSignet stack | mock identities, eSignet, Mimoto |
| `credebl` (`credebl-postgres`) | CREDEBL | users, orgs, schemas, credential records, Credo wallets |
| `citizens` (`citizens-postgres`) | demo data source | sample rows for the "Bulk from PostgreSQL" connector |

**Registries as data sources.** verifiably does not own citizen data — it READS
from external authoritative registries (Sunbird RC at `:18091`, the federated
agency registries at `*.registry.<domain>`) via the bulk engine's four connectors
(CSV / secured API / PostgreSQL / Sunbird search, `internal/handlers/bulk.go`),
mapping columns to fields, and writes the result into `certify.vc_subject`
(issuance claims) or `certify.identity_registry` (registrar enrolment). Configured
via `VERIFIABLY_REGISTRIES`. Full detail: [dpg/registries.md](dpg/registries.md).

## HTTP API surface

Beyond the HTMX HTML routes, verifiably exposes a REST API (bearer-authed) and a
set of registrar/holder HTML routes:

- **Issuance/credentials:** `POST /api/v1/schemas`, `GET /api/v1/schemas`,
  `POST /api/v1/subjects` (provision `vc_subject`),
  `POST /api/v1/credentials/issue[/bulk[/async]]`, `GET /api/v1/credentials[/{id}]`,
  `POST /api/v1/credentials/{id}/{revoke,reinstate}`, `GET /api/registry-credentials`.
- **Delegated access:** `POST /api/v1/delegation/{issue,issue/bulk}`,
  `/api/v1/delegation/inji/{setup,revoke,preauth/issue,preauth/claim}`,
  `POST /api/v1/delegation/verify/{sdjwt,request}`,
  `GET /api/v1/delegation/verify/result/{state}` — see [delegated-access.md](delegated-access.md).
- **Registrar (HTML, admin-gated):** `/registrar/identities`,
  `POST /registrar/identities/{source,preview,apply,registry-entities}`.
- **Holder (HTML):** `/holder/register` (registry-gated activation),
  `/holder/wallet/inji/*` (the in-app auth-code wallet + QR-on-PDF).

The `SubjectProvisioner` interface (`internal/handlers/api_subjects.go`) backs the
subject/identity/credential-config operations; it is implemented by
`internal/storage/pg`.

## Testing

`e2e/` holds puppeteer-core tests per DPG flow:

- `waltid-test.mjs` — end-to-end issue + hold + present on walt.id
- `inji-test.mjs` / `injiweb-test.mjs` / `injiverify-test.mjs` —
  flow-specific checks per MOSIP component
- `matrix-test.mjs` — every DPG × role combination renders and commits
- `injiweb-credentials-visible.mjs` — regression for the FX5 bug (UI origin
  mismatch caused "No Credentials found")
- `i18n-inner-pages.mjs` — translation middleware covers deep pages
- `bulk-csv-test.mjs` / `scan-upload-test.mjs` / `present-test.mjs` —
  isolated feature checks

Run a single test with `CHROME_PATH=/usr/bin/google-chrome node e2e/<name>.mjs`.
Go unit tests (currently `internal/adapters/registry` routing) run with
`go test ./...`.
