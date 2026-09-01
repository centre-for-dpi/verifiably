# DPG compatibility matrix

Capability claims in the UI reflect specific documented releases. These
versions are **not a tested-compatible matrix** — each vendor publishes
its own compatibility table. `cross-stack` scenarios (walt.id issues, Inji
verifies, etc.) work on a case-by-case basis; known breakage is called
out below with the workaround the verifiably-go inji-proxy applies.

> **Per-DPG implementation guides** (containers, env, Caddy, configs, DBs, APIs,
> gotchas) live in [`docs/dpg/`](dpg/README.md). This matrix is the compatibility
> view; the guides are the how-it-runs view.
>
> **Inji Certify runs as two independent instances** — Auth-Code
> ([guide](dpg/inji-certify-authcode.md)) and Pre-Auth
> ([guide](dpg/inji-certify-preauth.md)) — with separate containers, DBs, DIDs,
> and public hosts. Both are now **public issuers** (public `credential_issuer` +
> status-list URLs). The auth-code holder wallet is served **in-app** (QR-on-PDF
> download included), not via the external Inji Web SPA.

## Versions

| Component                 | Version  | Source                                                                 |
|---------------------------|----------|------------------------------------------------------------------------|
| walt.id Community Stack   | v0.18.2  | `waltid/issuer-api:0.18.2`, `wallet-api:0.18.2`, `verifier-api:0.18.2` |
| Inji Certify (both)       | v0.14.0  | `injistack/inji-certify-with-plugins:0.14.0`                           |
| Inji Web (Mimoto + SPA)   | v0.16.0 / v0.21.0 | `injistack/inji-web:0.16.0`, `injistack/mimoto:0.21.0`         |
| Inji Verify (UI + service)| v0.16.0  | `mosipid/inji-verify-ui:0.16.0`, `mosipid/inji-verify-service:0.16.0`  |
| eSignet + OIDC-UI         | v1.5.1   | `mosipid/esignet-with-plugins:1.5.1`, `mosipid/oidc-ui:1.5.1`          |
| mock-identity-system      | v0.10.1  | `mosipid/mock-identity-system:0.10.1`                                  |
| CREDEBL                   | v2.x     | `ghcr.io/credebl/*:latest` (unpinned; Credo-TS agent)                 |
| Keycloak                  | 25.0     | `quay.io/keycloak/keycloak:25.0`                                       |
| WSO2 Identity Server      | 7.0.0    | `wso2/wso2is:7.0.0`                                                     |
| LibreTranslate            | v1.6.5   | `libretranslate/libretranslate:v1.6.5`                                 |
| Sunbird RC (data source)  | RC v2.0.1| external stack; consumed via `VERIFIABLY_REGISTRIES` — [guide](dpg/registries.md) |

## walt.id Community Stack v0.18.2

**What works end-to-end**

- OID4VCI pre-authorized code flow (issuer → wallet → hold)
- OID4VCI authorization code flow (issuer → eSignet-like auth → wallet)
- Legacy OID4VP (Presentation Exchange 2.0)
- Credential formats: `w3c_vcdm_2` (JWT), `sd_jwt_vc` (IETF), `mso_mdoc`

**Known limitations**

- **OID4VP v1.0** is still landing in the wallet/demo apps through v0.18.2.
  Our verifier adapter uses the PE 2.0 path; switching to v1.0 means
  redoing `RequestPresentation` and `FetchPresentationResult` against
  `/openid4vc/v1/*` endpoints when they're available.
- **OID4VP submit requires format alignment across issue→verify.** Walt.id's
  wallet-api only has a tested VP pipeline for the format/type pairs its
  own E2E suite exercises
  (`waltid-services/waltid-e2e-tests/src/test/resources/presentation/*.json`):

  - `jwt_vc_json`  ↔  OpenBadge-style credentials with `type` in the PD
  - `vc+sd-jwt`    ↔  SD-JWT VCs with `vct` in the PD

  Other combinations that walt.id's issuer CAN produce (`jwt_vc_json-ld`,
  `ldp_vc`) don't have a tested claim→present pipeline in the wallet.
  Submitting a VP where the held credential's format doesn't match the
  format the verifier's PD asked for causes the wallet to build an
  array-form `vp_token` that trips an internal assertion
  (`.jsonPrimitive.content` on a `JsonArray`) inside
  `SSIKit2WalletService.usePresentationRequest`. The error surfaces as
  `400 "Element class kotlinx.serialization.json.JsonArray is not a
  JsonPrimitive"`. Our adapter now:
  1. Deduplicates walt.id's credential catalog by `(Name, Std)`, keeping
     the format walt.id has tested (jwt_vc_json for w3c_vcdm_2, vc+sd-jwt
     for sd_jwt_vc) via a `formatRank` preference.
  2. Builds the verifier's `request_credentials` with `vct` for SD-JWT
     formats and `type` otherwise, matching walt.id's E2E fixtures.
  End-to-end issue→claim→present→verify works on the `jwt_vc_json +
  OpenBadgeCredential` path (reproduced via curl with `verificationResult:
  true`).
- No documented QR-on-PDF export path. `IssueAsPDF` falls back to `DirectPDF: false`.
- The Kotlin wallet's OID4VCI client strips `credential_definition.@context`
  from credential requests. When using walt.id wallet against Inji Certify,
  our `/inji-proxy/issuance/credential` handler injects a sensible default
  (`https://www.w3.org/ns/credentials/v2`).

## Inji Certify v0.14.0

> Runs as two instances: **Auth-Code** (eSignet + in-app wallet + QR-on-PDF —
> [dpg/inji-certify-authcode.md](dpg/inji-certify-authcode.md)) and **Pre-Auth**
> (direct-to-PDF — [dpg/inji-certify-preauth.md](dpg/inji-certify-preauth.md)).
> Both sign public did:web credentials with public status-list URLs.

**What works**

- Issuance via both OID4VCI pre-authorized code (demo/staging) and
  authorization code (production) flows.
- Ed25519 signing; keys managed by MOSIP's keymanagerservice and stored
  in `certify.key_store`.

**Known bugs we work around**

1. **Split-kid VC vs status-list signing.** Inji Certify signs regular VCs
   with one kid fragment and bitstring status-list credentials with a
   different kid, both derived from the same Ed25519 key. Its own
   `.well-known/did.json` publishes only one. Inji Verify's
   `DidWebPublicKeyResolver` matches kid strictly, so verification either
   of the main VC or the status list (it needs both) fails with
   `PublicKeyResolutionFailedException` → the UI surfaces "Internal
   Server Error".

   **Workaround**: certify-nginx's `/.well-known/did.json` is rerouted
   through `verifiably-go:/inji-proxy/.well-known/did.json`. The proxy
   watches every VC it forwards for `proof.verificationMethod` kids and
   publishes all observed kids as synthetic `verificationMethod`
   entries — all pointing at the upstream `publicKeyMultibase`. The
   `/v1/certify/credentials/status-list/` endpoint is also proxied so
   status-list kids get recorded.

   The primary (auth-code) and pre-auth Inji Certify instances run
   under **separate DIDs** — `did:web:certify-nginx` and
   `did:web:certify-preauth-nginx` respectively — so their signing
   keys never appear in the same did.json. Before the split, both
   instances claimed `did:web:certify-nginx` and an unfortunate kid
   collision (different Ed25519 keys, same kid fragment) stranded
   whichever flow lost the merge-order race. Now each flow has its own
   resolution path: `/inji-proxy/.well-known/did.json` (primary) and
   `/inji-proxy-preauth/.well-known/did.json` (pre-auth), backed by
   separate `certify-nginx` + `certify-preauth-nginx` front-ends and
   separate `injidid.Primary` + `injidid.Preauth` kid observers.

2. **Key rotation desyncs status-list signatures.** If the Ed25519 key
   rotates (any compose reset that wipes `waltid_certify-pkcs12`) but
   the status-list credential row survives (`waltid_certify-db`), every
   previously-issued VC fails verification because its status-list can't
   verify against the new key. Symptom: `STATUS_VERIFICATION_ERROR -
   Invalid signature on status list VC`.

   **Workaround**: for local dev, do a full reset (see
   [deploy.md § Full reset](deploy.md#full-reset)) so keys and the
   status-list table regenerate together. In production, key rotation
   would require the issuer to re-sign the status-list VCs.

3. **Credential-issuance endpoint proxies back to us.** `certify-nginx`
   routes `POST /v1/certify/issuance/credential` through
   `host.docker.internal:8080/inji-proxy/issuance/credential`. Without
   our handler registering that route, Mimoto's credential download
   gets a 404 and Inji Web shows "An Error Occurred — unable to
   download the card". Our handler forwards to `inji-certify:8090`,
   optionally patching `credential_definition.@context`.

4. **mDoc (ISO 18013-5) issuance is real, not mock-only, since 2026-08-25.**
   This item used to say "mock-only per Inji Certify's own README at
   v0.14.0" — that was true when written and is no longer true: mso_mdoc
   (mDL and Photo ID) is now issued for real through Inji Certify's
   Pre-Auth path, alongside walt.id/issuer-api2 as a second production
   emitter. `internal/adapters/injicertify/db.go`'s `saveMdocSchema` writes
   a real `credential_config` row; the mso_mdoc option in the schema
   builder is offered unconditionally (not gated behind a mock-only
   warning — `templates/pages/issuer_schema_builder.html`, corrected in
   commit `b2b9851`). Reaching this took a run of fixes worth knowing about
   if you touch this path: claims must nest under the real ISO namespace
   before POSTing (`8b9aba7`), Velocity template markers resolve via
   bracket-notation nested access (`40fd683`), `ListSchemas` must resolve
   `driving_privileges`/`portrait`'s real Format (`3ff6b59`), and nginx +
   Spring Boot's embedded Tomcat both needed their max header size raised
   for Inji's larger access tokens (`2581b61`, `513327e`, `60befa3`).
   **Known limitation that IS still real**: Inji Certify's own mdoc
   conversion does not bstr-encode `portrait` correctly (`d222c33`) — an
   upstream defect in Inji Certify itself, not something this repo's config
   can work around; mitigated wallet-side in `cdpi-wallet`. See
   [`dpg/inji-certify-preauth.md`](dpg/inji-certify-preauth.md) for the
   operational detail this line summarizes.

5. **Two key aliases in `certify.key_alias`** for `CERTIFY_VC_SIGN_ED25519`
   (one with ref_id `ED25519_SIGN`, one with ref_id NULL). Only the
   former has a private key in `key_store`; the latter acts as a
   key-encryption-key wrapper. No action needed, but worth noting if you
   debug the DB.

## Inji Web Wallet v0.16.0

**What works**

- Guest + Google OIDC login
- Browser-hosted wallet (credentials live inside the SPA / Mimoto DB)
- PDF export with embedded QR for JSON-LD VCs (pixelpass compression)

**Known bugs we work around**

1. **`MIMOTO_URL` hardcodes `${PUBLIC_HOST}:3004`.** Injected at container
   start into `env.config.js`. If the browser loads the SPA on a
   different origin (e.g. `localhost:3004`) every `/v1/mimoto/*` XHR is
   cross-origin and browsers block the responses → UI falls back to "No
   Credentials found" even when Mimoto is healthy.

   **Workaround**: `UIURL` in verifiably-go's backends.json points at
   `http://172.24.0.1:3004` (matching `PUBLIC_HOST` in the shared `.env`),
   so the redirect lands on the SPA's configured origin.

2. **eSignet DB caches stale `redirect_uris`.** `seed-esignet-client.sh`
   returns OK on `duplicate_client_id` but doesn't update — so if a
   previous deploy used a different PUBLIC_HOST, eSignet rejects
   /authorize with `invalid_redirect_uri`. The client's redirects are
   also cached in Redis.

   **Workaround**: `repair_injiweb_client_redirect_uri` in deploy.sh
   appends the current redirect to the DB list and `DEL`s the Redis
   `clientdetails::wallet-demo-client` cache. Idempotent.

3. **SD-JWT credentials don't get a QR on PDF export.** Mimoto's pixelpass
   library is designed for structured JSON-LD VCs (CBOR-serialize
   credentialSubject → zlib → base45); SD-JWT is already a compact JWS
   string so the pipeline doesn't apply. v0.16.0 ships no alternative
   SD-JWT QR path. **Not fixed** — pick LDP Farmer (V2 or plain) if you
   need a QR; SD-JWT credential is storage-only.

4. **Auth-Code + Mimoto rejects Farmer Credential and Farmer Credential (V2)
   with `err_signature_verification_failed`.** The `/v1/mimoto/credentials/download`
   call returns HTTP 400 "we were unable to download the card" after a
   successful eSignet login. **SD-JWT variant works; LDP_VC variants don't.**

   **The bug is in MOSIP's vc-verifier library, not in Inji Certify's
   signing.** We proved this end-to-end:

   1. Intercepted the VC Inji Certify hands Mimoto via tcpdump on Mimoto's
      netns (port 80 on certify-nginx upstream).
   2. Ran the intercepted VC through pyld (reference Python URDNA2015) +
      pynacl Ed25519 verify, using the same public key certify-nginx's
      did.json advertises. Result: **VALID**. Signature matches
      SHA256(canon(proofOpts)) || SHA256(canon(doc)) per the
      Ed25519Signature2020 / W3C Data Integrity spec.
   3. Posted the same VC to Inji Verify's `/v1/verify/vc-verification`
      endpoint (which also uses `io.mosip.vercred.vcverifier`). Result:
      **INVALID** — same library, same rejection, independently of Mimoto.

   Conclusion: the library's URDNA2015 canonicaliser disagrees with the
   reference spec implementation for this VC. Most likely divergence points:
   the `BitstringStatusListEntry` credentialStatus block (VCDM 2.0 feature)
   or the `{"@vocab": "…"}` context fragment — setting
   `mosip.certify.issuer.ledger-enabled=false` in the Farmer plugin config
   doesn't actually strip `credentialStatus`, and replacing `@vocab` with
   explicit term definitions didn't fix it either. Both tested here.

   The danubetech/ld-signatures-java version Mimoto ships (v0.16.0) is
   older than Inji Certify's (v0.14.0). MOSIP's tested matrix is Mimoto
   v0.16.0 ↔ Inji Certify v0.13.1 — we run v0.14.0. Upstream issue to
   track against mosip/vc-verifier, not a verifiably-go fix.

   **Workaround**: use **Farmer Credential (SD-JWT)** in Auth-Code
   demos. SD-JWT verification is a plain JWS signature check — no
   URDNA2015, no context expansion, no canonicalisation — and
   round-trips cleanly. The LDP variants are "issue-only" for Auth-Code
   + Inji Web until Mimoto ships with an updated vc-verifier library.

   Reproduction (for tracking progress against upstream):

   ```bash
   # 1. capture a VC from Mimoto's download flow
   docker run -d --rm --name mimoto-tcpdump \
     --network=container:injiweb-mimoto \
     --cap-add=NET_ADMIN --cap-add=NET_RAW \
     -v /tmp/pcap:/cap nicolaka/netshoot \
     tcpdump -i any -A -s 0 -w /cap/mimoto.pcap 'tcp port 80'
   # drive the failing Auth-Code + Farmer Credential (V2) flow in the UI
   docker stop mimoto-tcpdump
   grep -a -o '{"credential":.\{500,6000\}"proof":[^}]*}}*' /tmp/pcap/mimoto.pcap | head -1 > /tmp/vc.json

   # 2. verify via pyld + pynacl (reference implementations)
   python3 -m venv /tmp/vv && /tmp/vv/bin/pip install pyld pynacl base58 requests
   /tmp/vv/bin/python - <<'PY'
   # (see docs/dpg-matrix.md — same script runs pyld URDNA2015 + pynacl Ed25519)
   PY
   # → VALID

   # 3. verify via MOSIP's library
   docker run --rm --network waltid_default -v /tmp/vc.json:/b.json:ro \
     curlimages/curl:latest -s -X POST -H 'Content-Type: application/json' \
     -d @/b.json http://inji-verify-service:8080/v1/verify/vc-verification
   # → {"verificationStatus":"INVALID"}
   ```

## Inji Verify v0.16.0

**What works**

- Direct upload / paste of JSON-LD VCs → `POST /v1/verify/vc-verification`
- SD-JWT VC submission (v0.16.0 added `POST /vc-submission` +
  `GET /vp-result/{transactionId}`)
- OID4VP cross-device flow via the Inji Verify SPA (full flow)

**Known bugs we work around**

1. **Missing `/assets/config.json` crashes the result screen.** The UI
   fetches this file at boot for its per-credential field render-order
   map. Upstream v0.16.0 ships without it, so nginx 404s fall through to
   `index.html`, the UI `JSON.parse`s HTML, gets an empty object, then
   crashes with `Cannot read properties of undefined (reading 'map')`
   after every successful verification.

   **Workaround**: we mount
   `deploy/injiweb-overrides/inji-verify-config.json` into the
   inji-verify-ui container at `/usr/share/nginx/html/assets/config.json`
   with render orders for the Farmer credential (and stubs for the
   other types the UI's switch covers).

2. **INJIVER-1131** (cross-device): Inji Verify v0.16.0 can report
   SUCCESS for a VC whose claims don't match the requested fields in a
   presentation definition. Our `injiverify` adapter re-checks the
   disclosed claims against the requested fields and downgrades the
   verdict if they don't match. This is flagged as `Caveats` on the
   Inji Verify DPG card.

3. **Tested-compatibility matrix**: per MOSIP's own release notes, Inji
   Verify v0.16.0 was tested against **Inji Certify v0.13.1** and **Inji
   Web v0.17.0**. We run v0.14.0 + v0.16.0 — so the two workarounds
   above (did.json kids + assets/config.json) also paper over pairing
   mismatches. Upstream is moving to a cleaner verify-service +
   canonicalization pipeline in their next minor.

## Cross-stack compatibility summary

| Issuer ↓ / Holder → / Verifier → | walt.id wallet      | Inji Web Wallet     | walt.id verifier | Inji Verify                         |
|----------------------------------|---------------------|---------------------|------------------|-------------------------------------|
| walt.id issuer                   | End-to-end          | Not supported (Inji Web is catalog-initiated, not offer-consuming) | End-to-end | Works for W3C VCDM formats after @context alignment |
| Inji Certify pre-auth            | End-to-end          | Not compatible (Mimoto assumes auth-code)                          | Works — adapter re-canonicalizes | Works (with inji-proxy kid fix) |
| Inji Certify auth-code           | Not supported (walt.id wallet has no eSignet login) | End-to-end          | Works              | Works (with inji-proxy kid fix) |

The DPG selection cards in the UI reflect these combinations via their
`Capabilities` arrays — users only see combinations that have been verified
to work.
