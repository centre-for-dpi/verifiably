# verifier-auth: staff login for the verifier role

`verifier-auth` logs verifier staff in with OpenID Connect and issues
ES256 session tokens. Other verifier services check a token with the
public key at `/.well-known/jwks.json` and keep no session table. This
page describes what differs from issuer-auth. The service
[README](../services/verifier-auth/README.md) tells you how to run it.

This implements ADR-036 decision 1. The flow, the session token, the
logout, and the machine clients come from [issuer-auth](issuer-auth.md),
which implements ADR-012. So do the provider records and the storage.
The two services share the code of `services/internal/oidcflow` and
the sign in chooser of `services/internal/signin`.

## What differs from issuer-auth

| Part | issuer-auth | verifier-auth |
|---|---|---|
| Audience of a session JWT | `vca-issuer` | `vca-verifier` |
| Roles | `issuer-admin`, `issuer-operator`, `issuer-viewer` | `verifier-admin`, `verifier-operator`, `verifier-viewer` |
| Variable prefix | `VCA_ISSUER_AUTH_` | `VCA_VERIFIER_AUTH_` |
| Session cookie | `vca_issuer_session` | `vca_verifier_session` |
| Connect service | `vca.issuerauth.v1.IssuerAuthService` | `vca.verifierauth.v1.VerifierAuthService` |
| Seed realm | `vca-issuer-realm` | `vca-verifier-realm` |
| Machine roles of an API key | `admin` gives admin, `issuer` gives operator | `admin` gives admin, `verifier` gives operator |

The audit log of issuer-auth applies here too. The service writes the
same sign in events and serves them only to the admin (ADR-039). A
session with `verifier-admin` does not open the audit store.

An issuer session never passes a verifier guard, because the audience
differs. A verifier staff member who also holds issuer roles at the
provider gets the verifier roles only: the mapping of this service
knows the three verifier role names and nothing else.

## Roles

`verifier-admin` changes policies, trust caches, and providers.
`verifier-operator` runs presentation requests and reads their results.
`verifier-viewer` reads every page and changes nothing. The default
mapping reads the realm roles claim and takes the three names as they
are. A subject with none of them cannot log in.

## Pages and routes

The pair proxy routes `/auth/*`, `/token`, and `/.well-known/jwks.json`
to the service. It routes the Connect service and
`/vca.admin.v1.AdminService/*` there too.
`GET /auth/` draws the sign in chooser of the verifier role (ADR-035),
`GET /auth/providers.json` lists the providers, and
`GET /auth/register` starts a registration. The service reads the theme
file of the deployment at start, like every service that draws pages
(ADR-032).

## Deployment

Every verifier pair runs the service (ADR-036 decision 1). It takes the
auth port of the pair, `VCA_PORTS_AUTH`, and adds 96 MiB to the memory
floor of the pair. The floor table in [deploy.md](deploy.md) carries
the new totals. The host ports of the other verifier services move up
by one. The CLI assigns them in service name order. `vca setup` writes
the new plan into `deploy/verifier-<dpg>/.env`.

## Staff session guard

The staff pages of `verifier-results`, `verifier-discovery`, and
`verifier-ingest` need a session of this service (ADR-036 decision 2).
The shared package `services/internal/staffsession` checks the session
JWT against the key set at `/.well-known/jwks.json`, the audience
`vca-verifier`, and the expiry time. A page request without a session
goes to the sign in chooser at `/auth/` with `return_to`. Any other
request without a session gets 401. Every POST of a staff page carries
a form token that the guard binds to the session. The citizen check,
the catalogue, and the OID4VP endpoints stay open.

The CLI writes `VCA_<SERVICE>_AUTH_JWKS_URL` and
`VCA_<SERVICE>_LOGIN_URL` for each guarded service. The issuer pages of
`schema-registry` and `schema-builder-ui` use the same guard against
`issuer-auth` (ADR-036 decision 3).

## Tests

The test suite runs the full flow against a fake OpenID Provider on
`httptest`. It covers the login with PKCE, the audience of the session,
the role mapping, and the register action. It covers the machine
clients and the provider RPCs too. Every package has 90 percent
statement coverage or more.
