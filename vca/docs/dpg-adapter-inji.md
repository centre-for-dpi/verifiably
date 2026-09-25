# Inji DPG adapter

The Inji DPG adapter connects Verifiable Credentials Adapters to Inji
Certify and Inji Verify. It is one of the three DPG adapters of ADR-002
decision 1. The vendor name appears in this service and nowhere else.

## Why the service exists

Inji Certify issues credentials and Inji Verify checks presentations.
Neither ships a wallet for a citizen. The legacy code closed that gap in
two ways. It ran the whole OID4VCI pre-authorized flow itself. It also
printed the credential on paper. This adapter keeps both abilities. It
drops the two acts that ADR-002 decision 4 forbids: it never writes the
Inji database, and it never restarts an Inji container.

## What it serves

| Service | State |
| --- | --- |
| `CapabilityService` | Always served. |
| `IssuerBackendService` | Served when the configuration names an Inji Certify URL. |
| `HolderBackendService` | Never served. Inji ships no wallet for a citizen. |
| `VerifierBackendService` | Served when the configuration names an Inji Verify URL. |
| `CatalogBackendService` | Served when the configuration names an Inji Certify URL. |
| `TenantBackendService` | Never served. Inji keeps no tenants. |

## The Inji endpoints

| Endpoint | What the adapter does with it |
| --- | --- |
| `POST /v1/certify/pre-authorized-data` | Stages the claims of one subject. |
| `GET` on the offer document | Reads the pre-authorized code and the issuer. |
| `POST /v1/certify/oauth/token` | Redeems the code for an access token and a nonce. |
| `POST /v1/certify/issuance/credential` | Asks for the signed credential. |
| `GET /v1/certify/issuance/.well-known/openid-credential-issuer` | Reads the catalogue. |
| `POST /v1/verify/vp-request` | Starts an OID4VP transaction. |
| `GET /v1/verify/vp-result/{id}` | Reads the answer of a transaction. |

## What the adapter can do

The answer of `GetCapabilities` reports what the deployment supports.

| Item | Value |
| --- | --- |
| Formats | `ldp_vc`, `vc+sd-jwt` |
| Channels | OID4VCI pre-authorized code and document. An identity provider adds the authorization code flow. |
| Protocols | OID4VCI, OID4VP, OID4VP with Presentation Exchange |
| Roles | The roles whose URL the configuration sets |
| Features | None today. Every RPC behind a feature answers `unimplemented`. |
| DID methods | None. The deployment sets the issuer identity of Inji Certify. |
| Status mechanisms | Bitstring status list and token status list, when the configuration names a Certify URL |
| DPG information | The stack name, the Certify release, and one component per wired role plus Keycloak |

Each component carries its pinned version, its repository, its
documentation, and its licence. The versions come from the
configuration, and a test binds the defaults to the stack file. A page
shows a feature on this stack only when the answer lists it (ADR-034).

## What the adapter does not do

| RPC | Reason |
| --- | --- |
| `RegisterCredentialConfiguration` | Inji Certify reads its configurations from its own database. The deployment applies them. |
| `GetIssuanceStatus` | Inji Certify reports no state of a staged offer. |
| `Revoke` | Inji Certify has no revocation API. The status services own the bits. |
| Every holder RPC | Inji ships no wallet for a citizen. |
| Every tenant RPC | Inji keeps no tenants. |

Each of these answers with the Connect code `unimplemented` and a
sentence that names the alternative.

## Interoperability knowledge

The adapter carries the knowledge the legacy code proved in the field.

**The proof header names the key once.** The holder proof carries `typ`,
`alg`, and `jwk`. It carries no `kid`. Inji rejects a header that names
the key twice.

**The proof payload has no holder.** The pre-authorized flow of OID4VCI
has no named holder, so the payload carries no `iss` and no `sub`. It
carries `aud`, `iat`, `exp`, and the nonce of the token endpoint.

**The proof audience is the issuer of the offer.** The offer document
names the credential issuer. That value is right in a local deployment
and in a public one. A fixed value breaks the flow the moment the
deployment gets a public name.

**The token endpoint is not under the issuance path.** Inji serves the
pre-authorized token endpoint at `/v1/certify/oauth/token`.

**The status markers are always present.** The credential template
carries two placeholders, `statusIdx` and `statusUri`. The staging call
must fill both, even with the index 0 and an empty address. An unfilled
placeholder makes Inji answer with a bad request. The same two markers
serve two shapes. One is the IETF token status list of an SD-JWT. The
other is the W3C bitstring status list entry of a JSON-LD credential.

**A marker the template never declared is an error.** The adapter adds
the validity markers only when the caller sends a validity window.

**The JSON-LD request repeats the context.** Inji compares the
`@context` of the credential request with the one of the metadata. The
adapter copies the value word for word.

**The offer document keeps its path and loses its host.** Inji advertises
the offer under the public name of the deployment. The adapter reads the
document from the instance it staged the claims on. A deployment with a
public name and an internal name then needs no rewrite rule.

**The adapter hosts the authorization code offer.** Inji Certify hosts
no such offer. The adapter builds the document, serves it at
`/offers/{id}`, and points the wallet at it.

**The wrong credential can pass the DPG check.** Inji Verify sometimes
reports a success for a presentation that answers with another
credential. The adapter records the claim names of the request. When the answer arrives, it checks that at
least one presented credential carries one of those names. It lowers the
verdict when nothing matches, and it adds a failed check that says so.

## The paper document channel

The `Issue` RPC returns the signed credential without a wallet. The
issuance service turns that credential into a one page document with a
QR code (ADR-016 decisions 3 and 4). The QR payload of the MOSIP reader
is the `core/pixelpass` encoding: the credential becomes CBOR, then zlib
deflate, then base45. A raw JSON payload breaks the base45 reader of the
MOSIP tools at the first character.

## Tests

The recorded set replays answers of Inji Certify 0.14.0 and Inji Verify
0.16.0 from `testdata` through an `httptest` fake. It runs in every
build.

The contract set targets a real Inji deployment. It carries the build
tag `contract_inji`. It skips itself when the variables hold no value.

## Reference

- Service folder: `services/dpg-adapter-inji`
- Contract: `proto/vca/backend/v1/backend.proto`
- Decisions: ADR-002 decisions 2 and 4, ADR-016 decisions 3, 4, and 6, ADR-030 decision 2
