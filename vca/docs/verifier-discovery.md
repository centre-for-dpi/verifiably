# Verifier discovery

This page describes the `verifier-discovery` service (ADR-022). The
service README at
[`services/verifier-discovery/README.md`](../services/verifier-discovery/README.md)
says how to run it. This page says how it works.

## The crawl

The crawler reads the trusted issuers from the trust registry
(ADR-022 decision 1). It calls `ListEntries` with the issuer role and the
active status. It calls `TrustLookup` for each entry, so the catalogue
records the trust outcome of the crawl.

For each issuer with a service endpoint the crawler fetches two documents.

| Document | Path | Content |
|---|---|---|
| Issuer metadata | `/.well-known/openid-credential-issuer` | The credential configurations of OpenID4VCI 1.0. |
| Schema list | `/api/schemas` | The published schemas of a VCA issuer, with the JSON Schema of each one. |

The crawler merges the two. The metadata gives the type, the
configuration id, the format, and the display metadata. The schema list
gives the claims and the schema document. A type that only the schema
list names joins the catalogue too.

A failed fetch does not empty the catalogue. The crawler keeps the last
good record. It writes the error into `last_error`. The pages then stay
useful while an issuer is down.

## The fetcher

The fetcher guards every request (ADR-023 decision 5 applies the same
rule to the ingestion service).

| Rule | Behaviour |
|---|---|
| Scheme | `https` only. `http` needs `ALLOW_PLAIN_HTTP`. |
| User name | The guard rejects a URL with a user name. |
| Host | The host must be on `ALLOWED_HOSTS` when the list is not empty. |
| Address | The guard rejects a loopback, private, link local, multicast, unspecified, or carrier shared address. `ALLOW_PRIVATE_NETWORK` turns the rule off for development. |
| Size | The body stops at `MAX_DOCUMENT_BYTES`. |

The fetcher caches each document. It answers from the cache while the
document is younger than `CACHE_TTL`. After that it sends
`If-None-Match` with the stored entity tag, so an unchanged document
costs one `304 Not Modified` answer.

## The catalogue

| RPC | Answer |
|---|---|
| `Crawl` | Runs the crawl now and counts the issuers it read and the issuers it could not read. |
| `ListIssuers` | The crawled issuers in pages, ordered by issuer URL. |
| `ListCredentialTypes` | The credential types. Three filters apply: the issuer, the format, and free text. |
| `GetFields` | The claims of one credential type in schema order, with the JSON Schema document. |

A field record carries the dotted claim path, the JSON Schema type, the
format, and the title. It also says whether the schema lists the claim as
required. It also says whether the holder can disclose the claim alone.
An SD-JWT VC and a mobile document disclose single claims. A JWT VC and a
Data Integrity credential do not.

The same catalogue is public and read only at these paths
(ADR-022 decision 5).

| Path | Answer |
|---|---|
| `GET /catalog` | Every issuer with its types and fields. |
| `GET /catalog/issuers` | The issuers without their types. |
| `GET /catalog/types` | Every type, with the `format` and `type` query filters. |

Each answer carries an entity tag, a `Cache-Control` header, and
`Access-Control-Allow-Origin: *`, because a wallet reads it from another
origin.

## Presentation templates

A template stores one presentation request as a DCQL query
(ADR-022 decision 3). The core package `core/dcql` holds the typed model,
the reader, the writer, and the rules of OpenID4VP 1.0.

| Part | Rule |
|---|---|
| `credentials` | At least one credential query. Each id is unique and uses letters, digits, the underscore, and the hyphen. |
| `format` | One of `vc+sd-jwt`, `dc+sd-jwt`, `jwt_vc_json`, `ldp_vc`, `mso_mdoc`. |
| `meta` | `vct_values` for an SD-JWT VC, `type_values` for a W3C credential, `doctype_value` for a mobile document. |
| `claims` | Each claim has a path. A path segment is a name, an array index, or null for every element. A mobile document path has two segments: the namespace and the name. |
| `claim_sets` | Each entry names a claim id the credential query defines. |
| `credential_sets` | Each option names a credential query id the query defines. |

The service also generates a Presentation Exchange 2.0 definition from
the same query, because walt.id 0.18 still needs the older language. One
credential query becomes one input descriptor. A credential set becomes
one submission rule. A set with one option becomes an `all` rule. A set
with more options becomes a `pick` rule of one. The generator sets
`limit_disclosure` to `required` for a format that discloses single
claims. It sets it to `preferred` for every other format.

## Versions

A template version never changes (ADR-022 decision 4).

| RPC | Behaviour |
|---|---|
| `CreateTemplate` | Stores version 1. The id comes from the display name when the caller sends none. A second create of the same id fails. |
| `VersionTemplate` | Stores the next version of an existing template. |
| `GetTemplate` | Reads one version. Version zero reads the latest version. |
| `ListTemplates` | The latest version of each template, with a tenant filter. |
| `DeleteTemplate` | Removes every version and counts them. |

The ingestion service (ADR-023) reads a template by id and version. The
combined presentation service (ADR-026) reads it the same way. A stored
request stays stable while staff work on the next version.

## Pages

The pages use the vca UI kit (ADR-022 decision 2). Every page passes the
structural WCAG 2.2 checks of `ui/a11ytest`.

| Path | Page |
|---|---|
| `GET /portal/` | The issuer list with the trust badge, the type count, the last crawl, and the crawl action. |
| `GET /portal/types` | The credential type list with the search box, the issuer filter, and the format filter. |
| `GET /portal/fields` | The claims of one type. Each claim has a tick box. The form below them saves a template. |
| `GET /portal/templates` | The template list. |
| `GET /portal/templates/{id}` | One template with its claims, its DCQL query, the generated older definition, and the delete action. |
| `GET /portal/pe/` | The DIF Presentation Exchange 2.0 form of every saved query, for stacks that read only that form. |
| `POST /portal/signout` | The sign out form of the user menu. |

A pair sets the prefix to `/discovery`. The pages then sit in the
verifier frame of `services/internal/staffshell` (board
Verifier-Portal). The frame shows the role chip, the switcher of the
live verifier pairs, the user menu, and the side navigation.

Every page calls a `DiscoveryService` RPC in process, so the pages and
the API cannot diverge.

## Storage

The state directory holds one JSON document for each record.

| Key | Content |
|---|---|
| `issuers/<hash>` | One crawled issuer. The hash is the SHA-256 of the issuer URL. |
| `templates/<id>/v<version>` | One template version. |

An empty `STATE_DIR` keeps the records in the process, so a restart loses
them. The crawl fills the catalogue again.
