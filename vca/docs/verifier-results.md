# Verifier presentation results

This page describes the `verifier-results` service (ADR-025). The service
README at [`services/verifier-results/README.md`](../services/verifier-results/README.md)
says how to run it. This page says how it works.

## Data model

One document holds one result. A second document holds the raw
presentation of that result. The keys are `result/<id>` and `raw/<id>`.

A `VerificationResult` carries these fields.

| Field | Meaning |
|---|---|
| `id` | The result id. The service makes a random hexadecimal id. |
| `verdict` | The overall verdict of the policy evaluation. |
| `checks` | The checks that ran on the whole presentation. |
| `cross_checks` | The cross credential rule results of ADR-026. |
| `credentials` | One `CredentialSummary` per credential. |
| `raw_ref` | The reference of the raw presentation. The purge clears it. |
| `template_id`, `template_version` | The presentation template. |
| `policy_set_id`, `policy_set_version` | The rules that ran (ADR-024 decision 6). |
| `received_at`, `evaluated_at`, `retain_until` | The times of the record. |
| `carrier` | How the presentation arrived, as a plain word. |
| `tenant_id` | The tenant that owns the result. |

A `CredentialSummary` is the card of one credential. It holds the title,
the type, and the wire format. It holds the issuer and the issuer display
name. It holds the trust word and the role in a combined presentation. It
holds the subject display fields and the check list. It holds the
validity window and the decoded credential as JSON.

## The card list

The `cards` package renders one result as a card list (ADR-025 decision 2):

1. A summary card. It shows the verdict badge and the check time. It also
   shows the carrier, the template, and the policy set.
2. One card per credential. It shows the issuer name and a trust badge.
   It also shows the type, the role, and the validity window. It ends with
   the subject display fields and the check list.
3. A disclosure inside each credential card. It holds the full JSON.

The staff portal and the citizen page both render this list. The two
views cannot drift apart. The `json` component of the UI kit gives the
disclosure a `summary` control and a labelled region. A screen reader
then announces the expanded state (ADR-025 decision 6, ADR-027 decision 8).

Every page test calls `a11ytest.AssertPage`. The assertions cover one
`h1`, the `lang` attribute, and the skip link. They also cover the
labelled navigation and the `main` landmark. They also cover named
buttons and labelled inputs. They reject a placeholder link.

## Trust words

The card shows one of four words. The `check` package reads them from the
`trust_chain` check of the policy evaluation.

| Word | Source |
|---|---|
| `trusted` | The trust chain check passed. |
| `untrusted` | The trust chain check failed. |
| `unavailable` | The trust chain check could not run. |
| `unknown` | No trust chain check ran. |

## Retention

The purge runs on a schedule and on request (ADR-025 decision 3). It
takes two steps for each result:

1. The raw presentation goes first. The purge acts when the evaluation
   time plus `RAW_RETENTION` has passed. It deletes the `raw/<id>`
   document. It clears `raw_ref` and every `decoded_json` field.
2. The result goes second. When `retain_until` has passed, the purge
   deletes the `result/<id>` document.

`RAW_RETENTION` must not be longer than `RETENTION`. The raw
presentation can then never outlive the result. A `dry_run` request
counts the deletions and writes nothing. A `raw_only` request does step 1
only.

## Query and export

`Query` reads every result, filters it, and returns a page. The newest
result comes first. The filter matches on the evaluation time and the
verdict. It also matches on the issuer of any credential, the template
id, and the tenant. The filter functions are pure. The Query RPC, the
Export RPC, and the portal list page all use the same code
(ADR-025 decision 4).

`Export` streams the matching results in 32 KiB chunks. The CSV form
follows RFC 4180. It has a header row and one row per credential. The
JSON form writes one compact JSON object per line. The portal serves the
same two encodings as a download at `GET <prefix>/export`.

## Staff pages

The staff pages sit in the verifier frame of
`services/internal/staffshell` (board Verifier-Portal, ADR-044 decisions
3 and 5). The frame shows the role chip and the switcher of the
verifier pairs that run. It also shows the user menu of the
`verifier-auth` session and the side navigation of `internal/rolenav`.
The sign
out form ends the session at `verifier-auth` and clears the cookie.

| Path | Page |
|---|---|
| `GET /portal/` | The overview: the saved queries, the open requests, the trust cache state, the schemas you can ask for, and the recent results. |
| `GET /portal/results/` | The result list with the filters and the export links. |
| `GET /portal/results/{id}` | The card list of one result. |
| `GET /portal/export` | The CSV or JSON download of the filtered results. |
| `GET /portal/cache/` | The trust cache of board Verifier-Caching: the age and the counts of each kind, every source, and the cache policy. |
| `POST /portal/cache/sync` | Sync now: the policy service reads every source at once. |
| `POST /portal/cache/policy` | Store the refresh intervals and the offline settings. |
| `GET /portal/help/` | What each verifier page does, and every verifier RPC. |
| `POST /portal/signout` | The sign out form of the user menu. |

The result list moved from `/portal/` to `/portal/results/`. An old
list URL with a query answers `301` to the new path with the query
kept.

The overview reads its counts on the compose network (ADR-047 decision
2). `ListTemplates`, `ListCredentialTypes`, and `GetFields` of the
discovery service at `VCA_VERIFIER_RESULTS_DISCOVERY_URL` give the saved
queries and the schemas. `ListTransactions` of the ingestion service at
`VCA_VERIFIER_RESULTS_INGEST_URL` counts the requests that wait for a
wallet. A card shows "Unknown now" when its service does not answer.
The trust cache card reads `GetCacheState` of the policy service at
`VCA_VERIFIER_RESULTS_POLICY_URL`. It shows the age of the oldest copy
and the offline window (ADR-041 decision 5).

## Audit log

The service writes one audit event for each stored result, with its verdict (ADR-039 decision 1).
The event names the actor, the action, the target, the outcome, and the
request id. It never holds a claim value. A failure names the Connect
code of the answer, never the text of the error. The service checks no
session itself, so the actor is the one its caller names in the
`X-Vca-Actor` header.

The events live in an append only store under `VCA_VERIFIER_RESULTS_AUDIT_DIR`.
The CLI sets it to `/data/audit`. The service serves the store as
`vca.audit.v1.AuditService` on the internal network. Only the admin
opens it: an admin session that the key set at `VCA_VERIFIER_RESULTS_ADMIN_JWKS_URL`
signed, or the token in `VCA_VERIFIER_RESULTS_ADMIN_TOKEN`. The pair proxy does not
route the service. `SetRetention` keeps the events of the last days the
admin sets and removes older ones.

## Citizen page

The public page takes one pasted credential or presentation
(ADR-025 decision 5). It calls the verifier policy service, builds a
result in memory, and renders the same card list. It never calls the
store, and a test asserts that the store stays empty after a check.

A deployment without `POLICY_URL` still serves the page. The page then
says that the deployment does not offer the check.

## Follow-ups

| Item | Reason |
|---|---|
| Raw presentation upload | The `Store` RPC takes a reference, not the bytes. The service that holds the bytes writes the raw document. The ingestion service does that. |
| Tenant access rules | The filter accepts a tenant. The service does not yet read a session. The admin service brings the session. |
