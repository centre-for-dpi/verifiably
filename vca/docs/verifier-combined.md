# Verifier combined presentation

This page describes the `verifier-combined` service (ADR-026). The
service README at
[`services/verifier-combined/README.md`](../services/verifier-combined/README.md)
says how to run it. This page says how it works.

## Combined template

A combined template holds a list of members and a list of cross rules.
One document holds one template under the key `combined/<id>`.

| Field | Meaning |
|---|---|
| `id` | The template id. An empty id gets a slug plus random hex. |
| `display_name` | The name staff read. |
| `members` | The presentation templates of the combination. |
| `rules` | The cross credential rules, in run order. |
| `policy_set_id` | The policy set each credential passes on its own. |
| `tenant_id` | The tenant that owns the template. |

A member names a presentation template id, a version, and an
alternative group. Members with the same group are alternatives. A
member with an empty group is mandatory.

## The DCQL query

`BuildDcql` reads each member template from the discovery service and
merges the credential queries into one DCQL query
(ADR-026 decision 1). The builder lives in `internal/dcql`. A shared
`core/dcql` package can replace it later without a change to the API.

The shape follows OID4VP 1.0 section 6:

```json
{
  "credentials": [
    {"id": "subject", "format": "ldp_vc",
     "meta": {"type_values": [["VerifiableCredential", "IdentityCredential"]]},
     "claims": [{"path": ["given_name"]}],
     "trusted_authorities": [{"type": "openid_federation",
                              "values": ["https://issuer.example"]}]},
    {"id": "delegation", "format": "dc+sd-jwt",
     "meta": {"vct_values": ["DelegatedAccessCredential"]}}
  ],
  "credential_sets": [
    {"options": [["subject"]], "required": true},
    {"options": [["delegation"]], "required": true}
  ]
}
```

An SD-JWT VC query narrows the type with `vct_values`. A W3C query
narrows it with `type_values`. Members of one alternative group share a
single `credential_sets` entry, and each member becomes one option of it.

A member template without the structured `queries` view falls back to
the DCQL text the discovery service stored.

## Cross credential rules

Each rule is a pure function in `internal/rules` over the credentials of
the presentation, keyed by DCQL query id.

| Kind | Parameters | What it checks |
|---|---|---|
| `SAME_SUBJECT` | `left`, `right`, optional `claim` | The two credentials name the same subject. An empty `claim` compares the subject id. |
| `DELEGATION_LINK` | `subject`, `delegation`, optional `action`, `fail_closed` | The delegation credential names the holder as the delegate of the other subject. |
| `DATE_ORDER` | `before_query`, `before_claim`, `after_query`, `after_claim` | The first date is not after the second date. |

`DELEGATION_LINK` calls `core/delegation`, which lifts the legacy
delegated access evaluator (ADR-026 decision 5). The rule reports the
linkage, the permission, and the invocation as evidence.

A rule whose named query is absent from the presentation reports `SKIP`.
A rule that cannot read a value reports `SKIP` too. Only a real mismatch
reports `FAIL`.

## Evaluation

`EvaluateCombined` takes the wallet response as one `RawPresentation`
and works in these steps (ADR-026 decisions 3 and 4):

1. It reads the combined template.
2. It assigns a DCQL query id to each credential. The request wins. The
   service then matches a free query by credential type. A credential
   with no match gets its position as the id.
3. It sends each credential to the policy service on its own. Each call
   carries a `RawPresentation` with one credential. A fault in one
   credential cannot hide inside a larger presentation.
4. It runs the cross rules over every credential.
5. It folds the per credential verdicts and the rule outcomes into one
   verdict. One `INVALID` credential or one failed rule gives `INVALID`.
   An `INDETERMINATE` credential or a rule that could not run gives
   `INDETERMINATE`.
6. It builds one card per credential. It puts the rule results in
   `cross_checks`. The summary card of the results service renders them.
7. It stores the result through the results service. Without a results
   client the answer carries the result and no id.

## Roles on a card

Each card carries a role, so staff see which credential is which:

| Role | Meaning |
|---|---|
| `delegation` | The credential carries a delegated permission. |
| `subject` | The credential carries subject attributes. |
| empty | The service could not decode the credential. |

## Follow-ups

| Item | Reason |
|---|---|
| Shared DCQL package | The builder lives in `internal/dcql`. A `core/dcql` package from another branch can replace it. The service API does not change. |
| Request creation | The service builds the query, and the ingestion service sends it to the wallet. The OID4VP transaction stays in that service (ADR-023). |
| More cross rules | The three rules of ADR-026 decision 2 are in place. A new rule is one function plus one enum value. |
