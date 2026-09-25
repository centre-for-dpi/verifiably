# `verifier-results`

The verifier results service stores one result per verification and shows it as a card list (ADR-025).

## What it does

- It stores a `VerificationResult`: the verdict, the check results, one summary per credential, the raw presentation reference, and the policy set version.
- It shows a card per credential: the issuer name, a trust badge, the subject display fields, the verdict, and the check list. A disclosure holds the full JSON.
- It keeps personal data only for the configured window. The purge deletes the raw presentation first.
- It answers queries by time, verdict, issuer, and template, and exports CSV or JSON lines.
- It serves a public citizen page that checks one pasted credential and stores nothing.
- Every page passes the structural WCAG 2.2 AA assertions of `ui/a11ytest`.

It does not run the checks. The `verifier-policy` service does that.

## How to run

```sh
cd services/verifier-results
VCA_VERIFIER_RESULTS_POLICY_URL=http://localhost:8086 go run .
```

Configuration comes from environment variables. The table lists each one.

| Variable | Meaning | Default |
|---|---|---|
| `VCA_VERIFIER_RESULTS_LISTEN` | The address the service listens on. | `:8087` |
| `VCA_VERIFIER_RESULTS_STATE_DIR` | The directory of the result files. | empty: in memory |
| `VCA_VERIFIER_RESULTS_RETENTION` | How long a result stays readable. | `720h` |
| `VCA_VERIFIER_RESULTS_RAW_RETENTION` | How long the raw presentation stays readable. | `24h` |
| `VCA_VERIFIER_RESULTS_PURGE_INTERVAL` | The time between two purge runs. Zero turns the job off. | `1h` |
| `VCA_VERIFIER_RESULTS_PORTAL_PREFIX` | The URL prefix of the staff pages. | `/portal` |
| `VCA_VERIFIER_RESULTS_PUBLIC_PREFIX` | The URL prefix of the citizen page. | `/verify` |
| `VCA_VERIFIER_RESULTS_POLICY_URL` | The base URL of the verifier policy service. | empty: no citizen page check |
| `VCA_VERIFIER_RESULTS_POLICY_TIMEOUT` | The time limit of one policy service call. | `10s` |
| `VCA_VERIFIER_RESULTS_MAX_PASTE_BYTES` | The maximum size of a pasted presentation. | `1048576` |
| `VCA_VERIFIER_RESULTS_PAGE_SIZE_MAX` | The maximum page size of `Query`. | `50` |
| `VCA_VERIFIER_RESULTS_AUDIT_DIR` | The directory of the audit store. | empty: in memory |
| `VCA_VERIFIER_RESULTS_ADMIN_JWKS_URL` | The key set of the admin service. An admin session it signed opens the audit store. | empty: no admin session is accepted |
| `VCA_VERIFIER_RESULTS_ADMIN_TOKEN` | The admin service token. It opens the audit store too. | empty: no token is accepted |
| `VCA_VERIFIER_RESULTS_AUTH_JWKS_URL` | The JWKS URL of `verifier-auth`. The staff pages accept only a session it signed. | empty: the staff pages accept no session |
| `VCA_VERIFIER_RESULTS_AUTH_JWKS_FILE` | A JWKS file that replaces the URL, for a test. | empty |
| `VCA_VERIFIER_RESULTS_AUTH_JWKS_TTL` | How long a fetched key set stays fresh. | `10m` |
| `VCA_VERIFIER_RESULTS_AUTH_ISSUER` | The `iss` claim every session must carry. | empty: any issuer of the key set |
| `VCA_VERIFIER_RESULTS_LOGIN_URL` | The sign in chooser a page request without a session goes to, with `return_to`. | empty: answer 401 |

The container image is `ghcr.io/centre-for-dpi/vca-verifier-results`. It listens on one port and runs as a non-root user with a read-only file system. Mount a volume at `/data` to keep the results across a restart.

## How to check it works

1. Open `http://localhost:8087/healthz`. The response is `200 OK`.
2. Open `http://localhost:8087/readyz`. The response is `200 OK`.
3. Run this command to store one result:

```sh
curl -s -X POST http://localhost:8087/vca.results.v1.ResultsService/Store \
  -H 'Content-Type: application/json' \
  -d '{"result":{"verdict":"VERDICT_VALID","carrier":"oid4vp",
       "credentials":[{"title":"Passport","issuer":"did:web:issuer","trust":"trusted"}]}}'
```

4. Open `http://localhost:8087/portal/`. The list shows the verification. Open it to see the cards.
5. Open `http://localhost:8087/portal/export?encoding=csv`. The download holds one row per credential.
6. Open `http://localhost:8087/verify/`. Paste a credential and read the same cards. The service keeps nothing.

## Reference

- [ADR-025](../../../ADR.md) for the decisions this service implements.
- [docs/verifier-results.md](../../docs/verifier-results.md) for the data model and the retention rules.
- [proto/vca/results/v1/results.proto](../../proto/vca/results/v1/results.proto) for the API.
