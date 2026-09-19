# `verifier-combined`

The verifier combined service asks for several credentials in one OID4VP transaction and evaluates them together (ADR-026).

## What it does

- It stores a combined template: a list of ADR-022 presentation templates plus cross credential rules.
- It merges the DCQL of the member templates into one query with `credential_sets`, so a wallet can answer alternatives.
- It runs each credential through the `verifier-policy` service on its own, then runs the cross credential rules.
- The cross rules are `SAME_SUBJECT`, `DELEGATION_LINK`, and `DATE_ORDER`. Each one is a pure function.
- The overall verdict is the conjunction. A weak credential cannot hide behind a strong one.
- It stores the result through the `verifier-results` service with one card per credential and a summary card.
- It follows [OID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) section 6 for the query.

It does not run the checks and it does not hold results. The policy service and the results service do that.

## How to run

```sh
cd services/verifier-combined
VCA_VERIFIER_COMBINED_POLICY_URL=http://localhost:8086 \
VCA_VERIFIER_COMBINED_RESULTS_URL=http://localhost:8087 \
VCA_VERIFIER_COMBINED_DISCOVERY_URL=http://localhost:8085 go run .
```

Configuration comes from environment variables. The table lists each one.

| Variable | Meaning | Default |
|---|---|---|
| `VCA_VERIFIER_COMBINED_LISTEN` | The address the service listens on. | `:8088` |
| `VCA_VERIFIER_COMBINED_STATE_DIR` | The directory of the combined template files. | empty: in memory |
| `VCA_VERIFIER_COMBINED_POLICY_URL` | The base URL of the verifier policy service. | empty |
| `VCA_VERIFIER_COMBINED_RESULTS_URL` | The base URL of the verifier results service. | empty: no storage |
| `VCA_VERIFIER_COMBINED_DISCOVERY_URL` | The base URL of the discovery service. | empty |
| `VCA_VERIFIER_COMBINED_CALL_TIMEOUT` | The time limit of one call to another service. | `10s` |
| `VCA_VERIFIER_COMBINED_DEFAULT_POLICY_SET` | The policy set a template without a set uses. | empty |
| `VCA_VERIFIER_COMBINED_PAGE_SIZE_MAX` | The maximum page size of `List`. | `50` |

The container image is `ghcr.io/centre-for-dpi/vca-verifier-combined`. It listens on one port and runs as a non-root user with a read-only file system. Mount a volume at `/data` to keep the templates across a restart.

## How to check it works

1. Open `http://localhost:8088/healthz`. The response is `200 OK`.
2. Open `http://localhost:8088/readyz`. The response is `200 OK`.
3. Run this command to save a combined template:

```sh
curl -s -X POST http://localhost:8088/vca.combined.v1.CombinedService/Create \
  -H 'Content-Type: application/json' \
  -d '{"template":{"id":"guardian-pair","displayName":"Guardian pair",
       "members":[{"templateId":"identity"},{"templateId":"guardian"}],
       "rules":[{"kind":"CROSS_RULE_DELEGATION_LINK","displayName":"Guardian link",
                 "params":{"subject":"subject","delegation":"delegation"}}]}}'
```

4. Run this command to read the merged query:

```sh
curl -s -X POST http://localhost:8088/vca.combined.v1.CombinedService/BuildDcql \
  -H 'Content-Type: application/json' -d '{"templateId":"guardian-pair"}'
```

The `dcql` field holds one `credentials` array and one `credential_sets` array.

5. Send the wallet response to `EvaluateCombined`. The answer holds one verdict per credential, the cross rule results, and the stored result.

## Reference

- [ADR-026](../../../ADR.md) for the decisions this service implements.
- [docs/verifier-combined.md](../../docs/verifier-combined.md) for the query shape and the rules.
- [proto/vca/combined/v1/combined.proto](../../proto/vca/combined/v1/combined.proto) for the API.
