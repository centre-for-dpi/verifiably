# `verifier-policy`

The verifier policy service runs the presentation checks of ADR-024. VCA does the mandatory checks itself, so a fault in a backend cannot make a bad presentation pass.

## What it does

- It runs a list of named checks over one normalised presentation. Each check is a pure function in `core/policy`.
- The mandatory checks always run: `signature`, `key_binding`, `nbf`, `exp`, `audience`, and `nonce`.
- The optional checks are `status`, `trust_chain`, and `schema`. A verifier turns each one on in a policy set.
- It stores named policy sets with versions. A result carries the set id and the set version.
- It follows these standards: [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html), [RFC 9901](https://www.rfc-editor.org/rfc/rfc9901.html), [Bitstring Status List v1.0](https://www.w3.org/TR/vc-bitstring-status-list/), [Token Status List](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/), and [VC JSON Schema](https://www.w3.org/TR/vc-json-schema/).

It does not store results. The `verifier-results` service does that.

A Data Integrity proof (`ldp_vc`) gives a `SKIP` with the detail `not implemented: RDF canonicalisation`. See [docs/verifier-policy.md](../../docs/verifier-policy.md).

## How to run

```sh
cd services/verifier-policy
VCA_VERIFIER_POLICY_TRUST_URL=http://localhost:8083 go run .
```

Configuration comes from environment variables. The table lists each one.

| Variable | Meaning | Default |
|---|---|---|
| `VCA_VERIFIER_POLICY_LISTEN` | The address the service listens on. | `:8086` |
| `VCA_VERIFIER_POLICY_STATE_DIR` | The directory of the policy set files. | empty: in memory |
| `VCA_VERIFIER_POLICY_DEFAULT_POLICY_SET` | The set that an `Evaluate` request without a set id uses. | empty: the built in set |
| `VCA_VERIFIER_POLICY_AUDIENCE` | The client id of this verifier, for the audience check. | empty |
| `VCA_VERIFIER_POLICY_TRUST_URL` | The base URL of the trust registry service. | empty |
| `VCA_VERIFIER_POLICY_TRUST_TIMEOUT` | The time limit of one trust registry call. | `5s` |
| `VCA_VERIFIER_POLICY_FETCH_TIMEOUT` | The time limit of one status list, DID, or schema fetch. | `5s` |
| `VCA_VERIFIER_POLICY_CACHE_TTL` | How long a fetched document stays in the cache. | `5m` |
| `VCA_VERIFIER_POLICY_CACHE_ENTRIES` | The maximum number of cached documents. | `256` |
| `VCA_VERIFIER_POLICY_FETCH_MAX_BYTES` | The maximum size of one fetched document. | `4194304` |
| `VCA_VERIFIER_POLICY_STATUS_FAIL_MODE` | `open` or `closed` for an unreachable status list. | `closed` |
| `VCA_VERIFIER_POLICY_LEEWAY` | The clock skew the temporal checks accept. | `60s` |
| `VCA_VERIFIER_POLICY_PAGE_SIZE_MAX` | The maximum page size of `ListPolicySets`. | `50` |

The container image is `ghcr.io/centre-for-dpi/vca-verifier-policy`. It listens on one port and runs as a non-root user with a read-only file system. Mount a volume at `/data` to keep the policy sets across a restart.

## How to check it works

1. Open `http://localhost:8086/healthz`. The response is `200 OK`.
2. Open `http://localhost:8086/readyz`. The response is `200 OK`.
3. Run this command to list the checks:

```sh
curl -s -X POST http://localhost:8086/vca.policy.v1.PolicyService/ListChecks \
  -H 'Content-Type: application/json' -d '{}'
```

The response names nine checks. Six of them are mandatory.

4. Run this command to save a policy set:

```sh
curl -s -X POST http://localhost:8086/vca.policy.v1.PolicyService/CreatePolicySet \
  -H 'Content-Type: application/json' \
  -d '{"policySet":{"id":"strict","displayName":"Strict",
       "checks":[{"name":"status","blocking":true,"params":{"fail_mode":"closed"}},
                 {"name":"trust_chain","blocking":true}]}}'
```

5. Send a presentation to `Evaluate` with `"policySetId":"strict"`. The response holds one result per check and the overall verdict.

## Reference

- [ADR-024](../../../ADR.md) for the decisions this service implements.
- [docs/verifier-policy.md](../../docs/verifier-policy.md) for the check list and the follow-ups.
- [proto/vca/policy/v1/policy.proto](../../proto/vca/policy/v1/policy.proto) for the API.
