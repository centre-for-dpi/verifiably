# dpg-adapter-waltid

## What it does

This service is the adapter between Verifiable Credentials Adapters and
the walt.id Community Stack. It serves the `vca.backend.v1` services over
Connect. Other services call it and never call walt.id.

It serves these roles:

- Issuer: it builds OID4VCI credential offers.
- Holder: it drives the walt.id hosted wallet.
- Verifier: it starts and reads OID4VP transactions.
- Catalogue: it lists the credential configurations of the issuer.

The service reaches walt.id over the HTTP API of walt.id only. It never
opens the walt.id database and it never controls a container.

walt.id 0.18.2 does not support every RPC. Such an RPC answers with the
Connect code `unimplemented`. The message says what to use instead.

## How to run

Set at least one walt.id URL. Each URL turns on one role.

| Variable | Meaning |
| --- | --- |
| `VCA_WALTID_LISTEN` | The address to bind. The default is `:8080`. |
| `VCA_WALTID_ISSUER_URL` | The base URL of the walt.id issuer API. |
| `VCA_WALTID_VERIFIER_URL` | The base URL of the walt.id verifier API. |
| `VCA_WALTID_WALLET_URL` | The base URL of the walt.id wallet API. |
| `VCA_WALTID_STANDARD_VERSION` | The OID4VCI draft name. The default is `draft13`. |
| `VCA_WALTID_DPG_VERSION` | The walt.id release the answer of `GetCapabilities` reports. |
| `VCA_WALTID_KEYCLOAK_VERSION` | The Keycloak release of the stack. The default is `25.0`. |
| `VCA_WALTID_ISSUER_DID` | The signing DID. Empty onboards one at first use. |
| `VCA_WALTID_ISSUER_KEY` | The signing key as a JSON web key wrapper. It is a secret. |
| `VCA_WALTID_VCT_BASE` | The base URL of the `vct` of a custom SD-JWT credential. |
| `VCA_WALTID_TIMEOUT` | The bound of one call to walt.id. The default is `30s`. |
| `VCA_WALTID_RETRIES` | The number of extra attempts. The default is `2`. |
| `VCA_WALTID_MAX_BYTES` | The bound of a response body. The default is 8 megabytes. |
| `VCA_WALTID_STORE_FILE` | The file that keeps the wallet sessions. Empty uses memory. |

Run the binary:

```
VCA_WALTID_ISSUER_URL=http://issuer-api:7002 \
VCA_WALTID_VERIFIER_URL=http://verifier-api:7003 \
VCA_WALTID_WALLET_URL=http://wallet-api:7001 \
go run ./services/dpg-adapter-waltid
```

Build the image from the module root:

```
docker build -f services/dpg-adapter-waltid/Dockerfile -t dpg-adapter-waltid .
```

## How to check it works

Ask for the health of the service:

```
curl -s localhost:8080/readyz
```

Ask for the capabilities:

```
curl -s -X POST localhost:8080/vca.backend.v1.CapabilityService/GetCapabilities \
  -H 'Content-Type: application/json' -d '{}'
```

The answer lists the roles, the formats, the channels, and the protocols.

Run the unit tests and the recorded contract tests:

```
go test ./services/dpg-adapter-waltid/...
```

Run the contract test against a real walt.id stack:

```
VCA_WALTID_CONTRACT_ISSUER_URL=http://localhost:7002 \
VCA_WALTID_CONTRACT_VERIFIER_URL=http://localhost:7003 \
go test -tags contract_waltid ./services/dpg-adapter-waltid/...
```

The contract test skips itself when the variables are empty. The script
`hack/contract-tests.sh` runs it in the nightly job.

## Reference

- Service document: `docs/dpg-adapter-waltid.md`
- Contract: `proto/vca/backend/v1/backend.proto`
- Decisions: ADR-002 decisions 2 and 4, ADR-016, ADR-030 decision 2
