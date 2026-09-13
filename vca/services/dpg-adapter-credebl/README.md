# dpg-adapter-credebl

## What it does

This service is the adapter between Verifiable Credentials Adapters and
a CREDEBL platform. It serves the `vca.backend.v1` services over
Connect. Other services call it and never call CREDEBL.

It serves these roles:

- Issuer: it stores schemas and credential templates. It builds OID4VCI
  pre-authorized code offers.
- Verifier: it starts and reads OID4VP transactions with DCQL queries.
- Catalogue: it lists the credential templates of the issuer.

CREDEBL ships no wallet for a citizen, so the holder service answers
with the Connect code `unimplemented`.

The service reaches CREDEBL over the api gateway of CREDEBL only. It
never opens the CREDEBL database and it never controls a container.

## How to run

| Variable | Meaning |
| --- | --- |
| `VCA_CREDEBL_LISTEN` | The address to bind. The default is `:8080`. |
| `VCA_CREDEBL_API_URL` | The base URL of the CREDEBL api gateway. Set it. |
| `VCA_CREDEBL_EMAIL` | The login name of the platform administrator. Set it. |
| `VCA_CREDEBL_PASSWORD` | The login secret. Set it. It holds a secret. |
| `VCA_CREDEBL_CRYPTO_KEY` | The pass phrase of the password encryption. It holds a secret. |
| `VCA_CREDEBL_ORG_ID` | The organisation the adapter works in. Set it. |
| `VCA_CREDEBL_ISSUER_ID` | The OID4VCI issuer of the organisation. |
| `VCA_CREDEBL_VERIFIER_ID` | The OID4VP verifier. Empty makes the adapter create one. |
| `VCA_CREDEBL_VERIFIER_NAME` | The name of the verifier the adapter creates. |
| `VCA_CREDEBL_PUBLIC_URL` | The host a wallet reaches the CREDEBL agent on. |
| `VCA_CREDEBL_INTERNAL_URL` | The host the CREDEBL agent writes into an offer. |
| `VCA_CREDEBL_DEFAULT_PIN` | The transaction code of an offer. It holds a secret. |
| `VCA_CREDEBL_DPG_VERSION` | The CREDEBL release the answer of `GetCapabilities` reports. |
| `VCA_CREDEBL_TIMEOUT` | The bound of one call. The default is `30s`. |
| `VCA_CREDEBL_RETRIES` | The number of extra attempts. The default is `2`. |
| `VCA_CREDEBL_MAX_BYTES` | The bound of a response body. The default is 8 megabytes. |
| `VCA_CREDEBL_STORE_FILE` | The file that keeps the verifier id. Empty uses memory. |

Run the binary:

```
VCA_CREDEBL_API_URL=https://credebl.example.org \
VCA_CREDEBL_EMAIL=admin@example.org \
VCA_CREDEBL_PASSWORD=... \
VCA_CREDEBL_CRYPTO_KEY=... \
VCA_CREDEBL_ORG_ID=... \
VCA_CREDEBL_ISSUER_ID=... \
go run ./services/dpg-adapter-credebl
```

Build the image from the module root:

```
docker build -f services/dpg-adapter-credebl/Dockerfile -t dpg-adapter-credebl .
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
go test ./services/dpg-adapter-credebl/...
```

Run the contract test against a real platform:

```
VCA_CREDEBL_CONTRACT_API_URL=https://credebl.example.org \
VCA_CREDEBL_CONTRACT_EMAIL=admin@example.org \
VCA_CREDEBL_CONTRACT_PASSWORD=... \
VCA_CREDEBL_CONTRACT_CRYPTO_KEY=... \
VCA_CREDEBL_CONTRACT_ORG_ID=... \
go test -tags contract_credebl ./services/dpg-adapter-credebl/...
```

The contract test skips itself when the variables are empty. The script
`hack/contract-tests.sh` runs it in the nightly job.

## Reference

- Service document: `docs/dpg-adapter-credebl.md`
- Contract: `proto/vca/backend/v1/backend.proto`
- Decisions: ADR-002 decisions 2 and 4, ADR-016, ADR-022 decision 3, ADR-030 decision 2
