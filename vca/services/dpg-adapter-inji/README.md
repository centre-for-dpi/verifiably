# dpg-adapter-inji

## What it does

This service is the adapter between Verifiable Credentials Adapters and
the Inji stack. It serves the `vca.backend.v1` services over Connect.
Other services call it and never call Inji.

It serves these roles:

- Issuer: it drives Inji Certify. It builds OID4VCI credential offers.
  It also runs the whole pre-authorized flow itself. It then returns the
  signed credential, which the paper document channel needs.
- Verifier: it drives Inji Verify. It starts and reads OID4VP
  transactions.
- Catalogue: it lists the credential configurations of the issuer.

Inji ships no wallet for a citizen, so the holder service answers with
the Connect code `unimplemented`.

The service reaches Inji over the HTTP API of Inji only. It never opens
the Inji database and it never controls a container.

## How to run

Set at least one Inji URL. Each URL turns on one role.

| Variable | Meaning |
| --- | --- |
| `VCA_INJI_LISTEN` | The address to bind. The default is `:8080`. |
| `VCA_INJI_CERTIFY_URL` | The base URL of Inji Certify. |
| `VCA_INJI_VERIFY_URL` | The base URL of Inji Verify. |
| `VCA_INJI_PUBLIC_URL` | The address a wallet reaches this adapter on. |
| `VCA_INJI_AUTHORIZATION_SERVER` | The identity provider of the authorization code flow. Empty names the first authorization server of the Certify metadata, eSignet in the stack file. |
| `VCA_INJI_OFFER_ISSUER` | The issuer identifier of a hosted offer. |
| `VCA_INJI_METADATA_PATH` | The path of the issuer metadata on Inji Certify. |
| `VCA_INJI_VERIFY_CLIENT_ID` | The DID Inji Verify shows a wallet. |
| `VCA_INJI_DPG_VERSION` | The Inji Certify release the answer of `GetCapabilities` reports. |
| `VCA_INJI_VERIFY_VERSION` | The Inji Verify release of the stack. The default is `0.16.0`. |
| `VCA_INJI_ESIGNET_VERSION` | The eSignet release of the stack. The default is `1.5.1`. |
| `VCA_INJI_MOCK_IDENTITY_VERSION` | The mock identity system release of the stack. The default is `0.10.1`. |
| `VCA_INJI_KEYCLOAK_VERSION` | The Keycloak release of the stack. The default is `25.0`. |
| `VCA_INJI_TIMEOUT` | The bound of one call to Inji. The default is `30s`. |
| `VCA_INJI_RETRIES` | The number of extra attempts. The default is `2`. |
| `VCA_INJI_MAX_BYTES` | The bound of a response body. The default is 8 megabytes. |
| `VCA_INJI_STORE_FILE` | The file that keeps the hosted offers. Empty uses memory. |
| `VCA_INJI_OFFER_TTL` | The life of a hosted offer. The default is `15m`. |
| `VCA_INJI_SIGNING_DID_URL` | The issuer DID URL of a configuration the adapter registers. Empty keeps the Certify default. |
| `VCA_INJI_LDP_KEY_APP_ID` | The Certify key application of `ldp_vc` proofs. The default is `CERTIFY_VC_SIGN_ED25519`. |
| `VCA_INJI_LDP_KEY_REF_ID` | The Certify key reference of `ldp_vc` proofs. The default is `ED25519_SIGN`. |
| `VCA_INJI_LDP_SIGNATURE_ALGO` | The signature algorithm of `ldp_vc` proofs. The default is `EdDSA`. |
| `VCA_INJI_LDP_CRYPTO_SUITE` | The proof type of `ldp_vc` credentials. The default is `Ed25519Signature2020`. |
| `VCA_INJI_SD_JWT_KEY_APP_ID` | The Certify key application of SD-JWT VCs. The default is `CERTIFY_VC_SIGN_EC_R1`. |
| `VCA_INJI_SD_JWT_KEY_REF_ID` | The Certify key reference of SD-JWT VCs. The default is `EC_SECP256R1_SIGN`. |
| `VCA_INJI_SD_JWT_SIGNATURE_ALGO` | The signature algorithm of SD-JWT VCs. The default is `ES256`. |
| `VCA_INJI_MDOC_KEY_APP_ID` | The Certify key application of mDocs. The default is `CERTIFY_VC_SIGN_EC_R1`. |
| `VCA_INJI_MDOC_KEY_REF_ID` | The Certify key reference of mDocs. The default is `EC_SECP256R1_SIGN`. |
| `VCA_INJI_MDOC_SIGNATURE_ALGO` | The COSE signature algorithm of mDocs. The default is `ES256`. |
| `VCA_INJI_CERTIFY_PLUGINS` | The plugins of the Certify deployment, comma separated. The DPG information lists them. The default is `MockCSVDataProviderPlugin,LoggerAuditService`. |
| `VCA_INJI_CA_DOMAIN` | The partner domain of an uploaded CA certificate. The default is `DEVICE`. |
| `VCA_INJI_RENDERING_TEMPLATE_ID` | The SVG template id of the Certify deployment. A registered `ldp_vc` configuration names it as its render method. |
| `VCA_INJI_PRESENTATION_DURING_ISSUANCE` | Set `true` once Certify reaches Inji Verify and holds a presentation definition. An offer can then ask the holder to present a credential first. The default is `false`. |

Run the binary:

```
VCA_INJI_CERTIFY_URL=http://inji-certify:8090 \
VCA_INJI_VERIFY_URL=http://inji-verify-service:8080 \
go run ./services/dpg-adapter-inji
```

Build the image from the module root:

```
docker build -f services/dpg-adapter-inji/Dockerfile -t dpg-adapter-inji .
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
go test ./services/dpg-adapter-inji/...
```

Run the contract test against a real Inji deployment:

```
VCA_INJI_CONTRACT_CERTIFY_URL=http://localhost:8090 \
VCA_INJI_CONTRACT_VERIFY_URL=http://localhost:8082 \
go test -tags contract_inji ./services/dpg-adapter-inji/...
```

The contract test skips itself when the variables are empty. The script
`hack/contract-tests.sh` runs it in the nightly job. A case that changes
the stack, such as a new credential configuration, also needs
`VCA_INJI_CONTRACT_WRITE=1`.

## Reference

- Service document: `docs/dpg-adapter-inji.md`
- Contract: `proto/vca/backend/v1/backend.proto`
- Decisions: ADR-002 decisions 2 and 4, ADR-016, ADR-030 decision 2
