# Fixtures written from the upstream documentation

The files in this directory follow the walt.id Community Stack 0.18.2
API documentation. No live stack recorded them. The nightly contract
run replaces each file with a recording.

| File | Endpoint | Source | Date |
| --- | --- | --- | --- |
| `onboard-issuer-ed25519.json` | `POST /onboard/issuer` with `keyType` `Ed25519` and `method` `key` | https://docs.walt.id/community-stack/issuer/api/onboarding | 2026-09-25 |

The answer has the shape of `onboard-issuer.json`: the key as a walt.id
JWK key object, and the DID. The test key is fixed, so the did:key in
the file matches the public key in it.
