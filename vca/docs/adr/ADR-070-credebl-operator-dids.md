## ADR-070: The operator makes each DID of a CREDEBL organisation
- Status: Proposed
- Owner: CDPI Architects
- Scope: The CREDEBL adapter, the backend and admin contracts, the admin tenant and API key pages, and the issuer identity page.
- Extends: ADR-001 decision 3, ADR-037, ADR-046, ADR-067 decision 4, ADR-068 decision 6. Replaces the did:key provision of P6-C1 on CREDEBL. Closes the P6-C1b row of the plan.
- Decision:
  1. The pinned api gateway refuses a `did:key`, a `did:indy` and a `did:web` without the private key of the DID in the request. Source: `Validator.validateDid` of `libs/common/src/validator.ts` at the platform tag `v2.2.1-alpha.4`. The pinned agent takes that field as the private key of the DID. Source: `handleKey`, `handleIndy` and `handleWeb` of `src/controllers/did/DidController.ts` at the agent tag `v2.2.1-alpha-jsonld-vc.2.1`. An Indy DID without a key needs an external endorser, and the platform drops the transaction to endorse.
  2. So the pinned release offers no key made by the agent for an organisation DID. The adapter never holds a private key. It provisions no DID, and a new tenant has none. The answer of `GetCapabilities` lists no `FEATURE_ISSUER_IDENTITY_PROVISION` on CREDEBL.
  3. The operator makes each DID in the platform, straight from the host. The key never passes through VCA. The answer of `GetCapabilities` names the methods in `operator_did_methods`. The admin tenant page and the issuer identity page say so. The CREDEBL adapter document holds the calls.
  4. The tenant backend gains `SetTenantPrimaryDid`, and the admin service gains the same RPC. An adapter serves it when it lists `FEATURE_TENANT_PRIMARY_DID`. The admin tenant page offers "Make primary" beside each other DID of a stack tenant.
  5. The answer of `GetCapabilities` names the key reference of an X.509 import in `x509_key_reference`. The identity page shows it in the hint of the field. A stack that takes one import kind names that kind in a sentence, such as "PKI (X.509)".
  6. The answer of `GetCapabilities` names the most client credentials of one tenant in `tenant_client_credential_limit`. The API key page leaves a full tenant out of the create form.
- Consequences:
  1. A CREDEBL issuer signs nothing until the operator makes the primary DID of its organisation.
  2. The operator keeps the private key of each DID in a store of its own choice.
  3. A later release that makes the key in the agent brings the provision back through a new record.
