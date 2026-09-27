## ADR-064: The issuer of an AnonCreds proof over DIDComm
- Status: Proposed
- Owner: CDPI Architects
- Scope: The adapter contract, `core/anoncreds`, the verifier discovery and ingest services, and the CREDEBL adapter.
- Extends: ADR-061 decisions 2, 3 and 4.
- Decision:
  1. A native template with the trusted issuer rule binds every attribute and every predicate to a credential definition. `anoncreds.CheckBound` checks it when the service builds the template. On a ledger anyone can publish a credential definition on a schema, so a schema alone admits any issuer.
  2. `CreateRequest` carries `any_issuer`. The ingest service sets it for a template without the trusted issuer rule. Without it the adapter refuses a part that binds no issuer. A part binds its issuer with one restriction that names a credential definition or an issuer DID. Over a connection the platform takes a credential definition only.
  3. The adapter keeps the parts of each proof request with what each binds. The issuer of a view is the credential definition or the issuer DID of the part. The adapter never takes the issuer from the answer of the platform. With no restriction the platform reports the first credential of the proof there.
  4. A value from a part that binds no issuer gives a view with no issuer. The result then carries the failed check `credebl-issuer-bound` with the reason. A request that the adapter did not record reads the same way.
- Consequences:
  1. A trust rule on an AnonCreds template checks the issuer that the proof met, and never a blank issuer.
  2. A verifier who accepts any issuer sees that plainly on the result.
  3. A template with the trust rule and a schema alone no longer saves. Staff pick a credential definition in the builder.
