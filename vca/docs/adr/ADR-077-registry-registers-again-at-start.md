## ADR-077: The schema registry registers each published version again at start
- Status: Proposed
- Owner: CDPI Architects
- Scope: The schema registry and `RegisterCredentialConfiguration` of every DPG adapter.
- Extends: ADR-013 decision 3. Follows the retirement of `VCA_WALTID_VCT_BASE`.
- Decision:
  1. At each start the schema registry calls `RegisterCredentialConfiguration` once per format of every published version. A draft and a retired version stay out.
  2. Each adapter answers a second registration of the same configuration as it answers the first. The walt.id adapter writes the record again. The CREDEBL adapter finds the template of the same name.
  3. While the stack refuses, the registry waits 15 seconds and tries again, until every version went or the service stops. It logs each refusal.
- Consequences:
  1. A walt.id configuration with the `vct` of the retired setting gets the `vct` of the registry at the next start. The operator does nothing.
  2. An adapter that lost its state gets every published registration back.
  3. Each start costs one call per format of each published version.
- Amendment of 2026-10-04:
  1. Decision 2 overstated the CREDEBL adapter. At the first release it found only the template of an SD-JWT configuration.
  2. With that release an AnonCreds configuration got the status conflict of the platform at each start, so decision 3 never ended. A W3C JSON-LD configuration got one more schema at each run.
  3. The CREDEBL adapter now lists the schemas of its organisation before each write. It reuses the AnonCreds schema, its credential definition and the W3C schema of the same name. The ledger sees one write of each.
  4. Decision 3 changes. The registry tries again only the versions that the stack refused with `unavailable` or `deadline_exceeded`. The wait starts at 15 seconds and doubles up to 5 minutes.
  5. Any other code stops that version. The registry logs it once. The detail page shows "registration failed" with the reason, and an action that registers it again.
