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
