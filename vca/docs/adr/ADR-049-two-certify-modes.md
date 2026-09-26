## ADR-049: Two authorization modes of Inji Certify in the Inji stack
- Status: Proposed
- Owner: CDPI Architects
- Scope: The Inji Certify containers of the Inji stack file, and the memory floor of an Inji pair.
- Extends: ADR-008 decision 7, ADR-045 decision 1.
- Decision:
  1. The stack runs Inji Certify 0.14.0 twice, on one database and one key store. Certify checks every access token against one issuer and one key set. One container cannot take both kinds of token.
  2. `inji-certify` is its own authorization server. It serves the pre-authorized code, the presentation during issuance, and every call of the adapter. Its data provider reads the claims that the adapter stages.
  3. `inji-certify-esignet` takes the tokens of the stack eSignet. It serves a claim in Inji Web and an authorization code offer. Its data provider reads the sample data of the release.
  4. The second container starts after the first one is ready. It then reads the keys that the first one made at its start.
  5. The floor of an Inji pair can rise above the 4 GB target for a container that a DPG feature needs. `vca doctor` names each such pair in its floor report.
- Consequences:
  1. Every issuance path of Certify works on one deployment.
  2. The Inji issuer pair needs more than 4 GB.
  3. Certify makes every key type at its start. A key that an operator adds later reaches the second container at its next start.
