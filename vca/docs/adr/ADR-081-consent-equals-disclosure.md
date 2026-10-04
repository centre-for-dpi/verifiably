## ADR-081: Consent equals disclosure on every holder path
- Status: Proposed
- Owner: CDPI Architects
- Scope: The wallet portal, `vca.walletportal.v1.Card`, the consent screen, the holder role of each adapter, and the Inji credential configuration.
- Extends: ADR-021 decision 5, ADR-063 decision 1.
- Decision:
  1. Consent equals disclosure is an invariant of every holder path. The consent screen lists each claim that leaves the wallet. The wallet sends no claim that the holder did not consent to. The presentation history names exactly the claims that left.
  2. A card names its fixed claims in `fixed_claims`. These are the SD-JWT claims outside any disclosure. They are also each claim of a format without selective disclosure. The consent screen lists each fixed claim of each match, ticked and locked, as "Always sent" (`always_sent`). It lists one also when the verifier did not ask for it.
  3. The browser store records the claim names that the posted tokens reveal. It reads them from the tokens, not from the ticks.
  4. The Inji adapter writes `sdClaim` as JSON paths from the root, as Certify 0.14.0 reads them. It adds `$.identityQR` when the configuration signs a Claim 169 code. The code then travels only to a verifier that asks for it.
  5. A stack wallet adapter reads what its wallet sends before it answers. It refuses with `FailedPrecondition` and names the claims when the holder did not consent to each. `shared_claims` names what the wallet sends.
  6. A guard test runs one contract against the holder service of each adapter. A meta test fails when an adapter package does not run it.
- Consequences:
  1. A verifier never reads a claim that the consent screen did not show.
  2. A credential with many plain claims shows a long consent screen. The holder sees the cost of the format before sharing.
  3. A Certify configuration registered before this record keeps the old `sdClaim`. The schema registry registers each published version again at start (ADR-077), which writes the new value.
