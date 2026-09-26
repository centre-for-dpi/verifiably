## ADR-051: The VCA claims store is the data provider of Inji Certify
- Status: Proposed
- Owner: CDPI Architects
- Scope: Both Inji Certify containers of the Inji stack, their Postgres, and the Inji adapter of the issuer pair.
- Supersedes: ADR-049 decisions 2 and 3.
- Decision:
  1. Certify reads the claims of every issuance from the foreign table `certify.vca_claims`. The module `file_fdw` maps that table onto the files of the volume `inji-claims`. Both containers use `PostgresDataProviderPlugin` with one query on that table.
  2. The Inji adapter writes one file per staged subject and deletes it when the offer expires. The adapter opens no database connection.
  3. Every VCA credential configuration on Certify has the scope `vca_credential`. Certify picks the configuration from the request body.
  4. The template of a configuration reads the claims from the columns `c1` to `c64`. The adapter keeps the map from claim name to column with the registration.
  5. The subject key is the staging id for the pre-authorized code and the holder authorization server. For a presentation during issuance it is the value of the identity claim of the presented credential.
  6. The adapter serves the presentation definition of the interactive authorization from the settings of the issuer.
- Consequences:
  1. The pre-authorized flow no longer names a plugin the image does not hold.
  2. A schema with more than 64 claims cannot go to Certify. The registration says so.
  3. The claims of an issuance sit on a volume for the life of the offer. The volume has the protection of the Certify database volume.
