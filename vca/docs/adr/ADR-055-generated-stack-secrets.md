## ADR-055: Stack secrets and identities come from setup or the operator
- Status: Proposed
- Owner: CDPI Architects
- Scope: Every compose default, properties literal and bootstrap default of the three stacks.
- Extends: ADR-029 decision 6, ADR-035 decision 7.
- Decision:
  1. Setup generates each database password, key store password, signing key, pepper and platform seed. It writes them to the `.env` of the stack directory with mode 0600. Compose reads them with `${VAR:?}`.
  2. A properties value of a MOSIP platform service that the stack does not run is empty.
  3. The subject of a key manager certificate names the issuer host and organisation that setup collected.
  4. The CREDEBL platform admin email is a required setting. Bootstrap runs the CREDEBL seed once with it.
  5. The secret scan checks `key=value` files as it checks `key: value` files.
- Consequences:
  1. Two deployments never share a password.
  2. A stack that starts without its `.env` fails with the name of the missing variable.
  3. The deploy report names every generated file.
