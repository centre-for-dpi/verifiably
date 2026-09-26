## ADR-048: Client assertion keys of a login provider
- Status: Proposed
- Owner: CDPI Architects
- Scope: The key of the private_key_jwt client assertion at a login provider, and the eSignet client of the Inji stack.
- Extends: ADR-011 decision 5, ADR-035 decision 4.
- Decision:
  1. The client assertion takes the algorithm of the key type. A P-256 key signs with ES256. An Ed25519 key signs with EdDSA. An RSA key of 2048 bits or more signs with RS256.
  2. RS256 serves only a provider that takes nothing else, such as eSignet 1.5.1. VCA signs its own tokens and lists with ES256 or EdDSA, as ADR-011 decision 5 says.
  3. `vca dpg bootstrap` of the Inji stack registers one VCA client in eSignet with an RSA public key. The private key stays in a file of mode 0600 in a directory that git ignores. A second run keeps the key and adds the redirect URI of its pair.
- Consequences:
  1. eSignet works as a login provider of the issuer and holder portals.
  2. The provider key is a registration secret of the operator, not a VCA signing key. The secret scan and the key file mode guard it.
  3. The key type of a registration decides the algorithm. The provider form needs no algorithm field.
