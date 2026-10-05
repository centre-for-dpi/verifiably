## ADR-083: A verifier policy requires holder binding
- Status: Proposed
- Owner: CDPI Architects
- Scope: The `key_binding` check of `core/policy` and the policy sets. The message `RawPresentation`. The wallet card, the consent screen, and the answers of the browser store.
- Extends: ADR-024 decision 2, ADR-073, ADR-081.
- Decision:
  1. A verifier policy can ask for holder binding. The `key_binding` check takes the parameter `require_holder_binding`. The default is `true`, so the default policy set asks for holder binding.
  2. The rule covers an OID4VP answer in a format that can carry holder binding: `dc+sd-jwt`, `vc+sd-jwt`, `jwt_vc_json` and `mso_mdoc`. An unbound answer fails with the detail "the presentation carries no holder binding". The verdict reads Not valid. A pasted or scanned credential is no presentation, so the rule does not apply.
  3. The consent screen says plainly when the browser store will send an answer with no holder binding. The wallet card carries `holder_unbound` for such a credential.
  4. A stack verifier that accepted an answer checked its binding. VCA gets only the credentials. So `RawPresentation` carries `stack_checked_holder`, and the check skips with the detail "the stack verifier checked the holder binding".
  5. The browser store binds what it can. It signs a VP JWT with the browser key around a `jwt_vc_json` credential that names that key. The check verifies the VP JWT with the key of `cnf.jwk`, or of a `did:jwk` or `did:key` subject. The audience and nonce checks read it.
  6. An mDoc of the browser store stays unbound. The store holds no session transcript and builds no `DeviceResponse`. VCA does not check a device signature yet, so it skips an mDoc that carries one.
- Consequences:
  1. An unbound `jwt_vc_json` or `mso_mdoc` answer of the browser store is no longer Valid by default. A verifier that accepts such answers turns the rule off in its policy set.
  2. A holder who needs a bound mDoc uses a stack wallet.
  3. No key can bind a `jwt_vc_json` credential that names no holder key. It fails the default policy.
