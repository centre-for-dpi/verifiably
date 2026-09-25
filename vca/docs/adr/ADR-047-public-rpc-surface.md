## ADR-047: The public RPC surface of a pair
- Status: Proposed
- Owner: CDPI Architects
- Scope: The routes of the reverse proxy of each pair, and the CLI calls that reach a running deployment.
- Extends: ADR-003 decision 7, ADR-007 decision 5.
- Decision:
  1. The reverse proxy publishes a Connect service only on two terms. A party outside the host calls it, and every RPC of it checks the caller. An allowlist in the CLI tests holds these services. Each entry names a test that calls every RPC of the service with no credential.
  2. Every other Connect service stays on the compose network. The pages draw on the server and reach those services by container name. The `Caddyfile` of each pair answers `404` to every Connect path that no route names.
  3. The CLI reaches an internal service at `127.0.0.1` and its host port. Compose binds that port to `VCA_BIND`. A variable per command, such as `VCA_BOOTSTRAP_ADAPTER_URL`, sets another address.
  4. The proxy keeps the plain HTTP paths that a protocol, a browser, or an auditor needs. A prefix service publishes its protocol paths under the prefix and never the Connect service behind the prefix.
- Consequences:
  1. A caller on the internet can no longer replace the issuer identity, revoke a credential, or issue one. It can no longer change a schema, a policy, a source, a status list, or a trust entry.
  2. A new Connect service stays private until it gets a caller check and an allowlist entry.
  3. `vca dpg bootstrap waltid` runs on the machine that runs compose, or it needs `VCA_BOOTSTRAP_ADAPTER_URL`.
  4. A client outside the host that called an internal service through the public host name stops working. No VCA page or command did that.
