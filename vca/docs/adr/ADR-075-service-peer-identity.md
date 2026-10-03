## ADR-075: Each internal Connect service checks which service calls it
- Status: Proposed
- Owner: CDPI Architects
- Scope: Every internal Connect service and its callers. Also `vca setup`, `vca dpg upgrade-secrets`, the compose file and the Helm charts.
- Extends: ADR-002 decision 5, ADR-047 decision 2, ADR-055 decision 1. Closes the gap that ADR-047 and ADR-062 accepted: a backend RPC trusted any caller on the network.
- Decision:
  1. Setup makes one authority key per deployment, an ECDSA key on P-256. It keeps the key in `deploy/peer/authority.pem` with mode 0600. No service holds it. A later run reuses it.
  2. Setup gives each service an identity file of its own: a new key of the service, and a statement of the authority. The statement is a JWT that binds the name of the service to the public key of the service. The file also holds the public key set of the authority and the callers of the service. Compose gives each container its own file and stops when the file is missing.
  3. A caller signs a JWT for each call with its own key. The token lives 60 seconds and names the procedure as its audience. The shared interceptor of `internal/peerauth` checks the statement, the token and the caller list. Every Connect handler on the compose network takes the interceptor. A missing or bad identity answers `unauthenticated`. A caller that the list does not name answers `permission_denied`.
  4. The catalogue of the CLI declares the callers of each internal Connect service next to its routes. The CLI writes them into the identity file. The vca command is the caller `cli`. It issues an identity of its own from the authority at each run.
  5. `vca dpg upgrade-secrets` makes the authority of a deployment from an earlier release and writes each missing identity file. It keeps every file that the authority signed, so a second run changes nothing.
  6. Each Helm chart reads its identity from the Secret `<release>-<service>-peer`. `vca peer secrets` writes one Secret per chart. A pod does not start without its Secret.
  7. A guard test fails when a service mounts a Connect handler without the interceptor. A public service that checks the user is the only exception (ADR-047 decision 1).
- Consequences:
  1. A container on the network that holds no identity of the deployment reaches no internal RPC. A service with an identity reaches only the RPCs that list it.
  2. The JWT form needs no new infrastructure. mTLS would need TLS on every listener and a new scheme in every internal URL. It would also need certificates in the proxy. The JWT form keeps h2c and plain URLs.
  3. A token names the procedure, not the instance of the callee. A party that reads a token on the network can replay it to the same procedure within 60 seconds. The network stays the boundary against such a party.
  4. The authority rotates when the operator removes `deploy/peer/authority.pem` and runs setup or `vca dpg upgrade-secrets`. Every identity file then gets a new statement. No list of revoked identities exists.
  5. A deployment from an earlier release stops at `docker compose up` until the operator runs `vca dpg upgrade-secrets`, because compose needs each identity file.
- Amendment of 2026-10-04:
  1. Consequence 3 understated the reach of a token. The token named the procedure only. So every server of that Connect service in the deployment took it, with any body.
  2. A token now names the procedure and the host of the callee in `aud`. A callee takes it for its own name only. That name is `<pair>-<service>` under compose and `<release>-<service>` under Helm, or a name in `VCA_PEER_HOSTS`.
  3. The authority marks the caller `cli` and the landing as deployment scoped in their statements. A callee takes their tokens at any host, because the vca command calls through a port of the host.
  4. What remains: a party that reads a token can replay it within the window. The replay reaches the same server and procedure, with any body. The token of a deployment scoped caller opens the same procedure on every server that lists that caller.
  5. The window is symmetric. A token counts from 30 seconds before its issue time to 30 seconds after its end. So two clocks can differ by 30 seconds either way, and a replay works for 90 seconds at most.
