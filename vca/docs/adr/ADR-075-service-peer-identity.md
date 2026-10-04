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
  6. Decision 2 changes. The private key of a service leaves the identity file. It is a file of its own in `<pair>/peer/keys/<service>.jwk`, and compose mounts it read only. `VCA_PEER_KEY_FILE` names it in the container.
  7. The key file has mode 0644, because the container user has another user id than the operator. Its directory has mode 0700, so no other user of the host opens it.
  8. Decision 6 changes. `vca peer secrets` writes a second Secret per chart with the key, and each pod mounts it as a file. A checksum of both Secrets is an annotation of each pod, so `helm upgrade` after a new run rolls the pods.
  9. `VCA_PEER_KEY` stays as a fallback for a platform that cannot mount a file. The CLI never writes it, because the environment shows the key.
- Amendment of 2026-10-04, deployment scoped callers:
  1. Item 3 of the first amendment let a callee take a token of `cli` or the landing at any host. Such a token opened the same procedure on every server that lists that caller.
  2. A callee now checks the host of every token. A token of a deployment scoped caller opens one callee only, as any other token does.
  3. Setup writes the published names of each service of a pair into `VCA_PEER_HOSTS`: `127.0.0.1` and `localhost`, each with the host port of the service. The vca command calls through these names.
  4. `vca dpg upgrade-secrets` treats an identity without those names as stale and writes it again. A name that the operator added to `VCA_PEER_HOSTS` stays. A loopback name of an earlier host port goes.
  5. The landing calls each adapter at its compose name or its cluster name, so its tokens name the callee already.
  6. A Helm release publishes no host port. A pod lists no published name, and the vca command does not call a pod.
  7. `vca peer secrets` keeps the identities of each release under `deploy/peer/helm/<release>`. A second run prints the same Secrets, as decision 5 promises for compose.
