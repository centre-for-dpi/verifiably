## ADR-033: Landing service, role picker, and role intro pages
- Status: Proposed
- Owner: CDPI Architects
- Scope: The front door of a deployment.
- Extends: ADR-001 decision 6, ADR-008 decision 1.
- Decision:
  1. A stateless `landing` service serves `/`, `/roles/`, `/roles/<role>/`, `/stacks`, and `/.well-known/vca.json`.
  2. The landing is a deployment scoped service. Compose runs one `vca-landing` container that every pair profile starts. It listens on host port 17900. `vca proxy` routes `vca.<domain>` to it.
  3. The landing explains VCA, the DPGs, and the triangle of trust in short text, and links out for depth.
  4. The landing lists each live stack with its components, pinned versions, and repository and documentation links. The data comes from the `GetCapabilities` answer of each adapter.
  5. The role picker lists only roles with a live pair. With one live role, the picker sends the browser to that role.
  6. Each role intro page shows step cards for the live features only. Then the page shows a sign in action on the pair of the role.
- Consequences:
  1. One address starts every journey.
  2. One small container per deployment, 96 MiB.
  3. Vendor names stay in the adapters.
  4. A pair that does not run never appears.
