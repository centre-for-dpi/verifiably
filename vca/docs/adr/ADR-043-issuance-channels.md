## ADR-043: Issuance channels and bulk sources
- Status: Proposed
- Owner: CDPI Architects
- Scope: How a credential reaches a holder.
- Extends: ADR-016 decisions 1, 3, 5, 6, ADR-015 decision 7.
- Supersedes: ADR-027 decision 9 in part (a second feature that needs JavaScript, with a fallback).
- Decision:
  1. The channels are:
     - OID4VCI pre-authorized code.
     - OID4VCI authorization code.
     - Digital Credentials API.
     - QR on a PDF.
     - Identity QR (Claim 169).
     - DIDComm out of band invitation.
     - Email through the DPG.
  2. The issue page offers a channel only when the adapter of the pair lists it. The page also offers the two channels that VCA provides on every stack: PDF and the Digital Credentials API.
  3. The Digital Credentials API button appears only when the browser has the API. The QR and the link are always on the page.
  4. Bulk issuance uses the VCA data sources (CSV, SQL, HTTP) and, where the DPG has it, the DPG bulk import.
- Consequences:
  1. Every holder gets a channel that works.
  2. The page never offers a channel the stack cannot run.
