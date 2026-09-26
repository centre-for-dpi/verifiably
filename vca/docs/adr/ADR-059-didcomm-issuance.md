## ADR-059: DIDComm issuance channels and the formats each channel carries
- Status: Proposed
- Owner: CDPI Architects
- Scope: The adapter contract, the issuance service, the issue pages, the wallet portal, and the CREDEBL adapter and stack file.
- Extends: ADR-043 decisions 1 and 2, ADR-045 decisions 1 and 2, ADR-016 decision 6.
- Decision:
  1. An adapter that issues over DIDComm lists `CHANNEL_DIDCOMM_OOB` and `PROTOCOL_DIDCOMM_ISSUE_V2`. `CreateOffer` on that channel makes an out of band invitation that carries the offer. With a `connection_id` it sends the offer over a connection of the issuer instead. `ListConnections` lists those connections.
  2. `GetCapabilitiesResponse.channel_formats` names the formats of a channel that carries only some formats. The issuance service refuses a format the channel does not carry. The delivery step shows a channel only for a schema with a format it carries.
  3. An adapter that lists `CHANNEL_EMAIL` sends the offer itself, to the address in `CreateOfferRequest.email`. On any other stack the email channel stays a pre-authorized offer that VCA mails.
  4. The configuration id of a DIDComm format comes from the publication of the schema, such as a credential definition. A DIDComm credential carries no status list entry of VCA.
  5. The wallet portal names a DIDComm invitation that a holder pastes or scans. It shows the issuer, whether the invitation carries an offer, and a link that a DIDComm wallet opens.
  6. The CREDEBL stack keeps the files of the platform on one volume that its services share. The CREDEBL adapter lists `CHANNEL_EMAIL` only when the stack `.env` names a mail provider. Setup keeps the values that the operator adds to a stack `.env`.
- Consequences:
  1. AnonCreds and W3C JSON-LD credentials of CREDEBL reach a holder from the issue page.
  2. A page never offers a channel that cannot carry the credential.
  3. A holder of the browser wallet learns what a DIDComm code is, instead of an error.
