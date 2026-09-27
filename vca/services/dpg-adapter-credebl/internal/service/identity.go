// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"encoding/json"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
)

// The issuer identity on CREDEBL is the primary DID of the organisation
// of the adapter (ADR-046, P6-C1). The agent of the organisation keeps
// every key. The pinned platform makes a DID only with its private key
// in the request, for every method, so the adapter provisions none
// (ADR-001 decision 3, ADR-070). The operator makes the DID in the
// platform, and the admin pages make it primary (P6-C1b).

// importMessage says why a DID import answers Unimplemented. An X.509
// chain imports (P6-C9, x509.go).
const importMessage = "the agent of the CREDEBL organisation keeps the key of every DID and takes no key reference, " +
	"so the adapter imports no DID; make a new identity, set the primary DID in the platform, or import an X.509 chain"

// keyBackend names the key store of the agent: the Askar wallet of Credo.
const keyBackend = "askar"

// OperatorDidMethods are the DID methods that the operator makes in the
// platform with a private key of the operator (P6-C1b). The pinned
// gateway refuses a did:key, a did:indy and a did:web without the key in
// the request (Validator.validateDid of libs/common/src/validator.ts at
// the platform tag v2.2.1-alpha.4). The pinned agent takes that key as
// the private key of the DID (handleKey, handleIndy and handleWeb of
// DidController.ts at the agent tag v2.2.1-alpha-jsonld-vc.2.1). An
// Indy DID without a key needs an endorser, and the platform drops the
// transaction to endorse. So the key goes from the operator to the
// platform, never through VCA, and the admin pages make such a DID the
// primary one.
var OperatorDidMethods = []string{"did:key", "did:indy", "did:web"}

// provisionMessage says why a provision answers Unimplemented.
const provisionMessage = "the CREDEBL platform makes a DID only with its private key in the request, and the adapter never holds one; " +
	"make the DID in the platform as the primary DID, or make it primary on the admin tenant page"

// X509KeyReference is the key reference of an X.509 import: the
// certificate row of the platform that keeps the key (ADR-068).
const X509KeyReference = `{"certificateId": "<certificate id>"}`

// ClientCredentialLimit is the number of client credentials the platform
// keeps per organisation (ADR-067 decision 4).
const ClientCredentialLimit = 1

// verificationKeyTypes maps a verification method type of a DID
// document onto a key type of the pages.
var verificationKeyTypes = map[string]string{
	"Ed25519VerificationKey2018":        "Ed25519",
	"Ed25519VerificationKey2020":        "Ed25519",
	"EcdsaSecp256k1VerificationKey2019": "secp256k1",
	"P256Key2021":                       "secp256r1",
}

// GetIssuerIdentity reads the DIDs of the organisation of the adapter,
// the primary DID first, with the DID document of the primary DID.
func (s *Service) GetIssuerIdentity(
	ctx context.Context, _ *connect.Request[backendv1.GetIssuerIdentityRequest],
) (*connect.Response[backendv1.GetIssuerIdentityResponse], error) {
	id, err := s.identity(ctx)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&backendv1.GetIssuerIdentityResponse{Identity: id}), nil
}

// identity builds the identity of the organisation of the adapter: its
// DIDs, then the subject of the imported X.509 chain while its
// certificate is active (P6-C9). It returns nil for an organisation with
// neither.
func (s *Service) identity(ctx context.Context) (*backendv1.IssuerIdentity, error) {
	orgID := s.client.OrgID()
	dids, err := s.client.OrgDids(ctx, orgID)
	if err != nil {
		return nil, failed("read the DIDs of the organisation", err)
	}
	id := &backendv1.IssuerIdentity{Key: &backendv1.IssuerIdentity_Key{Backend: keyBackend}}
	for _, d := range dids {
		id.Identifiers = append(id.Identifiers, d.Did)
	}
	if cerr := s.addChain(ctx, orgID, id); cerr != nil {
		return nil, cerr
	}
	if len(id.Identifiers) == 0 {
		return nil, nil
	}
	org, err := s.client.GetOrg(ctx, orgID)
	if err != nil {
		return nil, orgFailed(err)
	}
	id.Metadata = &backendv1.IssuerIdentity_Metadata{DisplayName: org.Name}
	if len(dids) == 0 {
		return id, nil
	}
	document := dids[0].DidDocument
	if len(org.Agents) > 0 && org.Agents[0].OrgDid == dids[0].Did && len(org.Agents[0].DidDocument) > 0 {
		document = org.Agents[0].DidDocument
	}
	if len(document) > 0 && string(document) != "null" {
		id.DidDocument = string(document)
		if t := documentKeyType(document); t != "" {
			id.Key.Type = t
		}
	}
	return id, nil
}

// documentKeyType reads the key type of the first verification method
// of a DID document. It returns "" for a type it does not know.
func documentKeyType(document json.RawMessage) string {
	var doc struct {
		VerificationMethod []struct {
			Type string `json:"type"`
		} `json:"verificationMethod"`
	}
	if err := json.Unmarshal(document, &doc); err != nil || len(doc.VerificationMethod) == 0 {
		return ""
	}
	return verificationKeyTypes[doc.VerificationMethod[0].Type]
}

// ProvisionIssuerIdentity is not available. See provisionMessage.
func (s *Service) ProvisionIssuerIdentity(
	context.Context, *connect.Request[backendv1.ProvisionIssuerIdentityRequest],
) (*connect.Response[backendv1.ProvisionIssuerIdentityResponse], error) {
	return nil, unimplemented(provisionMessage)
}
