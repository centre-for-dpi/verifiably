// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/credebl"
)

// The issuer identity on CREDEBL is the primary DID of the organisation
// of the adapter (ADR-046, P6-C1). The agent of the organisation makes
// and keeps every key, so the adapter never sees one (ADR-001 decision
// 3). The agent needs the private key in the request for a did:indy and
// a did:web, so the adapter provisions a did:key only.

// importMessage says why import answers Unimplemented.
const importMessage = "the agent of the CREDEBL organisation keeps every key and takes no key reference, " +
	"so the adapter imports no issuer identity; make a new identity or set the primary DID in the platform"

// keyBackend names the key store of the agent: the Askar wallet of Credo.
const keyBackend = "askar"

// DidMethods are the DID methods the adapter provisions.
var DidMethods = []string{"did:key"}

// KeyTypes are the key types of a provisioned did:key, as the pages
// name them.
var KeyTypes = []string{"Ed25519", "secp256r1", "secp256k1"}

// agentKeyTypes maps a key type of the pages onto the name the agent
// takes.
var agentKeyTypes = map[string]string{
	"Ed25519":   "ed25519",
	"secp256r1": "p256",
	"secp256k1": "k256",
}

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

// identity builds the identity of the organisation of the adapter. It
// returns nil for an organisation with no DID.
func (s *Service) identity(ctx context.Context) (*backendv1.IssuerIdentity, error) {
	orgID := s.client.OrgID()
	dids, err := s.client.OrgDids(ctx, orgID)
	if err != nil {
		return nil, failed("read the DIDs of the organisation", err)
	}
	if len(dids) == 0 {
		return nil, nil
	}
	org, err := s.client.GetOrg(ctx, orgID)
	if err != nil {
		return nil, orgFailed(err)
	}
	id := &backendv1.IssuerIdentity{
		Metadata: &backendv1.IssuerIdentity_Metadata{DisplayName: org.Name},
		Key:      &backendv1.IssuerIdentity_Key{Backend: keyBackend},
	}
	for _, d := range dids {
		id.Identifiers = append(id.Identifiers, d.Did)
	}
	document := dids[0].DidDocument
	if len(org.Agents) > 0 && org.Agents[0].OrgDid == dids[0].Did && len(org.Agents[0].DidDocument) > 0 {
		document = org.Agents[0].DidDocument
	}
	if len(document) > 0 && string(document) != "null" {
		id.DidDocument = string(document)
		id.Key.Type = documentKeyType(document)
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

// ProvisionIssuerIdentity asks the agent for a did:key and makes it the
// primary DID of the organisation of the adapter.
func (s *Service) ProvisionIssuerIdentity(
	ctx context.Context, req *connect.Request[backendv1.ProvisionIssuerIdentityRequest],
) (*connect.Response[backendv1.ProvisionIssuerIdentityResponse], error) {
	method := strings.TrimSpace(req.Msg.GetMethod())
	if !contains(DidMethods, method) {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("the adapter provisions did:key only; the agent needs the private key for another method"))
	}
	keyType := req.Msg.GetKeyType()
	if keyType == "" {
		keyType = KeyTypes[0]
	}
	agentType, ok := agentKeyTypes[keyType]
	if !ok {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the key type is not one of "+strings.Join(KeyTypes, ", ")))
	}
	if _, err := s.client.CreateDid(ctx, s.client.OrgID(), credebl.DidRequest{
		Method: strings.TrimPrefix(method, "did:"), KeyType: agentType, IsPrimaryDid: true,
	}); err != nil {
		return nil, failed("create the DID of the organisation", err)
	}
	id, err := s.identity(ctx)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&backendv1.ProvisionIssuerIdentityResponse{Identity: id}), nil
}

// ImportIssuerIdentity is not available. See importMessage.
func (s *Service) ImportIssuerIdentity(
	context.Context, *connect.Request[backendv1.ImportIssuerIdentityRequest],
) (*connect.Response[backendv1.ImportIssuerIdentityResponse], error) {
	return nil, unimplemented(importMessage)
}

// contains reports whether the list holds the value.
func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
