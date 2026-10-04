// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/service"
)

// ledgerDid is the did:indy of the recorded resolution.
const ledgerDid = "did:indy:bcovrin:testnet:Ra8FGb2mXsTg1d4VqVnYpS"

// TestResolveDidThroughTheAgent resolves a ledger DID with the DID
// resolver of the shared agent, in a tenant of the adapter's own, so no
// organisation wallet records the DID. VCA resolves no did:indy itself,
// so the trust registry keeps this document.
func TestResolveDidThroughTheAgent(t *testing.T) {
	ctx := context.Background()
	svc, agent, _ := newHolder(t, nil)
	for range 2 {
		resp, err := svc.ResolveDid(ctx, connect.NewRequest(&backendv1.ResolveDidRequest{Did: ledgerDid}))
		if err != nil {
			t.Fatalf("ResolveDid: %v", err)
		}
		var doc struct {
			ID                 string `json:"id"`
			VerificationMethod []any  `json:"verificationMethod"`
		}
		if err := json.Unmarshal([]byte(resp.Msg.GetDidDocument()), &doc); err != nil || doc.ID != ledgerDid || len(doc.VerificationMethod) != 2 {
			t.Fatalf("document = %s (%v)", resp.Msg.GetDidDocument(), err)
		}
	}
	tenants := 0
	for _, call := range agent.Calls() {
		if call == "POST /multi-tenancy/create-tenant" {
			tenants++
		}
	}
	if tenants != 1 {
		t.Errorf("the adapter made %d resolver tenants, want one it keeps", tenants)
	}
	if _, err := svc.ResolveDid(ctx, connect.NewRequest(&backendv1.ResolveDidRequest{Did: " "})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("an empty DID: %v", err)
	}
	// The agent answers a document of another DID: the adapter refuses it.
	if _, err := svc.ResolveDid(ctx, connect.NewRequest(&backendv1.ResolveDidRequest{Did: "did:indy:bcovrin:testnet:Other"})); err == nil ||
		!strings.Contains(err.Error(), "names another DID") {
		t.Errorf("a document of another DID: %v", err)
	}
	caps, err := svc.GetCapabilities(ctx, connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
	if err != nil || !slices.Contains(caps.Msg.GetFeatures(), backendv1.Feature_FEATURE_DID_RESOLVE) {
		t.Errorf("the capability answer lacks FEATURE_DID_RESOLVE: %v", err)
	}
	plain, _ := newService(t, nil)
	if _, err := plain.ResolveDid(ctx, connect.NewRequest(&backendv1.ResolveDidRequest{Did: ledgerDid})); connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Errorf("an adapter without the agent: %v", err)
	}
}

// TestAResolverOnlyAgentServesNoWallet: an issuer or a verifier pair
// reaches the agent to resolve ledger DIDs, so the admin needs no holder
// pair for that (ADR-062 amendment of 2026-10-04). Such a pair lists DID
// resolution but no holder role and no wallet feature.
func TestAResolverOnlyAgentServesNoWallet(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newHolder(t, func(o *service.Options) { o.AgentResolverOnly = true })
	caps, err := svc.GetCapabilities(ctx, connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	features := caps.Msg.GetFeatures()
	if !slices.Contains(features, backendv1.Feature_FEATURE_DID_RESOLVE) || slices.Contains(features, backendv1.Feature_FEATURE_WALLET_DIDCOMM) ||
		slices.Contains(caps.Msg.GetRoles(), commonv1.Role_ROLE_HOLDER) || len(caps.Msg.GetWalletDidMethods()) != 0 {
		t.Errorf("capabilities = %+v", caps.Msg)
	}
	if _, err := svc.ResolveDid(ctx, connect.NewRequest(&backendv1.ResolveDidRequest{Did: ledgerDid})); err != nil {
		t.Errorf("ResolveDid: %v", err)
	}
	if _, err := svc.Register(ctx, connect.NewRequest(&backendv1.RegisterRequest{PairwiseSubject: "s-1"})); connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Errorf("Register: %v", err)
	}
}
