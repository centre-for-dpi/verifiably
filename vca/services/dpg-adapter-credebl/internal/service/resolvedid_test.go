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
