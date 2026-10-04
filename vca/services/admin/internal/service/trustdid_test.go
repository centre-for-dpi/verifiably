// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"

	adminv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
)

// ledgerDid is the did:indy of an AnonCreds issuer.
const ledgerDid = "did:indy:bcovrin:testnet:Ra8FGb2mXsTg1d4VqVnYpS"

// ResolveDid answers the document of the ledger DID only.
func (f *fakeAdapter) ResolveDid(_ context.Context, req *connect.Request[backendv1.ResolveDidRequest]) (*connect.Response[backendv1.ResolveDidResponse], error) {
	if req.Msg.GetDid() != ledgerDid {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("the ledger holds no such DID"))
	}
	return connect.NewResponse(&backendv1.ResolveDidResponse{DidDocument: `{"id":"` + ledgerDid + `"}`}), nil
}

// TestUpsertTrustEntryResolvesALedgerDidThroughAStack is the trust step
// of an AnonCreds issuer: VCA resolves no did:indy, so the service asks
// the live stack that resolves DIDs and hands the document to the
// registry. A DID no stack resolves goes with the confirmation of the
// admin. A DID that VCA resolves asks no stack.
func TestUpsertTrustEntryResolvesALedgerDidThroughAStack(t *testing.T) {
	h := newHarness(t)
	withStacks(t, h, backendv1.Feature_FEATURE_DID_RESOLVE)
	ctx := context.Background()
	entry := func(id string) *trustv1.TrustEntry {
		return &trustv1.TrustEntry{Identifier: &trustv1.TrustEntry_Identifier{Id: &trustv1.TrustEntry_Identifier_Did{Did: id}},
			DisplayName: "Registry", Role: commonv1.Role_ROLE_ISSUER, Status: trustv1.Status_STATUS_ACTIVE}
	}
	if _, err := h.svc.UpsertTrustEntry(ctx, request(h, &adminv1.UpsertTrustEntryRequest{Entry: entry(ledgerDid)})); err != nil {
		t.Fatal(err)
	}
	stored := h.trust.entries[key(&trustv1.TrustEntry_Identifier{Id: &trustv1.TrustEntry_Identifier_Did{Did: ledgerDid}})]
	if stored.GetDidDocument() != `{"id":"`+ledgerDid+`"}` || stored.GetResolvedBy() != "Tenancy stack" {
		t.Fatalf("the registry got %+v", stored)
	}
	other := "did:indy:bcovrin:testnet:Unknown"
	if _, err := h.svc.UpsertTrustEntry(ctx, request(h, &adminv1.UpsertTrustEntryRequest{Entry: entry(other), ConfirmUnresolved: true})); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.UpsertTrustEntry(ctx, request(h, &adminv1.UpsertTrustEntryRequest{Entry: entry("did:web:issuer.example")})); err != nil {
		t.Fatal(err)
	}
	if got := h.trust.confirms; len(got) != 3 || got[0] || !got[1] || got[2] {
		t.Errorf("confirmations = %v", got)
	}
	for _, e := range h.trust.entries {
		if e.GetIdentifier().GetDid() != ledgerDid && e.GetDidDocument() != "" {
			t.Errorf("%s got a document: %s", e.GetIdentifier().GetDid(), e.GetDidDocument())
		}
	}
}

// TestApproveTrustEntryResolvesALedgerDid: an issuer asks for trust with
// its did:indy, and the pending entry carries no document. The approval
// asks the stack for it, so the registry can publish the entry.
func TestApproveTrustEntryResolvesALedgerDid(t *testing.T) {
	h := newHarness(t)
	withStacks(t, h, backendv1.Feature_FEATURE_DID_RESOLVE)
	id := &trustv1.TrustEntry_Identifier{Id: &trustv1.TrustEntry_Identifier_Did{Did: ledgerDid}}
	h.trust.entries[key(id)] = &trustv1.TrustEntry{Identifier: id, DisplayName: "Registry", Role: commonv1.Role_ROLE_ISSUER,
		Status: trustv1.Status_STATUS_PENDING}
	res, err := h.svc.ApproveTrustEntry(context.Background(), request(h, &adminv1.ApproveTrustEntryRequest{Identifier: id}))
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Msg.GetEntry(); got.GetStatus() != trustv1.Status_STATUS_ACTIVE || got.GetResolvedBy() != "Tenancy stack" || got.GetDidDocument() == "" {
		t.Fatalf("approved = %+v", got)
	}
}
