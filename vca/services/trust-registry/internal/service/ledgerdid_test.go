// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
)

// indyDid is the ledger DID of an AnonCreds issuer of a stack.
const indyDid = "did:indy:bcovrin:testnet:Ra8FGb2mXsTg1d4VqVnYpS"

// TestLedgerDidNeedsTheStackOrAConfirmation is the trust step of an
// AnonCreds issuer: VCA resolves no did:indy itself. The registry stores
// it with the DID document a stack resolved, or with the confirmation of
// an admin, and says which. Without either it refuses and says why. A
// DID that VCA resolves keeps no document and reads as resolved by VCA.
func TestLedgerDidNeedsTheStackOrAConfirmation(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, nil)
	put := func(e *trustv1.TrustEntry, confirm bool) (*trustv1.TrustEntry, error) {
		resp, err := f.svc.UpsertEntry(ctx, connect.NewRequest(&trustv1.UpsertEntryRequest{Entry: e, ConfirmUnresolved: confirm}))
		if err != nil {
			return nil, err
		}
		return resp.Msg.GetEntry(), nil
	}
	bare := protoEntry(indyDid, commonv1.Role_ROLE_ISSUER, trustv1.Status_STATUS_ACTIVE)
	if _, err := put(bare, false); code(err) != connect.CodeFailedPrecondition {
		t.Fatalf("a ledger DID with no document and no confirmation: %v", err)
	}
	confirmed, err := put(bare, true)
	if err != nil || confirmed.GetResolution() != trustv1.Resolution_RESOLUTION_CONFIRMED || confirmed.GetDidDocument() != "" {
		t.Fatalf("a confirmed ledger DID: %+v %v", confirmed, err)
	}
	withDoc := protoEntry(indyDid, commonv1.Role_ROLE_ISSUER, trustv1.Status_STATUS_ACTIVE)
	withDoc.DidDocument = `{"id":"` + indyDid + `","verificationMethod":[]}`
	withDoc.ResolvedBy = "Third stack"
	resolved, err := put(withDoc, false)
	if err != nil || resolved.GetResolution() != trustv1.Resolution_RESOLUTION_STACK || resolved.GetResolvedBy() != "Third stack" || resolved.GetDidDocument() == "" {
		t.Fatalf("a ledger DID with the document of a stack: %+v %v", resolved, err)
	}
	other := protoEntry(indyDid, commonv1.Role_ROLE_ISSUER, trustv1.Status_STATUS_ACTIVE)
	other.DidDocument = `{"id":"did:indy:bcovrin:testnet:Other"}`
	if _, oerr := put(other, false); code(oerr) != connect.CodeInvalidArgument {
		t.Fatalf("a document of another DID: %v", oerr)
	}
	got, err := f.svc.TrustLookup(ctx, connect.NewRequest(&trustv1.TrustLookupRequest{Identifier: didID(indyDid), Role: commonv1.Role_ROLE_ISSUER}))
	if err != nil || got.Msg.GetOutcome() != trustv1.TrustLookupResponse_OUTCOME_TRUSTED {
		t.Fatalf("the trust lookup of the ledger DID: %+v %v", got, err)
	}
	// A second write of a confirmed entry, such as a change of its name,
	// keeps the confirmation.
	again := protoEntry("did:indy:bcovrin:testnet:Kept", commonv1.Role_ROLE_ISSUER, trustv1.Status_STATUS_ACTIVE)
	if _, err = put(again, true); err != nil {
		t.Fatal(err)
	}
	again.DisplayName = "Renamed"
	if kept, kerr := put(again, false); kerr != nil || kept.GetResolution() != trustv1.Resolution_RESOLUTION_CONFIRMED {
		t.Fatalf("a renamed confirmed entry: %+v %v", kept, kerr)
	}
	// A pending entry waits for review and is never published, so it
	// needs no resolution yet. Its approval does.
	pending := protoEntry("did:indy:bcovrin:testnet:Pending", commonv1.Role_ROLE_ISSUER, trustv1.Status_STATUS_PENDING)
	if waiting, werr := put(pending, false); werr != nil || waiting.GetResolution() != trustv1.Resolution_RESOLUTION_UNSPECIFIED {
		t.Fatalf("a pending ledger DID: %+v %v", waiting, werr)
	}
	pending.Status = trustv1.Status_STATUS_ACTIVE
	if _, aerr := put(pending, false); code(aerr) != connect.CodeFailedPrecondition {
		t.Fatalf("the approval of an unresolved ledger DID: %v", aerr)
	}
	local, err := put(protoEntry("did:web:issuer.example", commonv1.Role_ROLE_ISSUER, trustv1.Status_STATUS_ACTIVE), false)
	if err != nil || local.GetResolution() != trustv1.Resolution_RESOLUTION_LOCAL {
		t.Fatalf("a did:web: %+v %v", local, err)
	}
	// A DID of a local method that does not resolve still fails, even
	// with a confirmation.
	if _, err := put(protoEntry("did:web:missing.example", commonv1.Role_ROLE_ISSUER, trustv1.Status_STATUS_ACTIVE), true); code(err) != connect.CodeInvalidArgument {
		t.Fatalf("a did:web that does not resolve: %v", err)
	}
}
