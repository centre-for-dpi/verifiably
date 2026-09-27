// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/fake"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/service"
)

// P6-C5: the state of an OID4VC offer and the list of issued
// credentials come from the issuance sessions of the agent, through the
// api gateway. The answers come from the platform and agent sources in
// testdata/doc.

// The sessions of the answers.
const (
	pendingSession   = "a1b2c3d4-0000-4e5f-8a9b-000000000001"
	completedSession = "a1b2c3d4-0000-4e5f-8a9b-000000000002"
	errorSession     = "a1b2c3d4-0000-4e5f-8a9b-000000000003"
)

// status reads the state of one offer.
func status(t *testing.T, svc interface {
	GetIssuanceStatus(context.Context, *connect.Request[backendv1.GetIssuanceStatusRequest]) (*connect.Response[backendv1.GetIssuanceStatusResponse], error)
}, offer string) (*backendv1.GetIssuanceStatusResponse, error) {
	t.Helper()
	res, err := svc.GetIssuanceStatus(context.Background(), connect.NewRequest(&backendv1.GetIssuanceStatusRequest{OfferId: offer}))
	if err != nil {
		return nil, err
	}
	return res.Msg, nil
}

// TestIssuanceStatusFromOfferList maps the state of the issuance session
// of an offer onto the contract: an offer a wallet has not claimed is
// pending until it ends, a completed session is issued, and a session in
// error failed with the reason of the agent.
func TestIssuanceStatusFromOfferList(t *testing.T) {
	svc, f := newService(t, nil)
	got, err := status(t, svc, pendingSession)
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	if got.GetState() != backendv1.GetIssuanceStatusResponse_STATE_PENDING || got.GetClaimedAt() != nil ||
		!got.GetExpiresAt().AsTime().Equal(time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)) {
		t.Errorf("pending = %v", got)
	}
	if calls := strings.Join(f.Calls(), " "); !strings.Contains(calls, "GET /v1/orgs/org-1/oid4vc/credential-offer/"+pendingSession) {
		t.Errorf("calls = %s", calls)
	}
	f.SetOfferSession(fake.OfferCompleted)
	got, err = status(t, svc, completedSession)
	if err != nil {
		t.Fatalf("completed: %v", err)
	}
	if got.GetState() != backendv1.GetIssuanceStatusResponse_STATE_ISSUED ||
		!got.GetClaimedAt().AsTime().Equal(time.Date(2026, 9, 26, 10, 5, 0, 0, time.UTC)) {
		t.Errorf("completed = %v", got)
	}
	f.SetOfferSession(fake.OfferError)
	got, err = status(t, svc, errorSession)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if got.GetState() != backendv1.GetIssuanceStatusResponse_STATE_FAILED || got.GetError() != "The wallet proof did not verify." {
		t.Errorf("error = %v", got)
	}
	_, err = status(t, svc, "")
	wantCode(t, err, connect.CodeInvalidArgument)
	f.SetStatus("/v1/orgs/org-1/oid4vc/credential-offer/gone", 404)
	_, err = status(t, svc, "gone")
	wantCode(t, err, connect.CodeNotFound)
}

// TestIssuanceStatusEndsAtTheExpiry: a pending offer past its end is
// expired.
func TestIssuanceStatusEndsAtTheExpiry(t *testing.T) {
	svc, _ := newService(t, func(o *service.Options) {
		o.Now = func() time.Time { return time.Date(2026, 9, 26, 13, 0, 0, 0, time.UTC) }
	})
	got, err := status(t, svc, pendingSession)
	if err != nil {
		t.Fatal(err)
	}
	if got.GetState() != backendv1.GetIssuanceStatusResponse_STATE_EXPIRED {
		t.Errorf("state = %v, want expired", got.GetState())
	}
}

// TestIssuedListPages lists the completed sessions of one credential
// type whose claims match, oldest first, one page at a time. An entry
// carries no claim value.
func TestIssuedListPages(t *testing.T) {
	svc, f := newService(t, nil)
	ctx := context.Background()
	req := &backendv1.ListIssuedCredentialsRequest{
		CredentialType: "RegistrationCertificate", Attributes: map[string]string{"registration_number": "[REGISTRATION NUMBER]"},
	}
	res, err := svc.ListIssuedCredentials(ctx, connect.NewRequest(req))
	if err != nil {
		t.Fatalf("ListIssuedCredentials: %v", err)
	}
	entries := res.Msg.GetCredentials()
	if len(entries) != 1 || entries[0].GetCredentialId() != completedSession || entries[0].GetCredentialType() != "RegistrationCertificate" ||
		!entries[0].GetIssuedAt().AsTime().Equal(time.Date(2026, 9, 26, 10, 5, 0, 0, time.UTC)) {
		t.Errorf("entries = %v", entries)
	}
	if !strings.Contains(strings.Join(f.Calls(), " "), "GET /v1/orgs/org-1/oid4vc/credential-offer") {
		t.Errorf("calls = %v", f.Calls())
	}
	// Both completed sessions of the type, with a page size of one.
	all := &backendv1.ListIssuedCredentialsRequest{CredentialType: "RegistrationCertificate", Page: &commonv1.Pagination{PageSize: 1}}
	first, err := svc.ListIssuedCredentials(ctx, connect.NewRequest(all))
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Msg.GetCredentials()) != 1 || first.Msg.GetCredentials()[0].GetCredentialId() != "a1b2c3d4-0000-4e5f-8a9b-000000000004" ||
		first.Msg.GetPage().GetNextPageToken() != "1" || first.Msg.GetPage().GetTotalSize() != 2 {
		t.Fatalf("first page = %v", first.Msg)
	}
	all.Page.PageToken = first.Msg.GetPage().GetNextPageToken()
	second, err := svc.ListIssuedCredentials(ctx, connect.NewRequest(all))
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Msg.GetCredentials()) != 1 || second.Msg.GetCredentials()[0].GetCredentialId() != completedSession ||
		second.Msg.GetPage().GetNextPageToken() != "" {
		t.Fatalf("second page = %v", second.Msg)
	}
	one, err := svc.ListIssuedCredentials(ctx, connect.NewRequest(&backendv1.ListIssuedCredentialsRequest{CredentialId: completedSession}))
	if err != nil || len(one.Msg.GetCredentials()) != 1 {
		t.Errorf("by id = %v, %v", one, err)
	}
	none, err := svc.ListIssuedCredentials(ctx, connect.NewRequest(&backendv1.ListIssuedCredentialsRequest{CredentialType: "OtherType"}))
	if err != nil || len(none.Msg.GetCredentials()) != 0 {
		t.Errorf("another type = %v, %v", none, err)
	}
	_, err = svc.ListIssuedCredentials(ctx, connect.NewRequest(&backendv1.ListIssuedCredentialsRequest{}))
	wantCode(t, err, connect.CodeInvalidArgument)
	_, err = svc.ListIssuedCredentials(ctx, connect.NewRequest(&backendv1.ListIssuedCredentialsRequest{
		CredentialType: "RegistrationCertificate", Page: &commonv1.Pagination{PageToken: "x"},
	}))
	wantCode(t, err, connect.CodeInvalidArgument)
	f.SetStatus("/v1/orgs/org-1/oid4vc/credential-offer", 500)
	_, err = svc.ListIssuedCredentials(ctx, connect.NewRequest(req))
	wantCode(t, err, connect.CodeUnavailable)
}

// TestRevokeNeedsAStatusListHost: the platform revokes an OID4VC
// session only with a status list host. Settings that name none make
// Revoke answer Unimplemented with the reason, and the answer lists no
// revocation. The VCA status services revoke instead.
func TestRevokeNeedsAStatusListHost(t *testing.T) {
	svc, _ := newService(t, nil)
	_, err := svc.Revoke(context.Background(), connect.NewRequest(&backendv1.RevokeRequest{CredentialId: completedSession}))
	wantCode(t, err, connect.CodeUnimplemented)
	if !strings.Contains(err.Error(), "status list host") {
		t.Errorf("the message %q does not say why", err)
	}
	caps, err := svc.GetCapabilities(context.Background(), connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	listed := map[backendv1.Feature]bool{}
	for _, f := range caps.Msg.GetFeatures() {
		listed[f] = true
	}
	if listed[backendv1.Feature_FEATURE_REVOCATION] || !listed[backendv1.Feature_FEATURE_ISSUANCE_STATUS] || !listed[backendv1.Feature_FEATURE_ISSUED_LEDGER] {
		t.Errorf("features = %v", caps.Msg.GetFeatures())
	}
}
