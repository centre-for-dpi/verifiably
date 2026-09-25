// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/fake"
)

// revoke calls Revoke with one credential id and an action.
func revoke(svc interface {
	Revoke(context.Context, *connect.Request[backendv1.RevokeRequest]) (*connect.Response[backendv1.RevokeResponse], error)
}, id string, action backendv1.RevokeRequest_Action,
) (*backendv1.RevokeResponse, error) {
	resp, err := svc.Revoke(context.Background(), connect.NewRequest(&backendv1.RevokeRequest{
		CredentialId: id, Action: action, Reason: "Lost card",
	}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// TestRevokeCallsStatusApi revokes a credential of the Certify ledger
// through the status API: the bit of the revocation purpose goes on.
func TestRevokeCallsStatusApi(t *testing.T) {
	svc, f := newService(t, both)
	for _, action := range []backendv1.RevokeRequest_Action{
		backendv1.RevokeRequest_ACTION_UNSPECIFIED, backendv1.RevokeRequest_ACTION_REVOKE,
	} {
		got, err := revoke(svc, fake.LedgerCredential, action)
		if err != nil {
			t.Fatalf("revoke: %v", err)
		}
		if want := time.Date(2026, 9, 26, 10, 0, 0, 0, time.UTC); !got.GetRevokedAt().AsTime().Equal(want) {
			t.Fatalf("revoked at %v", got.GetRevokedAt().AsTime())
		}
		var body struct {
			CredentialID     string `json:"credentialId"`
			Status           bool   `json:"status"`
			CredentialStatus struct {
				StatusPurpose string `json:"statusPurpose"`
			} `json:"credentialStatus"`
		}
		if err := f.RequestJSON("/v1/certify/credentials/status", &body); err != nil {
			t.Fatal(err)
		}
		if body.CredentialID != fake.LedgerCredential || !body.Status || body.CredentialStatus.StatusPurpose != "revocation" {
			t.Fatalf("the status call %+v", body)
		}
	}
	_, err := revoke(svc, "urn:uuid:unknown", backendv1.RevokeRequest_ACTION_REVOKE)
	wantCode(t, err, connect.CodeNotFound)
	_, err = revoke(svc, "", backendv1.RevokeRequest_ACTION_REVOKE)
	wantCode(t, err, connect.CodeFailedPrecondition)
	for _, action := range []backendv1.RevokeRequest_Action{backendv1.RevokeRequest_ACTION_SUSPEND, backendv1.RevokeRequest_ACTION_REINSTATE} {
		_, err = revoke(svc, fake.LedgerCredential, action)
		wantCode(t, err, connect.CodeUnimplemented)
	}
	f.SetStatus("/v1/certify/credentials/status", 503)
	_, err = revoke(svc, fake.LedgerCredential, backendv1.RevokeRequest_ACTION_REVOKE)
	wantCode(t, err, connect.CodeUnavailable)

	verifier, _ := newService(t, roles{verify: true})
	_, err = revoke(verifier, fake.LedgerCredential, backendv1.RevokeRequest_ACTION_REVOKE)
	wantCode(t, err, connect.CodeUnimplemented)
}

// list calls ListIssuedCredentials.
func list(svc interface {
	ListIssuedCredentials(context.Context, *connect.Request[backendv1.ListIssuedCredentialsRequest]) (
		*connect.Response[backendv1.ListIssuedCredentialsResponse], error)
}, req *backendv1.ListIssuedCredentialsRequest,
) (*backendv1.ListIssuedCredentialsResponse, error) {
	resp, err := svc.ListIssuedCredentials(context.Background(), connect.NewRequest(req))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// TestLedgerSearchPages searches the Certify ledger by type and an
// indexed attribute, and pages the answer. The issuer id comes from the
// DID document of Certify, and the type from the configuration.
func TestLedgerSearchPages(t *testing.T) {
	svc, _ := newService(t, both)
	query := &backendv1.ListIssuedCredentialsRequest{
		CredentialType: "FarmerCredential", Attributes: map[string]string{"farmerID": "F-1024"},
	}
	var ids []string
	for token, pages := "", 0; ; pages++ {
		query.Page = &commonv1.Pagination{PageToken: token}
		got, err := list(svc, query)
		if err != nil {
			t.Fatalf("page %d: %v", pages, err)
		}
		if got.GetPage().GetTotalSize() != 3 || len(got.GetCredentials()) != 1 {
			t.Fatalf("page %d: %+v", pages, got)
		}
		ids = append(ids, got.GetCredentials()[0].GetCredentialId())
		if token = got.GetPage().GetNextPageToken(); token == "" {
			break
		}
	}
	if len(ids) != 3 || ids[0] != fake.LedgerCredential {
		t.Fatalf("the pages hold %v, oldest issuance first", ids)
	}
	query.Page = nil
	query.CredentialId = fake.LedgerCredential
	one, err := list(svc, query)
	if err != nil || len(one.GetCredentials()) != 1 {
		t.Fatalf("one credential: %+v %v", one, err)
	}
	e := one.GetCredentials()[0]
	if e.GetCredentialType() != fake.LedgerType || e.GetStatusPurpose() != "revocation" ||
		e.GetStatus().GetIndex() != 17 || e.GetStatus().GetKind() != backendv1.StatusListBinding_KIND_BITSTRING ||
		e.GetStatus().GetPublishUrl() == "" || e.GetStatus().GetListId() != e.GetStatus().GetPublishUrl() {
		t.Fatalf("entry %+v", e)
	}
	if !e.GetIssuedAt().AsTime().Equal(time.Date(2026, 9, 20, 8, 15, 0, 0, time.UTC)) || e.GetExpiresAt() == nil {
		t.Fatalf("times %v %v", e.GetIssuedAt().AsTime(), e.GetExpiresAt())
	}
	// A type list and a bare type name reach the same ledger type.
	for _, typ := range []string{fake.LedgerType, "VerifiableCredential,FarmerCredential"} {
		got, lerr := list(svc, &backendv1.ListIssuedCredentialsRequest{CredentialType: typ, Attributes: query.Attributes})
		if lerr != nil || got.GetPage().GetTotalSize() != 3 {
			t.Fatalf("type %s: %+v %v", typ, got, lerr)
		}
	}
	none, err := list(svc, &backendv1.ListIssuedCredentialsRequest{CredentialType: "Unknown", Attributes: query.Attributes})
	if err != nil || len(none.GetCredentials()) != 0 || none.GetPage().GetTotalSize() != 0 {
		t.Fatalf("an unknown type: %+v %v", none, err)
	}
	past, err := list(svc, &backendv1.ListIssuedCredentialsRequest{CredentialType: "FarmerCredential",
		Attributes: query.Attributes, Page: &commonv1.Pagination{PageToken: "9"}})
	if err != nil || len(past.GetCredentials()) != 0 {
		t.Fatalf("a token past the end: %+v %v", past, err)
	}
	for _, bad := range []*backendv1.ListIssuedCredentialsRequest{
		{CredentialType: "FarmerCredential"},
		{Attributes: query.Attributes},
		{CredentialType: "FarmerCredential", Attributes: query.Attributes, Page: &commonv1.Pagination{PageToken: "x"}},
	} {
		_, berr := list(svc, bad)
		wantCode(t, berr, connect.CodeInvalidArgument)
	}
	verifier, _ := newService(t, roles{verify: true})
	_, err = list(verifier, query)
	wantCode(t, err, connect.CodeUnimplemented)
}

// TestLedgerSearchNeedsTheIssuerDid fails with a reason when Certify
// serves no DID document.
func TestLedgerSearchNeedsTheIssuerDid(t *testing.T) {
	svc, f := newService(t, both)
	f.SetStatus("/v1/certify/.well-known/did.json", 404)
	_, err := list(svc, &backendv1.ListIssuedCredentialsRequest{
		CredentialType: "FarmerCredential", Attributes: map[string]string{"farmerID": "F-1024"},
	})
	wantCode(t, err, connect.CodeNotFound)
	f.SetStatus("/v1/certify/.well-known/did.json", 0)
	f.SetStatus("/v1/certify/v2/ledger-search", 503)
	_, err = list(svc, &backendv1.ListIssuedCredentialsRequest{
		CredentialType: "FarmerCredential", Attributes: map[string]string{"farmerID": "F-1024"},
	})
	wantCode(t, err, connect.CodeUnavailable)
}

// TestRevocationAndLedgerFeaturesListed lists FEATURE_REVOCATION and
// FEATURE_ISSUED_LEDGER with a Certify URL, and FEATURE_SUSPENSION
// never: the stack allows the revocation purpose only.
func TestRevocationAndLedgerFeaturesListed(t *testing.T) {
	svc, _ := newService(t, roles{certify: true})
	caps, err := svc.GetCapabilities(context.Background(), connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	got := caps.Msg.GetFeatures()
	if !slices.Contains(got, backendv1.Feature_FEATURE_REVOCATION) || !slices.Contains(got, backendv1.Feature_FEATURE_ISSUED_LEDGER) ||
		slices.Contains(got, backendv1.Feature_FEATURE_SUSPENSION) {
		t.Fatalf("features %v", got)
	}
	verifier, _ := newService(t, roles{verify: true})
	caps, err = verifier.GetCapabilities(context.Background(), connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(caps.Msg.GetFeatures(), backendv1.Feature_FEATURE_REVOCATION) {
		t.Fatal("a verifier only adapter lists revocation")
	}
}
