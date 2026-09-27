// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/fake"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/service"
)

// P6-C5b: the stack runs the status list host of the platform, so an
// offer is revocable and Revoke revokes the credentials of an issuance
// session through the api gateway. The answers come from the platform
// and agent sources in testdata/doc.

// revocableSession is the completed session of the answers whose
// credential carries a status list entry.
const revocableSession = "a1b2c3d4-0000-4e5f-8a9b-000000000005"

// withStatusList turns the status list host of the stack on.
func withStatusList(o *service.Options) { o.StatusList = true }

// TestRevokeSession revokes the credentials of one issuance session
// through the revoke route of the api gateway.
func TestRevokeSession(t *testing.T) {
	svc, f := newService(t, withStatusList)
	_, err := svc.Revoke(context.Background(), connect.NewRequest(&backendv1.RevokeRequest{
		CredentialId: revocableSession, Reason: "Lost", Action: backendv1.RevokeRequest_ACTION_REVOKE,
	}))
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	want := "POST /v1/orgs/org-1/openid4vc/issuance-sessions/" + revocableSession + "/revoke"
	if !slices.Contains(f.Calls(), want) {
		t.Errorf("calls = %v, want %s", f.Calls(), want)
	}
	// ACTION_UNSPECIFIED revokes, as before the field existed.
	if _, err := svc.Revoke(context.Background(), connect.NewRequest(&backendv1.RevokeRequest{CredentialId: revocableSession})); err != nil {
		t.Errorf("Revoke without an action: %v", err)
	}
}

// TestRevokeRefusesWhatThePlatformCannotDo: the platform revokes an
// OID4VC session and nothing else. A suspension, a reinstatement, a
// DIDComm credential and a call without a session fail before any
// platform call. A session with no status list entry fails with the
// answer of the platform.
func TestRevokeRefusesWhatThePlatformCannotDo(t *testing.T) {
	svc, f := newService(t, withStatusList)
	ctx := context.Background()
	for name, req := range map[string]*backendv1.RevokeRequest{
		"no session": {},
		"suspend":    {CredentialId: revocableSession, Action: backendv1.RevokeRequest_ACTION_SUSPEND},
		"reinstate":  {CredentialId: revocableSession, Action: backendv1.RevokeRequest_ACTION_REINSTATE},
		"didcomm":    {CredentialId: service.DidcommOfferPrefix + "record-1"},
	} {
		_, err := svc.Revoke(ctx, connect.NewRequest(req))
		if connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: code %v, want InvalidArgument: %v", name, connect.CodeOf(err), err)
		}
	}
	for _, call := range f.Calls() {
		if strings.Contains(call, "/revoke") {
			t.Errorf("a refused revoke called the platform: %s", call)
		}
	}
	path := "/v1/orgs/org-1/openid4vc/issuance-sessions/" + completedSession + "/revoke"
	f.SetStatus(path, 400)
	_, err := svc.Revoke(ctx, connect.NewRequest(&backendv1.RevokeRequest{CredentialId: completedSession}))
	wantCode(t, err, connect.CodeInvalidArgument)
	f.SetStatus(path, 500)
	_, err = svc.Revoke(ctx, connect.NewRequest(&backendv1.RevokeRequest{CredentialId: completedSession}))
	wantCode(t, err, connect.CodeUnavailable)
}

// TestOfferIsRevocableWithAStatusList asks the platform for a revocable
// offer when the stack runs the status list host, and for a plain one
// when it does not. The platform refuses a revocable offer without the
// host.
func TestOfferIsRevocableWithAStatusList(t *testing.T) {
	for _, on := range []bool{true, false} {
		svc, f := newService(t, func(o *service.Options) { o.StatusList = on })
		f.SetOfferSession(fake.OfferRevocable)
		_, err := svc.CreateOffer(context.Background(), connect.NewRequest(&backendv1.CreateOfferRequest{
			Spec: &backendv1.IssueSpec{ConfigurationId: "FarmerCredential", SubjectData: `{"name":"[HOLDER NAME]"}`},
		}))
		if err != nil {
			t.Fatalf("status list %v: CreateOffer: %v", on, err)
		}
		var body map[string]any
		if err := f.RequestJSON("/v1/orgs/org-1/oid4vc/issuer-1/create-offer", &body); err != nil {
			t.Fatal(err)
		}
		if got := body["isRevocable"] == true; got != on {
			t.Errorf("status list %v: isRevocable = %v", on, body["isRevocable"])
		}
	}
}

// TestRevocationListedWithAStatusList lists FEATURE_REVOCATION when the
// stack runs the status list host, and never FEATURE_SUSPENSION: the
// platform sets a revoked bit and clears none.
func TestRevocationListedWithAStatusList(t *testing.T) {
	for _, on := range []bool{true, false} {
		svc, _ := newService(t, func(o *service.Options) { o.StatusList = on })
		caps, err := svc.GetCapabilities(context.Background(), connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		got := caps.Msg.GetFeatures()
		if slices.Contains(got, backendv1.Feature_FEATURE_REVOCATION) != on || slices.Contains(got, backendv1.Feature_FEATURE_SUSPENSION) {
			t.Errorf("status list %v: features = %v", on, got)
		}
		// A listed feature works: an empty request fails on its input,
		// not as Unimplemented.
		_, rerr := svc.Revoke(context.Background(), connect.NewRequest(&backendv1.RevokeRequest{}))
		if (connect.CodeOf(rerr) == connect.CodeUnimplemented) == on {
			t.Errorf("status list %v: Revoke = %v", on, rerr)
		}
	}
}

// TestLedgerEntryCarriesTheStatusListEntry reads the status list entry
// that the agent wrote into the credential of a revocable session: a
// Token Status List with the list, the index and the address a
// verifier fetches. A session with no entry has none.
func TestLedgerEntryCarriesTheStatusListEntry(t *testing.T) {
	svc, _ := newService(t, withStatusList)
	res, err := svc.ListIssuedCredentials(context.Background(), connect.NewRequest(&backendv1.ListIssuedCredentialsRequest{
		CredentialType: "TradeLicence", Page: &commonv1.Pagination{PageSize: 1},
	}))
	if err != nil {
		t.Fatal(err)
	}
	entries := res.Msg.GetCredentials()
	if len(entries) != 1 || entries[0].GetCredentialId() != revocableSession {
		t.Fatalf("entries = %v", entries)
	}
	got := entries[0].GetStatus()
	if got.GetKind() != backendv1.StatusListBinding_KIND_TOKEN || got.GetListId() != "6f1e2d3c-4b5a-4968-8778-a1b2c3d4e5f6" ||
		got.GetIndex() != 4211 || got.GetPublishUrl() != "http://credebl-status-list:3000/status-lists/6f1e2d3c-4b5a-4968-8778-a1b2c3d4e5f6" ||
		entries[0].GetStatusPurpose() != "revocation" {
		t.Errorf("status = %v, purpose %q", got, entries[0].GetStatusPurpose())
	}
	plain, err := svc.ListIssuedCredentials(context.Background(), connect.NewRequest(&backendv1.ListIssuedCredentialsRequest{CredentialId: completedSession}))
	if err != nil {
		t.Fatal(err)
	}
	if len(plain.Msg.GetCredentials()) != 1 || plain.Msg.GetCredentials()[0].GetStatus() != nil {
		t.Errorf("a session with no entry = %v", plain.Msg.GetCredentials())
	}
}

// createdSession is the issuance session of the create offer answer.
const createdSession = "5f2c1d7b-6a09-4e83-9c14-2b7d8e0f3a56"

// TestCreateOfferNamesTheStatusEntryOfTheStack: the credential of a
// revocable offer carries an entry of the status list of the stack, not
// the entry of VCA in the spec. The answer names that entry and the
// session that Revoke takes.
func TestCreateOfferNamesTheStatusEntryOfTheStack(t *testing.T) {
	svc, f := newService(t, withStatusList)
	f.SetOfferSession(fake.OfferRevocable)
	resp, err := svc.CreateOffer(context.Background(), connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec: &backendv1.IssueSpec{
			ConfigurationId: "FarmerCredential", SubjectData: `{"name":"[HOLDER NAME]"}`,
			Status: &backendv1.StatusListBinding{Kind: backendv1.StatusListBinding_KIND_TOKEN, ListId: "vca-list", Index: 7},
		},
	}))
	if err != nil {
		t.Fatalf("CreateOffer: %v", err)
	}
	want := &backendv1.StatusListBinding{
		Kind:       backendv1.StatusListBinding_KIND_TOKEN,
		ListId:     "6f1e2d3c-4b5a-4968-8778-a1b2c3d4e5f6",
		Index:      4211,
		PublishUrl: "http://credebl-status-list:3000/status-lists/6f1e2d3c-4b5a-4968-8778-a1b2c3d4e5f6",
		DpgList:    true,
	}
	if !proto.Equal(resp.Msg.GetStatus(), want) {
		t.Fatalf("status = %v, want the entry of the stack %v", resp.Msg.GetStatus(), want)
	}
	if resp.Msg.GetCredentialId() != createdSession {
		t.Fatalf("credential id = %q, want the session %s that Revoke takes", resp.Msg.GetCredentialId(), createdSession)
	}
}

// TestCreateOfferWithoutAStatusListNamesNoEntry: without the status list
// host the platform writes no status entry, and the credential carries
// none of VCA either.
func TestCreateOfferWithoutAStatusListNamesNoEntry(t *testing.T) {
	svc, _ := newService(t, nil)
	resp, err := svc.CreateOffer(context.Background(), connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec: &backendv1.IssueSpec{
			ConfigurationId: "FarmerCredential", SubjectData: `{"name":"[HOLDER NAME]"}`,
			Status: &backendv1.StatusListBinding{Kind: backendv1.StatusListBinding_KIND_TOKEN, ListId: "vca-list", Index: 7},
		},
	}))
	if err != nil {
		t.Fatalf("CreateOffer: %v", err)
	}
	if resp.Msg.GetStatus() != nil || resp.Msg.GetCredentialId() != "" {
		t.Fatalf("status = %v, credential id = %q, want none", resp.Msg.GetStatus(), resp.Msg.GetCredentialId())
	}
}

// TestCreateOfferReportsAnUnreadableStatusEntry: the offer names its
// status entry, or it fails. A revocable credential never goes out as
// one that VCA cannot revoke.
func TestCreateOfferReportsAnUnreadableStatusEntry(t *testing.T) {
	for name, answer := range map[string]fake.Answer{"no entry": fake.OfferPending, "unreadable": fake.OfferRevocable} {
		svc, f := newService(t, withStatusList)
		f.SetOfferSession(answer)
		if name == "unreadable" {
			f.SetStatus("/v1/orgs/org-1/oid4vc/credential-offer/"+createdSession, 500)
		}
		_, err := svc.CreateOffer(context.Background(), connect.NewRequest(&backendv1.CreateOfferRequest{
			Spec: &backendv1.IssueSpec{ConfigurationId: "FarmerCredential", SubjectData: `{"name":"[HOLDER NAME]"}`},
		}))
		wantCode(t, err, connect.CodeUnavailable)
	}
}
