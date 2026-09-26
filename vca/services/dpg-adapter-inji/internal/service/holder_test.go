// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/fake"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/service"
)

// The holder role through Mimoto (P6-I7a decision, docs/dpg-adapter-inji.md).

// holder wires Mimoto only, as the holder pair of the stack does.
var holder = roles{mimoto: true}

// idToken is an ID token of the holder login. The fake Mimoto takes any
// token but fake.RefusedToken.
const idToken = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ3YW5qaWt1In0.c2ln" //nolint:gosec // G101: a test token of the fake Mimoto, not a credential

// openWallet opens the wallet of the test holder.
func openWallet(t *testing.T, svc *service.Service) string {
	t.Helper()
	resp, err := svc.Register(context.Background(), connect.NewRequest(&backendv1.RegisterRequest{
		PairwiseSubject: "hash-of-iss-sub", IdToken: idToken,
	}))
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	return resp.Msg.GetWalletId()
}

// TestRegisterCreatesMimotoWallet logs in to Mimoto with the ID token of
// the holder login and makes one wallet with a PIN the adapter keeps. A
// second login opens the same wallet.
func TestRegisterCreatesMimotoWallet(t *testing.T) {
	svc, f := newService(t, holder)
	first := openWallet(t, svc)
	if first != "4f1c9a7e-2b8d-4d3a-9e61-7a2c5b0d8e13" || f.MimotoLogins() != 1 {
		t.Fatalf("wallet %q, logins %d", first, f.MimotoLogins())
	}
	var pin struct {
		Pin string `json:"walletPin"`
	}
	if err := f.RequestJSON("/v1/mimoto/wallets", &pin); err != nil || len(pin.Pin) != 6 {
		t.Fatalf("the wallet PIN %q is not six digits: %v", pin.Pin, err)
	}
	if again := openWallet(t, svc); again != first || f.MimotoLogins() != 2 {
		t.Fatalf("second login: wallet %q, logins %d", again, f.MimotoLogins())
	}
	ctx := context.Background()
	_, err := svc.Register(ctx, connect.NewRequest(&backendv1.RegisterRequest{PairwiseSubject: "s"}))
	wantCode(t, err, connect.CodeFailedPrecondition)
	_, err = svc.Register(ctx, connect.NewRequest(&backendv1.RegisterRequest{IdToken: idToken}))
	wantCode(t, err, connect.CodeInvalidArgument)
	_, err = svc.Register(ctx, connect.NewRequest(&backendv1.RegisterRequest{PairwiseSubject: "s", IdToken: fake.RefusedToken}))
	wantCode(t, err, connect.CodePermissionDenied)
}

// TestListCredentials lists the held credentials of the Mimoto wallet by
// their names. Mimoto returns no credential bytes.
func TestListCredentials(t *testing.T) {
	svc, f := newService(t, holder)
	wallet := openWallet(t, svc)
	resp, err := svc.ListCredentials(context.Background(), connect.NewRequest(&backendv1.ListCredentialsRequest{
		WalletId: wallet, Page: &commonv1.Pagination{PageSize: 1},
	}))
	if err != nil {
		t.Fatalf("ListCredentials: %v", err)
	}
	got := resp.Msg.GetCredentials()
	if len(got) != 1 || got[0].GetType() != "Farmer Credential" || got[0].GetIssuer() != "Ministry of Agriculture" ||
		got[0].GetId() != "c9d27f40-6a1e-4b95-8f3c-2e7d1a5b9c04" || resp.Msg.GetPage().GetTotalSize() != 2 ||
		resp.Msg.GetPage().GetNextPageToken() == "" {
		t.Fatalf("credentials = %v page %v", got, resp.Msg.GetPage())
	}
	next, err := svc.ListCredentials(context.Background(), connect.NewRequest(&backendv1.ListCredentialsRequest{
		WalletId: wallet, Page: &commonv1.Pagination{PageSize: 1, PageToken: resp.Msg.GetPage().GetNextPageToken()},
	}))
	if err != nil || len(next.Msg.GetCredentials()) != 1 || next.Msg.GetCredentials()[0].GetType() != "National ID" {
		t.Fatalf("second page = %v %v", next.Msg.GetCredentials(), err)
	}
	// A session that Mimoto ended asks the holder to sign in again.
	f.ForgetMimotoSession()
	_, err = svc.ListCredentials(context.Background(), connect.NewRequest(&backendv1.ListCredentialsRequest{WalletId: wallet}))
	wantCode(t, err, connect.CodeUnauthenticated)
	_, err = svc.ListCredentials(context.Background(), connect.NewRequest(&backendv1.ListCredentialsRequest{WalletId: "unknown"}))
	wantCode(t, err, connect.CodeNotFound)
}

// TestAcceptOfferPointsAtInjiWeb answers unimplemented and names Inji
// Web, where the browser runs the download of Mimoto.
func TestAcceptOfferPointsAtInjiWeb(t *testing.T) {
	svc, _ := newService(t, holder)
	_, err := svc.AcceptOffer(context.Background(), connect.NewRequest(&backendv1.AcceptOfferRequest{
		WalletId: openWallet(t, svc), OfferUri: "openid-credential-offer://?credential_offer_uri=x",
	}))
	wantCode(t, err, connect.CodeUnimplemented)
	if !strings.Contains(err.Error(), "https://inji-web.example") {
		t.Fatalf("the answer does not name Inji Web: %v", err)
	}
}

// TestPresentThroughMimoto answers an OID4VP request through Mimoto. A
// bare request object address becomes an openid4vp URL.
func TestPresentThroughMimoto(t *testing.T) {
	svc, f := newService(t, holder)
	wallet := openWallet(t, svc)
	resp, err := svc.Present(context.Background(), connect.NewRequest(&backendv1.PresentRequest{
		WalletId: wallet, RequestUri: "https://verify.inji.example/v1/verify/vp-request/r1",
		CredentialIds: []string{"c9d27f40-6a1e-4b95-8f3c-2e7d1a5b9c04"}, DisclosedClaims: []string{"fullName"},
	}))
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	if !resp.Msg.GetAccepted() || resp.Msg.GetRedirectUri() != "https://verify.inji.example/redirect" ||
		resp.Msg.GetVerifierState() != "7e2a4c91-5d3b-4f8e-b0a6-9c1d2e3f4a5b" {
		t.Fatalf("answer = %v", resp.Msg)
	}
	if !slices.Equal(f.MimotoPresented(), []string{"c9d27f40-6a1e-4b95-8f3c-2e7d1a5b9c04"}) {
		t.Fatalf("presented = %v", f.MimotoPresented())
	}
	_, err = svc.Present(context.Background(), connect.NewRequest(&backendv1.PresentRequest{WalletId: wallet}))
	wantCode(t, err, connect.CodeInvalidArgument)
}

// TestDelete removes a credential from the Mimoto wallet, and the PDF of
// Mimoto comes back as the document of a credential.
func TestDelete(t *testing.T) {
	svc, _ := newService(t, holder)
	wallet := openWallet(t, svc)
	ctx := context.Background()
	doc, err := svc.GetCredentialDocument(ctx, connect.NewRequest(&backendv1.GetCredentialDocumentRequest{
		WalletId: wallet, CredentialId: "c9d27f40-6a1e-4b95-8f3c-2e7d1a5b9c04",
	}))
	if err != nil || doc.Msg.GetMediaType() != "application/pdf" || !bytes.HasPrefix(doc.Msg.GetContent(), []byte("%PDF")) {
		t.Fatalf("document = %q %v", doc.Msg.GetMediaType(), err)
	}
	if _, derr := svc.DeleteCredential(ctx, connect.NewRequest(&backendv1.DeleteCredentialRequest{
		WalletId: wallet, CredentialId: "c9d27f40-6a1e-4b95-8f3c-2e7d1a5b9c04",
	})); derr != nil {
		t.Fatalf("DeleteCredential: %v", derr)
	}
	left, err := svc.ListCredentials(ctx, connect.NewRequest(&backendv1.ListCredentialsRequest{WalletId: wallet}))
	if err != nil || len(left.Msg.GetCredentials()) != 1 {
		t.Fatalf("after delete = %v %v", left.Msg.GetCredentials(), err)
	}
	_, err = svc.DeleteCredential(ctx, connect.NewRequest(&backendv1.DeleteCredentialRequest{WalletId: wallet}))
	wantCode(t, err, connect.CodeInvalidArgument)
	_, err = svc.GetCredentialDocument(ctx, connect.NewRequest(&backendv1.GetCredentialDocumentRequest{WalletId: wallet}))
	wantCode(t, err, connect.CodeInvalidArgument)
}

// TestCapabilitiesListHolderRole lists the holder role, the holder
// features, and the Mimoto and Inji Web components with a Mimoto URL.
// Inji Web carries its public address, where the holder claims.
func TestCapabilitiesListHolderRole(t *testing.T) {
	svc, _ := newService(t, holder)
	caps, err := svc.GetCapabilities(context.Background(), connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	msg := caps.Msg
	if !slices.Equal(msg.GetRoles(), []commonv1.Role{commonv1.Role_ROLE_HOLDER}) ||
		!slices.Contains(msg.GetFeatures(), backendv1.Feature_FEATURE_WALLET_DOCUMENT) ||
		!slices.Contains(msg.GetFeatures(), backendv1.Feature_FEATURE_WALLET_CLAIM_IN_STACK) ||
		!slices.Contains(msg.GetProtocols(), backendv1.Protocol_PROTOCOL_OID4VP) {
		t.Fatalf("capabilities = %v", msg)
	}
	names := map[string]*backendv1.Component{}
	for _, c := range msg.GetDpgInfo().GetComponents() {
		names[c.GetName()] = c
	}
	if names["mimoto"].GetVersion() != "0.21.0" || names["inji-web"].GetVersion() != "0.16.0" ||
		names["inji-web"].GetUrl() != "https://inji-web.example" || names["esignet"] == nil || names["certify"] != nil {
		t.Fatalf("components = %v", msg.GetDpgInfo().GetComponents())
	}
	issuer, _ := newService(t, both)
	caps, err = issuer.GetCapabilities(context.Background(), connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(caps.Msg.GetRoles(), commonv1.Role_ROLE_HOLDER) || slices.Contains(caps.Msg.GetFeatures(), backendv1.Feature_FEATURE_WALLET_DOCUMENT) {
		t.Fatalf("a deployment without Mimoto lists the holder role: %v", caps.Msg)
	}
}

// TestHolderWithoutMimoto answers unimplemented on a deployment without
// a Mimoto URL, and the answer names the alternatives.
func TestHolderWithoutMimoto(t *testing.T) {
	svc, _ := newService(t, both)
	ctx := context.Background()
	_, err := svc.Register(ctx, connect.NewRequest(&backendv1.RegisterRequest{PairwiseSubject: "s", IdToken: idToken}))
	wantCode(t, err, connect.CodeUnimplemented)
	_, err = svc.AcceptOffer(ctx, connect.NewRequest(&backendv1.AcceptOfferRequest{WalletId: "w"}))
	wantCode(t, err, connect.CodeUnimplemented)
	_, err = svc.GetCredentialDocument(ctx, connect.NewRequest(&backendv1.GetCredentialDocumentRequest{WalletId: "w"}))
	wantCode(t, err, connect.CodeUnimplemented)
	if !strings.Contains(err.Error(), "wallet portal") {
		t.Fatalf("the answer names no alternative: %v", err)
	}
	holderSvc, _ := newService(t, holder)
	_, err = holderSvc.DeleteCredential(ctx, connect.NewRequest(&backendv1.DeleteCredentialRequest{CredentialId: "c"}))
	wantCode(t, err, connect.CodeInvalidArgument)
}
