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
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// The holder role through Mimoto (P6-I7a decision, docs/dpg-adapter-inji.md).

// holder wires Mimoto only, as the holder pair of the stack does.
var holder = roles{mimoto: true}

// idToken is an ID token of the holder login. The fake Mimoto takes any
// token but fake.RefusedToken.
const idToken = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ3YW5qaWt1In0.c2ln" //nolint:gosec // G101: a test token of the fake Mimoto, not a credential

// holderPIN is the PIN the test holder chooses. The adapter never keeps
// it.
const holderPIN = "482915"

// signIn logs the test holder in and returns the wallet id.
func signIn(t *testing.T, svc *service.Service) string {
	t.Helper()
	resp, err := svc.Register(context.Background(), connect.NewRequest(&backendv1.RegisterRequest{
		PairwiseSubject: "hash-of-iss-sub", IdToken: idToken,
	}))
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	return resp.Msg.GetWalletId()
}

// openWallet logs the test holder in and opens the wallet with the PIN
// of the holder, as the PIN step of the wallet portal does.
func openWallet(t *testing.T, svc *service.Service) string {
	t.Helper()
	wallet := signIn(t, svc)
	if _, err := svc.UnlockWallet(context.Background(), connect.NewRequest(&backendv1.UnlockWalletRequest{
		WalletId: wallet, Pin: holderPIN,
	})); err != nil {
		t.Fatalf("UnlockWallet: %v", err)
	}
	return wallet
}

// lockOf returns the PIN state of a wallet.
func lockOf(t *testing.T, svc *service.Service, wallet string) backendv1.WalletLock {
	t.Helper()
	resp, err := svc.GetWalletLock(context.Background(), connect.NewRequest(&backendv1.GetWalletLockRequest{WalletId: wallet}))
	if err != nil {
		t.Fatalf("GetWalletLock: %v", err)
	}
	return resp.Msg.GetState()
}

// storeHolds reports whether any value of the store holds the text.
func storeHolds(t *testing.T, kv store.KeyValue, text string) bool {
	t.Helper()
	keys, err := kv.List(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		v, err := kv.Get(context.Background(), k)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(v), text) {
			return true
		}
	}
	return false
}

// TestRegisterLeavesThePinToTheHolder is the design of P6-I7c: the
// holder sets the PIN of the Mimoto wallet on first use in the VCA
// wallet, and the adapter never stores it. Register logs in and makes
// no wallet. The wallet asks for a new PIN, UnlockWallet makes the
// wallet with it and opens it, and the store holds no PIN. The next
// login keeps the wallet id and asks for the PIN again. A wrong PIN
// fails with invalid_argument and keeps the wallet shut.
func TestRegisterLeavesThePinToTheHolder(t *testing.T) {
	kv := store.Memory()
	svc, f := newServiceWith(t, holder, func(o *serviceOptions) { o.Store = kv })
	ctx := context.Background()
	wallet := signIn(t, svc)
	if wallet == "" || f.MimotoWalletPIN() != "" {
		t.Fatalf("Register made a wallet %q with the PIN %q", wallet, f.MimotoWalletPIN())
	}
	if got := lockOf(t, svc, wallet); got != backendv1.WalletLock_WALLET_LOCK_NEEDS_NEW_PIN {
		t.Fatalf("lock = %v, want a new PIN", got)
	}
	_, err := svc.ListCredentials(ctx, connect.NewRequest(&backendv1.ListCredentialsRequest{WalletId: wallet}))
	wantCode(t, err, connect.CodeFailedPrecondition)
	for _, bad := range []string{"", "12345", "12345a", "1234567"} {
		_, err = svc.UnlockWallet(ctx, connect.NewRequest(&backendv1.UnlockWalletRequest{WalletId: wallet, Pin: bad}))
		wantCode(t, err, connect.CodeInvalidArgument)
	}
	if _, err = svc.UnlockWallet(ctx, connect.NewRequest(&backendv1.UnlockWalletRequest{WalletId: wallet, Pin: holderPIN})); err != nil {
		t.Fatalf("UnlockWallet: %v", err)
	}
	if f.MimotoWalletPIN() != holderPIN || lockOf(t, svc, wallet) != backendv1.WalletLock_WALLET_LOCK_OPEN {
		t.Fatalf("the wallet PIN is %q", f.MimotoWalletPIN())
	}
	if storeHolds(t, kv, holderPIN) {
		t.Fatal("the adapter stored the PIN of the holder")
	}
	list, err := svc.ListCredentials(ctx, connect.NewRequest(&backendv1.ListCredentialsRequest{WalletId: wallet}))
	if err != nil || list.Msg.GetPage().GetTotalSize() != 2 {
		t.Fatalf("ListCredentials: %v %v", list, err)
	}

	again := signIn(t, svc)
	if again != wallet || f.MimotoLogins() != 2 || lockOf(t, svc, wallet) != backendv1.WalletLock_WALLET_LOCK_NEEDS_PIN {
		t.Fatalf("second login: wallet %q, logins %d", again, f.MimotoLogins())
	}
	_, err = svc.UnlockWallet(ctx, connect.NewRequest(&backendv1.UnlockWalletRequest{WalletId: wallet, Pin: "000000"}))
	wantCode(t, err, connect.CodeInvalidArgument)
	if !strings.Contains(err.Error(), "PIN") || lockOf(t, svc, wallet) != backendv1.WalletLock_WALLET_LOCK_NEEDS_PIN {
		t.Fatalf("a wrong PIN: %v", err)
	}
	if _, err = svc.UnlockWallet(ctx, connect.NewRequest(&backendv1.UnlockWalletRequest{WalletId: wallet, Pin: holderPIN})); err != nil {
		t.Fatalf("UnlockWallet again: %v", err)
	}
	if f.MimotoWalletsMade() != 1 {
		t.Fatalf("the adapter made %d wallets", f.MimotoWalletsMade())
	}
	_, err = svc.Register(ctx, connect.NewRequest(&backendv1.RegisterRequest{PairwiseSubject: "s"}))
	wantCode(t, err, connect.CodeFailedPrecondition)
	_, err = svc.Register(ctx, connect.NewRequest(&backendv1.RegisterRequest{IdToken: idToken}))
	wantCode(t, err, connect.CodeInvalidArgument)
	_, err = svc.Register(ctx, connect.NewRequest(&backendv1.RegisterRequest{PairwiseSubject: "s", IdToken: fake.RefusedToken}))
	wantCode(t, err, connect.CodePermissionDenied)
	_, err = svc.GetWalletLock(ctx, connect.NewRequest(&backendv1.GetWalletLockRequest{WalletId: "unknown"}))
	wantCode(t, err, connect.CodeNotFound)
	_, err = svc.UnlockWallet(ctx, connect.NewRequest(&backendv1.UnlockWalletRequest{WalletId: "unknown", Pin: holderPIN}))
	wantCode(t, err, connect.CodeNotFound)
}

// TestInjiWebClaimsWithThePinOfTheHolder is the whole claim path: the
// holder sets the PIN in the VCA wallet, then Inji Web opens its own
// Mimoto session, lists the same wallet, unlocks it with that PIN, and
// downloads a credential. The VCA wallet then lists it.
func TestInjiWebClaimsWithThePinOfTheHolder(t *testing.T) {
	svc, f := newService(t, holder)
	wallet := openWallet(t, svc)
	if err := f.ClaimInInjiWeb(idToken, "111111"); err == nil {
		t.Fatal("Inji Web claimed with a PIN the holder did not set")
	}
	if err := f.ClaimInInjiWeb(idToken, holderPIN); err != nil {
		t.Fatalf("the claim in Inji Web: %v", err)
	}
	list, err := svc.ListCredentials(context.Background(), connect.NewRequest(&backendv1.ListCredentialsRequest{
		WalletId: wallet, Page: &commonv1.Pagination{PageSize: 1, PageToken: "2"},
	}))
	if err != nil || list.Msg.GetPage().GetTotalSize() != 3 || list.Msg.GetCredentials()[0].GetIssuer() != "Inji Certify" {
		t.Fatalf("the VCA wallet after the claim = %v %v", list, err)
	}
}

// TestUnlockTheWalletMadeInInjiWeb opens a wallet that the holder made
// in Inji Web with its PIN. The adapter makes no second wallet.
func TestUnlockTheWalletMadeInInjiWeb(t *testing.T) {
	svc, f := newService(t, holder)
	f.SeedMimotoWallet("135790")
	wallet := signIn(t, svc)
	if got := lockOf(t, svc, wallet); got != backendv1.WalletLock_WALLET_LOCK_NEEDS_PIN {
		t.Fatalf("lock = %v", got)
	}
	if _, err := svc.UnlockWallet(context.Background(), connect.NewRequest(&backendv1.UnlockWalletRequest{WalletId: wallet, Pin: "135790"})); err != nil {
		t.Fatalf("UnlockWallet: %v", err)
	}
	if f.MimotoWalletsMade() != 0 || lockOf(t, svc, wallet) != backendv1.WalletLock_WALLET_LOCK_OPEN {
		t.Fatalf("made %d wallets", f.MimotoWalletsMade())
	}
}

// TestWalletLockedOutAfterWrongPins follows the passcode rule of
// Mimoto 0.21.0: the fourth wrong PIN warns of the last attempt, and the
// fifth locks the wallet (423 temporarily_locked).
func TestWalletLockedOutAfterWrongPins(t *testing.T) {
	svc, f := newService(t, holder)
	f.SeedMimotoWallet("135790")
	wallet := signIn(t, svc)
	ctx := context.Background()
	var err error
	for range 4 {
		_, err = svc.UnlockWallet(ctx, connect.NewRequest(&backendv1.UnlockWalletRequest{WalletId: wallet, Pin: "000000"}))
		wantCode(t, err, connect.CodeInvalidArgument)
	}
	if !strings.Contains(err.Error(), "one more wrong PIN") {
		t.Fatalf("the fourth answer = %v", err)
	}
	_, err = svc.UnlockWallet(ctx, connect.NewRequest(&backendv1.UnlockWalletRequest{WalletId: wallet, Pin: "000000"}))
	wantCode(t, err, connect.CodeFailedPrecondition)
	if got := lockOf(t, svc, wallet); got != backendv1.WalletLock_WALLET_LOCK_LOCKED_OUT {
		t.Fatalf("lock = %v", got)
	}
}

// TestLegacyRecordDropsItsPin: an earlier release made the wallet with
// a random PIN and stored it. The next login keeps the wallet id,
// removes the PIN from the store, and asks the holder for the PIN.
func TestLegacyRecordDropsItsPin(t *testing.T) {
	kv := store.Memory()
	svc, f := newServiceWith(t, holder, func(o *serviceOptions) { o.Store = kv })
	f.SeedMimotoWallet("902114")
	legacy := `{"wallet_id":"4f1c9a7e-2b8d-4d3a-9e61-7a2c5b0d8e13","pin":"902114","cookie":"SESSION=old"}`
	for _, key := range service.LegacyHolderKeys("hash-of-iss-sub", "4f1c9a7e-2b8d-4d3a-9e61-7a2c5b0d8e13") {
		if err := kv.Put(context.Background(), key, []byte(legacy)); err != nil {
			t.Fatal(err)
		}
	}
	wallet := signIn(t, svc)
	if wallet != "4f1c9a7e-2b8d-4d3a-9e61-7a2c5b0d8e13" {
		t.Fatalf("the wallet id changed to %q", wallet)
	}
	if storeHolds(t, kv, "902114") {
		t.Fatal("the store still holds the PIN of the earlier release")
	}
	if got := lockOf(t, svc, wallet); got != backendv1.WalletLock_WALLET_LOCK_NEEDS_PIN {
		t.Fatalf("lock = %v", got)
	}
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
		!slices.Contains(msg.GetFeatures(), backendv1.Feature_FEATURE_WALLET_PIN) ||
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
	if slices.Contains(caps.Msg.GetRoles(), commonv1.Role_ROLE_HOLDER) || slices.Contains(caps.Msg.GetFeatures(), backendv1.Feature_FEATURE_WALLET_DOCUMENT) ||
		slices.Contains(caps.Msg.GetFeatures(), backendv1.Feature_FEATURE_WALLET_PIN) {
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
	_, err = svc.GetWalletLock(ctx, connect.NewRequest(&backendv1.GetWalletLockRequest{WalletId: "w"}))
	wantCode(t, err, connect.CodeUnimplemented)
	_, err = svc.UnlockWallet(ctx, connect.NewRequest(&backendv1.UnlockWalletRequest{WalletId: "w", Pin: "123456"}))
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

// TestLostWalletKeyAsksForThePin: a session that lost the wallet key
// answers wallet_locked. The list then asks for the PIN, and the lock
// state says so.
func TestLostWalletKeyAsksForThePin(t *testing.T) {
	svc, f := newService(t, holder)
	wallet := openWallet(t, svc)
	f.LockMimotoSessions()
	_, err := svc.ListCredentials(context.Background(), connect.NewRequest(&backendv1.ListCredentialsRequest{WalletId: wallet}))
	wantCode(t, err, connect.CodeFailedPrecondition)
	if got := lockOf(t, svc, wallet); got != backendv1.WalletLock_WALLET_LOCK_NEEDS_PIN {
		t.Fatalf("lock = %v", got)
	}
}
