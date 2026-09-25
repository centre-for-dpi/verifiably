// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"strings"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
)

func TestListKeysAndDids(t *testing.T) {
	svc, f := newService(t, all)
	ctx := context.Background()
	wallet := registerWallet(t, svc)
	keys, err := svc.ListKeys(ctx, connect.NewRequest(&backendv1.ListKeysRequest{WalletId: wallet}))
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys.Msg.GetKeys()) != 2 || keys.Msg.GetKeys()[0].GetType() != "Ed25519" || keys.Msg.GetKeys()[1].GetName() != "Travel" {
		t.Fatalf("keys = %v", keys.Msg.GetKeys())
	}
	dids, err := svc.ListDids(ctx, connect.NewRequest(&backendv1.ListDidsRequest{WalletId: wallet}))
	if err != nil {
		t.Fatalf("ListDids: %v", err)
	}
	got := dids.Msg.GetDids()
	if len(got) != 2 || !got[0].GetDefault() || got[1].GetDefault() || got[0].GetAlias() != "Onboarding" || got[0].GetCreatedAt() == nil {
		t.Fatalf("dids = %v", got)
	}
	created, err := svc.CreateKey(ctx, connect.NewRequest(&backendv1.CreateKeyRequest{WalletId: wallet, KeyType: "secp256k1"}))
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	var body map[string]any
	if ierr := f.RequestJSON("/wallet-api/wallet/"+wallet+"/keys/generate", &body); ierr != nil {
		t.Fatal(ierr)
	}
	if body["backend"] != "jwk" || body["keyType"] != "secp256k1" || created.Msg.GetKey().GetId() == "" {
		t.Fatalf("generate body = %v, key = %v", body, created.Msg.GetKey())
	}
	did, err := svc.CreateDid(ctx, connect.NewRequest(&backendv1.CreateDidRequest{WalletId: wallet, Method: "did:jwk", KeyId: "k1", Alias: "Work"}))
	if err != nil {
		t.Fatalf("CreateDid: %v", err)
	}
	if !strings.HasPrefix(did.Msg.GetDid().GetDid(), "did:") || !strings.HasSuffix(f.LastPath(), "/dids/create/jwk") {
		t.Fatalf("did = %v, path %s", did.Msg.GetDid(), f.LastPath())
	}
	if q := f.LastQuery(); q.Get("keyId") != "k1" || q.Get("alias") != "Work" {
		t.Fatalf("query = %v", q)
	}
	for name, req := range map[string]*backendv1.CreateDidRequest{
		"unknown method":    {WalletId: wallet, Method: "did:web"},
		"cheqd with no key": {WalletId: wallet, Method: "did:ion"},
	} {
		if _, ierr := svc.CreateDid(ctx, connect.NewRequest(req)); connect.CodeOf(ierr) != connect.CodeInvalidArgument {
			t.Errorf("%s: %v", name, ierr)
		}
	}
	if _, ierr := svc.CreateKey(ctx, connect.NewRequest(&backendv1.CreateKeyRequest{WalletId: wallet, KeyType: "P-521"})); connect.CodeOf(ierr) != connect.CodeInvalidArgument {
		t.Errorf("an unknown key type: %v", ierr)
	}
	caps, err := svc.GetCapabilities(ctx, connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(caps.Msg.GetWalletKeyTypes(), ",") != "Ed25519,secp256r1,secp256k1,RSA" ||
		strings.Join(caps.Msg.GetWalletDidMethods(), ",") != "did:key,did:jwk,did:cheqd" {
		t.Errorf("wallet lists = %v %v", caps.Msg.GetWalletKeyTypes(), caps.Msg.GetWalletDidMethods())
	}
}

func TestSetDefaultDid(t *testing.T) {
	svc, f := newService(t, all)
	ctx := context.Background()
	wallet := registerWallet(t, svc)
	did := "did:jwk:eyJrdHkiOiJFQyJ9"
	if _, err := svc.SetDefaultDid(ctx, connect.NewRequest(&backendv1.SetDefaultDidRequest{WalletId: wallet, Did: did})); err != nil {
		t.Fatalf("SetDefaultDid: %v", err)
	}
	if f.LastPath() != "/wallet-api/wallet/"+wallet+"/dids/default" || f.LastQuery().Get("did") != did {
		t.Fatalf("path %s query %v", f.LastPath(), f.LastQuery())
	}
	if _, err := svc.SetDefaultDid(ctx, connect.NewRequest(&backendv1.SetDefaultDidRequest{WalletId: wallet})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("no DID: %v", err)
	}
	f.SetStatus("/wallet-api/wallet/"+wallet+"/dids/default", 400)
	if _, err := svc.SetDefaultDid(ctx, connect.NewRequest(&backendv1.SetDefaultDidRequest{WalletId: wallet, Did: did})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("a refused DID: %v", err)
	}
}

func TestRejectOffer(t *testing.T) {
	svc, f := newService(t, all)
	ctx := context.Background()
	wallet := registerWallet(t, svc)
	offer := "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fwalt-issuer.example.org%2Fo%2F1"
	if _, err := svc.RejectOffer(ctx, connect.NewRequest(&backendv1.RejectOfferRequest{WalletId: wallet, OfferUri: offer, Reason: "Not mine"})); err != nil {
		t.Fatalf("RejectOffer: %v", err)
	}
	claims := f.Bodies("/wallet-api/wallet/" + wallet + "/exchange/useOfferRequest")
	if len(claims) != 1 || string(claims[0]) != offer {
		t.Fatalf("claims = %q", claims)
	}
	var note map[string]string
	if err := f.RequestJSON("/wallet-api/wallet/"+wallet+"/credentials/urn:uuid:2f6b8c4e-1d3a-4f5b-9c7e-8a1b2c3d4e5f/reject", &note); err != nil {
		t.Fatalf("the pending credential was not rejected: %v", err)
	}
	if note["note"] != "Not mine" {
		t.Errorf("note = %v", note)
	}
	// A declined offer never lands among the held credentials.
	held, err := svc.ListCredentials(ctx, connect.NewRequest(&backendv1.ListCredentialsRequest{WalletId: wallet}))
	if err != nil || len(held.Msg.GetCredentials()) != 1 {
		t.Fatalf("held = %v %v", held, err)
	}
	if _, err := svc.RejectOffer(ctx, connect.NewRequest(&backendv1.RejectOfferRequest{WalletId: wallet})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("no offer: %v", err)
	}
	f.SetStatus("/wallet-api/wallet/"+wallet+"/credentials/urn:uuid:2f6b8c4e-1d3a-4f5b-9c7e-8a1b2c3d4e5f/reject", 400)
	if _, err := svc.RejectOffer(ctx, connect.NewRequest(&backendv1.RejectOfferRequest{WalletId: wallet, OfferUri: offer})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("a refused reject: %v", err)
	}
}

func TestListEvents(t *testing.T) {
	svc, f := newService(t, all)
	ctx := context.Background()
	wallet := registerWallet(t, svc)
	resp, err := svc.ListEvents(ctx, connect.NewRequest(&backendv1.ListEventsRequest{WalletId: wallet}))
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	ev := resp.Msg.GetEvents()
	if len(ev) != 2 || ev[0].GetAction() != "Receive" || ev[0].GetCounterpart() != "Ministry of Transport" || ev[0].GetAt() == nil || ev[1].GetCounterpart() != "" {
		t.Fatalf("events = %v", ev)
	}
	if q := f.LastQuery(); q.Get("sortOrder") != "desc" || q.Get("sortBy") != "timestamp" {
		t.Errorf("query = %v", q)
	}
}

// TestWalletFeaturesListedWithTheWallet lists the wallet features only
// when the wallet URL is set.
func TestWalletFeaturesListedWithTheWallet(t *testing.T) {
	for _, row := range []struct {
		r    roles
		want bool
	}{{roles{wallet: true}, true}, {roles{issuer: true}, false}} {
		svc, _ := newService(t, row.r)
		resp, err := svc.GetCapabilities(context.Background(), connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		listed := map[backendv1.Feature]bool{}
		for _, f := range resp.Msg.GetFeatures() {
			listed[f] = true
		}
		for _, f := range []backendv1.Feature{backendv1.Feature_FEATURE_WALLET_KEYS, backendv1.Feature_FEATURE_WALLET_DIDS,
			backendv1.Feature_FEATURE_WALLET_EVENTS, backendv1.Feature_FEATURE_WALLET_REJECT_OFFER} {
			if listed[f] != row.want {
				t.Errorf("%+v: %v listed = %v", row.r, f, listed[f])
			}
		}
	}
}

// TestAcceptOfferPassesTheCode sends the transaction code, and refuses a
// sign in grant for an offer without a pre-authorized code: the wallet
// API of 0.18.2 redeems that grant only.
func TestAcceptOfferPassesTheCode(t *testing.T) {
	svc, f := newService(t, all)
	ctx := context.Background()
	wallet := registerWallet(t, svc)
	if _, err := svc.AcceptOffer(ctx, connect.NewRequest(&backendv1.AcceptOfferRequest{
		WalletId: wallet, OfferUri: "openid-credential-offer://?credential_offer=%7B%7D", Pin: "1234", AuthorizationGrant: "issuer-token",
	})); err != nil {
		t.Fatalf("AcceptOffer: %v", err)
	}
	if f.LastClaimQuery().Get("pinOrTxCode") != "1234" {
		t.Errorf("claim query = %v", f.LastClaimQuery())
	}
	f.SetResolved("doc/resolve-offer-authcode.json")
	_, err := svc.AcceptOffer(ctx, connect.NewRequest(&backendv1.AcceptOfferRequest{
		WalletId: wallet, OfferUri: "openid-credential-offer://?credential_offer=%7B%7D", AuthorizationGrant: "issuer-token",
	}))
	wantCode(t, err, connect.CodeFailedPrecondition)
}
