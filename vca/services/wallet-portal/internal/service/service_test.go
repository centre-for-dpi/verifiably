// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/sdjwt"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	walletportalv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/cards"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/ports"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/present"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/session"
)

var clock = time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)

func now() time.Time { return clock }

func citizen() session.Citizen {
	return session.Citizen{Subject: "https://idp|abc", WalletID: "wallet-1", SessionID: "sid-1"}
}

func ctx() context.Context { return session.With(context.Background(), citizen()) }

// fakeHolder answers the holder backend RPCs.
type fakeHolder struct {
	backendv1connect.HolderBackendServiceClient
	credential  *backendv1.WalletCredential
	acceptErr   error
	listErr     error
	deleteErr   error
	presentErr  error
	accepted    bool
	seenOffer   string
	seenPin     string
	seenGrant   string
	seenPresent *backendv1.PresentRequest
	deletedID   string
}

func (f *fakeHolder) AcceptOffer(_ context.Context, req *connect.Request[backendv1.AcceptOfferRequest],
) (*connect.Response[backendv1.AcceptOfferResponse], error) {
	f.seenOffer, f.seenPin, f.seenGrant = req.Msg.GetOfferUri(), req.Msg.GetPin(), req.Msg.GetAuthorizationGrant()
	if f.acceptErr != nil {
		return nil, f.acceptErr
	}
	return connect.NewResponse(&backendv1.AcceptOfferResponse{Credential: f.credential}), nil
}

func (f *fakeHolder) ListCredentials(_ context.Context, _ *connect.Request[backendv1.ListCredentialsRequest],
) (*connect.Response[backendv1.ListCredentialsResponse], error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return connect.NewResponse(&backendv1.ListCredentialsResponse{
		Credentials: []*backendv1.WalletCredential{f.credential},
	}), nil
}

func (f *fakeHolder) DeleteCredential(_ context.Context, req *connect.Request[backendv1.DeleteCredentialRequest],
) (*connect.Response[backendv1.DeleteCredentialResponse], error) {
	f.deletedID = req.Msg.GetCredentialId()
	if f.deleteErr != nil {
		return nil, f.deleteErr
	}
	return connect.NewResponse(&backendv1.DeleteCredentialResponse{}), nil
}

func (f *fakeHolder) Present(_ context.Context, req *connect.Request[backendv1.PresentRequest],
) (*connect.Response[backendv1.PresentResponse], error) {
	f.seenPresent = req.Msg
	if f.presentErr != nil {
		return nil, f.presentErr
	}
	return connect.NewResponse(&backendv1.PresentResponse{
		Accepted: f.accepted, RedirectUri: "https://verifier.example/done",
	}), nil
}

// credential returns one SD-JWT credential of the fake wallet.
func credential(t *testing.T) *backendv1.WalletCredential {
	t.Helper()
	token, _ := sdjwtFixture(t)
	return &backendv1.WalletCredential{
		Id: "c1", Type: "DriverLicence", Issuer: "did:web:issuer.example",
		Credential: &commonv1.Credential{
			Format: commonv1.Format_FORMAT_DC_SD_JWT, Payload: []byte(token),
		},
	}
}

func offerings() []*walletportalv1.Offering {
	return []*walletportalv1.Offering{
		{CredentialIssuer: "https://b.example", IssuerName: "Agency B",
			Schema: &schemav1.PublicSchema{Id: "pp", Type: "Passport"}},
		{CredentialIssuer: "https://a.example", IssuerName: "Agency A",
			Trust:  trustv1.TrustLookupResponse_OUTCOME_TRUSTED,
			Schema: &schemav1.PublicSchema{Id: "dl", Type: "DriverLicence"}},
	}
}

// token returns the SD-JWT text a citizen pastes.
func token(t *testing.T) string {
	t.Helper()
	text, _ := sdjwtFixture(t)
	return text
}

func trust(_ context.Context, _, _ string) (cards.Trust, error) {
	return cards.Trust{Outcome: trustv1.TrustLookupResponse_OUTCOME_TRUSTED, Name: "Agency A"}, nil
}

// build makes a service with the options a test changes.
func build(t *testing.T, change func(*service.Options)) *service.Service {
	t.Helper()
	ids := 0
	opts := service.Options{
		Catalogue: ports.CatalogueFunc(func(context.Context) ([]*walletportalv1.Offering, error) {
			return offerings(), nil
		}),
		Eligible: func(_ context.Context, ref string, o *walletportalv1.Offering) (bool, error) {
			if ref == "" {
				t.Fatal("want a salted subject reference")
			}
			return o.GetSchema().GetId() == "dl", nil
		},
		Salt:         "salt",
		Cards:        cards.New(cards.Options{Trust: trust, Now: now}),
		Trust:        trust,
		Store:        store.Memory(),
		RequestHosts: []string{"verifier.example"},
		PendingTTL:   15 * time.Minute,
		Now:          now,
		NewID: func() string {
			ids++
			return "id-" + string(rune('0'+ids))
		},
	}
	if change != nil {
		change(&opts)
	}
	svc, err := service.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func withHolder(h *fakeHolder) func(*service.Options) {
	return func(o *service.Options) { o.Holder = h }
}

func TestNewRejectsMissingParts(t *testing.T) {
	if _, err := service.New(service.Options{Store: store.Memory()}); err == nil {
		t.Fatal("want a card builder error")
	}
	if _, err := service.New(service.Options{Cards: cards.New(cards.Options{})}); err == nil {
		t.Fatal("want a store error")
	}
	svc, err := service.New(service.Options{Cards: cards.New(cards.Options{}), Store: store.Memory()})
	if err != nil {
		t.Fatal(err)
	}
	if !svc.Ready() || !svc.BrowserStorage() {
		t.Fatal("want a ready service in browser storage mode")
	}
}

func TestListDiscoverable(t *testing.T) {
	svc := build(t, nil)
	resp, err := svc.ListDiscoverable(ctx(), connect.NewRequest(&walletportalv1.ListDiscoverableRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	got := resp.Msg.GetOfferings()
	if len(got) != 2 || got[0].GetSchema().GetType() != "DriverLicence" {
		t.Fatalf("offerings = %+v", got)
	}
	if resp.Msg.GetPage().GetTotalSize() != 2 {
		t.Fatalf("total = %d", resp.Msg.GetPage().GetTotalSize())
	}
	first, err := svc.ListDiscoverable(ctx(), connect.NewRequest(&walletportalv1.ListDiscoverableRequest{
		Page: &commonv1.Pagination{PageSize: 1},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Msg.GetOfferings()) != 1 || first.Msg.GetPage().GetNextPageToken() != "1" {
		t.Fatalf("page = %+v", first.Msg)
	}
	second, err := svc.ListDiscoverable(ctx(), connect.NewRequest(&walletportalv1.ListDiscoverableRequest{
		Page: &commonv1.Pagination{PageSize: 1, PageToken: first.Msg.GetPage().GetNextPageToken()},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Msg.GetOfferings()) != 1 || second.Msg.GetPage().GetNextPageToken() != "" {
		t.Fatalf("second page = %+v", second.Msg)
	}
	odd, err := svc.ListDiscoverable(ctx(), connect.NewRequest(&walletportalv1.ListDiscoverableRequest{
		Page: &commonv1.Pagination{PageSize: 900, PageToken: "nope"},
	}))
	if err != nil || len(odd.Msg.GetOfferings()) != 2 {
		t.Fatalf("odd page = %+v %v", odd.Msg, err)
	}
}

func TestListDiscoverableNeedsSessionAndCatalogue(t *testing.T) {
	svc := build(t, nil)
	_, err := svc.ListDiscoverable(context.Background(),
		connect.NewRequest(&walletportalv1.ListDiscoverableRequest{}))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("no session: %v", err)
	}
	none := build(t, func(o *service.Options) { o.Catalogue = nil })
	if _, err := none.ListDiscoverable(ctx(),
		connect.NewRequest(&walletportalv1.ListDiscoverableRequest{})); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("no catalogue: %v", err)
	}
	down := build(t, func(o *service.Options) {
		o.Catalogue = ports.CatalogueFunc(func(context.Context) ([]*walletportalv1.Offering, error) {
			return nil, errors.New("down")
		})
	})
	if _, err := down.ListDiscoverable(ctx(),
		connect.NewRequest(&walletportalv1.ListDiscoverableRequest{})); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("catalogue down: %v", err)
	}
}

func TestListClaimable(t *testing.T) {
	svc := build(t, nil)
	resp, err := svc.ListClaimable(ctx(), connect.NewRequest(&walletportalv1.ListClaimableRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	items := resp.Msg.GetItems()
	if len(items) != 2 {
		t.Fatalf("items = %d", len(items))
	}
	answers := map[string]bool{}
	for _, item := range items {
		answers[item.GetOffering().GetSchema().GetId()] = item.GetEligible()
	}
	if !answers["dl"] || answers["pp"] {
		t.Fatalf("answers = %v", answers)
	}
	_, err = svc.ListClaimable(context.Background(), connect.NewRequest(&walletportalv1.ListClaimableRequest{}))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("no session: %v", err)
	}
	down := build(t, func(o *service.Options) {
		o.Eligible = func(context.Context, string, *walletportalv1.Offering) (bool, error) {
			return false, errors.New("down")
		}
	})
	if _, serr := down.ListClaimable(ctx(),
		connect.NewRequest(&walletportalv1.ListClaimableRequest{})); connect.CodeOf(serr) != connect.CodeUnavailable {
		t.Fatalf("hook down: %v", serr)
	}
	noCatalogue := build(t, func(o *service.Options) { o.Catalogue = nil })
	if _, serr := noCatalogue.ListClaimable(ctx(),
		connect.NewRequest(&walletportalv1.ListClaimableRequest{})); serr == nil {
		t.Fatal("want a catalogue error")
	}
	deny := build(t, func(o *service.Options) { o.Eligible = nil })
	answer, err := deny.ListClaimable(ctx(), connect.NewRequest(&walletportalv1.ListClaimableRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range answer.Msg.GetItems() {
		if item.GetEligible() {
			t.Fatal("want no by default")
		}
	}
}

func TestClaimWithHolder(t *testing.T) {
	holder := &fakeHolder{credential: credential(t)}
	svc := build(t, withHolder(holder))
	resp, err := svc.Claim(ctx(), connect.NewRequest(&walletportalv1.ClaimRequest{
		CredentialIssuer: "https://a.example", SchemaId: "dl",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Msg.GetCard().GetType() != "DriverLicence" {
		t.Fatalf("card = %+v", resp.Msg.GetCard())
	}
	if !strings.Contains(holder.seenOffer, "authorization_code") {
		t.Fatalf("offer = %q", holder.seenOffer)
	}
	if !strings.HasPrefix(holder.seenOffer, "openid-credential-offer://") {
		t.Fatalf("offer = %q", holder.seenOffer)
	}
}

func TestClaimInBrowserMode(t *testing.T) {
	svc := build(t, nil)
	resp, err := svc.Claim(ctx(), connect.NewRequest(&walletportalv1.ClaimRequest{
		CredentialIssuer: "https://a.example", SchemaId: "dl",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Msg.GetOfferId() == "" {
		t.Fatal("want a pending offer id")
	}
	if _, err := svc.Accept(ctx(), connect.NewRequest(&walletportalv1.AcceptRequest{
		OfferId: resp.Msg.GetOfferId(),
	})); connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("accept in browser mode: %v", err)
	}
}

func TestClaimRejects(t *testing.T) {
	svc := build(t, nil)
	if _, err := svc.Claim(context.Background(), connect.NewRequest(&walletportalv1.ClaimRequest{})); err == nil {
		t.Fatal("want a session error")
	}
	if _, err := svc.Claim(ctx(), connect.NewRequest(&walletportalv1.ClaimRequest{
		CredentialIssuer: "https://a.example",
	})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("no schema: %v", err)
	}
	holder := &fakeHolder{acceptErr: errors.New("down")}
	down := build(t, withHolder(holder))
	if _, err := down.Claim(ctx(), connect.NewRequest(&walletportalv1.ClaimRequest{
		CredentialIssuer: "https://a.example", SchemaId: "dl",
	})); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("holder down: %v", err)
	}
}

const offerText = `openid-credential-offer://?credential_offer=` +
	`%7B%22credential_issuer%22%3A%22https%3A%2F%2Fa.example%22%2C` +
	`%22credential_configuration_ids%22%3A%5B%22dl%22%5D%2C%22grants%22%3A%7B` +
	`%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22tx_code%22%3A%7B%7D%7D%7D%7D`

func TestScanOfferThenAccept(t *testing.T) {
	holder := &fakeHolder{credential: credential(t)}
	svc := build(t, withHolder(holder))
	scan, err := svc.Scan(ctx(), connect.NewRequest(&walletportalv1.ScanRequest{Text: offerText}))
	if err != nil {
		t.Fatal(err)
	}
	found := scan.Msg.GetDetected()
	if found.GetKind() != walletportalv1.Detected_KIND_CREDENTIAL_OFFER {
		t.Fatalf("kind = %v", found.GetKind())
	}
	if !found.GetOffer().GetNeedsPin() || found.GetOffer().GetIssuerName() != "Agency A" {
		t.Fatalf("offer = %+v", found.GetOffer())
	}
	if found.GetOffer().GetTrust() != trustv1.TrustLookupResponse_OUTCOME_TRUSTED {
		t.Fatalf("trust = %v", found.GetOffer().GetTrust())
	}
	accept, err := svc.Accept(ctx(), connect.NewRequest(&walletportalv1.AcceptRequest{
		OfferId: found.GetOfferId(), Pin: "1234",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if accept.Msg.GetCard().GetId() != "c1" || holder.seenPin != "1234" {
		t.Fatalf("accept = %+v pin %q", accept.Msg.GetCard(), holder.seenPin)
	}
	if _, err := svc.Accept(ctx(), connect.NewRequest(&walletportalv1.AcceptRequest{
		OfferId: found.GetOfferId(),
	})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("accept twice: %v", err)
	}
}

func TestScanAndPasteKinds(t *testing.T) {
	svc := build(t, nil)
	request, err := svc.Scan(ctx(), connect.NewRequest(&walletportalv1.ScanRequest{
		Text: "openid4vp://?client_id=v&request_uri=https://verifier.example/r/1",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if request.Msg.GetDetected().GetKind() != walletportalv1.Detected_KIND_PRESENTATION_REQUEST ||
		request.Msg.GetDetected().GetPresentationId() == "" {
		t.Fatalf("request = %+v", request.Msg.GetDetected())
	}
	held, err := svc.Paste(ctx(), connect.NewRequest(&walletportalv1.PasteRequest{Text: token(t)}))
	if err != nil {
		t.Fatal(err)
	}
	if held.Msg.GetDetected().GetKind() != walletportalv1.Detected_KIND_CREDENTIAL {
		t.Fatalf("credential = %+v", held.Msg.GetDetected())
	}
	unknown, err := svc.Paste(ctx(), connect.NewRequest(&walletportalv1.PasteRequest{Text: "hello there"}))
	if err != nil {
		t.Fatal(err)
	}
	if unknown.Msg.GetDetected().GetKind() != walletportalv1.Detected_KIND_UNKNOWN {
		t.Fatalf("unknown = %+v", unknown.Msg.GetDetected())
	}
	if unknown.Msg.GetDetected().GetError().GetCode() != "VCA-421" {
		t.Fatalf("error = %+v", unknown.Msg.GetDetected().GetError())
	}
	if _, err := svc.Paste(ctx(), connect.NewRequest(&walletportalv1.PasteRequest{
		Text: "",
	})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("empty: %v", err)
	}
	if _, err := svc.Scan(context.Background(),
		connect.NewRequest(&walletportalv1.ScanRequest{Text: offerText})); err == nil {
		t.Fatal("want a session error")
	}
	long := build(t, func(o *service.Options) { o.MaxPasteBytes = 4 })
	if _, err := long.Paste(ctx(), connect.NewRequest(&walletportalv1.PasteRequest{
		Text: "a longer text",
	})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("long: %v", err)
	}
}

func TestRejectAndDelete(t *testing.T) {
	holder := &fakeHolder{credential: credential(t)}
	svc := build(t, withHolder(holder))
	scan, err := svc.Scan(ctx(), connect.NewRequest(&walletportalv1.ScanRequest{Text: offerText}))
	if err != nil {
		t.Fatal(err)
	}
	id := scan.Msg.GetDetected().GetOfferId()
	if _, err := svc.Reject(ctx(), connect.NewRequest(&walletportalv1.RejectRequest{OfferId: id})); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Accept(ctx(), connect.NewRequest(&walletportalv1.AcceptRequest{
		OfferId: id,
	})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("after reject: %v", err)
	}
	if _, err := svc.Reject(ctx(), connect.NewRequest(&walletportalv1.RejectRequest{
		OfferId: "bad/id",
	})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("bad id: %v", err)
	}
	if _, err := svc.Reject(context.Background(),
		connect.NewRequest(&walletportalv1.RejectRequest{OfferId: id})); err == nil {
		t.Fatal("want a session error")
	}
	if _, err := svc.Delete(ctx(), connect.NewRequest(&walletportalv1.DeleteRequest{Id: "c1"})); err != nil {
		t.Fatal(err)
	}
	if holder.deletedID != "c1" {
		t.Fatalf("deleted = %q", holder.deletedID)
	}
	if _, err := svc.Delete(ctx(), connect.NewRequest(&walletportalv1.DeleteRequest{
		Id: "",
	})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("no id: %v", err)
	}
	if _, err := svc.Delete(context.Background(),
		connect.NewRequest(&walletportalv1.DeleteRequest{Id: "c1"})); err == nil {
		t.Fatal("want a session error")
	}
	down := build(t, withHolder(&fakeHolder{deleteErr: errors.New("down")}))
	if _, err := down.Delete(ctx(), connect.NewRequest(&walletportalv1.DeleteRequest{
		Id: "c1",
	})); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("holder down: %v", err)
	}
}

func TestDeleteInBrowserMode(t *testing.T) {
	svc := build(t, nil)
	held, err := svc.Paste(ctx(), connect.NewRequest(&walletportalv1.PasteRequest{Text: token(t)}))
	if err != nil {
		t.Fatal(err)
	}
	id := held.Msg.GetDetected().GetOfferId()
	if _, serr := svc.Delete(ctx(), connect.NewRequest(&walletportalv1.DeleteRequest{Id: id})); serr != nil {
		t.Fatal(serr)
	}
	list, err := svc.ListMine(ctx(), connect.NewRequest(&walletportalv1.ListMineRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Msg.GetCards()) != 0 {
		t.Fatalf("cards = %+v", list.Msg.GetCards())
	}
	if _, err := svc.Delete(ctx(), connect.NewRequest(&walletportalv1.DeleteRequest{
		Id: "bad/id",
	})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("bad id: %v", err)
	}
}

func TestListMine(t *testing.T) {
	holder := &fakeHolder{credential: credential(t)}
	svc := build(t, withHolder(holder))
	resp, err := svc.ListMine(ctx(), connect.NewRequest(&walletportalv1.ListMineRequest{
		Page: &commonv1.Pagination{PageSize: 5},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Msg.GetCards()) != 1 || resp.Msg.GetCards()[0].GetIssuerName() != "Agency A" {
		t.Fatalf("cards = %+v", resp.Msg.GetCards())
	}
	if _, serr := svc.ListMine(context.Background(),
		connect.NewRequest(&walletportalv1.ListMineRequest{})); serr == nil {
		t.Fatal("want a session error")
	}
	down := build(t, withHolder(&fakeHolder{listErr: errors.New("down")}))
	if _, serr := down.ListMine(ctx(),
		connect.NewRequest(&walletportalv1.ListMineRequest{})); connect.CodeOf(serr) != connect.CodeUnavailable {
		t.Fatalf("holder down: %v", serr)
	}
	big, err := svc.ListMine(ctx(), connect.NewRequest(&walletportalv1.ListMineRequest{
		Page: &commonv1.Pagination{PageSize: 900},
	}))
	if err != nil || len(big.Msg.GetCards()) != 1 {
		t.Fatalf("big page = %+v %v", big.Msg, err)
	}
}

// sdjwtFixture returns one SD-JWT with two disclosures and the encoded
// disclosure of each claim name.
func sdjwtFixture(t *testing.T) (string, map[string]string) {
	t.Helper()
	payload := map[string]any{
		"vct": "DriverLicence", "iss": "did:web:issuer.example",
		"given_name": "Ada", "birth_date": "1990-01-01",
	}
	concealed, discs, err := sdjwt.Conceal(payload, []string{"given_name", "birth_date"})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(concealed)
	if err != nil {
		t.Fatal(err)
	}
	token := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"dc+sd-jwt"}`)) +
		"." + base64.RawURLEncoding.EncodeToString(body) + ".sig"
	encoded := map[string]string{}
	for _, d := range discs {
		token += "~" + d.Encoded
		encoded[d.Name] = d.Encoded
	}
	return token + "~", encoded
}

// requestObject returns one OID4VP request object.
func requestObject() []byte {
	doc := map[string]any{
		"client_id":    "https://verifier.example",
		"nonce":        "n-1",
		"response_uri": "https://verifier.example/direct_post",
		"state":        "s-1",
		"dcql_query": map[string]any{"credentials": []any{map[string]any{
			"id": "licence", "format": "dc+sd-jwt",
			"meta":   map[string]any{"vct_values": []string{"DriverLicence"}},
			"claims": []any{map[string]any{"path": []string{"given_name"}}},
		}}},
	}
	raw, verr := json.Marshal(doc)
	if verr != nil {
		panic(verr)
	}
	return raw
}

func fetchRequest(context.Context, string) ([]byte, error) { return requestObject(), nil }

func TestPresentStartAndConfirmWithHolder(t *testing.T) {
	holder := &fakeHolder{credential: credential(t), accepted: true}
	svc := build(t, func(o *service.Options) {
		o.Holder = holder
		o.Fetch = fetchRequest
	})
	scan, err := svc.Scan(ctx(), connect.NewRequest(&walletportalv1.ScanRequest{
		Text: "openid4vp://?client_id=v&request_uri=https://verifier.example/r/1",
	}))
	if err != nil {
		t.Fatal(err)
	}
	id := scan.Msg.GetDetected().GetPresentationId()
	start, err := svc.PresentStart(ctx(), connect.NewRequest(&walletportalv1.PresentStartRequest{
		PresentationId: id,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if start.Msg.GetVerifier() != "https://verifier.example" || start.Msg.GetVerifierName() != "Agency A" {
		t.Fatalf("start = %+v", start.Msg)
	}
	requested := start.Msg.GetRequested()
	if len(requested) != 1 || len(requested[0].GetClaims()) != 1 {
		t.Fatalf("requested = %+v", requested)
	}
	if requested[0].GetClaims()[0].GetValue() != "Ada" {
		t.Fatalf("claim = %+v", requested[0].GetClaims()[0])
	}
	confirm, err := svc.PresentConfirm(ctx(), connect.NewRequest(&walletportalv1.PresentConfirmRequest{
		PresentationId: id,
		SelectedCards:  map[string]string{"licence": "c1"},
		Disclosed: map[string]*walletportalv1.PresentConfirmRequest_ClaimPaths{
			"licence": {Paths: []string{"given_name"}},
		},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !confirm.Msg.GetAccepted() || confirm.Msg.GetRedirectUri() == "" {
		t.Fatalf("confirm = %+v", confirm.Msg)
	}
	if holder.seenPresent.GetRequestUri() != "https://verifier.example/r/1" {
		t.Fatalf("request uri = %q", holder.seenPresent.GetRequestUri())
	}
	if len(holder.seenPresent.GetCredentialIds()) != 1 || holder.seenPresent.GetCredentialIds()[0] != "c1" {
		t.Fatalf("credential ids = %v", holder.seenPresent.GetCredentialIds())
	}
	if len(holder.seenPresent.GetDisclosedClaims()) != 1 {
		t.Fatalf("disclosed = %v", holder.seenPresent.GetDisclosedClaims())
	}
}

func TestPresentConfirmRefused(t *testing.T) {
	holder := &fakeHolder{credential: credential(t)}
	svc := build(t, func(o *service.Options) {
		o.Holder = holder
		o.Fetch = fetchRequest
	})
	confirm, err := svc.PresentConfirm(ctx(), connect.NewRequest(&walletportalv1.PresentConfirmRequest{
		PresentationId: "openid4vp://?request_uri=https://verifier.example/r/1",
		SelectedCards:  map[string]string{"licence": "c1"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if confirm.Msg.GetAccepted() || !strings.Contains(confirm.Msg.GetMessage(), "did not accept") {
		t.Fatalf("confirm = %+v", confirm.Msg)
	}
	down := build(t, func(o *service.Options) {
		o.Holder = &fakeHolder{presentErr: errors.New("down")}
		o.Fetch = fetchRequest
	})
	if _, err := down.PresentConfirm(ctx(), connect.NewRequest(&walletportalv1.PresentConfirmRequest{
		PresentationId: "openid4vp://?request_uri=https://verifier.example/r/1",
		SelectedCards:  map[string]string{"licence": "c1"},
	})); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("holder down: %v", err)
	}
}

func TestPresentDirectInBrowserMode(t *testing.T) {
	var seen url.Values
	svc := build(t, func(o *service.Options) {
		o.Fetch = fetchRequest
		o.Post = func(_ context.Context, _ string, form url.Values) ([]byte, error) {
			seen = form
			return []byte(`{"redirect_uri":"https://verifier.example/done"}`), nil
		}
	})
	text, encoded := sdjwtFixture(t)
	held, err := svc.Paste(ctx(), connect.NewRequest(&walletportalv1.PasteRequest{Text: text}))
	if err != nil {
		t.Fatal(err)
	}
	cardID := held.Msg.GetDetected().GetOfferId()
	start, err := svc.PresentStart(ctx(), connect.NewRequest(&walletportalv1.PresentStartRequest{
		PresentationId: "openid4vp://?request_uri=https://verifier.example/r/1",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(start.Msg.GetRequested()[0].GetMatches()) != 1 {
		t.Fatalf("matches = %+v", start.Msg.GetRequested()[0].GetMatches())
	}
	confirm, err := svc.PresentConfirm(ctx(), connect.NewRequest(&walletportalv1.PresentConfirmRequest{
		PresentationId: start.Msg.GetPresentationId(),
		SelectedCards:  map[string]string{"licence": cardID},
		Disclosed: map[string]*walletportalv1.PresentConfirmRequest_ClaimPaths{
			"licence": {Paths: []string{"given_name"}},
		},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !confirm.Msg.GetAccepted() {
		t.Fatalf("confirm = %+v", confirm.Msg)
	}
	sent := seen.Get("vp_token")
	if !strings.Contains(sent, encoded["given_name"]) {
		t.Fatalf("token = %q", sent)
	}
	if strings.Contains(sent, encoded["birth_date"]) {
		t.Fatal("want no claim the citizen did not agree to")
	}
	if seen.Get("state") != "s-1" {
		t.Fatalf("state = %q", seen.Get("state"))
	}
}

func TestPresentDirectProblems(t *testing.T) {
	svc := build(t, func(o *service.Options) { o.Fetch = fetchRequest })
	_, err := svc.PresentConfirm(ctx(), connect.NewRequest(&walletportalv1.PresentConfirmRequest{
		PresentationId: "openid4vp://?request_uri=https://verifier.example/r/1",
		SelectedCards:  map[string]string{"licence": "missing"},
	}))
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("missing card: %v", err)
	}
	noPost := build(t, func(o *service.Options) { o.Fetch = fetchRequest })
	held, err := noPost.Paste(ctx(), connect.NewRequest(&walletportalv1.PasteRequest{Text: token(t)}))
	if err != nil {
		t.Fatal(err)
	}
	if _, serr := noPost.PresentConfirm(ctx(), connect.NewRequest(&walletportalv1.PresentConfirmRequest{
		PresentationId: "openid4vp://?request_uri=https://verifier.example/r/1",
		SelectedCards:  map[string]string{"licence": held.Msg.GetDetected().GetOfferId()},
	})); connect.CodeOf(serr) != connect.CodeUnavailable {
		t.Fatalf("no poster: %v", serr)
	}
	broken := build(t, func(o *service.Options) {
		o.Fetch = fetchRequest
		o.Post = func(context.Context, string, url.Values) ([]byte, error) { return nil, nil }
	})
	scan, err := broken.Paste(ctx(), connect.NewRequest(&walletportalv1.PasteRequest{
		Text: `{"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiableCredential"]}`,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := broken.PresentConfirm(ctx(), connect.NewRequest(&walletportalv1.PresentConfirmRequest{
		PresentationId: "openid4vp://?request_uri=https://verifier.example/r/1",
		SelectedCards:  map[string]string{"licence": scan.Msg.GetDetected().GetOfferId()},
	})); err != nil {
		t.Fatalf("json-ld token: %v", err)
	}
}

func TestPresentStartRejects(t *testing.T) {
	svc := build(t, func(o *service.Options) { o.Fetch = fetchRequest })
	if _, err := svc.PresentStart(context.Background(),
		connect.NewRequest(&walletportalv1.PresentStartRequest{})); err == nil {
		t.Fatal("want a session error")
	}
	if _, err := svc.PresentStart(ctx(), connect.NewRequest(&walletportalv1.PresentStartRequest{
		PresentationId: " ",
	})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("empty id: %v", err)
	}
	if _, err := svc.PresentStart(ctx(), connect.NewRequest(&walletportalv1.PresentStartRequest{
		PresentationId: "https://attacker.example/r/1",
	})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("other host: %v", err)
	}
	if _, err := svc.PresentConfirm(ctx(), connect.NewRequest(&walletportalv1.PresentConfirmRequest{
		PresentationId: "openid4vp://?request_uri=https://verifier.example/r/1",
	})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("no selection: %v", err)
	}
	if _, err := svc.PresentConfirm(context.Background(),
		connect.NewRequest(&walletportalv1.PresentConfirmRequest{})); err == nil {
		t.Fatal("want a session error")
	}
	broken := build(t, func(o *service.Options) {
		o.Fetch = func(context.Context, string) ([]byte, error) { return []byte("{oops"), nil }
	})
	if _, err := broken.PresentStart(ctx(), connect.NewRequest(&walletportalv1.PresentStartRequest{
		PresentationId: "https://verifier.example/r/1",
	})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("broken object: %v", err)
	}
	holderDown := build(t, func(o *service.Options) {
		o.Holder = &fakeHolder{listErr: errors.New("down")}
		o.Fetch = fetchRequest
	})
	if _, err := holderDown.PresentStart(ctx(), connect.NewRequest(&walletportalv1.PresentStartRequest{
		PresentationId: "https://verifier.example/r/1",
	})); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("holder down: %v", err)
	}
}

func TestPendingRecordsExpire(t *testing.T) {
	svc := build(t, func(o *service.Options) { o.PendingTTL = time.Minute })
	scan, err := svc.Scan(ctx(), connect.NewRequest(&walletportalv1.ScanRequest{Text: offerText}))
	if err != nil {
		t.Fatal(err)
	}
	old := clock
	clock = clock.Add(2 * time.Minute)
	defer func() { clock = old }()
	if _, err := svc.Accept(ctx(), connect.NewRequest(&walletportalv1.AcceptRequest{
		OfferId: scan.Msg.GetDetected().GetOfferId(),
	})); connect.CodeOf(err) != connect.CodeDeadlineExceeded {
		t.Fatalf("expired: %v", err)
	}
	if list, err := svc.ListMine(ctx(), connect.NewRequest(&walletportalv1.ListMineRequest{})); err != nil ||
		len(list.Msg.GetCards()) != 0 {
		t.Fatalf("expired held = %+v %v", list, err)
	}
}

func TestPresentStartExpiredRecord(t *testing.T) {
	svc := build(t, func(o *service.Options) {
		o.PendingTTL = time.Minute
		o.Fetch = fetchRequest
	})
	scan, err := svc.Scan(ctx(), connect.NewRequest(&walletportalv1.ScanRequest{
		Text: "openid4vp://?request_uri=https://verifier.example/r/1",
	}))
	if err != nil {
		t.Fatal(err)
	}
	old := clock
	clock = clock.Add(2 * time.Minute)
	defer func() { clock = old }()
	if _, err := svc.PresentStart(ctx(), connect.NewRequest(&walletportalv1.PresentStartRequest{
		PresentationId: scan.Msg.GetDetected().GetPresentationId(),
	})); connect.CodeOf(err) != connect.CodeDeadlineExceeded {
		t.Fatalf("expired: %v", err)
	}
}

func TestStoreProblems(t *testing.T) {
	svc := build(t, func(o *service.Options) {
		o.Store = failingKV{}
		o.Fetch = fetchRequest
	})
	if _, err := svc.Scan(ctx(), connect.NewRequest(&walletportalv1.ScanRequest{
		Text: offerText,
	})); connect.CodeOf(err) != connect.CodeInternal {
		t.Fatalf("offer: %v", err)
	}
	if _, err := svc.Scan(ctx(), connect.NewRequest(&walletportalv1.ScanRequest{
		Text: "openid4vp://?request_uri=https://verifier.example/r/1",
	})); connect.CodeOf(err) != connect.CodeInternal {
		t.Fatalf("request: %v", err)
	}
	if _, err := svc.Paste(ctx(), connect.NewRequest(&walletportalv1.PasteRequest{
		Text: token(t),
	})); connect.CodeOf(err) != connect.CodeInternal {
		t.Fatalf("credential: %v", err)
	}
	if _, err := svc.Claim(ctx(), connect.NewRequest(&walletportalv1.ClaimRequest{
		CredentialIssuer: "https://a.example", SchemaId: "dl",
	})); connect.CodeOf(err) != connect.CodeInternal {
		t.Fatalf("claim: %v", err)
	}
	if _, err := svc.ListMine(ctx(),
		connect.NewRequest(&walletportalv1.ListMineRequest{})); connect.CodeOf(err) != connect.CodeInternal {
		t.Fatalf("list: %v", err)
	}
	if _, err := svc.Accept(ctx(), connect.NewRequest(&walletportalv1.AcceptRequest{
		OfferId: "id-1",
	})); connect.CodeOf(err) != connect.CodeInternal {
		t.Fatalf("accept: %v", err)
	}
	if _, err := svc.Delete(ctx(), connect.NewRequest(&walletportalv1.DeleteRequest{
		Id: "c1",
	})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("delete: %v", err)
	}
	if _, err := svc.PresentStart(ctx(), connect.NewRequest(&walletportalv1.PresentStartRequest{
		PresentationId: "openid4vp://?request_uri=https://verifier.example/r/1",
	})); connect.CodeOf(err) != connect.CodeInternal {
		t.Fatalf("present start: %v", err)
	}
}

func TestBadRecordDocument(t *testing.T) {
	kv := store.Memory()
	svc := build(t, func(o *service.Options) { o.Store = kv })
	if err := kv.Put(context.Background(), "offer/wallet-1/id-9", []byte("{oops")); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Accept(ctx(), connect.NewRequest(&walletportalv1.AcceptRequest{
		OfferId: "id-9",
	})); connect.CodeOf(err) != connect.CodeInternal {
		t.Fatalf("broken record: %v", err)
	}
	if err := kv.Put(context.Background(), "held/wallet-1/id-8", []byte("{oops")); err != nil {
		t.Fatal(err)
	}
	list, err := svc.ListMine(ctx(), connect.NewRequest(&walletportalv1.ListMineRequest{}))
	if err != nil || len(list.Msg.GetCards()) != 0 {
		t.Fatalf("list = %+v %v", list, err)
	}
}

// failingKV fails every call.
type failingKV struct{}

func (failingKV) Get(context.Context, string) ([]byte, error) { return nil, errors.New("down") }
func (failingKV) Put(context.Context, string, []byte) error   { return errors.New("down") }
func (failingKV) Delete(context.Context, string) error        { return errors.New("down") }
func (failingKV) List(context.Context, string) ([]string, error) {
	return nil, errors.New("down")
}
func (failingKV) CompareAndSwap(context.Context, string, []byte, []byte) error {
	return errors.New("down")
}

func TestPresentSummaryHelper(t *testing.T) {
	// The consent screen sentence comes from the present package. The
	// service test checks that the wording reaches the response.
	svc := build(t, func(o *service.Options) { o.Fetch = fetchRequest })
	start, err := svc.PresentStart(ctx(), connect.NewRequest(&walletportalv1.PresentStartRequest{
		PresentationId: "openid4vp://?request_uri=https://verifier.example/r/1",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got := present.Summary(start.Msg.GetRequested()); !strings.Contains(got, "one credential") {
		t.Fatalf("summary = %q", got)
	}
}

func TestDefaultIDMaker(t *testing.T) {
	svc := build(t, func(o *service.Options) { o.NewID = nil })
	first, err := svc.Scan(ctx(), connect.NewRequest(&walletportalv1.ScanRequest{Text: offerText}))
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.Scan(ctx(), connect.NewRequest(&walletportalv1.ScanRequest{Text: offerText}))
	if err != nil {
		t.Fatal(err)
	}
	a, b := first.Msg.GetDetected().GetOfferId(), second.Msg.GetDetected().GetOfferId()
	if a == "" || a == b {
		t.Fatalf("ids = %q %q", a, b)
	}
}
