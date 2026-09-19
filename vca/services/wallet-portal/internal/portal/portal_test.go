// SPDX-License-Identifier: Apache-2.0

package portal_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
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
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/portal"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/ports"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/session"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

var clock = time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)

func now() time.Time { return clock }

func citizen() session.Citizen {
	return session.Citizen{Subject: "https://idp|abc", WalletID: "wallet-1", SessionID: "sid-1"}
}

// fakeHolder answers the holder backend RPCs.
type fakeHolder struct {
	backendv1connect.HolderBackendServiceClient
	credential *backendv1.WalletCredential
	listErr    error
	acceptErr  error
	deleteErr  error
	accepted   bool
	deletedID  string
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

func (f *fakeHolder) AcceptOffer(_ context.Context, _ *connect.Request[backendv1.AcceptOfferRequest],
) (*connect.Response[backendv1.AcceptOfferResponse], error) {
	if f.acceptErr != nil {
		return nil, f.acceptErr
	}
	return connect.NewResponse(&backendv1.AcceptOfferResponse{Credential: f.credential}), nil
}

func (f *fakeHolder) DeleteCredential(_ context.Context, req *connect.Request[backendv1.DeleteCredentialRequest],
) (*connect.Response[backendv1.DeleteCredentialResponse], error) {
	f.deletedID = req.Msg.GetCredentialId()
	if f.deleteErr != nil {
		return nil, f.deleteErr
	}
	return connect.NewResponse(&backendv1.DeleteCredentialResponse{}), nil
}

func (f *fakeHolder) Present(_ context.Context, _ *connect.Request[backendv1.PresentRequest],
) (*connect.Response[backendv1.PresentResponse], error) {
	return connect.NewResponse(&backendv1.PresentResponse{Accepted: f.accepted}), nil
}

// sdjwtToken returns one SD-JWT with two disclosures.
func sdjwtToken(t *testing.T) string {
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
	token := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256"}`)) + "." +
		base64.RawURLEncoding.EncodeToString(body) + ".sig"
	for _, d := range discs {
		token += "~" + d.Encoded
	}
	return token + "~"
}

func credential(t *testing.T) *backendv1.WalletCredential {
	t.Helper()
	return &backendv1.WalletCredential{
		Id: "c1", Type: "DriverLicence", Issuer: "did:web:issuer.example",
		Credential: &commonv1.Credential{
			Format: commonv1.Format_FORMAT_DC_SD_JWT, Payload: []byte(sdjwtToken(t)),
		},
	}
}

func offerings() []*walletportalv1.Offering {
	return []*walletportalv1.Offering{
		{CredentialIssuer: "https://a.example", IssuerName: "Agency A",
			Trust: trustv1.TrustLookupResponse_OUTCOME_TRUSTED,
			Schema: &schemav1.PublicSchema{Id: "dl", Type: "DriverLicence",
				Display: []*schemav1.Display{{Name: "Driver licence"}}}},
		{CredentialIssuer: "https://b.example",
			Schema: &schemav1.PublicSchema{Id: "pp", Type: "Passport"}},
	}
}

func trust(_ context.Context, _, _ string) (cards.Trust, error) {
	return cards.Trust{Outcome: trustv1.TrustLookupResponse_OUTCOME_TRUSTED, Name: "Agency A"}, nil
}

const requestURI = "openid4vp://?client_id=v&request_uri=https://verifier.example/r/1"

// requestObject returns one OID4VP request object.
func requestObject(purpose string) []byte {
	doc := map[string]any{
		"client_id":    "https://verifier.example",
		"nonce":        "n-1",
		"response_uri": "https://verifier.example/direct_post",
		"state":        "s-1",
		"dcql_query": map[string]any{"credentials": []any{map[string]any{
			"id": "licence", "format": "dc+sd-jwt",
			"meta": map[string]any{"vct_values": []string{"DriverLicence"}},
			"claims": []any{
				map[string]any{"path": []string{"given_name"}},
				map[string]any{"path": []string{"unknown_field"}},
			},
		}}},
	}
	if purpose != "" {
		doc["presentation_definition"] = nil
	}
	raw, _ := json.Marshal(doc)
	return raw
}

// setup builds the service, the portal, and the handler under test.
type harness struct {
	handler http.Handler
	guard   session.Guard
	holder  *fakeHolder
	svc     *service.Service
}

func setup(t *testing.T, change func(*service.Options)) *harness {
	t.Helper()
	holder := &fakeHolder{credential: credential(t), accepted: true}
	opts := service.Options{
		Holder: holder,
		Catalogue: ports.CatalogueFunc(func(context.Context) ([]*walletportalv1.Offering, error) {
			return offerings(), nil
		}),
		Eligible: func(_ context.Context, _ string, o *walletportalv1.Offering) (bool, error) {
			return o.GetSchema().GetId() == "dl", nil
		},
		Salt:         "salt",
		Cards:        cards.New(cards.Options{Trust: trust, Now: now}),
		Trust:        trust,
		Store:        store.Memory(),
		RequestHosts: []string{"verifier.example"},
		Fetch: func(context.Context, string) ([]byte, error) {
			return requestObject(""), nil
		},
		Post: func(context.Context, string, url.Values) ([]byte, error) { return nil, nil },
		Now:  now,
	}
	if change != nil {
		change(&opts)
	}
	svc, err := service.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := session.NewGuard([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	pages, err := portal.New(portal.Options{Service: svc, Guard: guard, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	pages.Register(mux)
	mux.Handle("GET /wallet/wallet.js", pages.Script())
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(w, r.WithContext(session.With(r.Context(), citizen())))
	})
	if pages.Prefix() != "/wallet" {
		t.Fatalf("prefix = %q", pages.Prefix())
	}
	return &harness{handler: handler, guard: guard, holder: holder, svc: svc}
}

// get renders one page and checks the accessibility rules.
func (h *harness) get(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if rec.Code == http.StatusOK {
		a11ytest.AssertPage(t, rec.Body.String())
	}
	return rec
}

// post sends one form with the synchronizer token.
func (h *harness) post(t *testing.T, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	if form == nil {
		form = url.Values{}
	}
	form.Set(session.Field, h.guard.Token(citizen()))
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		a11ytest.AssertPage(t, rec.Body.String())
	}
	return rec
}

func TestMinePage(t *testing.T) {
	h := setup(t, nil)
	rec := h.get(t, "/wallet/")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"My credentials", "DriverLicence", "Issuer: trusted",
		"given_name", "Ada", "Remove from my wallet"} {
		if !strings.Contains(body, want) {
			t.Fatalf("page misses %q", want)
		}
	}
}

func TestMinePageWithoutCredentials(t *testing.T) {
	h := setup(t, func(o *service.Options) { o.Holder = &fakeHolder{credential: nil} })
	rec := h.get(t, "/wallet/")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "cannot read this credential") {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestMinePageWhenTheWalletIsDown(t *testing.T) {
	h := setup(t, func(o *service.Options) {
		o.Holder = &fakeHolder{listErr: errors.New("down")}
	})
	rec := h.get(t, "/wallet/")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "not available") {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func TestMinePageInBrowserMode(t *testing.T) {
	h := setup(t, func(o *service.Options) { o.Holder = nil })
	rec := h.get(t, "/wallet/")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"wallet-file", "wallet-paste", "wallet.js", "wallet-status",
		"You hold no credential yet", `name="csrf_token"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("page misses %q", want)
		}
	}
}

func TestScriptIsServed(t *testing.T) {
	h := setup(t, nil)
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/wallet.js", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "AES-GCM") {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestDiscoverPage(t *testing.T) {
	h := setup(t, nil)
	rec := h.get(t, "/wallet/discover")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"What issuers offer", "Driver licence", "Agency A",
		"https://b.example", "Passport"} {
		if !strings.Contains(body, want) {
			t.Fatalf("page misses %q", want)
		}
	}
}

func TestDiscoverPageWithoutCatalogue(t *testing.T) {
	h := setup(t, func(o *service.Options) { o.Catalogue = nil })
	rec := h.get(t, "/wallet/discover")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "not available") {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func TestClaimablePage(t *testing.T) {
	h := setup(t, nil)
	rec := h.get(t, "/wallet/claimable")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"What I can get", "yes", "not now", "Get it", "Driver licence"} {
		if !strings.Contains(body, want) {
			t.Fatalf("page misses %q", want)
		}
	}
}

func TestClaimablePageProblem(t *testing.T) {
	h := setup(t, func(o *service.Options) {
		o.Eligible = func(context.Context, string, *walletportalv1.Offering) (bool, error) {
			return false, errors.New("down")
		}
	})
	rec := h.get(t, "/wallet/claimable")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "not available") {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestClaim(t *testing.T) {
	h := setup(t, nil)
	rec := h.post(t, "/wallet/claim", url.Values{
		"credential_issuer": {"https://a.example"}, "schema_id": {"dl"},
	})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/wallet/" {
		t.Fatalf("status = %d location = %q", rec.Code, rec.Header().Get("Location"))
	}
	down := setup(t, func(o *service.Options) {
		o.Holder = &fakeHolder{acceptErr: errors.New("down")}
	})
	rec = down.post(t, "/wallet/claim", url.Values{
		"credential_issuer": {"https://a.example"}, "schema_id": {"dl"},
	})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "did not give the credential") {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func TestClaimInBrowserModeShowsTheOffer(t *testing.T) {
	h := setup(t, func(o *service.Options) { o.Holder = nil })
	rec := h.post(t, "/wallet/claim", url.Values{
		"credential_issuer": {"https://a.example"}, "schema_id": {"dl"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Add it to my wallet") {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestScanFormAndOffer(t *testing.T) {
	h := setup(t, nil)
	rec := h.get(t, "/wallet/scan")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Scan or paste a code") {
		t.Fatalf("status = %d", rec.Code)
	}
	offer := `{"credential_issuer":"https://a.example",` +
		`"credential_configuration_ids":["dl"],"grants":{` +
		`"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"tx_code":{}}}}`
	rec = h.post(t, "/wallet/scan", url.Values{"text": {offer}})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"An issuer offers you a credential", "Agency A",
		"The code the issuer gave you", "No thank you"} {
		if !strings.Contains(body, want) {
			t.Fatalf("page misses %q", want)
		}
	}
	form := formValues(t, body)
	rec = h.post(t, "/wallet/accept", url.Values{
		"offer_id": {form.Get("offer_id")}, "pin": {"1234"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("accept status = %d", rec.Code)
	}
}

// formValues reads the hidden inputs of a rendered page.
func formValues(t *testing.T, body string) url.Values {
	t.Helper()
	out := url.Values{}
	for _, part := range strings.Split(body, `<input type="hidden"`)[1:] {
		name := between(part, `name="`, `"`)
		value := between(part, `value="`, `"`)
		if name != "" {
			out.Set(name, value)
		}
	}
	return out
}

func between(text, start, end string) string {
	i := strings.Index(text, start)
	if i < 0 {
		return ""
	}
	rest := text[i+len(start):]
	j := strings.Index(rest, end)
	if j < 0 {
		return ""
	}
	return rest[:j]
}

func TestScanRejectsAndUnknownText(t *testing.T) {
	h := setup(t, nil)
	rec := h.post(t, "/wallet/scan", url.Values{"text": {"hello there"}})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "does not know this text") {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	rec = h.post(t, "/wallet/scan", url.Values{"text": {""}})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "could not read that text") {
		t.Fatalf("empty status = %d", rec.Code)
	}
}

func TestScanCredentialAndPresentationRequest(t *testing.T) {
	h := setup(t, func(o *service.Options) { o.Holder = nil })
	rec := h.post(t, "/wallet/scan", url.Values{"text": {sdjwtToken(t)}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/wallet/" {
		t.Fatalf("credential status = %d", rec.Code)
	}
	rec = h.post(t, "/wallet/scan", url.Values{"text": {requestURI}})
	if rec.Code != http.StatusSeeOther ||
		!strings.HasPrefix(rec.Header().Get("Location"), "/wallet/present?id=") {
		t.Fatalf("request status = %d location = %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestRejectAndDelete(t *testing.T) {
	h := setup(t, nil)
	offer := `{"credential_issuer":"https://a.example","credential_configuration_ids":["dl"]}`
	rec := h.post(t, "/wallet/scan", url.Values{"text": {offer}})
	id := formValues(t, rec.Body.String()).Get("offer_id")
	rec = h.post(t, "/wallet/reject", url.Values{"offer_id": {id}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("reject status = %d", rec.Code)
	}
	rec = h.post(t, "/wallet/reject", url.Values{"offer_id": {"bad/id"}})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "could not refuse") {
		t.Fatalf("bad reject status = %d", rec.Code)
	}
	rec = h.post(t, "/wallet/delete", url.Values{"id": {"c1"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("delete status = %d", rec.Code)
	}
	if h.holder.deletedID != "c1" {
		t.Fatalf("deleted = %q", h.holder.deletedID)
	}
	rec = h.post(t, "/wallet/delete", url.Values{"id": {""}})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "did not remove") {
		t.Fatalf("bad delete status = %d", rec.Code)
	}
	rec = h.post(t, "/wallet/accept", url.Values{"offer_id": {"missing"}})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "did not take the credential") {
		t.Fatalf("bad accept status = %d", rec.Code)
	}
}

func TestConsentAndSubmit(t *testing.T) {
	h := setup(t, nil)
	rec := h.get(t, "/wallet/present?id="+url.QueryEscape(requestURI))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"A verifier asks for your credential", "Who asks: Agency A, trusted",
		"given_name", "Ada", "no value in your wallet", "Send these fields",
		"The verifier asks for one credential and 2 fields."} {
		if !strings.Contains(body, want) {
			t.Fatalf("page misses %q", want)
		}
	}
	hidden := formValues(t, body)
	form := url.Values{
		"id":             {hidden.Get("id")},
		"card.licence":   {"c1"},
		"claims.licence": {hidden.Get("claims.licence")},
	}
	rec = h.post(t, "/wallet/present", form)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "sent") {
		t.Fatalf("submit status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func TestConsentProblem(t *testing.T) {
	h := setup(t, nil)
	rec := h.get(t, "/wallet/present?id=https://attacker.example/r/1")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "could not read the request") {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func TestConsentShowsThePurpose(t *testing.T) {
	definition := map[string]any{
		"client_id":    "https://verifier.example",
		"nonce":        "n-1",
		"response_uri": "https://verifier.example/direct_post",
		"presentation_definition": map[string]any{
			"id": "pd-1", "purpose": "Prove your age",
			"input_descriptors": []any{map[string]any{
				"id": "licence", "format": map[string]any{"dc+sd-jwt": map[string]any{}},
				"constraints": map[string]any{"fields": []any{
					map[string]any{"path": []string{"$.vct"},
						"filter": map[string]any{"pattern": "DriverLicence"}},
					map[string]any{"path": []string{"$.given_name"}},
				}},
			}},
		},
	}
	raw, err := json.Marshal(definition)
	if err != nil {
		t.Fatal(err)
	}
	h := setup(t, func(o *service.Options) {
		o.Fetch = func(context.Context, string) ([]byte, error) { return raw, nil }
	})
	rec := h.get(t, "/wallet/present?id="+url.QueryEscape(requestURI))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Why: Prove your age") {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func TestSubmitRefused(t *testing.T) {
	h := setup(t, func(o *service.Options) {
		o.Holder = &fakeHolder{credential: credential(t), accepted: false}
	})
	rec := h.post(t, "/wallet/present", url.Values{
		"id": {requestURI}, "card.licence": {"c1"}, "claims.licence": {"given_name"},
	})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "not sent") {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "did not accept") {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestSubmitRedirects(t *testing.T) {
	h := setup(t, func(o *service.Options) { o.Holder = nil })
	rec := h.post(t, "/wallet/scan", url.Values{"text": {sdjwtToken(t)}})
	if rec.Code != http.StatusSeeOther {
		t.Fatal("want the wallet page")
	}
	mine := h.get(t, "/wallet/")
	id := between(mine.Body.String(), `name="id" value="`, `"`)
	_ = id
	posted := h.post(t, "/wallet/present", url.Values{
		"id": {requestURI}, "card.licence": {"missing"}, "claims.licence": {"given_name"},
	})
	if posted.Code != http.StatusOK || !strings.Contains(posted.Body.String(), "did not send") {
		t.Fatalf("status = %d body = %s", posted.Code, posted.Body.String())
	}
}

func TestSubmitWithRedirectURI(t *testing.T) {
	var seen url.Values
	h := setup(t, func(o *service.Options) {
		o.Holder = nil
		o.Post = func(_ context.Context, _ string, form url.Values) ([]byte, error) {
			seen = form
			return []byte(`{"redirect_uri":"https://verifier.example/done"}`), nil
		}
	})
	rec := h.post(t, "/wallet/scan", url.Values{"text": {sdjwtToken(t)}})
	if rec.Code != http.StatusSeeOther {
		t.Fatal("want the wallet page")
	}
	consent := h.get(t, "/wallet/present?id="+url.QueryEscape(requestURI))
	hidden := formValues(t, consent.Body.String())
	cardID := between(consent.Body.String(), `<option value="`, `"`)
	sent := h.post(t, "/wallet/present", url.Values{
		"id":             {hidden.Get("id")},
		"card.licence":   {cardID},
		"claims.licence": {hidden.Get("claims.licence")},
	})
	if sent.Code != http.StatusSeeOther ||
		sent.Header().Get("Location") != "https://verifier.example/done" {
		t.Fatalf("status = %d location = %q", sent.Code, sent.Header().Get("Location"))
	}
	if seen.Get("vp_token") == "" {
		t.Fatal("want a vp_token")
	}
}

func TestPostsNeedTheToken(t *testing.T) {
	h := setup(t, nil)
	for _, path := range []string{"/wallet/claim", "/wallet/scan", "/wallet/accept",
		"/wallet/reject", "/wallet/delete", "/wallet/present"} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader("a=b"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		h.handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s = %d", path, rec.Code)
		}
	}
}

func TestPostsNeedASession(t *testing.T) {
	h := setup(t, nil)
	guard, err := session.NewGuard([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	pages, err := portal.New(portal.Options{Service: h.svc, Guard: guard, LoginPath: "/login"})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	pages.Register(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/accept", nil))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("status = %d location = %q", rec.Code, rec.Header().Get("Location"))
	}
	bare, err := portal.New(portal.Options{Service: h.svc, Guard: guard})
	if err != nil {
		t.Fatal(err)
	}
	other := http.NewServeMux()
	bare.Register(other)
	rec = httptest.NewRecorder()
	other.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/accept", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestNewRejectsAndDefaults(t *testing.T) {
	if _, err := portal.New(portal.Options{}); err == nil {
		t.Fatal("want a service error")
	}
	h := setup(t, nil)
	guard, err := session.NewGuard([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	pages, err := portal.New(portal.Options{Service: h.svc, Guard: guard, Prefix: "citizen/"})
	if err != nil {
		t.Fatal(err)
	}
	if pages.Prefix() != "/citizen" {
		t.Fatalf("prefix = %q", pages.Prefix())
	}
}

// dated returns one JSON-LD credential with a validity window.
func dated(t *testing.T) *backendv1.WalletCredential {
	t.Helper()
	doc := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "did:web:issuer.example",
		"validFrom":         "2026-01-01T00:00:00Z",
		"validUntil":        "2027-01-01T00:00:00Z",
		"credentialSubject": map[string]any{"given_name": "Ada"},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return &backendv1.WalletCredential{
		Id: "c2", Type: "Licence", Issuer: "did:web:issuer.example",
		Credential: &commonv1.Credential{Format: commonv1.Format_FORMAT_LDP_VC, Payload: raw},
	}
}

func TestMinePageShowsTheValidityWindow(t *testing.T) {
	h := setup(t, func(o *service.Options) { o.Holder = &fakeHolder{credential: dated(t)} })
	rec := h.get(t, "/wallet/")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"Valid from 2026-01-01", "Valid until 2027-01-01"} {
		if !strings.Contains(body, want) {
			t.Fatalf("page misses %q", want)
		}
	}
}

func TestConsentWithoutAVerifierName(t *testing.T) {
	anonymous := map[string]any{
		"nonce":        "n-1",
		"response_uri": "https://verifier.example/direct_post",
		"dcql_query": map[string]any{"credentials": []any{map[string]any{
			"id": "any", "format": "dc+sd-jwt",
		}}},
	}
	raw, err := json.Marshal(anonymous)
	if err != nil {
		t.Fatal(err)
	}
	h := setup(t, func(o *service.Options) {
		o.Trust = nil
		o.Fetch = func(context.Context, string) ([]byte, error) { return raw, nil }
	})
	rec := h.get(t, "/wallet/present?id=https://verifier.example/r/1")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"an unnamed verifier", "this request", "asks for no field"} {
		if !strings.Contains(body, want) {
			t.Fatalf("page misses %q", want)
		}
	}
}

func TestDiscoverPageWithoutNames(t *testing.T) {
	h := setup(t, func(o *service.Options) {
		o.Catalogue = ports.CatalogueFunc(func(context.Context) ([]*walletportalv1.Offering, error) {
			return []*walletportalv1.Offering{{Schema: &schemav1.PublicSchema{Id: "x"}}}, nil
		})
	})
	rec := h.get(t, "/wallet/discover")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "A credential") {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
}
