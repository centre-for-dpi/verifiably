// SPDX-License-Identifier: Apache-2.0

package portal_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	"github.com/centre-for-dpi/vc-adapters/core/sdjwt"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/cards"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/session"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// optionalRequest asks for the given name and, as an optional field,
// the unknown field.
func optionalRequest() []byte {
	doc := map[string]any{
		"client_id": "https://verifier.example", "nonce": "n-1", "state": "s-1",
		"response_uri": "https://verifier.example/direct_post",
		"presentation_definition": map[string]any{"id": "pd", "purpose": "Check your licence", "input_descriptors": []any{map[string]any{
			"id": "licence", "format": map[string]any{"dc+sd-jwt": map[string]any{}},
			"constraints": map[string]any{"fields": []any{
				map[string]any{"path": []string{"$.vct"}, "filter": map[string]any{"pattern": "DriverLicence"}},
				map[string]any{"path": []string{"$.given_name"}},
				map[string]any{"path": []string{"$.birth_date"}, "optional": true},
			}},
		}}},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		panic(err)
	}
	return raw
}

// upload posts one request file with the page token.
func (h *harness) upload(t *testing.T, content []byte) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	if err := w.WriteField(session.Field, h.guard.Token(citizen())); err != nil {
		t.Fatal(err)
	}
	part, err := w.CreateFormFile("request_file", "request.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/wallet/present/upload", &body)
	req.Header.Set("Content-Type", w.FormDataContentType())
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		a11ytest.AssertPage(t, rec.Body.String())
	}
	return rec
}

// TestPresentIntakeFollowsTheBoard checks the three ways in of board
// Holder-Present: the camera, a pasted request link, and a request file.
func TestPresentIntakeFollowsTheBoard(t *testing.T) {
	h := setupShell(t, nil, holderDeployment())
	body := h.get(t, "/wallet/present").Body.String()
	for _, want := range []string{
		"A verifier asked for something. See who asks, choose what to share, then share.",
		"Scan a QR", `id="scan-start"`, "Paste a request link", `action="/wallet/present/read"`,
		"Upload a request file", `enctype="multipart/form-data"`, `type="file"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("present misses %s\n%s", want, body)
		}
	}
}

// TestPresentFromPastedLink checks that a pasted request link opens the
// request card, and that text that is no request stays with an error.
func TestPresentFromPastedLink(t *testing.T) {
	h := setupShell(t, nil, holderDeployment())
	rec := h.post(t, "/wallet/present/read", url.Values{"request": {requestURI}})
	if rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "/wallet/present?id=") {
		t.Fatalf("status = %d location = %q", rec.Code, rec.Header().Get("Location"))
	}
	page := h.get(t, noFragment(rec.Header().Get("Location"))).Body.String()
	for _, want := range []string{"Request from Agency A", "Verifier identity checked", "https://verifier.example",
		"Matched credential", "They ask for", "given_name", "Share selected", "Decline"} {
		if !strings.Contains(page, want) {
			t.Fatalf("request card misses %s\n%s", want, page)
		}
	}
	for _, text := range []string{"hello there", ""} {
		bad := h.post(t, "/wallet/present/read", url.Values{"request": {text}})
		if bad.Code != http.StatusOK || !strings.Contains(bad.Body.String(), `aria-invalid="true"`) {
			t.Fatalf("%q: status = %d", text, bad.Code)
		}
	}
}

// TestPresentFromUploadedRequestFile checks that a request object in a
// file opens the request card of the browser store. A stack wallet
// takes a request link only, so its page says why it cannot answer
// (ADR-063 decision 2).
func TestPresentFromUploadedRequestFile(t *testing.T) {
	stack := setupShell(t, nil, holderDeployment())
	refused := stack.upload(t, optionalRequest())
	page := stack.get(t, noFragment(refused.Header().Get("Location"))).Body.String()
	if !strings.Contains(page, "answers a request link only") {
		t.Fatalf("stack wallet page = %s", page)
	}
	h := setupShell(t, func(o *serviceOptions) { o.Holder = nil }, holderDeployment())
	rec := h.upload(t, optionalRequest())
	if rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "/wallet/present?id=") {
		t.Fatalf("status = %d location = %q body = %s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	page = h.get(t, noFragment(rec.Header().Get("Location"))).Body.String()
	if !strings.Contains(page, "Purpose: Check your licence") {
		t.Fatalf("page = %s", page)
	}
	bad := h.upload(t, []byte("not a request"))
	if bad.Code != http.StatusOK || !strings.Contains(bad.Body.String(), "holds no presentation request") {
		t.Fatalf("bad file: status = %d", bad.Code)
	}
}

// TestOptionalClaimsOffByDefault checks the list "They ask for": a
// required claim is ticked and locked and still travels in a hidden
// field, and an optional claim is off.
func TestOptionalClaimsOffByDefault(t *testing.T) {
	h := setupShell(t, func(o *serviceOptions) {
		o.Fetch = func(context.Context, string) ([]byte, error) { return optionalRequest(), nil }
	}, holderDeployment())
	page := h.get(t, "/wallet/present?id="+url.QueryEscape(requestURI)).Body.String()
	required := between(page, `type="checkbox" id="ask-0-1"`, `>`)
	optional := between(page, `type="checkbox" id="ask-0-2"`, `>`)
	if !strings.Contains(required, "checked") || !strings.Contains(required, "disabled") {
		t.Fatalf("required = %q", required)
	}
	if strings.Contains(optional, "checked") || strings.Contains(optional, "disabled") {
		t.Fatalf("optional = %q", optional)
	}
	if !strings.Contains(page, `<input type="hidden" name="claim.licence" value="given_name">`) {
		t.Fatal("the required claim has no hidden field")
	}
	for _, want := range []string{"Required", "Optional. Off by default."} {
		if !strings.Contains(page, want) {
			t.Fatalf("page misses %s", want)
		}
	}
}

// TestConfirmAndDeclineWriteRecords checks the two answers of the
// request card and the list of recent presentations on the home page.
func TestConfirmAndDeclineWriteRecords(t *testing.T) {
	h := setupShell(t, nil, holderDeployment())
	shared := h.post(t, "/wallet/present", url.Values{
		"id": {requestURI}, "card.licence": {"c1"}, "claim.licence": {"given_name"},
	})
	if shared.Code != http.StatusOK || !strings.Contains(shared.Body.String(), "You sent the credential.") {
		t.Fatalf("share: status = %d", shared.Code)
	}
	declined := h.post(t, "/wallet/present/decline", url.Values{"id": {requestURI}})
	if declined.Code != http.StatusSeeOther || declined.Header().Get("Location") != "/wallet/" {
		t.Fatalf("decline: status = %d location = %q", declined.Code, declined.Header().Get("Location"))
	}
	bad := h.post(t, "/wallet/present/decline", url.Values{"id": {"https://attacker.example/r"}})
	if bad.Code != http.StatusOK || !strings.Contains(bad.Body.String(), "could not read the request") {
		t.Fatalf("bad decline: status = %d", bad.Code)
	}
}

// TestHomeShowsRecentPresentations checks the table of board
// Holder-Portal: when, the verifier, the shared claim names, and the
// result.
func TestHomeShowsRecentPresentations(t *testing.T) {
	h := setupShell(t, nil, holderDeployment())
	empty := h.get(t, "/wallet/").Body.String()
	if !strings.Contains(empty, "You have not answered a verifier yet.") {
		t.Fatal("the home page misses the empty presentations row")
	}
	h.post(t, "/wallet/present", url.Values{"id": {requestURI}, "card.licence": {"c1"}, "claim.licence": {"given_name"}})
	h.post(t, "/wallet/present/decline", url.Values{"id": {requestURI}})
	body := h.get(t, "/wallet/").Body.String()
	for _, want := range []string{"Recent presentations", "Agency A", "given_name", "Accepted", "Declined by you", "Declined", "19 Sep 2026"} {
		if !strings.Contains(body, want) {
			t.Fatalf("home misses %s\n%s", want, body)
		}
	}
	table := body[strings.Index(body, `id="recent"`):]
	if strings.Index(table, "Declined by you") > strings.Index(table, ">given_name<") {
		t.Fatal("the newest record does not come first")
	}
}

// TestRequestCardMatches checks the matched credential: several matches
// give a choice, and no match turns the share button off.
func TestRequestCardMatches(t *testing.T) {
	two := setupShell(t, func(o *serviceOptions) {
		cred := credential(t)
		o.Holder = &twoHolder{fakeHolder: fakeHolder{credential: cred}}
	}, holderDeployment())
	page := two.get(t, "/wallet/present?id="+url.QueryEscape(requestURI)).Body.String()
	if !strings.Contains(page, `<select`) || !strings.Contains(page, `name="card.licence"`) {
		t.Fatalf("two matches give no choice\n%s", page)
	}
	none := setupShell(t, func(o *serviceOptions) { o.Holder = &fakeHolder{credential: dated(t)} }, holderDeployment())
	page = none.get(t, "/wallet/present?id="+url.QueryEscape(requestURI)).Body.String()
	if !strings.Contains(page, "You hold no credential that matches this request.") || !strings.Contains(page, "disabled>Share selected") {
		t.Fatalf("no match\n%s", page)
	}
}

// twoHolder holds the same credential twice.
type twoHolder struct{ fakeHolder }

func (f *twoHolder) ListCredentials(context.Context, *connect.Request[backendv1.ListCredentialsRequest],
) (*connect.Response[backendv1.ListCredentialsResponse], error) {
	second := proto.CloneOf(f.credential)
	second.Id = "c2"
	return connect.NewResponse(&backendv1.ListCredentialsResponse{Credentials: []*backendv1.WalletCredential{f.credential, second}}), nil
}

// noFragment drops the fragment of a location, as a browser does before
// it sends the request.
func noFragment(location string) string {
	before, _, _ := strings.Cut(location, "#")
	return before
}

// TestConsentListsAlwaysSentClaims shows a claim the credential sends in
// every answer: ticked, locked, carried by a hidden field, and labelled,
// although the verifier did not ask for it (ADR-081).
func TestConsentListsAlwaysSentClaims(t *testing.T) {
	cred := credential(t)
	cred.Credential.Payload = []byte(plainToken(t))
	h := setupShell(t, func(o *serviceOptions) { o.Holder = &fakeHolder{credential: cred} }, holderDeployment())
	page := h.get(t, "/wallet/present?id="+url.QueryEscape(requestURI)).Body.String()
	for _, want := range []string{
		"Always sent. This credential shows it in every answer.", "NCF-CODE",
		`<input type="hidden" name="claim.licence" value="identityQR">`,
	} {
		if !strings.Contains(page, want) {
			t.Fatalf("page misses %q\n%s", want, page)
		}
	}
}

// plainToken is an SD-JWT that carries identityQR outside any
// disclosure.
func plainToken(t *testing.T) string {
	t.Helper()
	payload := map[string]any{
		"vct": "DriverLicence", "iss": "did:web:issuer.example",
		"given_name": "Ada", "birth_date": "1990-01-01", "identityQR": "NCF-CODE",
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

// TestConsentOfAStackWalletThatPicksTheClaims names the whole
// credential, says that a whole query wallet refuses an unlisted claim,
// and words the whole credential in the history (ADR-081).
func TestConsentOfAStackWalletThatPicksTheClaims(t *testing.T) {
	h := setupShell(t, func(o *serviceOptions) {
		o.WholeCredential = func(context.Context) bool { return true }
	}, holderDeployment(backendv1.Feature_FEATURE_WALLET_WHOLE_QUERY))
	page := h.get(t, "/wallet/present?id="+url.QueryEscape(requestURI)).Body.String()
	for _, want := range []string{
		"Every claim", "This wallet sends the whole credential.",
		`<input type="hidden" name="claim.licence" value="*">`,
		"It refuses to answer when it would send a claim this screen does not list.",
	} {
		if !strings.Contains(page, want) {
			t.Fatalf("page misses %q\n%s", want, page)
		}
	}
	h.post(t, "/wallet/present", url.Values{
		"id": {requestURI}, "card.licence": {"c1"}, "claim.licence": {"given_name", "*"},
	})
	if home := h.get(t, "/wallet/").Body.String(); !strings.Contains(home, "given_name, Every claim") {
		t.Fatalf("the history does not word the whole credential\n%s", home)
	}
}

// TestOutcomeNamesWhatLeft checks the page after an answer: it names
// the verifier, the request it answered, the credential, and the claims
// that left the wallet.
func TestOutcomeNamesWhatLeft(t *testing.T) {
	h := setupShell(t, nil, holderDeployment())
	sent := h.post(t, "/wallet/present", url.Values{
		"id": {requestURI}, "card.licence": {"c1"}, "claim.licence": {"given_name"},
	})
	page := sent.Body.String()
	if sent.Code != http.StatusOK {
		t.Fatalf("status = %d", sent.Code)
	}
	a11ytest.AssertPage(t, page)
	left := between(page, `id="left"`, "</table>")
	for _, want := range []string{"What left your wallet", "Verifier", "Agency A", "Request", ">1<", "Credential", "DriverLicence", "Claims", "given_name"} {
		if !strings.Contains(left, want) {
			t.Fatalf("the outcome misses %q\n%s", want, page)
		}
	}
}

// longDID is a did:key issuer with no break in it.
const longDID = "did:key:z6MksE9FrDEMgX62GjquSt8oKHhWR9mxavDkSKJLEzAPjqrf"

// TestCardShortensALongIssuerDID checks a card whose issuer is a long
// DID: the card names a short form, and the full DID rides in the title
// so the holder can still read it.
func TestCardShortensALongIssuerDID(t *testing.T) {
	didTrust := func(context.Context, string, string) (cards.Trust, error) {
		return cards.Trust{Outcome: trustv1.TrustLookupResponse_OUTCOME_TRUSTED, Name: longDID}, nil
	}
	h := setup(t, func(o *serviceOptions) {
		o.Cards = cards.New(cards.Options{Trust: didTrust, Now: now})
		o.Trust = didTrust
	})
	page := h.get(t, "/wallet/").Body.String()
	a11ytest.AssertPage(t, page)
	if strings.Contains(page, ">"+longDID+"<") || strings.Contains(page, longDID+" is on the trust list") {
		t.Fatalf("the card shows the whole DID as text\n%s", page)
	}
	short := cards.ShortDID(longDID)
	if short == longDID || len(short) > 32 {
		t.Fatalf("ShortDID = %q", short)
	}
	for _, want := range []string{`title="` + longDID + `">` + short + "<", short + "</span> is on the trust list."} {
		if !strings.Contains(page, want) {
			t.Fatalf("the card misses %q\n%s", want, page)
		}
	}
}
