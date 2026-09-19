// SPDX-License-Identifier: Apache-2.0

package present_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/core/dcql"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	walletportalv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/cards"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/present"
)

const dcqlQuery = `{"credentials":[{"id":"licence","format":"dc+sd-jwt",
"meta":{"vct_values":["DriverLicence"]},
"claims":[{"path":["given_name"]},{"path":["birth_date"]}]}]}`

// object returns one request object document.
func object(extra map[string]any) []byte {
	doc := map[string]any{
		"client_id":    "https://verifier.example",
		"nonce":        "n-1",
		"response_uri": "https://verifier.example/direct_post",
		"state":        "s-1",
	}
	var query any
	_ = json.Unmarshal([]byte(dcqlQuery), &query)
	doc["dcql_query"] = query
	for k, v := range extra {
		if v == nil {
			delete(doc, k)
			continue
		}
		doc[k] = v
	}
	raw, _ := json.Marshal(doc)
	return raw
}

func TestParseRequestURI(t *testing.T) {
	got, err := present.Parse("openid4vp://?client_id=x&request_uri=https://verifier.example/r/1")
	if err != nil {
		t.Fatal(err)
	}
	if got.RequestURI != "https://verifier.example/r/1" || got.ClientID != "x" {
		t.Fatalf("request = %+v", got)
	}
	bare, err := present.Parse("https://verifier.example/r/1")
	if err != nil || bare.RequestURI != "https://verifier.example/r/1" {
		t.Fatalf("bare = %+v %v", bare, err)
	}
}

func TestParseInlineRequest(t *testing.T) {
	uri := "openid4vp://?client_id=https%3A%2F%2Fverifier.example&nonce=n-1" +
		"&response_uri=https%3A%2F%2Fverifier.example%2Fdirect_post&state=s-1" +
		"&dcql_query=" + url.QueryEscape(dcqlQuery)
	got, err := present.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	if got.Nonce != "n-1" || got.ResponseURI != "https://verifier.example/direct_post" {
		t.Fatalf("request = %+v", got)
	}
	if len(got.Query.Credentials) != 1 || got.Query.Credentials[0].Type() != "DriverLicence" {
		t.Fatalf("query = %+v", got.Query)
	}
	if got.ResponseMode != present.ResponseModeDirectPost {
		t.Fatalf("response mode = %q", got.ResponseMode)
	}
	fromObject, err := present.Parse(string(object(nil)))
	if err != nil || fromObject.Nonce != "n-1" {
		t.Fatalf("object = %+v %v", fromObject, err)
	}
}

func TestParseRejects(t *testing.T) {
	if _, err := present.Parse("  "); !errors.Is(err, present.ErrBadRequest) {
		t.Fatalf("empty: %v", err)
	}
	if _, err := present.Parse("openid4vp://?dcql_query=%7Boops"); !errors.Is(err, present.ErrBadRequest) {
		t.Fatalf("broken query: %v", err)
	}
	if _, err := present.Parse("openid4vp://?nonce=n"); !errors.Is(err, present.ErrBadRequest) {
		t.Fatalf("no credential: %v", err)
	}
	noNonce := object(map[string]any{"nonce": nil})
	if _, err := present.ParseObject(noNonce); !errors.Is(err, present.ErrBadRequest) {
		t.Fatalf("no nonce: %v", err)
	}
	fragment := object(map[string]any{"response_mode": "fragment"})
	if _, err := present.ParseObject(fragment); !errors.Is(err, present.ErrNotSupported) {
		t.Fatalf("fragment: %v", err)
	}
	badDCQL := object(map[string]any{"dcql_query": map[string]any{"credentials": "no"}})
	if _, err := present.ParseObject(badDCQL); !errors.Is(err, present.ErrBadRequest) {
		t.Fatalf("bad dcql: %v", err)
	}
	if _, err := present.ParseObject([]byte("{oops")); !errors.Is(err, present.ErrBadRequest) {
		t.Fatalf("broken object: %v", err)
	}
	if _, err := present.ParseObject([]byte("not a jwt")); !errors.Is(err, present.ErrBadRequest) {
		t.Fatalf("not a jwt: %v", err)
	}
	if _, err := present.Parse("openid4vp://%zz?a=b"); !errors.Is(err, present.ErrBadRequest) {
		t.Fatalf("broken uri: %v", err)
	}
}

func TestAllowHost(t *testing.T) {
	hosts := []string{"verifier.example", " Other.Example "}
	if err := present.AllowHost("https://verifier.example/r/1", hosts); err != nil {
		t.Fatal(err)
	}
	if err := present.AllowHost("https://OTHER.example/r/1", hosts); err != nil {
		t.Fatal(err)
	}
	if err := present.AllowHost("https://attacker.example/r/1", hosts); !errors.Is(err, present.ErrHostNotAllowed) {
		t.Fatalf("other host: %v", err)
	}
	if err := present.AllowHost("file:///etc/passwd", hosts); !errors.Is(err, present.ErrHostNotAllowed) {
		t.Fatalf("file: %v", err)
	}
	if err := present.AllowHost("https://verifier.example/r/1", nil); !errors.Is(err, present.ErrHostNotAllowed) {
		t.Fatalf("empty allowlist: %v", err)
	}
	if err := present.AllowHost("http://%zz", hosts); !errors.Is(err, present.ErrBadRequest) {
		t.Fatalf("broken uri: %v", err)
	}
}

func TestFetch(t *testing.T) {
	hosts := []string{"verifier.example"}
	start := present.Request{RequestURI: "https://verifier.example/r/1", ClientID: "https://verifier.example"}
	got, err := present.Fetch(context.Background(), start, hosts,
		func(_ context.Context, url string) ([]byte, error) {
			if url != start.RequestURI {
				t.Fatalf("url = %q", url)
			}
			return object(map[string]any{"client_id": nil}), nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if got.ClientID != "https://verifier.example" || got.RequestURI != start.RequestURI {
		t.Fatalf("request = %+v", got)
	}
	inline := present.Request{Nonce: "n"}
	if same, err := present.Fetch(context.Background(), inline, hosts, nil); err != nil || same.Nonce != "n" {
		t.Fatalf("inline = %+v %v", same, err)
	}
	if _, err := present.Fetch(context.Background(), start, nil, nil); !errors.Is(err, present.ErrHostNotAllowed) {
		t.Fatalf("host: %v", err)
	}
	if _, err := present.Fetch(context.Background(), start, hosts, nil); !errors.Is(err, present.ErrNotSupported) {
		t.Fatalf("no fetcher: %v", err)
	}
	down := func(context.Context, string) ([]byte, error) { return nil, errors.New("down") }
	if _, err := present.Fetch(context.Background(), start, hosts, down); err == nil {
		t.Fatal("want a fetch error")
	}
	broken := func(context.Context, string) ([]byte, error) { return []byte("{oops"), nil }
	if _, err := present.Fetch(context.Background(), start, hosts, broken); !errors.Is(err, present.ErrBadRequest) {
		t.Fatalf("broken object: %v", err)
	}
}

func TestParseObjectReadsSignedRequest(t *testing.T) {
	key, err := jose.GenerateKey(jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(object(nil), &claims); err != nil {
		t.Fatal(err)
	}
	signed, err := jose.Sign(key, "k1", "oauth-authz-req+jwt", claims)
	if err != nil {
		t.Fatal(err)
	}
	got, err := present.ParseObject([]byte(signed))
	if err != nil {
		t.Fatal(err)
	}
	if got.Nonce != "n-1" || got.State != "s-1" {
		t.Fatalf("request = %+v", got)
	}
}

const definition = `{"id":"pd-1","purpose":"Prove your age",
"input_descriptors":[{"id":"licence","name":"Licence","format":{"vc+sd-jwt":{}},
"constraints":{"fields":[{"path":["$.vct"],"filter":{"pattern":"DriverLicence"}},
{"path":["$.credentialSubject.given_name","$.given_name"]},{"path":[""]},{"path":["$.a[b"]}]}}]}`

func TestParseObjectReadsPresentationExchange(t *testing.T) {
	var def any
	if err := json.Unmarshal([]byte(definition), &def); err != nil {
		t.Fatal(err)
	}
	raw := object(map[string]any{"dcql_query": nil, "presentation_definition": def})
	got, err := present.ParseObject(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.DefinitionID != "pd-1" || got.Purpose != "Prove your age" {
		t.Fatalf("request = %+v", got)
	}
	if len(got.Query.Credentials) != 1 {
		t.Fatalf("query = %+v", got.Query)
	}
	cq := got.Query.Credentials[0]
	if cq.Type() != "DriverLicence" || cq.Format != "vc+sd-jwt" {
		t.Fatalf("credential query = %+v", cq)
	}
	if len(cq.Claims) != 1 || cq.Claims[0].Path.String() != "given_name" {
		t.Fatalf("claims = %+v", cq.Claims)
	}
}

func TestParseObjectRejectsEmptyDefinition(t *testing.T) {
	empty := object(map[string]any{"dcql_query": nil,
		"presentation_definition": map[string]any{"id": "pd", "input_descriptors": []any{}}})
	if _, err := present.ParseObject(empty); !errors.Is(err, present.ErrBadRequest) {
		t.Fatalf("empty definition: %v", err)
	}
	broken := object(map[string]any{"dcql_query": nil, "presentation_definition": "not an object"})
	if _, err := present.ParseObject(broken); !errors.Is(err, present.ErrBadRequest) {
		t.Fatalf("broken definition: %v", err)
	}
	noFormat := `{"id":"pd","input_descriptors":[{"id":"a","constraints":{"fields":[]}}]}`
	var def any
	if err := json.Unmarshal([]byte(noFormat), &def); err != nil {
		t.Fatal(err)
	}
	got, err := present.ParseObject(object(map[string]any{"dcql_query": nil, "presentation_definition": def}))
	if err != nil {
		t.Fatal(err)
	}
	if got.Query.Credentials[0].Format != dcql.FormatSDJWT {
		t.Fatalf("format = %q", got.Query.Credentials[0].Format)
	}
}

// card builds one card for the consent tests.
func card(id, credType string, format commonv1.Format, claims map[string]string) *walletportalv1.Card {
	return &walletportalv1.Card{Id: id, Type: credType, Format: format, Claims: claims}
}

func TestConsentListsEveryClaim(t *testing.T) {
	req, err := present.ParseObject(object(nil))
	if err != nil {
		t.Fatal(err)
	}
	held := []*walletportalv1.Card{
		card("c1", "DriverLicence", commonv1.Format_FORMAT_DC_SD_JWT,
			map[string]string{"given_name": "Ada", "birth_date": "1990-01-01", "secret": "hidden"}),
		card("c2", "Passport", commonv1.Format_FORMAT_DC_SD_JWT, nil),
	}
	entries := present.Consent(req, held)
	if len(entries) != 1 {
		t.Fatalf("entries = %d", len(entries))
	}
	entry := entries[0]
	if entry.GetQueryId() != "licence" || entry.GetType() != "DriverLicence" {
		t.Fatalf("entry = %+v", entry)
	}
	if len(entry.GetMatches()) != 1 || entry.GetMatches()[0].GetId() != "c1" {
		t.Fatalf("matches = %+v", entry.GetMatches())
	}
	if len(entry.GetClaims()) != 2 {
		t.Fatalf("claims = %+v", entry.GetClaims())
	}
	values := map[string]string{}
	for _, c := range entry.GetClaims() {
		values[c.GetPath()] = c.GetValue()
		if !c.GetMandatory() {
			t.Fatalf("claim %s must be mandatory", c.GetPath())
		}
	}
	if values["given_name"] != "Ada" || values["birth_date"] != "1990-01-01" {
		t.Fatalf("values = %v", values)
	}
	if names := present.ClaimNames(entry); len(names) != 2 {
		t.Fatalf("names = %v", names)
	}
	if got := present.Summary(entries); got != "The verifier asks for one credential and 2 fields." {
		t.Fatalf("summary = %q", got)
	}
}

func TestConsentWithoutMatches(t *testing.T) {
	req, err := present.ParseObject(object(nil))
	if err != nil {
		t.Fatal(err)
	}
	entries := present.Consent(req, nil)
	if len(entries[0].GetMatches()) != 0 || entries[0].GetClaims()[0].GetValue() != "" {
		t.Fatalf("entry = %+v", entries[0])
	}
	if got := present.Summary(nil); got != "The verifier asks for no credential." {
		t.Fatalf("summary = %q", got)
	}
	two := append(entries, entries[0])
	if !strings.Contains(present.Summary(two), "2 credentials") {
		t.Fatalf("summary = %q", present.Summary(two))
	}
}

func TestMatchesIgnoresFormatWhenUnknown(t *testing.T) {
	cq := dcql.CredentialQuery{ID: "a", Format: dcql.FormatSDJWT,
		Meta: &dcql.Meta{VctValues: []string{"DriverLicence"}}}
	held := []*walletportalv1.Card{
		card("c1", "DriverLicence", commonv1.Format_FORMAT_UNSPECIFIED, nil),
		card("c2", "DriverLicence", commonv1.Format_FORMAT_LDP_VC, nil),
	}
	if got := present.Matches(cq, held); len(got) != 1 || got[0].GetId() != "c1" {
		t.Fatalf("matches = %+v", got)
	}
	any := dcql.CredentialQuery{ID: "a"}
	if got := present.Matches(any, held); len(got) != 2 {
		t.Fatalf("matches = %+v", got)
	}
}

func TestValueOfNestedPath(t *testing.T) {
	req, err := present.Parse("openid4vp://?client_id=v&nonce=n&response_uri=https%3A%2F%2Fv.example%2Fp" +
		"&dcql_query=" + url.QueryEscape(`{"credentials":[{"id":"a","format":"dc+sd-jwt",
"meta":{"vct_values":["Address"]},"claims":[{"path":["address","street"]}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	held := []*walletportalv1.Card{card("c1", "Address", commonv1.Format_FORMAT_DC_SD_JWT,
		map[string]string{"street": "Main road"})}
	entries := present.Consent(req, held)
	if got := entries[0].GetClaims()[0].GetValue(); got != "Main road" {
		t.Fatalf("value = %q", got)
	}
}

func TestFormatMapping(t *testing.T) {
	pairs := map[string]commonv1.Format{
		dcql.FormatSDJWT:       commonv1.Format_FORMAT_DC_SD_JWT,
		dcql.FormatSDJWTLegacy: commonv1.Format_FORMAT_VC_SD_JWT,
		dcql.FormatJWTVCJSON:   commonv1.Format_FORMAT_JWT_VC_JSON,
		dcql.FormatLDPVC:       commonv1.Format_FORMAT_LDP_VC,
		dcql.FormatMdoc:        commonv1.Format_FORMAT_MSO_MDOC,
		"other":                commonv1.Format_FORMAT_UNSPECIFIED,
	}
	for name, want := range pairs {
		if got := present.FormatOf(name); got != want {
			t.Fatalf("%s = %v", name, got)
		}
		if name != "other" && present.FormatName(want) != name {
			t.Fatalf("%v = %q", want, present.FormatName(want))
		}
	}
	if present.FormatName(commonv1.Format_FORMAT_UNSPECIFIED) != "" {
		t.Fatal("want an empty format name")
	}
}

// sdjwtToken builds a small SD-JWT with two disclosures.
func sdjwtToken(t *testing.T) string {
	t.Helper()
	head := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256"}`))
	body := base64.RawURLEncoding.EncodeToString([]byte(`{"vct":"DriverLicence"}`))
	given := base64.RawURLEncoding.EncodeToString([]byte(`["salt1","given_name","Ada"]`))
	birth := base64.RawURLEncoding.EncodeToString([]byte(`["salt2","birth_date","1990-01-01"]`))
	element := base64.RawURLEncoding.EncodeToString([]byte(`["salt3","element"]`))
	return head + "." + body + ".sig~" + given + "~" + birth + "~" + element + "~"
}

func TestDisclosedKeepsOnlyAgreedClaims(t *testing.T) {
	token := sdjwtToken(t)
	got, err := present.Disclosed(token, []string{"given_name"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(got, "~") != 3 {
		t.Fatalf("token = %q", got)
	}
	if !strings.Contains(got, base64.RawURLEncoding.EncodeToString([]byte(`["salt1","given_name","Ada"]`))) {
		t.Fatal("want the agreed disclosure")
	}
	if strings.Contains(got, base64.RawURLEncoding.EncodeToString([]byte(`["salt2","birth_date","1990-01-01"]`))) {
		t.Fatal("want no disclosure the citizen did not agree to")
	}
	nested, err := present.Disclosed(token, []string{"address.birth_date"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(nested, base64.RawURLEncoding.EncodeToString([]byte(`["salt2","birth_date","1990-01-01"]`))) {
		t.Fatal("want the nested claim name to match")
	}
	if _, err := present.Disclosed("not a token", nil); !errors.Is(err, present.ErrBadRequest) {
		t.Fatalf("bad token: %v", err)
	}
}

func TestSubmit(t *testing.T) {
	req := present.Request{ResponseURI: "https://verifier.example/direct_post", State: "s-1"}
	var seen url.Values
	got, err := present.Submit(context.Background(), req, "vp-token",
		func(_ context.Context, url string, form url.Values) ([]byte, error) {
			if url != req.ResponseURI {
				t.Fatalf("url = %q", url)
			}
			seen = form
			return []byte(`{"redirect_uri":"https://verifier.example/done"}`), nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if seen.Get("vp_token") != "vp-token" || seen.Get("state") != "s-1" {
		t.Fatalf("form = %v", seen)
	}
	if !got.Accepted || got.RedirectURI != "https://verifier.example/done" {
		t.Fatalf("result = %+v", got)
	}
	if !strings.Contains(got.Message, "You sent the credential") {
		t.Fatalf("message = %q", got.Message)
	}
	plain, err := present.Submit(context.Background(), present.Request{ResponseURI: "u"}, "t",
		func(context.Context, string, url.Values) ([]byte, error) { return []byte("ok"), nil })
	if err != nil || plain.RedirectURI != "" {
		t.Fatalf("plain = %+v %v", plain, err)
	}
}

func TestSubmitRejects(t *testing.T) {
	req := present.Request{ResponseURI: "https://verifier.example/direct_post"}
	if _, err := present.Submit(context.Background(), req, "t", nil); !errors.Is(err, present.ErrNotSupported) {
		t.Fatalf("no poster: %v", err)
	}
	post := func(context.Context, string, url.Values) ([]byte, error) { return nil, nil }
	if _, err := present.Submit(context.Background(), req, " ", post); !errors.Is(err, present.ErrBadRequest) {
		t.Fatalf("no token: %v", err)
	}
	down := func(context.Context, string, url.Values) ([]byte, error) { return nil, errors.New("down") }
	got, err := present.Submit(context.Background(), req, "t", down)
	if err == nil || got.Accepted {
		t.Fatalf("down = %+v %v", got, err)
	}
	if !strings.Contains(got.Message, "did not take the credential") {
		t.Fatalf("message = %q", got.Message)
	}
}

func TestTrustOf(t *testing.T) {
	lookup := func(context.Context, string, string) (cards.Trust, error) {
		return cards.Trust{Outcome: trustv1.TrustLookupResponse_OUTCOME_TRUSTED, Name: "Bank"}, nil
	}
	got := present.TrustOf(context.Background(), lookup, "https://verifier.example")
	if got.Name != "Bank" {
		t.Fatalf("trust = %+v", got)
	}
	if present.TrustOf(context.Background(), nil, "x").Name != "" {
		t.Fatal("want no trust without a lookup")
	}
	if present.TrustOf(context.Background(), lookup, "").Name != "" {
		t.Fatal("want no trust without a client id")
	}
	down := func(context.Context, string, string) (cards.Trust, error) {
		return cards.Trust{}, errors.New("down")
	}
	if present.TrustOf(context.Background(), down, "x").Name != "" {
		t.Fatal("want no trust after an error")
	}
}
