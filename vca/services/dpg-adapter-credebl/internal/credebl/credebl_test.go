// SPDX-License-Identifier: Apache-2.0

package credebl

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/internal/dpgclient"
)

// fixedSalt is the salt the tests use, so the cipher text never changes.
var fixedSalt = []byte{1, 2, 3, 4, 5, 6, 7, 8}

// newClient returns a client for the server without a retry wait.
func newClient(srv *httptest.Server, change func(*Options)) *Client {
	opts := Options{
		HTTP: dpgclient.New(dpgclient.Options{
			BaseURL: srv.URL, HTTP: srv.Client(), Retries: -1, Sleep: func(time.Duration) {},
		}),
		Account:    Account{Email: "admin@example.org", Password: "secret", CryptoKey: "key"},
		OrgID:      "org-1",
		IssuerID:   "issuer-1",
		RandomSalt: func() ([]byte, error) { return fixedSalt, nil },
	}
	if change != nil {
		change(&opts)
	}
	return New(opts)
}

func TestNewWithoutATransportTurnsEveryRoleOff(t *testing.T) {
	if New(Options{}) != nil {
		t.Fatal("a missing transport must turn every role off")
	}
	var c *Client
	ctx := context.Background()
	if c.OrgID() != "" || c.IssuerID() != "" || c.BaseURL() != "" {
		t.Fatal("a missing client has no names")
	}
	if _, err := c.Token(ctx); !errors.Is(err, ErrNoPlatform) {
		t.Fatalf("Token error = %v", err)
	}
	if _, err := c.Templates(ctx); !errors.Is(err, ErrNoPlatform) {
		t.Fatalf("Templates error = %v", err)
	}
	if _, err := c.CreateOffer(ctx, "t", "", nil, false); !errors.Is(err, ErrNoPlatform) {
		t.Fatalf("CreateOffer error = %v", err)
	}
	if _, err := c.CreateSchema(ctx, "n", "d", nil); !errors.Is(err, ErrNoPlatform) {
		t.Fatalf("CreateSchema error = %v", err)
	}
	if _, err := c.CreateTemplate(ctx, "n", "f", "v", nil); !errors.Is(err, ErrNoPlatform) {
		t.Fatalf("CreateTemplate error = %v", err)
	}
	if _, err := c.CreatePresentation(ctx, "v", DcqlQuery{}); !errors.Is(err, ErrNoPlatform) {
		t.Fatalf("CreatePresentation error = %v", err)
	}
	if _, err := c.Presentation(ctx, "s"); !errors.Is(err, ErrNoPlatform) {
		t.Fatalf("Presentation error = %v", err)
	}
	if _, err := c.EnsureVerifier(ctx, "n", ""); !errors.Is(err, ErrNoPlatform) {
		t.Fatalf("EnsureVerifier error = %v", err)
	}
}

func TestEncryptPasswordMatchesTheCryptoJsForm(t *testing.T) {
	got, err := EncryptPassword("secret", "key", fixedSalt)
	if err != nil {
		t.Fatalf("EncryptPassword: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(got)
	if err != nil {
		t.Fatalf("the value is not base64: %v", err)
	}
	if string(raw[:8]) != "Salted__" {
		t.Fatalf("the value has no OpenSSL marker: %q", raw[:8])
	}
	if string(raw[8:16]) != string(fixedSalt) {
		t.Fatal("the value does not carry the salt")
	}
	// The decryption gives the JSON form of the password.
	key, iv := deriveKey([]byte("key"), fixedSalt, 32, 16)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	plain := make([]byte, len(raw)-16)
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, raw[16:])
	padding := int(plain[len(plain)-1])
	if string(plain[:len(plain)-padding]) != `"secret"` {
		t.Fatalf("plain text = %q, CryptoJS encrypts the JSON form", plain)
	}
}

func TestEncryptPasswordNeedsAnEightByteSalt(t *testing.T) {
	if _, err := EncryptPassword("s", "k", []byte{1}); err == nil {
		t.Fatal("EncryptPassword accepted a short salt")
	}
}

func TestTokenExpiryReadsTheClaim(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"exp":1777000000}`))
	if got := TokenExpiry("h." + payload + ".s"); got.Unix() != 1777000000 {
		t.Fatalf("expiry = %v", got)
	}
	for _, bad := range []string{"", "a.b", "h.!!!.s", "h." + base64.RawURLEncoding.EncodeToString([]byte(`{}`)) + ".s"} {
		if got := TokenExpiry(bad); !got.IsZero() {
			t.Fatalf("TokenExpiry(%q) = %v, want the zero time", bad, got)
		}
	}
}

func TestTokenSignsInOnceAndCachesTheAnswer(t *testing.T) {
	calls := 0
	// The token ends far in the future, so the cache holds.
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"exp":4070908800}`))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/signin" {
			calls++
		}
		mustWrite(t, w, []byte(`{"data":{"access_token":"h.`+payload+`.s"}}`))
	}))
	defer srv.Close()
	c := newClient(srv, nil)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := c.Token(ctx); err != nil {
			t.Fatalf("Token: %v", err)
		}
	}
	if calls != 1 {
		t.Fatalf("sign in calls = %d, want 1", calls)
	}
	c.Forget()
	if _, err := c.Token(ctx); err != nil {
		t.Fatalf("Token: %v", err)
	}
	if calls != 2 {
		t.Fatalf("sign in calls = %d, want 2 after Forget", calls)
	}
}

func TestTokenUsesAnHourWhenTheTokenNamesNoEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mustWrite(t, w, []byte(`{"data":{"access_token":"opaque"}}`))
	}))
	defer srv.Close()
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	c := newClient(srv, func(o *Options) { o.Now = func() time.Time { return now } })
	if _, err := c.Token(context.Background()); err != nil {
		t.Fatalf("Token: %v", err)
	}
	if c.expires.Sub(now) != time.Hour {
		t.Fatalf("the token ends after %v, want one hour", c.expires.Sub(now))
	}
}

func TestTokenReportsAnEmptyAnswerAndAFailure(t *testing.T) {
	body := `{"data":{"access_token":""}}`
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		mustWrite(t, w, []byte(body))
	}))
	defer srv.Close()
	c := newClient(srv, nil)
	if _, err := c.Token(context.Background()); err == nil {
		t.Fatal("Token accepted an empty access token")
	}
	status = http.StatusForbidden
	if _, err := c.Token(context.Background()); err == nil {
		t.Fatal("Token accepted a failure")
	}
}

func TestTokenReportsAFailedSalt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	c := newClient(srv, func(o *Options) {
		o.RandomSalt = func() ([]byte, error) { return nil, errors.New("no entropy") }
	})
	if _, err := c.Token(context.Background()); err == nil {
		t.Fatal("Token accepted a failed salt")
	}
}

func TestACallSignsInAgainAfterAnUnauthorizedAnswer(t *testing.T) {
	signins, calls := 0, 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/signin" {
			signins++
			mustWrite(t, w, []byte(`{"data":{"access_token":"t"}}`))
			return
		}
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		mustWrite(t, w, []byte(`{"data":[]}`))
	}))
	defer srv.Close()
	c := newClient(srv, nil)
	if _, err := c.Templates(context.Background()); err != nil {
		t.Fatalf("Templates: %v", err)
	}
	if signins != 2 || calls != 2 {
		t.Fatalf("sign ins = %d calls = %d; a stale token must make one new sign in", signins, calls)
	}
}

func TestACallGivesUpAfterTwoUnauthorizedAnswers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/signin" {
			mustWrite(t, w, []byte(`{"data":{"access_token":"t"}}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	if _, err := newClient(srv, nil).Templates(context.Background()); err == nil {
		t.Fatal("the call accepted two refusals")
	}
}

func TestTemplatesReadTheAttributesColumn(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/signin" {
			mustWrite(t, w, []byte(`{"data":{"access_token":"t"}}`))
			return
		}
		if r.URL.Path != "/v1/orgs/org-1/oid4vc/issuer-1/template" {
			t.Errorf("path = %q", r.URL.Path)
		}
		mustWrite(t, w, []byte(`{"data":[{"id":"t-1","name":"Farmer","format":"dc+sd-jwt",
          "attributes":{"vct":"https://v.example/vct","attributes":[
            {"key":"fullName","value_type":"string","disclose":true}]}}]}`))
	}))
	defer srv.Close()
	got, err := newClient(srv, nil).Templates(context.Background())
	if err != nil {
		t.Fatalf("Templates: %v", err)
	}
	if len(got) != 1 || got[0].Body.Vct != "https://v.example/vct" {
		t.Fatalf("templates = %+v", got)
	}
	if len(got[0].Body.Attributes) != 1 || !got[0].Body.Attributes[0].Disclose {
		t.Fatalf("attributes = %+v", got[0].Body.Attributes)
	}
}

func TestCreateOfferSendsThePreAuthorizedType(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/signin" {
			mustWrite(t, w, []byte(`{"data":{"access_token":"t"}}`))
			return
		}
		if cerr := json.NewDecoder(r.Body).Decode(&body); cerr != nil {
			t.Fatalf("unexpected error: %v", cerr)
		}
		mustWrite(t, w, []byte(`{"data":{"credentialOffer":"openid-credential-offer://x",
          "issuanceSession":{"id":"s-1","userPin":"1234"}}}`))
	}))
	defer srv.Close()
	got, err := newClient(srv, nil).CreateOffer(context.Background(), "t-1", "0000",
		map[string]any{"fullName": "Ada"}, false)
	if err != nil {
		t.Fatalf("CreateOffer: %v", err)
	}
	if got.SessionID != "s-1" || got.PIN != "1234" {
		t.Fatalf("offer = %+v", got)
	}
	if body["authorizationType"] != "preAuthorizedCodeFlow" {
		t.Fatalf("body = %v", body)
	}
	credentials := mustAs[[]any](t, body["credentials"])
	first := mustAs[map[string]any](t, credentials[0])
	if first["templateId"] != "t-1" {
		t.Fatalf("credentials = %v", credentials)
	}
	payload := mustAs[map[string]any](t, first["payload"])
	if payload["fullName"] != "Ada" {
		t.Fatalf("payload = %v", payload)
	}
	if _, ok := payload["id"]; ok {
		t.Fatal("an extra claim makes the template check fail")
	}
}

func TestCreateOfferChecksItsInputAndTheAnswer(t *testing.T) {
	body := `{"data":{"credentialOffer":""}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/signin" {
			mustWrite(t, w, []byte(`{"data":{"access_token":"t"}}`))
			return
		}
		mustWrite(t, w, []byte(body))
	}))
	defer srv.Close()
	c := newClient(srv, nil)
	if _, err := c.CreateOffer(context.Background(), "  ", "", nil, false); err == nil {
		t.Fatal("CreateOffer accepted an empty template id")
	}
	if _, err := c.CreateOffer(context.Background(), "t-1", "", nil, false); err == nil {
		t.Fatal("CreateOffer accepted an empty offer")
	}
}

func TestRewritePublic(t *testing.T) {
	uri := "openid-credential-offer://?credential_offer_uri=http://credebl-agent:8001/offers/1"
	got := RewritePublic(uri, "http://credebl-agent:8001", "https://credebl.example.org")
	if !strings.Contains(got, "https://credebl.example.org/offers/1") {
		t.Fatalf("uri = %q", got)
	}
	if RewritePublic(uri, "", "https://x") != uri {
		t.Fatal("a missing internal host changes nothing")
	}
	if RewritePublic(uri, "http://x", "") != uri {
		t.Fatal("a missing public host changes nothing")
	}
}

func TestCreateSchemaAndTemplateReadTheIdentifier(t *testing.T) {
	body := `{"data":{"id":"","schemaId":"","schemaLedgerId":"ledger-1"}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/signin" {
			mustWrite(t, w, []byte(`{"data":{"access_token":"t"}}`))
			return
		}
		mustWrite(t, w, []byte(body))
	}))
	defer srv.Close()
	c := newClient(srv, nil)
	got, err := c.CreateSchema(context.Background(), "Farmer", "a farmer",
		[]Attribute{{Key: "fullName", ValueType: "string"}})
	if err != nil || got != "ledger-1" {
		t.Fatalf("CreateSchema = %q, %v", got, err)
	}
	body = `{"data":{}}`
	if _, serr := c.CreateSchema(context.Background(), "Farmer", "", nil); serr == nil {
		t.Fatal("CreateSchema accepted an answer without an identifier")
	}
	if _, serr := c.CreateTemplate(context.Background(), "Farmer", "dc+sd-jwt", "v", nil); serr == nil {
		t.Fatal("CreateTemplate accepted an answer without an identifier")
	}
	body = `{"data":{"id":"tpl-1"}}`
	tpl, err := c.CreateTemplate(context.Background(), "Farmer", "dc+sd-jwt", "v", nil)
	if err != nil || tpl != "tpl-1" {
		t.Fatalf("CreateTemplate = %q, %v", tpl, err)
	}
}

func TestFindTemplateMatchesTheNameOrTheIdentifier(t *testing.T) {
	list := []Template{{ID: "t-1", Name: "Farmer"}}
	if _, ok := FindTemplate(list, "Farmer"); !ok {
		t.Fatal("the name must match")
	}
	if _, ok := FindTemplate(list, "t-1"); !ok {
		t.Fatal("the identifier must match")
	}
	if _, ok := FindTemplate(list, "other"); ok {
		t.Fatal("an unknown name must not match")
	}
}

// The enums of the schema body of the api gateway, read on 2026-09-27
// from libs/enum/src/enum.ts of the platform (testdata/doc/SOURCE.md):
// the type of GenericSchemaDTO, the schemaType of CreateW3CSchemaDto,
// and the schemaDataType of W3CAttributeValue.
var (
	platformSchemaTypes     = []string{"json", "indy"}
	platformJSONSchemaTypes = []string{"polygon", "no_ledger"}
	platformW3CDataTypes    = []string{"number", "integer", "string", "datetime-local", "array", "object", "boolean"}
)

// TestCreateSchemaSendsTheSchemaTypeOfThePlatform: the schema of an
// SD-JWT template is a W3C schema of the type json. Its schemaType must
// be a value of the JSONSchemaType enum; the platform refuses "json".
// The stack runs no Polygon ledger, so the value is no_ledger. The
// description must not be empty, and each data type is a value of the
// W3C enum.
func TestCreateSchemaSendsTheSchemaTypeOfThePlatform(t *testing.T) {
	var sent []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/signin" {
			mustWrite(t, w, []byte(`{"data":{"access_token":"t"}}`))
			return
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read the body: %v", err)
		}
		sent = raw
		mustWrite(t, w, []byte(`{"data":{"schemaLedgerId":"http://credebl-schema-file-server:4000/schemas/s-1"}}`))
	}))
	defer srv.Close()
	c := newClient(srv, nil)
	if _, err := c.CreateSchema(context.Background(), "FarmerCredential", "",
		[]Attribute{{Key: "fullName", ValueType: "string"}, {Key: "acres", ValueType: "number"}, {Key: "notes", ValueType: "null"}}); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	var body struct {
		Type    string `json:"type"`
		Payload struct {
			SchemaName  string `json:"schemaName"`
			SchemaType  string `json:"schemaType"`
			Description string `json:"description"`
			Attributes  []struct {
				AttributeName  string `json:"attributeName"`
				SchemaDataType string `json:"schemaDataType"`
				DisplayName    string `json:"displayName"`
			} `json:"attributes"`
		} `json:"schemaPayload"`
	}
	if err := json.Unmarshal(sent, &body); err != nil {
		t.Fatalf("the body %s: %v", sent, err)
	}
	if !contains(platformSchemaTypes, body.Type) || body.Type != "json" {
		t.Errorf("type = %q, want json", body.Type)
	}
	if !contains(platformJSONSchemaTypes, body.Payload.SchemaType) || body.Payload.SchemaType != "no_ledger" {
		t.Errorf("schemaType = %q, want no_ledger of %v", body.Payload.SchemaType, platformJSONSchemaTypes)
	}
	if body.Payload.Description == "" {
		t.Error("the description is empty; the platform needs one")
	}
	if len(body.Payload.Attributes) != 3 {
		t.Fatalf("attributes = %+v", body.Payload.Attributes)
	}
	for _, a := range body.Payload.Attributes {
		if !contains(platformW3CDataTypes, a.SchemaDataType) || a.DisplayName == "" {
			t.Errorf("attribute %+v breaks the W3C enum of the platform", a)
		}
	}
}

func contains(list []string, value string) bool {
	for _, v := range list {
		if v == value {
			return true
		}
	}
	return false
}
