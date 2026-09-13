// SPDX-License-Identifier: Apache-2.0

package credebl

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	if _, err := c.CreateOffer(ctx, "t", "", nil); !errors.Is(err, ErrNoPlatform) {
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
		_, _ = w.Write([]byte(`{"data":{"access_token":"h.` + payload + `.s"}}`))
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
		_, _ = w.Write([]byte(`{"data":{"access_token":"opaque"}}`))
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
		_, _ = w.Write([]byte(body))
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
			_, _ = w.Write([]byte(`{"data":{"access_token":"t"}}`))
			return
		}
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"data":[]}`))
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
			_, _ = w.Write([]byte(`{"data":{"access_token":"t"}}`))
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
			_, _ = w.Write([]byte(`{"data":{"access_token":"t"}}`))
			return
		}
		if r.URL.Path != "/v1/orgs/org-1/oid4vc/issuer-1/template" {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"data":[{"id":"t-1","name":"Farmer","format":"dc+sd-jwt",
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
			_, _ = w.Write([]byte(`{"data":{"access_token":"t"}}`))
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, _ = w.Write([]byte(`{"data":{"credentialOffer":"openid-credential-offer://x",
          "issuanceSession":{"id":"s-1","userPin":"1234"}}}`))
	}))
	defer srv.Close()
	got, err := newClient(srv, nil).CreateOffer(context.Background(), "t-1", "0000",
		map[string]any{"fullName": "Ada"})
	if err != nil {
		t.Fatalf("CreateOffer: %v", err)
	}
	if got.SessionID != "s-1" || got.PIN != "1234" {
		t.Fatalf("offer = %+v", got)
	}
	if body["authorizationType"] != "preAuthorizedCodeFlow" {
		t.Fatalf("body = %v", body)
	}
	credentials, _ := body["credentials"].([]any)
	first, _ := credentials[0].(map[string]any)
	if first["templateId"] != "t-1" {
		t.Fatalf("credentials = %v", credentials)
	}
	payload, _ := first["payload"].(map[string]any)
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
			_, _ = w.Write([]byte(`{"data":{"access_token":"t"}}`))
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	c := newClient(srv, nil)
	if _, err := c.CreateOffer(context.Background(), "  ", "", nil); err == nil {
		t.Fatal("CreateOffer accepted an empty template id")
	}
	if _, err := c.CreateOffer(context.Background(), "t-1", "", nil); err == nil {
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
			_, _ = w.Write([]byte(`{"data":{"access_token":"t"}}`))
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	c := newClient(srv, nil)
	got, err := c.CreateSchema(context.Background(), "Farmer", "a farmer",
		[]Attribute{{Key: "fullName", ValueType: "string"}})
	if err != nil || got != "ledger-1" {
		t.Fatalf("CreateSchema = %q, %v", got, err)
	}
	body = `{"data":{}}`
	if _, err := c.CreateSchema(context.Background(), "Farmer", "", nil); err == nil {
		t.Fatal("CreateSchema accepted an answer without an identifier")
	}
	if _, err := c.CreateTemplate(context.Background(), "Farmer", "dc+sd-jwt", "v", nil); err == nil {
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
