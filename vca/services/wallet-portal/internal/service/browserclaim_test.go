// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/sdjwt"
	walletportalv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/ports"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/service"
)

// The addresses of the issuer that the browser store claims from.
const (
	claimIssuer   = "https://issuer.example"
	claimOfferURI = "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffers%2F1"
	claimToken    = claimIssuer + "/token"
	claimEndpoint = claimIssuer + "/credential"
)

// browserHolder is the signing key of the browser, as wallet.js keeps
// it, and its public JWK as the page sends it.
type browserHolder struct {
	key *ecdsa.PrivateKey
	jwk string
}

func newBrowserHolder(t *testing.T) browserHolder {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := jose.PublicJWK(key.Public(), "")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(pub)
	if err != nil {
		t.Fatal(err)
	}
	return browserHolder{key: key, jwk: string(raw)}
}

// sign signs a signing input as WebCrypto does, in the raw r and s form.
func (b browserHolder) sign(t *testing.T, input string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, b.key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return base64.RawURLEncoding.EncodeToString(sig)
}

// claimStack answers as an OID4VCI issuer with a pre-authorized offer.
// Its credential endpoint checks the proof and binds the credential to
// the key of the proof, as an issuer does.
type claimStack struct {
	t        *testing.T
	issuer   crypto.PrivateKey
	offer    string
	metadata string
	tokens   []url.Values
	requests []map[string]any
	// tokenErr and credErr fail the two endpoints.
	tokenErr, credErr error
	// answer shapes the credential answer: "" for draft 13, "list" for
	// the credentials list of OID4VCI 1.0.
	answer string
	// version10 makes the credential endpoint take only the proofs
	// object of OID4VCI 1.0 section 8.2, as an issuer of that version
	// does. Else it takes only the proof of draft 13.
	version10 bool
	// posted is the direct_post answer of a presentation.
	posted url.Values
	// freshNonce makes the verifier hand each read of its request a new
	// nonce, as a verifier that signs the request at each read does.
	freshNonce bool
	// fetches counts the reads of the request of the verifier.
	fetches int
	// issue makes the credential for the key of the proof. Nil makes
	// the SD-JWT VC of the driver licence.
	issue func(jwk map[string]any) string
}

func newClaimStack(t *testing.T) *claimStack {
	t.Helper()
	issuer, err := jose.GenerateKey(jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	return &claimStack{
		t: t, issuer: issuer,
		offer: `{"credential_issuer":"` + claimIssuer + `","credential_configuration_ids":["licence_sd_jwt"],` +
			`"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"code-1","tx_code":{"length":4}}}}`,
		metadata: `{"credential_issuer":"` + claimIssuer + `","credential_endpoint":"` + claimEndpoint + `",` +
			`"credential_configurations_supported":{"licence_sd_jwt":{"format":"dc+sd-jwt","vct":"DriverLicence"}}}`,
	}
}

func (c *claimStack) fetch(_ context.Context, address string) ([]byte, error) {
	switch address {
	case claimIssuer + "/offers/1":
		return []byte(c.offer), nil
	case claimIssuer + "/.well-known/openid-credential-issuer":
		return []byte(c.metadata), nil
	case claimIssuer + "/.well-known/oauth-authorization-server":
		return []byte(`{"issuer":"` + claimIssuer + `","token_endpoint":"` + claimToken + `"}`), nil
	case "https://verifier.example/r/1":
		c.fetches++
		if c.freshNonce {
			return requestObjectWith("n-" + strconv.Itoa(c.fetches)), nil
		}
		return requestObject(), nil
	}
	return nil, errors.New("unknown address " + address)
}

func (c *claimStack) post(_ context.Context, address string, form url.Values) ([]byte, error) {
	if address == "https://verifier.example/direct_post" {
		c.posted = form
		return []byte(`{}`), nil
	}
	c.tokens = append(c.tokens, form)
	if c.tokenErr != nil {
		return nil, c.tokenErr
	}
	return []byte(`{"access_token":"at-1","token_type":"bearer","c_nonce":"nonce-1"}`), nil
}

func (c *claimStack) credential(_ context.Context, address, token string, body []byte) ([]byte, error) {
	if address == claimIssuer+"/nonce" {
		return []byte(`{"c_nonce":"nonce-2"}`), nil
	}
	if c.credErr != nil {
		return nil, c.credErr
	}
	var req map[string]any
	if err := json.Unmarshal(body, &req); err != nil || token != "at-1" || address != claimEndpoint {
		return nil, &ports.StatusError{Status: 400}
	}
	c.requests = append(c.requests, req)
	jwt, ok := c.proofOf(req)
	if !ok {
		return nil, &ports.StatusError{Status: 400, Body: []byte(`{"error":"invalid_proof"}`)}
	}
	hdr, err := jose.PeekHeader(jwt)
	if err != nil {
		return nil, &ports.StatusError{Status: 400, Body: []byte(`{"error":"invalid_proof"}`)}
	}
	parts := strings.Split(jwt, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	var header struct {
		JWK map[string]any `json:"jwk"`
	}
	if err = json.Unmarshal(raw, &header); err != nil {
		return nil, err
	}
	key, err := jose.JWKFromMap(header.JWK)
	if err != nil {
		return nil, err
	}
	payload, _, err := jose.Verify(jwt, key.Key, []jose.Algorithm{jose.ES256})
	if err != nil || hdr.Typ != "openid4vci-proof+jwt" {
		return nil, &ports.StatusError{Status: 400, Body: []byte(`{"error":"invalid_proof"}`)}
	}
	var claims map[string]any
	if err = json.Unmarshal(payload, &claims); err != nil || claims["aud"] != claimIssuer ||
		(claims["nonce"] != "nonce-1" && claims["nonce"] != "nonce-2") {
		return nil, &ports.StatusError{Status: 400, Body: []byte(`{"error":"invalid_nonce"}`)}
	}
	if c.issue != nil {
		return json.Marshal(map[string]any{"credential": c.issue(header.JWK)})
	}
	disclosed, discs, err := sdjwt.Conceal(map[string]any{"given_name": "Wanjiku"}, []string{"given_name"})
	if err != nil {
		return nil, err
	}
	disclosed["iss"], disclosed["vct"], disclosed["cnf"] = claimIssuer, "DriverLicence", map[string]any{"jwk": header.JWK}
	signed, err := jose.Sign(c.issuer, "issuer-key", "dc+sd-jwt", disclosed)
	if err != nil {
		return nil, err
	}
	credential := sdjwt.Serialize(sdjwt.Presentation{IssuerJWT: signed, Disclosures: discs})
	if c.answer == "list" {
		return json.Marshal(map[string]any{"credentials": []any{map[string]any{"credential": credential}}})
	}
	return json.Marshal(map[string]any{"credential": credential})
}

// proofOf reads the proof JWT of a credential request in the shape of
// the version of the issuer: the proofs object with one JWT for OID4VCI
// 1.0, the proof object for draft 13. A request that carries both is
// refused, as section 8.2 of OID4VCI 1.0 says.
func (c *claimStack) proofOf(req map[string]any) (string, bool) {
	proof, single := req["proof"].(map[string]any)
	proofs, many := req["proofs"].(map[string]any)
	switch {
	case single && many:
		return "", false
	case c.version10 && many:
		list, ok := proofs["jwt"].([]any)
		if !ok || len(list) != 1 {
			return "", false
		}
		jwt, ok := list[0].(string)
		return jwt, ok
	case !c.version10 && single && proof["proof_type"] == "jwt":
		jwt, ok := proof["jwt"].(string)
		return jwt, ok
	}
	return "", false
}

// browserStore builds the service of a wallet with no stack wallet,
// wired to the issuer.
func browserStore(t *testing.T, c *claimStack) *service.Service {
	t.Helper()
	return build(t, func(o *service.Options) {
		o.Fetch, o.Post, o.PostCredential = c.fetch, c.post, c.credential
		o.RequestHosts = []string{"issuer.example", "verifier.example"}
	})
}

// pasteOffer reads the offer of the stack and returns its id.
func pasteOffer(t *testing.T, svc *service.Service) string {
	t.Helper()
	resp, err := svc.Paste(ctx(), connect.NewRequest(&walletportalv1.PasteRequest{Text: claimOfferURI}))
	if err != nil {
		t.Fatal(err)
	}
	return resp.Msg.GetDetected().GetOfferId()
}

// TestClaimIntoTheBrowserStoreSignsWithTheBrowserKey is ADR-073: the
// portal trades the code, the browser signs the proof, the issuer binds
// the credential to the key of the browser, and the store holds it.
func TestClaimIntoTheBrowserStoreSignsWithTheBrowserKey(t *testing.T) {
	stack := newClaimStack(t)
	svc := browserStore(t, stack)
	browser := newBrowserHolder(t)
	step, err := svc.ClaimStart(ctx(), pasteOffer(t, svc), "4821", browser.jwk)
	if err != nil {
		t.Fatalf("ClaimStart: %v", err)
	}
	if got := stack.tokens[0]; got.Get("pre-authorized_code") != "code-1" || got.Get("tx_code") != "4821" ||
		got.Get("grant_type") != "urn:ietf:params:oauth:grant-type:pre-authorized_code" {
		t.Fatalf("token request = %v", got)
	}
	got, err := svc.ClaimFinish(ctx(), step.ID, browser.sign(t, step.SigningInput))
	if err != nil {
		t.Fatalf("ClaimFinish: %v", err)
	}
	if req := stack.requests[0]; req["credential_configuration_id"] != "licence_sd_jwt" || req["format"] != "dc+sd-jwt" || req["vct"] != "DriverLicence" {
		t.Fatalf("credential request = %v", req)
	}
	pres, err := sdjwt.Parse(got.Credential)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := jose.PeekPayload(pres.IssuerJWT)
	if err != nil {
		t.Fatal(err)
	}
	cnf, ok := payload["cnf"].(map[string]any)
	if !ok {
		t.Fatalf("the credential names no holder key: %v", payload)
	}
	jwk, ok := cnf["jwk"].(map[string]any)
	if !ok {
		t.Fatalf("the credential names no holder JWK: %v", cnf)
	}
	var sent map[string]any
	if err = json.Unmarshal([]byte(browser.jwk), &sent); err != nil {
		t.Fatal(err)
	}
	if jwk["x"] != sent["x"] || jwk["y"] != sent["y"] {
		t.Fatal("the credential is not bound to the key of the browser")
	}
	held, err := svc.ListMine(ctx(), connect.NewRequest(&walletportalv1.ListMineRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(held.Msg.GetCards()) != 1 || held.Msg.GetCards()[0].GetId() != got.ID || !held.Msg.GetCards()[0].GetInBrowser() {
		t.Fatalf("held = %v", held.Msg.GetCards())
	}
	// A step runs once.
	if _, err := svc.ClaimFinish(ctx(), step.ID, browser.sign(t, step.SigningInput)); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("a replayed step: err = %v, want NotFound", err)
	}
}

// TestClaimReadsTheAnswerOfOid4vci10: the credentials list of OID4VCI
// 1.0 and the nonce endpoint work too.
func TestClaimReadsTheAnswerOfOid4vci10(t *testing.T) {
	stack := newClaimStack(t)
	stack.answer = "list"
	stack.version10 = true
	stack.metadata = strings.Replace(stack.metadata, `"credential_endpoint"`, `"nonce_endpoint":"`+claimIssuer+`/nonce","credential_endpoint"`, 1)
	svc := build(t, func(o *service.Options) {
		o.Fetch, o.PostCredential = stack.fetch, stack.credential
		o.Post = func(ctx context.Context, address string, form url.Values) ([]byte, error) {
			stack.tokens = append(stack.tokens, form)
			return []byte(`{"access_token":"at-1"}`), nil
		}
		o.RequestHosts = []string{"issuer.example"}
	})
	browser := newBrowserHolder(t)
	step, err := svc.ClaimStart(ctx(), pasteOffer(t, svc), "4821", browser.jwk)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(decodePayload(t, step.SigningInput), `"nonce":"nonce-2"`) {
		t.Fatalf("the proof has no nonce of the nonce endpoint: %s", decodePayload(t, step.SigningInput))
	}
	if _, err := svc.ClaimFinish(ctx(), step.ID, browser.sign(t, step.SigningInput)); err != nil {
		t.Fatalf("ClaimFinish: %v", err)
	}
	// The request carries the proofs object of OID4VCI 1.0 and no proof
	// of draft 13 (section 8.2).
	last := stack.requests[len(stack.requests)-1]
	if _, single := last["proof"]; single {
		t.Errorf("the request carries the proof of draft 13: %v", last)
	}
	proofs, ok := last["proofs"].(map[string]any)
	list, listed := proofs["jwt"].([]any)
	if !ok || !listed || len(list) != 1 {
		t.Errorf("the request carries no proofs object with one JWT: %v", last)
	}
}

// TestClaimSendsTheProofOfDraft13: an issuer with no nonce endpoint is
// one of draft 13, so the request carries its proof object only.
func TestClaimSendsTheProofOfDraft13(t *testing.T) {
	stack := newClaimStack(t)
	svc := browserStore(t, stack)
	browser := newBrowserHolder(t)
	step, err := svc.ClaimStart(ctx(), pasteOffer(t, svc), "4821", browser.jwk)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ClaimFinish(ctx(), step.ID, browser.sign(t, step.SigningInput)); err != nil {
		t.Fatalf("ClaimFinish: %v", err)
	}
	last := stack.requests[len(stack.requests)-1]
	if _, many := last["proofs"]; many {
		t.Errorf("a draft 13 request carries proofs: %v", last)
	}
	if proof, ok := last["proof"].(map[string]any); !ok || proof["proof_type"] != "jwt" {
		t.Errorf("the request carries no proof of draft 13: %v", last)
	}
}

// decodePayload returns the payload of a signing input as text.
func decodePayload(t *testing.T, input string) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(input, ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// TestClaimRefusals: each fault of the step names its reason.
func TestClaimRefusals(t *testing.T) {
	browser := newBrowserHolder(t)
	cases := map[string]struct {
		change func(*claimStack, *service.Options)
		jwk    string
		code   connect.Code
	}{
		"stack wallet":     {func(_ *claimStack, o *service.Options) { o.Holder = &fakeHolder{} }, browser.jwk, connect.CodeFailedPrecondition},
		"no poster":        {func(_ *claimStack, o *service.Options) { o.PostCredential = nil }, browser.jwk, connect.CodeFailedPrecondition},
		"bad key":          {nil, `{"kty":"oct"}`, connect.CodeInvalidArgument},
		"host not allowed": {func(_ *claimStack, o *service.Options) { o.RequestHosts = []string{"verifier.example"} }, browser.jwk, connect.CodeFailedPrecondition},
		"no code": {func(c *claimStack, _ *service.Options) {
			c.offer = strings.ReplaceAll(c.offer, "pre-authorized_code", "other")
		}, browser.jwk, connect.CodeFailedPrecondition},
		"no endpoint": {func(c *claimStack, _ *service.Options) { c.metadata = `{"credential_issuer":"x"}` }, browser.jwk, connect.CodeUnavailable},
		"unknown type": {func(c *claimStack, _ *service.Options) {
			c.metadata = strings.Replace(c.metadata, "licence_sd_jwt", "other", 1)
		}, browser.jwk, connect.CodeFailedPrecondition},
		"bad configuration": {func(c *claimStack, _ *service.Options) {
			c.metadata = strings.Replace(c.metadata, `{"format"`, `["format"`, 1)
		}, browser.jwk, connect.CodeUnavailable},
		"refused code": {func(c *claimStack, _ *service.Options) { c.tokenErr = &ports.StatusError{Status: 400} }, browser.jwk, connect.CodeInvalidArgument},
		"issuer down":  {func(c *claimStack, _ *service.Options) { c.tokenErr = errors.New("down") }, browser.jwk, connect.CodeUnavailable},
	}
	for name, c := range cases {
		stack := newClaimStack(t)
		svc := build(t, func(o *service.Options) {
			o.Fetch, o.Post, o.PostCredential = stack.fetch, stack.post, stack.credential
			o.RequestHosts = []string{"issuer.example"}
			if c.change != nil {
				c.change(stack, o)
			}
		})
		offer := "id-missing"
		if resp, err := svc.Paste(ctx(), connect.NewRequest(&walletportalv1.PasteRequest{Text: claimOfferURI})); err == nil {
			offer = resp.Msg.GetDetected().GetOfferId()
		}
		if _, err := svc.ClaimStart(ctx(), offer, "4821", c.jwk); connect.CodeOf(err) != c.code {
			t.Errorf("%s: err = %v, want %v", name, err, c.code)
		}
	}
	stack := newClaimStack(t)
	svc := browserStore(t, stack)
	if _, err := svc.ClaimStart(ctx(), "id-none", "4821", browser.jwk); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("an unknown offer: err = %v", err)
	}
	for name, fault := range map[string]func(*claimStack){
		"other signature": nil,
		"issuer refuses":  func(c *claimStack) { c.credErr = &ports.StatusError{Status: 400} },
		"issuer down":     func(c *claimStack) { c.credErr = errors.New("down") },
		"no credential":   func(c *claimStack) { c.credErr = nil; c.answer = "list"; c.issuer = nil },
	} {
		stack := newClaimStack(t)
		svc := browserStore(t, stack)
		step, err := svc.ClaimStart(ctx(), pasteOffer(t, svc), "4821", browser.jwk)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		signature := browser.sign(t, step.SigningInput)
		if fault == nil {
			signature = newBrowserHolder(t).sign(t, step.SigningInput)
		} else {
			fault(stack)
		}
		if _, err := svc.ClaimFinish(ctx(), step.ID, signature); err == nil {
			t.Errorf("%s: the claim finished", name)
		}
	}
}
