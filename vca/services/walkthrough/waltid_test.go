// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package walkthrough_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/did"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/sdjwt"
)

// The issuer API of the walt.id Community Stack 0.18.2, as a test
// double. It serves the catalogue that vca setup writes, from the
// fixture of the adapter, and the calls the adapter and a wallet make:
//
//	GET  /draft13/.well-known/openid-credential-issuer
//	GET  /draft13/.well-known/oauth-authorization-server
//	POST /onboard/issuer
//	POST /openid4vc/sdjwt/issue
//	GET  /draft13/credentialOffer?id=
//	POST /draft13/token
//	POST /draft13/credential
//
// It signs an SD-JWT VC with the key of the issue request, as walt.id
// does, and posts the session events to the callback address of the
// request. A credential request without a proof gets a credential with
// no holder key, which the browser store of the wallet can present.
type waltidIssuer struct {
	t   *testing.T
	srv *httptest.Server

	mu     sync.Mutex
	offers map[string]*waltidOffer
	codes  map[string]string
	tokens map[string]string
	// onboarded counts the onboarding calls.
	onboarded int
}

// waltidOffer is one issue request and its offer.
type waltidOffer struct {
	request  waltidIssue
	callback string
	code     string
}

// waltidIssue is the part of the issue request the double reads.
type waltidIssue struct {
	IssuerKey struct {
		JWK json.RawMessage `json:"jwk"`
	} `json:"issuerKey"`
	IssuerDid                 string          `json:"issuerDid"`
	CredentialConfigurationID string          `json:"credentialConfigurationId"`
	CredentialData            map[string]any  `json:"credentialData"`
	Vct                       string          `json:"vct"`
	SelectiveDisclosure       json.RawMessage `json:"selectiveDisclosure"`
}

const waltidDraft = "/draft13"

func newWaltidIssuer(t *testing.T) *waltidIssuer {
	t.Helper()
	w := &waltidIssuer{t: t, offers: map[string]*waltidOffer{}, codes: map[string]string{}, tokens: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+waltidDraft+"/.well-known/openid-credential-issuer", w.metadata)
	mux.HandleFunc("GET "+waltidDraft+"/.well-known/oauth-authorization-server", w.authServer)
	mux.HandleFunc("GET "+waltidDraft+"/.well-known/openid-configuration", w.authServer)
	mux.HandleFunc("POST /onboard/issuer", w.onboard)
	mux.HandleFunc("POST /openid4vc/sdjwt/issue", w.issue)
	mux.HandleFunc("GET "+waltidDraft+"/credentialOffer", w.offer)
	mux.HandleFunc("POST "+waltidDraft+"/token", w.token)
	mux.HandleFunc("POST "+waltidDraft+"/credential", w.credential)
	w.srv = httptest.NewServer(mux)
	t.Cleanup(w.srv.Close)
	return w
}

// base is the credential issuer identifier.
func (w *waltidIssuer) base() string { return w.srv.URL + waltidDraft }

// metadata serves the catalogue of vca setup at the address of the
// double.
func (w *waltidIssuer) metadata(rw http.ResponseWriter, _ *http.Request) {
	raw, err := os.ReadFile(filepath.Join("..", "dpg-adapter-waltid", "testdata", "doc", "issuer-metadata-vca.json"))
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	doc["credential_issuer"] = w.base()
	doc["credential_endpoint"] = w.base() + "/credential"
	doc["authorization_servers"] = []string{w.base()}
	writeJSON(rw, doc)
}

// authServer serves the metadata of the authorization server.
func (w *waltidIssuer) authServer(rw http.ResponseWriter, _ *http.Request) {
	writeJSON(rw, map[string]any{
		"issuer": w.base(), "token_endpoint": w.base() + "/token",
		"grant_types_supported": []string{"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
	})
}

// onboard makes a key of the asked type and the DID of the asked method.
func (w *waltidIssuer) onboard(rw http.ResponseWriter, r *http.Request) {
	var req struct {
		Key struct {
			KeyType string `json:"keyType"`
		} `json:"key"`
		Did struct {
			Method string `json:"method"`
		} `json:"did"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	var key crypto.Signer
	var err error
	switch req.Key.KeyType {
	case "Ed25519":
		_, key, err = ed25519.GenerateKey(rand.Reader)
	case "secp256r1", "":
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	default:
		http.Error(rw, "the double makes Ed25519 and secp256r1 keys", http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	var id string
	switch req.Did.Method {
	case "key", "":
		id, err = did.FromPublicKey(key.Public())
	default:
		http.Error(rw, "the double makes did:key only", http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	private, err := json.Marshal(jose.JWK{Key: key, KeyID: strings.TrimPrefix(id, "did:key:")})
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	w.mu.Lock()
	w.onboarded++
	w.mu.Unlock()
	writeJSON(rw, map[string]any{"issuerKey": map[string]any{"type": "jwk", "jwk": json.RawMessage(private)}, "issuerDid": id})
}

// issue keeps the issue request and answers with the offer URI.
func (w *waltidIssuer) issue(rw http.ResponseWriter, r *http.Request) {
	var req waltidIssue
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	id, code := randomID(), randomID()
	w.mu.Lock()
	w.offers[id] = &waltidOffer{request: req, callback: r.Header.Get("statusCallbackUri"), code: code}
	w.codes[code] = id
	w.mu.Unlock()
	offerURI := w.base() + "/credentialOffer?id=" + id
	rw.Header().Set("Content-Type", "text/plain")
	if _, err := io.WriteString(rw, "openid-credential-offer://?credential_offer_uri="+url.QueryEscape(offerURI)); err != nil {
		w.t.Log(err)
	}
}

// offer serves the credential offer of one issue request.
func (w *waltidIssuer) offer(rw http.ResponseWriter, r *http.Request) {
	w.mu.Lock()
	o, ok := w.offers[r.URL.Query().Get("id")]
	w.mu.Unlock()
	if !ok {
		http.NotFound(rw, r)
		return
	}
	w.event(o, "resolved_credential_offer", map[string]any{})
	writeJSON(rw, map[string]any{
		"credential_issuer":            w.base(),
		"credential_configuration_ids": []string{o.request.CredentialConfigurationID},
		"grants": map[string]any{"urn:ietf:params:oauth:grant-type:pre-authorized_code": map[string]any{
			"pre-authorized_code": o.code,
		}},
	})
}

// token trades a pre-authorized code for an access token.
func (w *waltidIssuer) token(rw http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	w.mu.Lock()
	id, ok := w.codes[r.PostForm.Get("pre-authorized_code")]
	delete(w.codes, r.PostForm.Get("pre-authorized_code"))
	token := randomID()
	if ok {
		w.tokens[token] = id
	}
	o := w.offers[id]
	w.mu.Unlock()
	if !ok || r.PostForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:pre-authorized_code" {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusBadRequest)
		writeJSON(rw, map[string]any{"error": "invalid_grant"})
		return
	}
	w.event(o, "requested_token", map[string]any{})
	writeJSON(rw, map[string]any{"access_token": token, "token_type": "bearer", "expires_in": 300, "c_nonce": randomID()})
}

// credential signs the SD-JWT VC of the offer of the access token.
func (w *waltidIssuer) credential(rw http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	w.mu.Lock()
	id, ok := w.tokens[token]
	delete(w.tokens, token)
	o := w.offers[id]
	w.mu.Unlock()
	if !ok {
		http.Error(rw, "invalid_token", http.StatusUnauthorized)
		return
	}
	cred, err := o.sign(time.Now())
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	w.event(o, "sdjwt_issue", map[string]any{"sdjwt": cred})
	w.event(o, "issuance_status", map[string]any{"status": "SUCCESSFUL"})
	writeJSON(rw, map[string]any{"credential": cred})
}

// sign builds the SD-JWT VC: every claim of the disclosure map becomes a
// disclosure, and the issuer key signs the JWT.
func (o *waltidOffer) sign(now time.Time) (string, error) {
	jwk, err := jose.ParseJWK(o.request.IssuerKey.JWK)
	if err != nil {
		return "", err
	}
	var sd struct {
		Fields map[string]json.RawMessage `json:"fields"`
	}
	if len(o.request.SelectiveDisclosure) > 0 {
		if jerr := json.Unmarshal(o.request.SelectiveDisclosure, &sd); jerr != nil {
			return "", jerr
		}
	}
	names := make([]string, 0, len(sd.Fields))
	for name := range sd.Fields {
		if _, ok := o.request.CredentialData[name]; ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	payload, discs, err := sdjwt.Conceal(o.request.CredentialData, names)
	if err != nil {
		return "", err
	}
	payload["iss"] = o.request.IssuerDid
	payload["iat"] = now.Unix()
	payload["vct"] = o.request.Vct
	kid := o.request.IssuerDid
	if strings.HasPrefix(kid, "did:key:") {
		kid += "#" + strings.TrimPrefix(kid, "did:key:")
	}
	jwt, err := jose.Sign(jwk.Key, kid, "dc+sd-jwt", payload)
	if err != nil {
		return "", err
	}
	return sdjwt.Serialize(sdjwt.Presentation{IssuerJWT: jwt, Disclosures: discs}), nil
}

// event posts one session event to the callback address of the offer.
func (w *waltidIssuer) event(o *waltidOffer, kind string, data map[string]any) {
	if o.callback == "" {
		return
	}
	raw, err := json.Marshal(map[string]any{"id": randomID(), "type": kind, "data": data})
	if err != nil {
		w.t.Error(err)
		return
	}
	res, err := http.Post(o.callback, "application/json", bytes.NewReader(raw)) // #nosec G107 -- the adapter named the address
	if err != nil {
		w.t.Logf("callback %s: %v", kind, err)
		return
	}
	if _, err := io.Copy(io.Discard, res.Body); err != nil {
		w.t.Log(err)
	}
	if err := res.Body.Close(); err != nil {
		w.t.Log(err)
	}
}

// randomID returns 16 random bytes as base64url.
func randomID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// writeJSON writes one JSON answer.
func writeJSON(rw http.ResponseWriter, v any) {
	if rw.Header().Get("Content-Type") == "" {
		rw.Header().Set("Content-Type", "application/json")
	}
	if err := json.NewEncoder(rw).Encode(v); err != nil && !errors.Is(err, http.ErrHandlerTimeout) {
		return
	}
}

// claim runs the pre-authorized code flow of OID4VCI as a wallet on
// the phone of the holder does, and returns the credential. It sends
// the transaction code when the issuer gave one. It sends no proof, so
// the credential names no holder key.
func claim(t *testing.T, offerURI, txCode string) string {
	t.Helper()
	u, err := url.Parse(offerURI)
	if err != nil {
		t.Fatal(err)
	}
	var offer struct {
		Issuer string   `json:"credential_issuer"`
		IDs    []string `json:"credential_configuration_ids"`
		Grants map[string]struct {
			Code string `json:"pre-authorized_code"`
		} `json:"grants"`
	}
	getJSON(t, u.Query().Get("credential_offer_uri"), &offer)
	var meta struct {
		Endpoint string                     `json:"credential_endpoint"`
		Configs  map[string]json.RawMessage `json:"credential_configurations_supported"`
	}
	getJSON(t, offer.Issuer+"/.well-known/openid-credential-issuer", &meta)
	var as struct {
		Token string `json:"token_endpoint"`
	}
	getJSON(t, offer.Issuer+"/.well-known/oauth-authorization-server", &as)
	grant := offer.Grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"].Code
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:pre-authorized_code"}, "pre-authorized_code": {grant}}
	if txCode != "" {
		form.Set("tx_code", txCode)
	}
	res, err := http.PostForm(as.Token, form) // #nosec G107 -- the address of the double
	if err != nil {
		t.Fatal(err)
	}
	var tok struct {
		Access string `json:"access_token"`
	}
	readJSON(t, res, &tok)
	var cfg struct {
		Format string `json:"format"`
	}
	if jerr := json.Unmarshal(meta.Configs[offer.IDs[0]], &cfg); jerr != nil {
		t.Fatal(jerr)
	}
	body, err := json.Marshal(map[string]any{"format": cfg.Format})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, meta.Endpoint, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tok.Access)
	req.Header.Set("Content-Type", "application/json")
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Credential string `json:"credential"`
	}
	readJSON(t, res, &out)
	return out.Credential
}

// getJSON reads one JSON document.
func getJSON(t *testing.T, target string, out any) {
	t.Helper()
	res, err := http.Get(target) // #nosec G107 -- an address the test holds
	if err != nil {
		t.Fatal(err)
	}
	readJSON(t, res, out)
}

// readJSON reads a JSON answer and fails on any status but 200.
func readJSON(t *testing.T, res *http.Response, out any) {
	t.Helper()
	raw, err := io.ReadAll(res.Body)
	if cerr := res.Body.Close(); cerr != nil {
		t.Log(cerr)
	}
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("%s answered %d: %s", res.Request.URL, res.StatusCode, raw)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatalf("%s: %v: %s", res.Request.URL, err, raw)
	}
}
