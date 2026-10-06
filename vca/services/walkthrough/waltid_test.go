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
	"crypto/sha256"
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
//	POST /openid4vc/mdoc/issue
//	GET  /draft13/credentialOffer?id=
//	POST /draft13/par
//	GET  /draft13/authorize
//	POST /draft13/token
//	POST /draft13/credential
//
// It signs an SD-JWT VC with the key of the issue request, as walt.id
// does, or an mDoc of the doctype the catalogue names (waltid_mdoc_test.go),
// and posts the session events to the callback address of the
// request. A credential request with a proof gets a credential bound to
// the key of the proof, as the browser store of the wallet claims it
// (ADR-073). One without a proof gets no holder key. An issue request
// with the authentication method NONE gets an offer with the
// authorization code grant. The wallet pushes its authorization request
// with PKCE (RFC 9126), the authorization endpoint sends the browser
// back with a code, as walt.id does for NONE, and the token endpoint
// checks the code verifier (ADR-082).
type waltidIssuer struct {
	t   *testing.T
	srv *httptest.Server

	mu     sync.Mutex
	offers map[string]*waltidOffer
	codes  map[string]string
	tokens map[string]string
	// nonces holds the c_nonce of each access token.
	nonces map[string]string
	// onboarded counts the onboarding calls.
	onboarded int
	// pushed holds the pushed authorization requests by request_uri.
	pushed map[string]url.Values
	// grants holds the pushed request of each authorization code.
	grants map[string]url.Values
}

// waltidOffer is one issue request and its offer.
type waltidOffer struct {
	request  waltidIssue
	callback string
	code     string
	// state is the issuer_state of an offer with the authorization code
	// grant.
	state string
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
	AuthenticationMethod      string          `json:"authenticationMethod"`
	// MdocData holds the claims of an mDoc by namespace.
	MdocData map[string]map[string]any `json:"mdocData"`
}

const waltidDraft = "/draft13"

func newWaltidIssuer(t *testing.T) *waltidIssuer {
	t.Helper()
	w := &waltidIssuer{t: t, offers: map[string]*waltidOffer{}, codes: map[string]string{}, tokens: map[string]string{}, nonces: map[string]string{},
		pushed: map[string]url.Values{}, grants: map[string]url.Values{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+waltidDraft+"/.well-known/openid-credential-issuer", w.metadata)
	mux.HandleFunc("GET "+waltidDraft+"/.well-known/oauth-authorization-server", w.authServer)
	mux.HandleFunc("GET "+waltidDraft+"/.well-known/openid-configuration", w.authServer)
	mux.HandleFunc("POST /onboard/issuer", w.onboard)
	mux.HandleFunc("POST /openid4vc/sdjwt/issue", w.issue)
	mux.HandleFunc("POST /openid4vc/mdoc/issue", w.issue)
	mux.HandleFunc("GET "+waltidDraft+"/credentialOffer", w.offer)
	mux.HandleFunc("POST "+waltidDraft+"/par", w.par)
	mux.HandleFunc("GET "+waltidDraft+"/authorize", w.authorize)
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
		"authorization_endpoint":                w.base() + "/authorize",
		"pushed_authorization_request_endpoint": w.base() + "/par",
		"code_challenge_methods_supported":      []string{"S256"},
		"grant_types_supported":                 []string{"urn:ietf:params:oauth:grant-type:pre-authorized_code", "authorization_code"},
	})
}

// par takes a pushed authorization request with PKCE for an offer of the
// authorization code grant (RFC 9126 section 2).
func (w *waltidIssuer) par(rw http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	f := r.PostForm
	w.mu.Lock()
	known := false
	for _, o := range w.offers {
		known = known || (o.state != "" && o.state == f.Get("issuer_state"))
	}
	uri := "urn:ietf:params:oauth:request_uri:" + randomID()
	if known {
		w.pushed[uri] = f
	}
	w.mu.Unlock()
	if !known || f.Get("code_challenge_method") != "S256" || f.Get("code_challenge") == "" ||
		f.Get("client_id") == "" || f.Get("redirect_uri") == "" || f.Get("response_type") != "code" {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusBadRequest)
		writeJSON(rw, map[string]any{"error": "invalid_request"})
		return
	}
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusCreated)
	writeJSON(rw, map[string]any{"request_uri": uri, "expires_in": 60})
}

// authorize answers the authorization request of a pushed request. For
// the authentication method NONE walt.id sends the browser straight back
// with a code.
func (w *waltidIssuer) authorize(rw http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	w.mu.Lock()
	pushed, ok := w.pushed[q.Get("request_uri")]
	delete(w.pushed, q.Get("request_uri"))
	code := randomID()
	if ok {
		w.grants[code] = pushed
	}
	w.mu.Unlock()
	if !ok || pushed.Get("client_id") != q.Get("client_id") {
		http.Error(rw, "invalid_request_uri", http.StatusBadRequest)
		return
	}
	back := url.Values{"code": {code}, "state": {pushed.Get("state")}}
	http.Redirect(rw, r, pushed.Get("redirect_uri")+"?"+back.Encode(), http.StatusFound)
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
	o := &waltidOffer{request: req, callback: r.Header.Get("statusCallbackUri"), code: code}
	if req.AuthenticationMethod == "NONE" {
		o.state, o.code = randomID(), ""
	} else {
		w.codes[code] = id
	}
	w.offers[id] = o
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
	grants := map[string]any{"urn:ietf:params:oauth:grant-type:pre-authorized_code": map[string]any{
		"pre-authorized_code": o.code,
	}}
	if o.state != "" {
		grants = map[string]any{"authorization_code": map[string]any{"issuer_state": o.state}}
	}
	writeJSON(rw, map[string]any{
		"credential_issuer":            w.base(),
		"credential_configuration_ids": []string{o.request.CredentialConfigurationID},
		"grants":                       grants,
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
	grant := r.PostForm.Get("grant_type") == "urn:ietf:params:oauth:grant-type:pre-authorized_code"
	if r.PostForm.Get("grant_type") == "authorization_code" {
		id, ok = w.authorizationGrant(r.PostForm)
		grant = ok
	}
	token, nonce := randomID(), randomID()
	if ok {
		w.tokens[token], w.nonces[token] = id, nonce
	}
	o := w.offers[id]
	w.mu.Unlock()
	if !ok || !grant {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusBadRequest)
		writeJSON(rw, map[string]any{"error": "invalid_grant"})
		return
	}
	w.event(o, "requested_token", map[string]any{})
	writeJSON(rw, map[string]any{"access_token": token, "token_type": "bearer", "expires_in": 300, "c_nonce": nonce})
}

// authorizationGrant checks an authorization code against its pushed
// request: the client, the redirect URI and the PKCE verifier. It
// returns the id of the offer whose issuer_state the request named. The
// caller holds the lock.
func (w *waltidIssuer) authorizationGrant(f url.Values) (string, bool) {
	pushed, ok := w.grants[f.Get("code")]
	delete(w.grants, f.Get("code"))
	sum := sha256.Sum256([]byte(f.Get("code_verifier")))
	if !ok || pushed.Get("client_id") != f.Get("client_id") || pushed.Get("redirect_uri") != f.Get("redirect_uri") ||
		base64.RawURLEncoding.EncodeToString(sum[:]) != pushed.Get("code_challenge") {
		return "", false
	}
	for id, o := range w.offers {
		if o.state != "" && o.state == pushed.Get("issuer_state") {
			return id, true
		}
	}
	return "", false
}

// credential signs the SD-JWT VC of the offer of the access token. A
// request with a proof gets a credential bound to the key of the proof.
func (w *waltidIssuer) credential(rw http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	w.mu.Lock()
	id, ok := w.tokens[token]
	nonce := w.nonces[token]
	delete(w.tokens, token)
	delete(w.nonces, token)
	o := w.offers[id]
	w.mu.Unlock()
	if !ok {
		http.Error(rw, "invalid_token", http.StatusUnauthorized)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	holder, err := proofKey(body, w.base(), nonce)
	if err != nil {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusBadRequest)
		writeJSON(rw, map[string]any{"error": "invalid_proof", "error_description": err.Error()})
		return
	}
	if o.request.CredentialConfigurationID == mdocConfiguration {
		w.mdocCredential(rw, o, body, holder)
		return
	}
	cred, err := o.sign(time.Now(), holder)
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
func (o *waltidOffer) sign(now time.Time, holder map[string]any) (string, error) {
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
	if holder != nil {
		payload["cnf"] = map[string]any{"jwk": holder}
	}
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
