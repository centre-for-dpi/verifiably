// SPDX-License-Identifier: Apache-2.0

// Package oidctest is a fake OpenID Provider on httptest for full flow
// tests. It serves discovery, a JWKS, an authorization endpoint that
// redirects back with a code, a token endpoint that checks PKCE, and an
// end session endpoint.
package oidctest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/oidc"
)

// Provider is the fake OpenID Provider.
type Provider struct {
	// Server is the httptest server. Close it when the test ends.
	Server *httptest.Server
	// ClientID and ClientSecret are what the token endpoint expects.
	// An empty ClientSecret makes the client public.
	ClientID     string
	ClientSecret string
	// Claims are added to every ID token, for example roles.
	Claims map[string]any
	// Subject is the sub claim of every ID token.
	Subject string
	// ExpiresIn is the access token lifetime the token endpoint returns.
	ExpiresIn int64
	// TokenError, when set, makes the token endpoint return this error.
	TokenError string
	// OmitIDToken makes the token endpoint return no id_token.
	OmitIDToken bool
	// WrongNonce makes the ID token carry a wrong nonce.
	WrongNonce bool
	// NoEndSession removes end_session_endpoint from discovery.
	NoEndSession bool
	// Now returns the time the ID tokens are issued at.
	Now func() time.Time

	mu    sync.Mutex
	key   crypto.PrivateKey
	kid   string
	codes map[string]authRequest
	// Requests counts calls per path.
	Requests map[string]int
}

type authRequest struct {
	challenge   string
	nonce       string
	redirectURI string
	clientID    string
}

// New starts a fake provider with a fresh ES256 key.
func New() *Provider {
	key := anyval.Must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	return start(key)
}

// NewRS256 starts a fake provider with a fresh RSA key.
func NewRS256() *Provider {
	key := anyval.Must(rsa.GenerateKey(rand.Reader, 2048))
	return start(key)
}

func start(key crypto.PrivateKey) *Provider {
	p := &Provider{
		ClientID:  "client",
		Subject:   "user-1",
		ExpiresIn: 300,
		Now:       time.Now,
		codes:     map[string]authRequest{},
		Requests:  map[string]int{},
		Claims:    map[string]any{},
	}
	p.setKey(key)
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("/jwks", p.jwks)
	mux.HandleFunc("/authorize", p.authorize)
	mux.HandleFunc("/token", p.token)
	mux.HandleFunc("/logout", p.logout)
	p.Server = httptest.NewServer(p.count(mux))
	return p
}

func (p *Provider) setKey(key crypto.PrivateKey) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.key = key
	pub := anyval.Must(jose.PublicJWK(key, ""))
	p.kid = anyval.Must(jose.Thumbprint(pub))
}

// RotateKey replaces the signing key, to test JWKS refresh.
func (p *Provider) RotateKey() {
	key := anyval.Must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	p.setKey(key)
}

// Close stops the server.
func (p *Provider) Close() { p.Server.Close() }

// Issuer returns the issuer URL.
func (p *Provider) Issuer() string { return p.Server.URL }

// DiscoveryURL returns the well-known URL.
func (p *Provider) DiscoveryURL() string { return oidc.DiscoveryURL(p.Server.URL) }

// Authorize follows an authorization URL without a browser and returns
// the redirect location the provider answers with.
func (p *Provider) Authorize(authorizationURL string) (string, error) {
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Get(authorizationURL)
	if err != nil {
		return "", err
	}
	defer func() { anyval.Discard(res.Body.Close()) }()
	return res.Header.Get("Location"), nil
}

func (p *Provider) count(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		p.Requests[r.URL.Path]++
		p.mu.Unlock()
		next.ServeHTTP(w, r)
	})
}

func (p *Provider) discovery(w http.ResponseWriter, _ *http.Request) {
	doc := map[string]any{
		"issuer":                 p.Server.URL,
		"authorization_endpoint": p.Server.URL + "/authorize",
		"token_endpoint":         p.Server.URL + "/token",
		"jwks_uri":               p.Server.URL + "/jwks",
		"scopes_supported":       []string{"openid", "profile", "email"},
	}
	if !p.NoEndSession {
		doc["end_session_endpoint"] = p.Server.URL + "/logout"
	}
	writeJSON(w, http.StatusOK, doc)
}

func (p *Provider) jwks(w http.ResponseWriter, _ *http.Request) {
	p.mu.Lock()
	pub := anyval.Must(jose.PublicJWK(p.key, p.kid))
	p.mu.Unlock()
	writeJSON(w, http.StatusOK, jose.JWKS{Keys: []jose.JWK{pub}})
}

func (p *Provider) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		http.Error(w, "unsupported request", http.StatusBadRequest)
		return
	}
	if q.Get("client_id") != p.ClientID {
		http.Error(w, "unknown client", http.StatusBadRequest)
		return
	}
	code := oidc.NewState()
	p.mu.Lock()
	p.codes[code] = authRequest{challenge: q.Get("code_challenge"), nonce: q.Get("nonce"), redirectURI: q.Get("redirect_uri"), clientID: q.Get("client_id")}
	p.mu.Unlock()
	u := anyval.OrZero(url.Parse(q.Get("redirect_uri")))
	v := u.Query()
	v.Set("code", code)
	v.Set("state", q.Get("state"))
	u.RawQuery = v.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || r.Method != http.MethodPost {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	if p.TokenError != "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": p.TokenError})
		return
	}
	if p.ClientSecret != "" {
		id, secret, ok := r.BasicAuth()
		if !ok || id != url.QueryEscape(p.ClientID) || secret != url.QueryEscape(p.ClientSecret) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
			return
		}
	}
	p.mu.Lock()
	req, ok := p.codes[r.PostFormValue("code")]
	delete(p.codes, r.PostFormValue("code"))
	p.mu.Unlock()
	if r.PostFormValue("grant_type") != "authorization_code" || !ok || req.redirectURI != r.PostFormValue("redirect_uri") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	if !oidc.VerifyChallenge(r.PostFormValue("code_verifier"), req.challenge) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "pkce"})
		return
	}
	nonce := req.nonce
	if p.WrongNonce {
		nonce = "wrong"
	}
	body := map[string]any{"access_token": "at-" + oidc.NewState(), "token_type": "Bearer", "expires_in": p.ExpiresIn}
	if !p.OmitIDToken {
		body["id_token"] = p.IDToken(req.clientID, nonce)
	}
	writeJSON(w, http.StatusOK, body)
}

// IDToken signs an ID token for aud with the current key and Claims.
func (p *Provider) IDToken(aud, nonce string) string {
	now := p.Now()
	claims := map[string]any{
		"iss":   p.Server.URL,
		"sub":   p.Subject,
		"aud":   aud,
		"exp":   now.Add(5 * time.Minute).Unix(),
		"iat":   now.Unix(),
		"nonce": nonce,
	}
	for k, v := range p.Claims {
		claims[k] = v
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	tok := anyval.Must(signAny(p.key, p.kid, claims))
	return tok
}

func (p *Provider) logout(w http.ResponseWriter, r *http.Request) {
	if to := r.URL.Query().Get("post_logout_redirect_uri"); to != "" {
		http.Redirect(w, r, to, http.StatusFound)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	anyval.Discard(json.NewEncoder(w).Encode(v))
}

// signAny signs with ES256 through core/jose, or with RS256 directly.
func signAny(key crypto.PrivateKey, kid string, claims map[string]any) (string, error) {
	if _, ok := key.(*rsa.PrivateKey); !ok {
		return jose.Sign(key, kid, "JWT", claims)
	}
	return signRS256(anyval.As[*rsa.PrivateKey](key), kid, claims)
}

func signRS256(key *rsa.PrivateKey, kid string, claims map[string]any) (string, error) {
	header := anyval.Must(json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid}))
	payload := anyval.Must(json.Marshal(claims))
	input := b64(header) + "." + b64(payload)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return input + "." + b64(sig), nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
