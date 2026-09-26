// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/oidc"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
)

// maxTokenBody bounds the form of a token request.
const maxTokenBody = 64 << 10

// verifierPattern is a PKCE code verifier (RFC 7636 section 4.1).
var verifierPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)

// assertionAlgs are the algorithms of a client assertion the server
// takes: the key type of the registered key decides (ADR-048 decision 1).
var assertionAlgs = []jose.Algorithm{jose.RS256, jose.ES256, jose.EdDSA}

func assertionAlgNames() []string {
	out := make([]string, 0, len(assertionAlgs))
	for _, a := range assertionAlgs {
		out = append(out, string(a))
	}
	return out
}

// tokenError is an error answer of RFC 6749 section 5.2.
type tokenError struct {
	status      int
	code        string
	description string
}

func (e tokenError) Error() string { return e.code + ": " + e.description }

func badClient(description string) tokenError {
	return tokenError{http.StatusUnauthorized, "invalid_client", description}
}

func badGrant(description string) tokenError {
	return tokenError{http.StatusBadRequest, "invalid_grant", description}
}

// token trades an authorization code for an access token (RFC 6749
// section 4.1.3). It authenticates the client first, then uses the code
// up, then checks the code against the client, the redirect URI and the
// PKCE verifier. A code that comes back a second time removes the row of
// its first token (section 4.1.2).
func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxTokenBody)
	if err := r.ParseForm(); err != nil {
		s.tokenFail(w, tokenError{http.StatusBadRequest, "invalid_request", "The body is not a form."})
		return
	}
	answer, err := s.exchange(r)
	if err != nil {
		var te tokenError
		if !errors.As(err, &te) {
			te = tokenError{http.StatusInternalServerError, "server_error", "The token could not be made."}
		}
		s.tokenFail(w, te)
		return
	}
	writeJSON(w, http.StatusOK, answer)
}

func (s *Server) tokenFail(w http.ResponseWriter, e tokenError) {
	s.log.Info("the holder authorization server refused a token request", "error", e.Error())
	if e.code == "invalid_client" {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_client"`)
	}
	writeJSON(w, e.status, map[string]string{"error": e.code, "error_description": e.description})
}

// exchange runs the checks of one token request.
func (s *Server) exchange(r *http.Request) (map[string]any, error) {
	form := r.PostForm
	for _, name := range []string{"grant_type", "code", "redirect_uri", "client_id", "code_verifier", "client_assertion", "client_assertion_type"} {
		if len(form[name]) > 1 {
			return nil, tokenError{http.StatusBadRequest, "invalid_request", "The parameter " + name + " appears twice."}
		}
	}
	if form.Get("grant_type") != "authorization_code" {
		return nil, tokenError{http.StatusBadRequest, "unsupported_grant_type", "The server trades authorization codes only."}
	}
	client, err := s.authenticate(r)
	if err != nil {
		return nil, err
	}
	ctx := r.Context()
	var c code
	found, used, err := consume(ctx, s.kv, hashed(codePrefix, form.Get("code")), &c, func(rec *code) bool {
		was := rec.Used
		rec.Used = true
		return was
	})
	switch {
	case err != nil:
		return nil, err
	case form.Get("code") == "" || !found:
		return nil, badGrant("The code is unknown.")
	case used:
		// RFC 6749 section 4.1.2: a code used twice revokes what the
		// first use gave. The row goes, so Certify issues nothing more.
		if uerr := s.offers.Unstage(ctx, c.Subject); uerr != nil {
			s.log.Warn("the row of a reused code stays", "error", uerr)
		}
		return nil, badGrant("The code was already used.")
	case !s.now().Before(c.ExpiresAt):
		return nil, badGrant("The code has expired.")
	case c.ClientID != client.ID:
		return nil, badGrant("The code belongs to another client.")
	case c.RedirectURI != form.Get("redirect_uri"):
		return nil, badGrant("The redirect URI differs from the one of the request.")
	case !verifierPattern.MatchString(form.Get("code_verifier")) || !oidc.VerifyChallenge(form.Get("code_verifier"), c.Challenge):
		return nil, badGrant("The PKCE code verifier does not match.")
	}
	answer, err := s.mint(client, c.Subject)
	if err != nil {
		return nil, err
	}
	// The holder has the token, so the offer keeps nothing of its
	// subject (ADR-056 decision 4). The row serves the credential.
	if c.OfferID != "" {
		if ferr := s.offers.Finish(ctx, c.OfferID); ferr != nil {
			s.log.Warn("the claimed offer still holds its subject", "offer", c.OfferID, "error", ferr)
		}
	}
	return answer, nil
}

// authenticate finds the client of a token request and checks its
// authentication. A client with a key must sign a client assertion. A
// public client must send none. No client may send a secret.
func (s *Server) authenticate(r *http.Request) (Client, error) {
	form := r.PostForm
	if _, _, basic := r.BasicAuth(); basic || form.Get("client_secret") != "" {
		return Client{}, badClient("The server takes no client secret.")
	}
	id := form.Get("client_id")
	client, ok := s.clients[id]
	if id == "" || !ok {
		return Client{}, badClient("The client is unknown.")
	}
	assertion := form.Get("client_assertion")
	if len(client.JWK) == 0 {
		if assertion != "" || form.Get("client_assertion_type") != "" {
			return Client{}, badClient("This client has no key, so it sends no assertion.")
		}
		return client, nil
	}
	if form.Get("client_assertion_type") != oidcflow.ClientAssertionType || assertion == "" {
		return Client{}, badClient("This client must sign a client assertion.")
	}
	if err := s.checkAssertion(r, client, assertion); err != nil {
		return Client{}, err
	}
	return client, nil
}

// checkAssertion checks a client assertion (RFC 7523 section 3): the
// signature of the registered key, iss and sub equal to the client, the
// token endpoint or the issuer in aud, an exp in the next minutes, and a
// jti the server has not seen.
func (s *Server) checkAssertion(r *http.Request, client Client, assertion string) error {
	key, err := client.key()
	if err != nil {
		return badClient("The key of the client does not load.")
	}
	raw, _, err := jose.Verify(assertion, key.Key, assertionAlgs)
	if err != nil {
		return badClient("The client assertion does not verify with the key of the client.")
	}
	var claims struct {
		Iss string `json:"iss"`
		Sub string `json:"sub"`
		Aud any    `json:"aud"`
		Jti string `json:"jti"`
		Exp int64  `json:"exp"`
	}
	if uerr := json.Unmarshal(raw, &claims); uerr != nil {
		return badClient("The client assertion is not a JSON object.")
	}
	now := s.now()
	exp := time.Unix(claims.Exp, 0)
	switch {
	case subtle.ConstantTimeCompare([]byte(claims.Iss), []byte(client.ID)) != 1 || claims.Sub != client.ID:
		return badClient("The client assertion names another client.")
	case !s.audienceOK(claims.Aud):
		return badClient("The client assertion names another audience.")
	case claims.Exp == 0 || !now.Before(exp) || exp.After(now.Add(maxAssertionLife)):
		return badClient("The client assertion has expired or lives too long.")
	case claims.Jti == "":
		return badClient("The client assertion has no jti.")
	}
	// A new record per jti: the compare and swap fails when the jti was
	// seen before.
	rec, err := json.Marshal(jti{ExpiresAt: exp})
	if err != nil {
		return err
	}
	if err := s.kv.CompareAndSwap(r.Context(), hashed(jtiPrefix, client.ID+"|"+claims.Jti), nil, rec); err != nil {
		return badClient("The client assertion was already used.")
	}
	return nil
}

// audienceOK reports whether aud names the token endpoint or the issuer.
func (s *Server) audienceOK(aud any) bool {
	var list []string
	switch a := aud.(type) {
	case string:
		list = []string{a}
	case []any:
		for _, item := range a {
			if v, ok := item.(string); ok {
				list = append(list, v)
			}
		}
	}
	for _, v := range list {
		if v == s.issuer+TokenPath || v == s.issuer {
			return true
		}
	}
	return false
}

// mint signs the access token of one claim. Its subject is the key of
// the claims row, and its audience is the credential endpoint of the
// Certify that trusts this server (ADR-052 decision 4).
func (s *Server) mint(client Client, subject string) (map[string]any, error) {
	now := s.now()
	nonce := oidc.NewState()
	claims := map[string]any{
		"iss":                s.issuer,
		"sub":                subject,
		"aud":                s.audience,
		"client_id":          client.ID,
		"scope":              Scope,
		"iat":                now.Unix(),
		"nbf":                now.Unix(),
		"exp":                now.Add(TokenTTL).Unix(),
		"jti":                oidc.NewState(),
		"c_nonce":            nonce,
		"c_nonce_expires_in": int64(NonceTTL / time.Second),
	}
	token, err := jose.SignRS256(s.key.private, s.key.public.KeyID, "JWT", claims)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"access_token":       token,
		"token_type":         "Bearer",
		"expires_in":         int64(TokenTTL / time.Second),
		"scope":              Scope,
		"c_nonce":            nonce,
		"c_nonce_expires_in": int64(NonceTTL / time.Second),
	}, nil
}
