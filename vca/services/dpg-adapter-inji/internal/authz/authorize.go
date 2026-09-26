// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/centre-for-dpi/vc-adapters/core/oidc"
)

// challengePattern is an S256 code challenge: 43 base64url characters
// (RFC 7636 section 4.2).
var challengePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// The descriptions a wallet shows when the server denies a claim.
const (
	// DeniedAnotherPerson is the answer to a holder whose ID token does
	// not match the binding rule of the offer.
	DeniedAnotherPerson = "This offer is for another person."
	// DeniedOfferOnly is the answer to a claim without an offer when the
	// credential has no sign in source.
	DeniedOfferOnly = "Claim this credential from an offer of the issuer."
	// DeniedNoRecord is the answer when the sign in source holds no
	// record of the holder.
	DeniedNoRecord = "No record of the issuer matches your sign in."
	// DeniedNameTheType is the answer to a claim without an offer
	// that names no credential while several have a sign in source.
	DeniedNameTheType = "Name the credential in authorization_details."
	// DeniedSignIn is the answer when the sign in at the provider fails.
	DeniedSignIn = "The sign in did not finish."
)

// authorize checks the authorization request of a wallet and sends the
// browser to the holder provider. An unknown client or a redirect URI
// the client did not register gets an error page and no redirect
// (RFC 6749 section 4.1.2.1), so the server never sends a code or an
// error to an address the operator did not approve.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	c, ok := s.clients[q.Get("client_id")]
	if !ok {
		s.refuse(w, "unknown client", "client_id", q.Get("client_id"))
		return
	}
	redirect := q.Get("redirect_uri")
	if !c.allows(redirect) {
		s.refuse(w, "the redirect URI is not registered for this client", "client_id", c.ID)
		return
	}
	req := authRequest{
		ClientID: c.ID, RedirectURI: redirect, State: q.Get("state"),
		Challenge: q.Get("code_challenge"), IssuerState: q.Get("issuer_state"),
	}
	back := func(code, description string) { s.redirectError(w, r, req, code, description) }
	switch {
	case q.Get("response_type") != "code":
		back("unsupported_response_type", "The server gives codes only.")
		return
	case req.State == "":
		back("invalid_request", "The request needs a state.")
		return
	case q.Get("code_challenge_method") != "S256" || !challengePattern.MatchString(req.Challenge):
		back("invalid_request", "The request needs a PKCE code challenge with the method S256.")
		return
	}
	configID, details := credentialOf(q.Get("authorization_details"))
	if !details && !hasScope(q.Get("scope")) {
		back("invalid_scope", "The request needs the scope "+Scope+" or authorization_details.")
		return
	}
	req.ConfigID = configID
	if req.IssuerState != "" {
		if _, open := s.offers.Offer(r.Context(), req.IssuerState); !open {
			back("invalid_request", "The offer does not exist, has expired, or was claimed.")
			return
		}
	}
	p, ok := s.holderProvider()
	if !ok {
		back("temporarily_unavailable", "No sign in is set up for holders.")
		return
	}
	pend, loginURL, err := s.flow.Begin(r.Context(), p, s.issuer+CallbackPath, "")
	if err != nil {
		s.log.Warn("the holder sign in did not start", "provider", p.ID, "error", err)
		back("temporarily_unavailable", "The sign in is not available.")
		return
	}
	rec := login{Request: req, Pending: pend, ExpiresAt: s.now().Add(RequestTTL)}
	if err := putJSON(r.Context(), s.kv, hashed(loginPrefix, pend.State), rec); err != nil {
		back("server_error", "The request could not be kept.")
		return
	}
	http.Redirect(w, r, loginURL, http.StatusFound)
}

// hasScope reports whether a scope list holds the shared scope.
func hasScope(scope string) bool {
	for _, v := range strings.Fields(scope) {
		if v == Scope {
			return true
		}
	}
	return false
}

// credentialOf reads the credential configuration of RFC 9396
// authorization details of type openid_credential (OID4VCI section
// 5.1.1). It reports whether the request carried such details.
func credentialOf(raw string) (string, bool) {
	if strings.TrimSpace(raw) == "" {
		return "", false
	}
	var details []struct {
		Type     string `json:"type"`
		ConfigID string `json:"credential_configuration_id"`
	}
	if json.Unmarshal([]byte(raw), &details) != nil {
		return "", false
	}
	for _, d := range details {
		if d.Type == "openid_credential" && d.ConfigID != "" {
			return d.ConfigID, true
		}
	}
	return "", false
}

// callback finishes the sign in at the provider, finds the claims of
// the holder, and sends the wallet a one time code. The login record is
// used once: a replayed callback finds it used.
func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	state := q.Get("state")
	var rec login
	found, used, err := consume(ctx, s.kv, hashed(loginPrefix, state), &rec, func(l *login) bool {
		was := l.Used
		l.Used = true
		return was
	})
	if state == "" || err != nil || !found || used || !s.now().Before(rec.ExpiresAt) {
		s.refuse(w, "the state of the sign in is unknown, used, or expired", "found", found)
		return
	}
	req := rec.Request
	if e := q.Get("error"); e != "" {
		s.log.Info("the holder provider refused the sign in", "error", e)
		s.redirectError(w, r, req, "access_denied", DeniedSignIn)
		return
	}
	p, err := s.registry.Get(rec.Pending.ProviderID)
	if err != nil {
		s.redirectError(w, r, req, "temporarily_unavailable", "The sign in is not available.")
		return
	}
	result, err := s.flow.Complete(ctx, p, rec.Pending, q.Get("code"))
	if err != nil {
		s.log.Info("the holder sign in failed", "provider", p.ID, "error", err)
		s.redirectError(w, r, req, "access_denied", DeniedSignIn)
		return
	}
	subject := oidc.NewState()
	if description, ok := s.stage(r, req, result.Claims, p.VerifiedClaims, subject); !ok {
		s.redirectError(w, r, req, "access_denied", description)
		return
	}
	value := oidc.NewVerifier()
	c := code{
		ClientID: req.ClientID, RedirectURI: req.RedirectURI, Challenge: req.Challenge,
		Subject: subject, ExpiresAt: s.now().Add(CodeTTL),
	}
	if err := putJSON(ctx, s.kv, hashed(codePrefix, value), c); err != nil {
		s.redirectError(w, r, req, "server_error", "The code could not be kept.")
		return
	}
	s.redirect(w, r, req, url.Values{"code": {value}})
}

// stage writes the claims row of the holder under subject: the row of
// the offer after its binding rule matched, or the row the sign in
// source holds for the holder. vouched lists the claims the provider
// record names as verified. It returns the description of a denial.
func (s *Server) stage(r *http.Request, req authRequest, claims map[string]any, vouched []string, subject string) (string, bool) {
	ctx := r.Context()
	if req.IssuerState != "" {
		offer, open := s.offers.Offer(ctx, req.IssuerState)
		if !open {
			return "The offer has expired or was claimed.", false
		}
		if !offer.Binding.matches(claims, offer.Subject, vouched) {
			return DeniedAnotherPerson, false
		}
		if err := s.offers.StageOffer(ctx, req.IssuerState, subject); err != nil {
			s.log.Warn("the claims row of an offer was not written", "error", err)
			return "The offer has expired or was claimed.", false
		}
		return "", true
	}
	if s.lookup == nil {
		return DeniedOfferOnly, false
	}
	src, description, ok := s.sourceFor(r, req.ConfigID)
	if !ok {
		return description, false
	}
	value, ok := tokenValue(claims, src.TokenClaim, vouched)
	if !ok {
		return DeniedNoRecord, false
	}
	row, found, err := s.lookup.Lookup(ctx, src, value)
	if err != nil {
		s.log.Warn("the sign in source did not answer", "source", src.SourceID, "error", err)
		return "The issuer cannot read its records now.", false
	}
	if !found {
		return DeniedNoRecord, false
	}
	if err := s.offers.StageSubject(ctx, src.ConfigID, row, subject); err != nil {
		s.log.Warn("the claims row of a sign in was not written", "error", err)
		return "The issuer cannot write the credential now.", false
	}
	return "", true
}

// sourceFor returns the sign in source of the credential of a claim
// without an offer: the one the request names, or the only one stored.
func (s *Server) sourceFor(r *http.Request, configID string) (SignInSource, string, bool) {
	sources, err := s.signInSources(r.Context())
	if err != nil {
		return SignInSource{}, "The issuer cannot read its records now.", false
	}
	if configID != "" {
		for _, src := range sources {
			if src.ConfigID == configID {
				return src, "", true
			}
		}
		return SignInSource{}, DeniedOfferOnly, false
	}
	switch len(sources) {
	case 0:
		return SignInSource{}, DeniedOfferOnly, false
	case 1:
		return sources[0], "", true
	}
	return SignInSource{}, DeniedNameTheType, false
}

// redirect sends the browser back to the wallet with the parameters,
// the state of the wallet, and the issuer (RFC 9207).
func (s *Server) redirect(w http.ResponseWriter, r *http.Request, req authRequest, params url.Values) {
	u, err := url.Parse(req.RedirectURI)
	if err != nil {
		s.refuse(w, "the redirect URI does not parse", "client_id", req.ClientID)
		return
	}
	q := u.Query()
	for k, v := range params {
		q[k] = v
	}
	if req.State != "" {
		q.Set("state", req.State)
	}
	q.Set("iss", s.issuer)
	u.RawQuery = q.Encode()
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// redirectError sends an error of RFC 6749 section 4.1.2.1 back to the
// wallet.
func (s *Server) redirectError(w http.ResponseWriter, r *http.Request, req authRequest, code, description string) {
	s.redirect(w, r, req, url.Values{"error": {code}, "error_description": {description}})
}

// refuse answers a request the server cannot send back to a wallet.
func (s *Server) refuse(w http.ResponseWriter, reason string, args ...any) {
	s.log.Info("the holder authorization server refused a request: "+reason, args...)
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, fmt.Sprintf("The request was refused: %s.", reason), http.StatusBadRequest)
}
