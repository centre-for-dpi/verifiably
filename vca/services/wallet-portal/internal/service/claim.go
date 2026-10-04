// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"

	"connectrpc.com/connect"

	walletportalv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/issuers"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/present"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/session"
)

// DefaultClientID is the client id of the wallet at an issuer
// authorization server.
const DefaultClientID = "vca-wallet"

// signIn starts the authorization code flow in the browser (spec HO3,
// ADR-082). It runs with a redirect URI and an issuer whose
// authorization server names its endpoints, for a DPG wallet and for
// the browser store. A pending offer names the issuer, the
// configuration, the issuer_state and the authorization server. The
// request carries PKCE always, and it goes as a pushed authorization
// request when the server takes one (RFC 9126). The second value is
// false when the flow does not apply, so the caller falls back.
func (s *Service) signIn(ctx context.Context, citizen session.Citizen, msg *walletportalv1.ClaimRequest,
) (string, bool, error) {
	if s.opts.Endpoints == nil || msg.GetRedirectUri() == "" {
		return "", false, nil
	}
	issuer, config, issuerState, server := msg.GetCredentialIssuer(), msg.GetSchemaId(), "", ""
	if id := msg.GetOfferId(); id != "" {
		offer, err := s.get(ctx, KindOffer, citizen.WalletKey(), id)
		if err != nil {
			return "", false, recordError(err)
		}
		grant, ok := s.readOffer(ctx, offer.URI)
		if !ok || grant.Issuer == "" || len(grant.IDs) == 0 || grant.Grants.Code == nil {
			return "", false, claimFail(connect.CodeFailedPrecondition, "this offer names no sign in at the issuer")
		}
		issuer, config = grant.Issuer, grant.IDs[0]
		issuerState, server = grant.Grants.Code.IssuerState, grant.Grants.Code.Server
	}
	ends, ok := s.authorizationServer(ctx, issuer, server)
	switch {
	case !ok && msg.GetOfferId() != "":
		return "", false, claimFail(connect.CodeFailedPrecondition,
			"the issuer names no authorization server where you can sign in")
	case !ok:
		return "", false, nil
	}
	verifier := randomText()
	sum := sha256.Sum256([]byte(verifier))
	rec := record{
		ID: s.opts.NewID(), Issuer: issuer, Types: []string{config},
		Verifier: verifier, Token: ends.Token, Redirect: msg.GetRedirectUri(),
	}
	if err := s.put(ctx, KindSignIn, citizen.WalletKey(), rec); err != nil {
		return "", false, connect.NewError(connect.CodeInternal, err)
	}
	details, err := json.Marshal([]map[string]string{{
		"type": "openid_credential", "credential_configuration_id": config,
	}})
	if err != nil {
		return "", false, connect.NewError(connect.CodeInternal, err)
	}
	q := url.Values{
		"response_type": {"code"}, "client_id": {s.opts.ClientID}, "redirect_uri": {msg.GetRedirectUri()},
		"state": {rec.ID}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"}, "authorization_details": {string(details)},
	}
	if issuerState != "" {
		q.Set("issuer_state", issuerState)
	}
	if ends.PushedAuthorization != "" {
		pushed, perr := s.push(ctx, ends.PushedAuthorization, q)
		if perr != nil {
			return "", false, perr
		}
		q = url.Values{"client_id": {s.opts.ClientID}, "request_uri": {pushed}}
	}
	sep := "?"
	if strings.Contains(ends.Authorization, "?") {
		sep = "&"
	}
	return ends.Authorization + sep + q.Encode(), true, nil
}

// push sends a pushed authorization request and returns its request_uri
// (RFC 9126 section 2).
func (s *Service) push(ctx context.Context, endpoint string, form url.Values) (string, error) {
	refused := connect.NewError(connect.CodeUnavailable, errors.New("the issuer did not take the authorization request"))
	if s.opts.Post == nil {
		return "", refused
	}
	raw, err := s.opts.Post(ctx, endpoint, form)
	if err != nil {
		return "", refused
	}
	var answer struct {
		RequestURI string `json:"request_uri"`
	}
	if json.Unmarshal(raw, &answer) != nil || answer.RequestURI == "" {
		return "", refused
	}
	return answer.RequestURI, nil
}

// authorizationServer returns the endpoints of the server an offer
// names, or of the authorization server of the issuer. It reports false
// when neither names an authorization endpoint.
func (s *Service) authorizationServer(ctx context.Context, issuer, server string) (issuers.Endpoints, bool) {
	if server != "" && s.opts.Servers != nil {
		if ends, err := s.opts.Servers(ctx, server); err == nil && ends.Authorization != "" {
			return ends, true
		}
	}
	return s.endpoints(ctx, issuer)
}

// endpoints returns the endpoints of an issuer, or false when its
// authorization server names none.
func (s *Service) endpoints(ctx context.Context, issuer string) (issuers.Endpoints, bool) {
	ends, err := s.opts.Endpoints(ctx, issuer)
	return ends, err == nil
}

// ClaimComplete trades the code of the issuer for an access token and
// claims the credential into the DPG wallet with it (spec HO3).
func (s *Service) ClaimComplete(ctx context.Context, req *connect.Request[walletportalv1.ClaimCompleteRequest],
) (*connect.Response[walletportalv1.ClaimCompleteResponse], error) {
	citizen, err := session.Require(ctx)
	if err != nil {
		return nil, err
	}
	rec, err := s.get(ctx, KindSignIn, citizen.WalletKey(), req.Msg.GetState())
	if err != nil {
		return nil, recordError(err)
	}
	ignored := s.drop(ctx, KindSignIn, citizen.WalletKey(), rec.ID)
	_ = ignored
	if req.Msg.GetError() != "" {
		return nil, connect.NewError(connect.CodePermissionDenied,
			errors.New("the issuer did not confirm who you are"))
	}
	token, nonce, err := s.token(ctx, rec, req.Msg.GetCode())
	if err != nil {
		return nil, err
	}
	if s.opts.Holder == nil {
		// The browser store claims with its own key, so the wallet keeps
		// the token for the proof step of the browser (ADR-082).
		return s.authorized(ctx, citizen, rec, token, nonce)
	}
	offerURI, err := authCodeOffer(rec.Issuer, strings.Join(rec.Types, ""))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	card, err := s.accept(ctx, citizen, offerURI, "", token)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&walletportalv1.ClaimCompleteResponse{Card: card}), nil
}

// authorized keeps the access token of a sign in as an offer that the
// browser store claims with its key, and returns the offer.
func (s *Service) authorized(ctx context.Context, citizen session.Citizen, rec record, token, nonce string,
) (*connect.Response[walletportalv1.ClaimCompleteResponse], error) {
	offer := record{ID: s.opts.NewID(), Issuer: rec.Issuer, Types: rec.Types, AccessToken: token, Nonce: nonce}
	if err := s.put(ctx, KindOffer, citizen.WalletKey(), offer); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	trust := present.TrustOf(ctx, s.opts.Trust, rec.Issuer)
	view := s.offerDetails(ctx, rec.Issuer, rec.Types)
	return connect.NewResponse(&walletportalv1.ClaimCompleteResponse{OfferId: offer.ID, Offer: &walletportalv1.OfferSummary{
		CredentialIssuer: rec.Issuer, IssuerName: orName(trust.Name, view.name), Trust: trust.Outcome,
		Types: rec.Types, Display: view.displays, Claims: view.claims, MetadataRead: view.read,
	}}), nil
}

// token trades the code at the token endpoint with the PKCE verifier.
// It returns the access token and the c_nonce of the answer.
func (s *Service) token(ctx context.Context, rec record, code string) (string, string, error) {
	unavailable := connect.NewError(connect.CodeUnavailable, errors.New("the issuer did not give an access token"))
	if s.opts.Post == nil {
		return "", "", unavailable
	}
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"client_id": {s.opts.ClientID}, "code_verifier": {rec.Verifier},
	}
	if rec.Redirect != "" {
		form.Set("redirect_uri", rec.Redirect)
	}
	raw, err := s.opts.Post(ctx, rec.Token, form)
	if err != nil {
		return "", "", unavailable
	}
	var answer tokenAnswer
	if json.Unmarshal(raw, &answer) != nil || answer.AccessToken == "" {
		return "", "", unavailable
	}
	return answer.AccessToken, answer.CNonce, nil
}

// randomText returns 32 random bytes in base64url, for a PKCE verifier.
func randomText() string {
	b := make([]byte, 32)
	// crypto/rand cannot fail on a platform that Go supports.
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
