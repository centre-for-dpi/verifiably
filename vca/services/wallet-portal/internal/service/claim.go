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
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/session"
)

// DefaultClientID is the client id of the wallet at an issuer
// authorization server.
const DefaultClientID = "vca-wallet"

// signIn starts the authorization code flow in the browser (spec HO3).
// It runs only with a DPG wallet, a redirect URI, and an issuer whose
// authorization server names its endpoints. The second value is false
// when the flow does not apply, so the caller falls back.
func (s *Service) signIn(ctx context.Context, citizen session.Citizen, msg *walletportalv1.ClaimRequest,
) (string, bool, error) {
	if s.opts.Holder == nil || s.opts.Endpoints == nil || msg.GetRedirectUri() == "" {
		return "", false, nil
	}
	ends, ok := s.endpoints(ctx, msg.GetCredentialIssuer())
	if !ok {
		return "", false, nil
	}
	verifier := randomText()
	sum := sha256.Sum256([]byte(verifier))
	rec := record{
		ID: s.opts.NewID(), Issuer: msg.GetCredentialIssuer(), Types: []string{msg.GetSchemaId()},
		Verifier: verifier, Token: ends.Token, Redirect: msg.GetRedirectUri(),
	}
	if err := s.put(ctx, KindSignIn, citizen.WalletKey(), rec); err != nil {
		return "", false, connect.NewError(connect.CodeInternal, err)
	}
	details, err := json.Marshal([]map[string]string{{
		"type": "openid_credential", "credential_configuration_id": msg.GetSchemaId(),
	}})
	if err != nil {
		return "", false, connect.NewError(connect.CodeInternal, err)
	}
	q := url.Values{
		"response_type": {"code"}, "client_id": {s.opts.ClientID}, "redirect_uri": {msg.GetRedirectUri()},
		"state": {rec.ID}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"}, "authorization_details": {string(details)},
	}
	sep := "?"
	if strings.Contains(ends.Authorization, "?") {
		sep = "&"
	}
	return ends.Authorization + sep + q.Encode(), true, nil
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
	token, err := s.token(ctx, rec, req.Msg.GetCode())
	if err != nil {
		return nil, err
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

// token trades the code at the token endpoint with the PKCE verifier.
func (s *Service) token(ctx context.Context, rec record, code string) (string, error) {
	unavailable := connect.NewError(connect.CodeUnavailable, errors.New("the issuer did not give an access token"))
	if s.opts.Post == nil {
		return "", unavailable
	}
	raw, err := s.opts.Post(ctx, rec.Token, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {rec.Redirect},
		"client_id": {s.opts.ClientID}, "code_verifier": {rec.Verifier},
	})
	if err != nil {
		return "", unavailable
	}
	var answer struct {
		AccessToken string `json:"access_token"`
	}
	if json.Unmarshal(raw, &answer) != nil || answer.AccessToken == "" {
		return "", unavailable
	}
	return answer.AccessToken, nil
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
