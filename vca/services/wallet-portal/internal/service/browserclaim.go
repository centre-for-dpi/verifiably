// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/detect"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/holderkey"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/ports"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/present"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/session"
)

// The browser store claims an offer with the holder key of the browser
// (ADR-073). The portal runs the OID4VCI calls. The browser signs the
// proof, and the private key never leaves it.

// KindClaim keeps a claim of the browser store between its two steps.
const KindClaim = "claim"

// Paths of the metadata documents the claim reads.
const (
	issuerMetadataPath = "/.well-known/openid-credential-issuer"
	serverMetadataPath = "/.well-known/oauth-authorization-server"
	preAuthorizedGrant = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
)

// CredentialPoster posts a credential request with an access token and
// returns the answer of the issuer.
type CredentialPoster func(ctx context.Context, url, accessToken string, body []byte) ([]byte, error)

// Claim is the first step of a claim into the browser store: the id of
// the step and the signing input of the proof the browser signs.
type Claim struct {
	ID           string
	SigningInput string
}

// Claimed is a credential the browser store took.
type Claimed struct {
	// ID is the id of the held credential.
	ID string
	// Credential is the credential as the issuer gave it.
	Credential string
	// Format is its wire format.
	Format commonv1.Format
}

// issuerMetadata is the part of the issuer metadata a claim reads.
type issuerMetadata struct {
	CredentialEndpoint   string                     `json:"credential_endpoint"`
	NonceEndpoint        string                     `json:"nonce_endpoint"`
	TokenEndpoint        string                     `json:"token_endpoint"`
	AuthorizationServers []string                   `json:"authorization_servers"`
	Configurations       map[string]json.RawMessage `json:"credential_configurations_supported"`
}

// tokenAnswer is the answer of the token endpoint.
type tokenAnswer struct {
	AccessToken string `json:"access_token"`
	CNonce      string `json:"c_nonce"`
}

// claimFail answers a failed step with the reason the holder reads.
func claimFail(code connect.Code, text string) error {
	return connect.NewError(code, errors.New(text))
}

// ClaimStart reads a pending offer, trades its pre-authorized code for
// an access token, and returns the proof the browser signs. jwk is the
// public holder key of the browser.
func (s *Service) ClaimStart(ctx context.Context, offerID, pin, jwk string) (Claim, error) {
	citizen, err := session.Require(ctx)
	if err != nil {
		return Claim{}, err
	}
	if !s.KeepsBrowser(ctx) {
		return Claim{}, claimFail(connect.CodeFailedPrecondition, "the wallet of the stack claims this offer")
	}
	if s.opts.Fetch == nil || s.opts.Post == nil || s.opts.PostCredential == nil {
		return Claim{}, claimFail(connect.CodeFailedPrecondition, "this wallet cannot claim an offer in the browser")
	}
	key, err := holderkey.ParseKey(jwk)
	if err != nil {
		return Claim{}, claimFail(connect.CodeInvalidArgument, "the browser sent no usable holder key")
	}
	offer, err := s.get(ctx, KindOffer, citizen.WalletKey(), offerID)
	if err != nil {
		return Claim{}, recordError(err)
	}
	if offer.AccessToken != "" {
		// The holder signed in at the issuer, so the wallet holds the
		// access token already (ADR-082).
		return s.claimProof(ctx, citizen, offer, offer.Issuer, offer.Types, tokenAnswer{AccessToken: offer.AccessToken, CNonce: offer.Nonce}, jwk, key)
	}
	grant, ok := s.readOffer(ctx, offer.URI)
	if !ok || len(grant.IDs) == 0 || grant.Issuer == "" {
		return Claim{}, claimFail(connect.CodeFailedPrecondition,
			"the wallet cannot read this offer; its link must point at a host on the request host list")
	}
	code := grant.Grants.PreAuthorized.Code
	if code == "" {
		return Claim{}, claimFail(connect.CodeFailedPrecondition, "this offer needs a sign in at the issuer, which the browser store does not run")
	}
	meta, err := s.issuerMetadata(ctx, grant.Issuer)
	if err != nil {
		return Claim{}, err
	}
	if _, err = credentialRequest(meta, grant.IDs[0]); err != nil {
		return Claim{}, err
	}
	token, err := s.preAuthorizedToken(ctx, meta, grant.Issuer, code, pin)
	if err != nil {
		return Claim{}, err
	}
	return s.claimProof(ctx, citizen, offer, grant.Issuer, grant.IDs, token, jwk, key)
}

// claimProof returns the proof the browser signs for an access token,
// and keeps the claim for the second step.
func (s *Service) claimProof(ctx context.Context, citizen session.Citizen, offer record, issuer string, ids []string,
	token tokenAnswer, jwk string, key jose.JWK,
) (Claim, error) {
	if len(ids) == 0 {
		return Claim{}, claimFail(connect.CodeFailedPrecondition, "the offer names no credential")
	}
	meta, err := s.issuerMetadata(ctx, issuer)
	if err != nil {
		return Claim{}, err
	}
	request, err := credentialRequest(meta, ids[0])
	if err != nil {
		return Claim{}, err
	}
	nonce := token.CNonce
	if nonce == "" && meta.NonceEndpoint != "" {
		nonce = s.freshNonce(ctx, meta.NonceEndpoint)
	}
	input, err := holderkey.ProofInput(key, issuer, nonce, s.opts.Now())
	if err != nil {
		return Claim{}, connect.NewError(connect.CodeInternal, err)
	}
	rec := record{
		ID: s.opts.NewID(), URI: meta.CredentialEndpoint, Issuer: issuer, Types: ids,
		AccessToken: token.AccessToken, SigningInput: input, HolderKey: jwk, Request: string(request), Offer: offer.ID,
		// An issuer with a nonce endpoint follows OID4VCI 1.0 or a draft
		// after 13, which take the proofs object (section 8.2).
		Proofs: meta.NonceEndpoint != "",
	}
	if err := s.put(ctx, KindClaim, citizen.WalletKey(), rec); err != nil {
		return Claim{}, connect.NewError(connect.CodeInternal, err)
	}
	return Claim{ID: rec.ID, SigningInput: input}, nil
}

// ClaimFinish sends the credential request with the proof the browser
// signed, keeps the credential as a held one, and returns it, so the
// browser seals it into its store.
func (s *Service) ClaimFinish(ctx context.Context, claimID, signature string) (Claimed, error) {
	citizen, err := session.Require(ctx)
	if err != nil {
		return Claimed{}, err
	}
	rec, err := s.get(ctx, KindClaim, citizen.WalletKey(), claimID)
	if err != nil {
		return Claimed{}, recordError(err)
	}
	// A step runs once, so a replayed signature finds nothing.
	ignored := s.drop(ctx, KindClaim, citizen.WalletKey(), rec.ID)
	_ = ignored
	key, err := holderkey.ParseKey(rec.HolderKey)
	if err != nil {
		return Claimed{}, connect.NewError(connect.CodeInternal, err)
	}
	proof, err := holderkey.Join(rec.SigningInput, signature, key)
	if err != nil {
		return Claimed{}, claimFail(connect.CodeInvalidArgument, "the browser signature does not match its holder key")
	}
	var body map[string]any
	if err = json.Unmarshal([]byte(rec.Request), &body); err != nil {
		return Claimed{}, connect.NewError(connect.CodeInternal, err)
	}
	body["proof"] = map[string]any{"proof_type": "jwt", "jwt": proof}
	if rec.Proofs {
		// OID4VCI 1.0 takes the proofs object, and never both.
		delete(body, "proof")
		body["proofs"] = map[string]any{"jwt": []string{proof}}
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return Claimed{}, connect.NewError(connect.CodeInternal, err)
	}
	answer, err := s.opts.PostCredential(ctx, rec.URI, rec.AccessToken, raw)
	if err != nil {
		return Claimed{}, issuerRefusal("the issuer did not give the credential", err)
	}
	text := credentialOf(answer)
	got, err := detect.Text(text, s.opts.MaxPasteBytes)
	if err != nil || got.Kind != detect.Credential {
		return Claimed{}, claimFail(connect.CodeUnavailable, "the issuer answered with no credential this wallet reads")
	}
	held := record{ID: s.opts.NewID(), Payload: got.Credential, Format: got.Format}
	if err := s.put(ctx, KindHeld, citizen.WalletKey(), held); err != nil {
		return Claimed{}, connect.NewError(connect.CodeInternal, err)
	}
	ignored2 := s.drop(ctx, KindOffer, citizen.WalletKey(), rec.Offer)
	_ = ignored2
	return Claimed{ID: held.ID, Credential: string(got.Credential), Format: got.Format}, nil
}

// issuerMetadata reads the metadata of an issuer on the request host
// list.
func (s *Service) issuerMetadata(ctx context.Context, issuer string) (issuerMetadata, error) {
	raw, err := s.guardedFetch(ctx, strings.TrimRight(issuer, "/")+issuerMetadataPath)
	if err != nil {
		return issuerMetadata{}, claimFail(connect.CodeUnavailable, "the wallet cannot read the metadata of the issuer")
	}
	var meta issuerMetadata
	if json.Unmarshal(raw, &meta) != nil || meta.CredentialEndpoint == "" {
		return issuerMetadata{}, claimFail(connect.CodeUnavailable, "the metadata of the issuer names no credential endpoint")
	}
	return meta, nil
}

// credentialRequest returns the credential request of a configuration,
// with no proof. It names the configuration in the way of OID4VCI 1.0,
// and the format with its type in the way of draft 13, so both kinds of
// issuer read it.
func credentialRequest(meta issuerMetadata, id string) ([]byte, error) {
	raw, ok := meta.Configurations[id]
	if !ok {
		return nil, claimFail(connect.CodeFailedPrecondition, "the issuer does not describe the credential of this offer")
	}
	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, claimFail(connect.CodeUnavailable, "the issuer describes the credential of this offer in a shape the wallet cannot read")
	}
	body := map[string]json.RawMessage{}
	quoted, err := json.Marshal(id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	body["credential_configuration_id"] = quoted
	for _, name := range []string{"format", "vct", "doctype", "credential_definition"} {
		if v, ok := cfg[name]; ok {
			body[name] = v
		}
	}
	return json.Marshal(body)
}

// preAuthorizedToken trades the pre-authorized code of an offer for an
// access token.
func (s *Service) preAuthorizedToken(ctx context.Context, meta issuerMetadata, issuer, code, pin string) (tokenAnswer, error) {
	endpoint := meta.TokenEndpoint
	if endpoint == "" {
		server := issuer
		if len(meta.AuthorizationServers) > 0 {
			server = meta.AuthorizationServers[0]
		}
		raw, err := s.guardedFetch(ctx, strings.TrimRight(server, "/")+serverMetadataPath)
		var as struct {
			Token string `json:"token_endpoint"`
		}
		if err != nil || json.Unmarshal(raw, &as) != nil || as.Token == "" {
			return tokenAnswer{}, claimFail(connect.CodeUnavailable, "the authorization server of the issuer names no token endpoint")
		}
		endpoint = as.Token
	}
	form := url.Values{"grant_type": {preAuthorizedGrant}, "pre-authorized_code": {code}}
	if pin = strings.TrimSpace(pin); pin != "" {
		form.Set("tx_code", pin)
	}
	raw, err := s.opts.Post(ctx, endpoint, form)
	if err != nil {
		return tokenAnswer{}, issuerRefusal("the issuer refused the code; check the transaction code", err)
	}
	var token tokenAnswer
	if json.Unmarshal(raw, &token) != nil || token.AccessToken == "" {
		return tokenAnswer{}, claimFail(connect.CodeUnavailable, "the issuer gave no access token")
	}
	return token, nil
}

// freshNonce asks the nonce endpoint of OID4VCI 1.0 for a nonce. An
// endpoint that does not answer leaves the proof with no nonce, and
// the issuer says so.
func (s *Service) freshNonce(ctx context.Context, endpoint string) string {
	raw, err := s.opts.PostCredential(ctx, endpoint, "", nil)
	if err != nil {
		return ""
	}
	var out struct {
		CNonce string `json:"c_nonce"`
	}
	if json.Unmarshal(raw, &out) != nil {
		return ""
	}
	return out.CNonce
}

// guardedFetch reads a document from a host on the request host list.
func (s *Service) guardedFetch(ctx context.Context, address string) ([]byte, error) {
	if err := present.AllowHost(ctx, address, s.opts.RequestHosts); err != nil {
		return nil, err
	}
	return s.opts.Fetch(ctx, address)
}

// issuerRefusal maps a refusal of the issuer to an error. A 4xx answer
// is the fault of the request, and anything else of the issuer.
func issuerRefusal(text string, err error) error {
	var status *ports.StatusError
	if errors.As(err, &status) && status.Status < 500 {
		return claimFail(connect.CodeInvalidArgument, text)
	}
	return claimFail(connect.CodeUnavailable, text)
}

// credentialOf reads the credential of an answer: the credential field
// of draft 13, or the first entry of the credentials list of 1.0.
func credentialOf(answer []byte) string {
	var out struct {
		Credential  json.RawMessage   `json:"credential"`
		Credentials []json.RawMessage `json:"credentials"`
	}
	if json.Unmarshal(answer, &out) != nil {
		return ""
	}
	raw := out.Credential
	if len(raw) == 0 && len(out.Credentials) > 0 {
		raw = out.Credentials[0]
		var entry struct {
			Credential json.RawMessage `json:"credential"`
		}
		if json.Unmarshal(raw, &entry) == nil && len(entry.Credential) > 0 {
			raw = entry.Credential
		}
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text
	}
	return string(raw)
}
