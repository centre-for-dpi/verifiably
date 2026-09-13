// SPDX-License-Identifier: Apache-2.0

// Package inji talks to Inji Certify 0.14.0 and Inji Verify 0.16.0 over
// their HTTP APIs. The vendor name and every vendor detail stay in this
// service (ADR-001 decision 4).
//
// Inji Certify serves these endpoints:
//
//   - POST /v1/certify/pre-authorized-data stages the claims of one
//     subject and returns a credential offer URI.
//   - POST /v1/certify/oauth/token redeems the pre-authorized code.
//   - POST /v1/certify/issuance/credential returns the signed credential.
//   - GET /v1/certify/issuance/.well-known/openid-credential-issuer
//     serves the OID4VCI issuer metadata.
//
// The adapter runs the whole pre-authorized flow itself. The citizen
// types nothing and needs no wallet, which is what makes the paper
// document channel of ADR-016 decision 3 work for this DPG.
package inji

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/centre-for-dpi/vc-adapters/services/internal/dpgclient"
)

// ErrNoCertify reports that the Inji Certify URL is not configured.
var ErrNoCertify = errors.New("inji: no Inji Certify URL")

// ErrNoVerify reports that the Inji Verify URL is not configured.
var ErrNoVerify = errors.New("inji: no Inji Verify URL")

// PreAuthGrant is the OID4VCI pre-authorized code grant name.
const PreAuthGrant = "urn:ietf:params:oauth:grant-type:pre-authorized_code"

// Certify calls one Inji Certify instance.
type Certify struct {
	client *dpgclient.Client
	// metadataPath is the path of the issuer metadata document.
	metadataPath string
}

// NewCertify returns a Certify client. A nil client turns the issuer
// role off.
func NewCertify(client *dpgclient.Client, metadataPath string) *Certify {
	if client == nil {
		return nil
	}
	if metadataPath == "" {
		metadataPath = "/v1/certify/issuance/.well-known/openid-credential-issuer"
	}
	return &Certify{client: client, metadataPath: metadataPath}
}

// BaseURL returns the root of the Inji Certify API.
func (c *Certify) BaseURL() string {
	if c == nil {
		return ""
	}
	return c.client.BaseURL()
}

// Metadata is the OID4VCI issuer metadata of Inji Certify.
type Metadata struct {
	// CredentialIssuer is the issuer identifier URL.
	CredentialIssuer string `json:"credential_issuer"`
	// CredentialEndpoint is the OID4VCI credential endpoint.
	CredentialEndpoint string `json:"credential_endpoint"`
	// AuthorizationServers lists the identity providers of the
	// authorization code flow.
	AuthorizationServers []string `json:"authorization_servers"`
	// Configurations holds one entry per credential the issuer offers.
	Configurations map[string]Configuration `json:"credential_configurations_supported"`
	// Raw is the document as Inji Certify served it.
	Raw json.RawMessage `json:"-"`
}

// Configuration is one credential configuration of the metadata.
type Configuration struct {
	// Format is the OID4VCI format identifier.
	Format string `json:"format"`
	// Scope is the OAuth scope of the configuration.
	Scope string `json:"scope,omitempty"`
	// Vct is the SD-JWT VC type.
	Vct string `json:"vct,omitempty"`
	// Order lists the claim names in display order.
	Order []string `json:"order,omitempty"`
	// Display holds the display metadata.
	Display []json.RawMessage `json:"display,omitempty"`
	// CredentialDefinition carries the W3C context and type names.
	CredentialDefinition *CredentialDefinition `json:"credential_definition,omitempty"`
}

// CredentialDefinition is the W3C part of one configuration.
type CredentialDefinition struct {
	// Context lists the JSON-LD context URLs.
	Context []string `json:"@context,omitempty"`
	// Type lists the credential type names.
	Type []string `json:"type,omitempty"`
}

// Metadata reads the OID4VCI issuer metadata.
func (c *Certify) Metadata(ctx context.Context) (Metadata, error) {
	if c == nil {
		return Metadata{}, ErrNoCertify
	}
	resp, err := c.client.Do(ctx, dpgclient.Request{
		Method: http.MethodGet, Path: c.metadataPath, Accept: "application/json",
	})
	if err != nil {
		return Metadata{}, err
	}
	var meta Metadata
	if err := json.Unmarshal(resp.Body, &meta); err != nil {
		return Metadata{}, fmt.Errorf("inji: read the issuer metadata: %w", err)
	}
	meta.Raw = resp.Body
	return meta, nil
}

// stageRequest is the body of POST /v1/certify/pre-authorized-data.
type stageRequest struct {
	CredentialConfigurationID string         `json:"credential_configuration_id"`
	Claims                    map[string]any `json:"claims"`
}

// stageResponse is the answer of POST /v1/certify/pre-authorized-data.
type stageResponse struct {
	CredentialOfferURI string `json:"credential_offer_uri"`
	Errors             []struct {
		ErrorCode    string `json:"errorCode"`
		ErrorMessage string `json:"errorMessage"`
	} `json:"errors"`
}

// Stage puts the claims of one subject in the Certify cache and returns
// the credential offer URI of the pre-authorized flow.
func (c *Certify) Stage(ctx context.Context, configurationID string, claims map[string]any) (string, error) {
	if c == nil {
		return "", ErrNoCertify
	}
	var out stageResponse
	body := stageRequest{CredentialConfigurationID: configurationID, Claims: claims}
	if err := c.client.JSON(ctx, http.MethodPost, "/v1/certify/pre-authorized-data", body, &out); err != nil {
		return "", err
	}
	if len(out.Errors) > 0 {
		return "", fmt.Errorf("inji: the issuer rejected the claims: %s %s",
			out.Errors[0].ErrorCode, out.Errors[0].ErrorMessage)
	}
	if out.CredentialOfferURI == "" {
		return "", errors.New("inji: the staged answer has no credential offer URI")
	}
	return out.CredentialOfferURI, nil
}

// Offer is the credential offer document Inji Certify hosts.
type Offer struct {
	// CredentialIssuer is the issuer identifier of the offer. The proof
	// audience must equal it.
	CredentialIssuer string `json:"credential_issuer"`
	// Grants holds the pre-authorized code.
	Grants map[string]struct {
		PreAuthorizedCode string `json:"pre-authorized_code"`
	} `json:"grants"`
}

// OfferDocumentURL unwraps the openid-credential-offer envelope and
// returns the path of the offer document.
//
// Inji Certify advertises the document under the public host of the
// deployment. The adapter reads the document from the instance it staged
// the claims on, so it keeps the path and drops the host. A compose
// deployment with a public host and an internal host then works without
// a rewrite rule.
func OfferDocumentURL(offerURI string) (string, error) {
	if strings.TrimSpace(offerURI) == "" {
		return "", errors.New("inji: the offer URI is empty")
	}
	inner := offerURI
	if u, err := url.Parse(offerURI); err == nil {
		if q := u.Query().Get("credential_offer_uri"); q != "" {
			inner = q
		}
	}
	if u, err := url.Parse(inner); err == nil && u.Host != "" {
		return u.RequestURI(), nil
	}
	return inner, nil
}

// FetchOffer reads the offer document Inji Certify hosts.
func (c *Certify) FetchOffer(ctx context.Context, documentURL string) (Offer, error) {
	if c == nil {
		return Offer{}, ErrNoCertify
	}
	var out Offer
	if err := c.client.JSON(ctx, http.MethodGet, documentURL, nil, &out); err != nil {
		return Offer{}, err
	}
	grant, ok := out.Grants[PreAuthGrant]
	if !ok || grant.PreAuthorizedCode == "" {
		return Offer{}, errors.New("inji: the offer has no pre-authorized code grant")
	}
	return out, nil
}

// PreAuthorizedCode returns the pre-authorized code of the offer.
func (o Offer) PreAuthorizedCode() string { return o.Grants[PreAuthGrant].PreAuthorizedCode }

// Token is the answer of the Inji Certify token endpoint.
type Token struct {
	// AccessToken authorises the credential request.
	AccessToken string `json:"access_token"`
	// TokenType is always bearer for this flow.
	TokenType string `json:"token_type"`
	// ExpiresIn is the life of the token in seconds.
	ExpiresIn int `json:"expires_in"`
	// CNonce is the nonce the proof must carry.
	CNonce string `json:"c_nonce"`
}

// Redeem exchanges the pre-authorized code for an access token. Inji
// serves this endpoint at /v1/certify/oauth/token and not under the
// issuance path.
func (c *Certify) Redeem(ctx context.Context, code string) (Token, error) {
	if c == nil {
		return Token{}, ErrNoCertify
	}
	form := url.Values{"grant_type": {PreAuthGrant}, "pre-authorized_code": {code}}
	var out Token
	if err := c.client.Form(ctx, http.MethodPost, "/v1/certify/oauth/token", form, &out); err != nil {
		return Token{}, err
	}
	if out.AccessToken == "" {
		return Token{}, errors.New("inji: the token answer has no access token")
	}
	return out, nil
}

// CredentialRequest is the body of POST /v1/certify/issuance/credential.
type CredentialRequest struct {
	Format               string                `json:"format"`
	Vct                  string                `json:"vct,omitempty"`
	CredentialDefinition *CredentialDefinition `json:"credential_definition,omitempty"`
	Proof                ProofBody             `json:"proof"`
}

// ProofBody carries the holder key proof of the credential request.
type ProofBody struct {
	ProofType string `json:"proof_type"`
	JWT       string `json:"jwt"`
}

// BuildCredentialRequest returns the credential request of one
// configuration.
//
// The ldp_vc branch repeats the JSON-LD context of the metadata word for
// word. Inji compares the two sets and rejects a request whose context
// differs.
func BuildCredentialRequest(cfg Configuration, proofJWT string) CredentialRequest {
	req := CredentialRequest{
		Format: cfg.Format,
		Proof:  ProofBody{ProofType: "jwt", JWT: proofJWT},
	}
	if cfg.Format == "ldp_vc" && cfg.CredentialDefinition != nil {
		req.CredentialDefinition = &CredentialDefinition{
			Type:    cfg.CredentialDefinition.Type,
			Context: cfg.CredentialDefinition.Context,
		}
		return req
	}
	req.Vct = cfg.Vct
	return req
}

// credentialResponse is the answer of the credential endpoint.
type credentialResponse struct {
	Credential json.RawMessage `json:"credential"`
	Format     string          `json:"format"`
}

// RequestCredential asks Inji Certify for the signed credential. It
// returns the credential exactly as Inji produced it, and the format.
//
// A JSON-LD credential comes back as a JSON object. An SD-JWT VC comes
// back as a JSON string, which the adapter unwraps to the compact form.
// Neither is re-encoded (ADR-003 decision 6).
func (c *Certify) RequestCredential(ctx context.Context, accessToken string, body CredentialRequest) ([]byte, string, error) {
	if c == nil {
		return nil, "", ErrNoCertify
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, "", fmt.Errorf("inji: encode the credential request: %w", err)
	}
	resp, err := c.client.Do(ctx, dpgclient.Request{
		Method:      http.MethodPost,
		Path:        "/v1/certify/issuance/credential",
		Body:        raw,
		ContentType: "application/json",
		Accept:      "application/json",
		Token:       accessToken,
	})
	if err != nil {
		return nil, "", err
	}
	var out credentialResponse
	if err := json.Unmarshal(resp.Body, &out); err != nil {
		return nil, "", fmt.Errorf("inji: read the credential answer: %w", err)
	}
	if len(out.Credential) == 0 {
		return nil, "", errors.New("inji: the credential answer is empty")
	}
	credential := out.Credential
	var compact string
	if json.Unmarshal(credential, &compact) == nil {
		credential = []byte(compact)
	}
	return credential, out.Format, nil
}
