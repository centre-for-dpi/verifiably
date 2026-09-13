// SPDX-License-Identifier: Apache-2.0

// Package waltid talks to the walt.id Community Stack 0.18.2 over its
// HTTP API. The vendor name and every vendor detail stay in this service
// (ADR-001 decision 4).
//
// The stack has three services:
//
//   - issuer-api: POST /onboard/issuer, POST /openid4vc/{jwt,sdjwt,mdoc}/issue,
//     GET /{standardVersion}/.well-known/openid-credential-issuer.
//   - verifier-api: POST /openid4vc/verify, GET /openid4vc/session/{id}.
//     Release 0.18.2 has no endpoint that checks one pasted credential.
//   - wallet-api: POST /wallet-api/auth/{register,login},
//     GET /wallet-api/wallet/accounts/wallets,
//     POST /wallet-api/wallet/{id}/exchange/{resolveCredentialOffer,
//     useOfferRequest,usePresentationRequest},
//     GET and DELETE /wallet-api/wallet/{id}/credentials.
//
// Release 0.18.2 speaks OID4VCI draft 13 and OID4VP with Presentation
// Exchange 2.0. It has no DCQL query support.
package waltid

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/centre-for-dpi/vc-adapters/services/internal/dpgclient"
)

// Client calls the three walt.id services.
type Client struct {
	issuer   *dpgclient.Client
	verifier *dpgclient.Client
	wallet   *dpgclient.Client
	// standardVersion is the draft name in the metadata path.
	standardVersion string

	mu        sync.Mutex
	issuerKey json.RawMessage
	issuerDid string
}

// Options configure New.
type Options struct {
	// Issuer calls the issuer-api. Nil turns the issuer role off.
	Issuer *dpgclient.Client
	// Verifier calls the verifier-api. Nil turns the verifier role off.
	Verifier *dpgclient.Client
	// Wallet calls the wallet-api. Nil turns the holder role off.
	Wallet *dpgclient.Client
	// StandardVersion is the draft name, for example draft13.
	StandardVersion string
	// IssuerKey is the JWK wrapper of the signing key, as JSON.
	IssuerKey string
	// IssuerDid is the signing DID.
	IssuerDid string
}

// New returns a client for the walt.id stack.
func New(opts Options) *Client {
	c := &Client{
		issuer:          opts.Issuer,
		verifier:        opts.Verifier,
		wallet:          opts.Wallet,
		standardVersion: opts.StandardVersion,
		issuerDid:       opts.IssuerDid,
	}
	if c.standardVersion == "" {
		c.standardVersion = "draft13"
	}
	if key := strings.TrimSpace(opts.IssuerKey); key != "" {
		c.issuerKey = json.RawMessage(key)
	}
	return c
}

// HasIssuer reports whether the issuer role is configured.
func (c *Client) HasIssuer() bool { return c.issuer != nil }

// HasVerifier reports whether the verifier role is configured.
func (c *Client) HasVerifier() bool { return c.verifier != nil }

// HasWallet reports whether the holder role is configured.
func (c *Client) HasWallet() bool { return c.wallet != nil }

// IssuerMetadata is the part of the OID4VCI issuer metadata the adapter
// reads.
type IssuerMetadata struct {
	// CredentialIssuer is the issuer identifier URL.
	CredentialIssuer string `json:"credential_issuer"`
	// CredentialEndpoint is the OID4VCI credential endpoint.
	CredentialEndpoint string `json:"credential_endpoint"`
	// CredentialConfigurationsSupported holds one entry per offer type.
	CredentialConfigurationsSupported map[string]ConfigurationEntry `json:"credential_configurations_supported"`
	// Raw is the document as walt.id served it.
	Raw json.RawMessage `json:"-"`
}

// ConfigurationEntry is one credential configuration of the metadata.
type ConfigurationEntry struct {
	// Format is the OID4VCI format identifier.
	Format string `json:"format"`
	// Vct is the SD-JWT VC type. It is empty for the W3C formats.
	Vct string `json:"vct,omitempty"`
	// Display holds the display metadata of the configuration.
	Display []json.RawMessage `json:"display,omitempty"`
	// CredentialDefinition carries the W3C type names.
	CredentialDefinition *struct {
		Type []string `json:"type"`
	} `json:"credential_definition,omitempty"`
}

// Metadata fetches the OID4VCI issuer metadata.
func (c *Client) Metadata(ctx context.Context) (IssuerMetadata, error) {
	if c.issuer == nil {
		return IssuerMetadata{}, ErrNoIssuer
	}
	path := "/" + c.standardVersion + "/.well-known/openid-credential-issuer"
	resp, err := c.issuer.Do(ctx, dpgclient.Request{
		Method: http.MethodGet, Path: path, Accept: "application/json",
	})
	if err != nil {
		return IssuerMetadata{}, err
	}
	var meta IssuerMetadata
	if err := json.Unmarshal(resp.Body, &meta); err != nil {
		return IssuerMetadata{}, fmt.Errorf("waltid: read the issuer metadata: %w", err)
	}
	meta.Raw = resp.Body
	return meta, nil
}

// onboardResponse is the answer of POST /onboard/issuer.
type onboardResponse struct {
	// IssuerKey is the JWK wrapper of the new signing key.
	IssuerKey json.RawMessage `json:"issuerKey"`
	// IssuerDid is the DID of the new signing key.
	IssuerDid string `json:"issuerDid"`
}

// EnsureIssuerKey returns the signing key and the DID. It onboards a new
// key at the first call when the configuration pins none.
func (c *Client) EnsureIssuerKey(ctx context.Context) (json.RawMessage, string, error) {
	c.mu.Lock()
	key, did := c.issuerKey, c.issuerDid
	c.mu.Unlock()
	if len(key) > 0 && did != "" {
		return key, did, nil
	}
	if c.issuer == nil {
		return nil, "", ErrNoIssuer
	}
	body := map[string]any{
		"key": map[string]any{"backend": "jwk", "keyType": "secp256r1"},
		"did": map[string]any{"method": "key"},
	}
	var out onboardResponse
	if err := c.issuer.JSON(ctx, http.MethodPost, "/onboard/issuer", body, &out); err != nil {
		return nil, "", fmt.Errorf("waltid: onboard the issuer: %w", err)
	}
	if len(out.IssuerKey) == 0 || out.IssuerDid == "" {
		return nil, "", fmt.Errorf("waltid: the onboard answer has no key or no DID")
	}
	c.mu.Lock()
	c.issuerKey, c.issuerDid = out.IssuerKey, out.IssuerDid
	c.mu.Unlock()
	return out.IssuerKey, out.IssuerDid, nil
}

// IssuanceRequest is the body of POST /openid4vc/{format}/issue. Only
// the fields the adapter sets appear here. walt.id ignores the rest.
type IssuanceRequest struct {
	IssuerKey                 json.RawMessage `json:"issuerKey"`
	CredentialConfigurationID string          `json:"credentialConfigurationId"`
	IssuerDid                 string          `json:"issuerDid,omitempty"`
	AuthenticationMethod      string          `json:"authenticationMethod,omitempty"`
	StandardVersion           string          `json:"standardVersion,omitempty"`
	CredentialData            json.RawMessage `json:"credentialData,omitempty"`
	MdocData                  json.RawMessage `json:"mdocData,omitempty"`
	Vct                       string          `json:"vct,omitempty"`
	// SelectiveDisclosure is the walt.id SDMap. Without it every claim
	// stays in the signed JWT in the clear and the holder can hide
	// nothing at presentation time.
	SelectiveDisclosure json.RawMessage `json:"selectiveDisclosure,omitempty"`
}

// CreateOffer posts one issuance request and returns the offer URI.
// walt.id answers with the URI as plain text.
func (c *Client) CreateOffer(ctx context.Context, path string, req IssuanceRequest) (string, error) {
	if c.issuer == nil {
		return "", ErrNoIssuer
	}
	raw, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("waltid: encode the issuance request: %w", err)
	}
	uri, err := c.issuer.Text(ctx, http.MethodPost, path, "application/json", raw)
	if err != nil {
		return "", err
	}
	if uri == "" {
		return "", fmt.Errorf("waltid: the issue answer has no offer URI")
	}
	return uri, nil
}

// VerifyRequest is the body of POST /openid4vc/verify.
type VerifyRequest struct {
	// RequestCredentials holds one entry per credential the wallet must
	// present.
	RequestCredentials []map[string]any `json:"request_credentials"`
	// VPPolicies are the checks on the presentation envelope.
	VPPolicies []any `json:"vp_policies,omitempty"`
	// VCPolicies are the checks on each credential.
	VCPolicies []any `json:"vc_policies,omitempty"`
}

// Verify starts an OID4VP transaction. walt.id answers with the
// authorize URL as plain text.
func (c *Client) Verify(ctx context.Context, req VerifyRequest) (string, error) {
	if c.verifier == nil {
		return "", ErrNoVerifier
	}
	raw, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("waltid: encode the verify request: %w", err)
	}
	uri, err := c.verifier.Text(ctx, http.MethodPost, "/openid4vc/verify", "application/json", raw)
	if err != nil {
		return "", err
	}
	if uri == "" {
		return "", fmt.Errorf("waltid: the verify answer has no request URI")
	}
	return uri, nil
}

// Session is the part of GET /openid4vc/session/{id} the adapter reads.
type Session struct {
	// ID is the session identifier.
	ID string `json:"id"`
	// TokenResponse holds the wallet answer. It is empty while pending.
	TokenResponse json.RawMessage `json:"tokenResponse"`
	// VerificationResult is the overall verdict of walt.id.
	VerificationResult *bool `json:"verificationResult"`
	// PolicyResults holds the per check verdicts.
	PolicyResults json.RawMessage `json:"policyResults"`
}

// SessionResult reads one verifier session.
func (c *Client) SessionResult(ctx context.Context, id string) (Session, error) {
	if c.verifier == nil {
		return Session{}, ErrNoVerifier
	}
	var out Session
	path := "/openid4vc/session/" + url.PathEscape(id)
	if err := c.verifier.JSON(ctx, http.MethodGet, path, nil, &out); err != nil {
		return Session{}, err
	}
	return out, nil
}
