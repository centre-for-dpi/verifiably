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
//   - verifier-api2: POST /verification-session/create,
//     GET /verification-session/{id}/info and /request. It speaks
//     OID4VP 1.0 with DCQL and the Digital Credentials API.
//   - wallet-api: POST /wallet-api/auth/{register,login},
//     GET /wallet-api/wallet/accounts/wallets,
//     POST /wallet-api/wallet/{id}/exchange/{resolveCredentialOffer,
//     useOfferRequest,usePresentationRequest},
//     GET and DELETE /wallet-api/wallet/{id}/credentials.
//
// Release 0.18.2 speaks OID4VCI draft 13. The verifier-api speaks OID4VP
// with Presentation Exchange 2.0; the verifier-api2 of the same release
// speaks OID4VP 1.0 with DCQL.
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
	// verifier2 calls the verifier-api2. Nil turns DCQL off.
	verifier2 *dpgclient.Client
	// standardVersion is the draft name in the metadata path.
	standardVersion string

	mu        sync.Mutex
	issuerKey json.RawMessage
	issuerDid string
	x5c       []string
	// pinned reports that the configuration named the key and the DID.
	pinned bool
	// onboarded receives a key that EnsureIssuerKey onboarded.
	onboarded func(key json.RawMessage, did string)
}

// Options configure New.
type Options struct {
	// Issuer calls the issuer-api. Nil turns the issuer role off.
	Issuer *dpgclient.Client
	// Verifier calls the verifier-api. Nil turns the verifier role off.
	Verifier *dpgclient.Client
	// Wallet calls the wallet-api. Nil turns the holder role off.
	Wallet *dpgclient.Client
	// Verifier2 calls the verifier-api2. Nil turns DCQL requests off.
	Verifier2 *dpgclient.Client
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
		verifier2:       opts.Verifier2,
		standardVersion: opts.StandardVersion,
		issuerDid:       opts.IssuerDid,
	}
	if c.standardVersion == "" {
		c.standardVersion = "draft13"
	}
	if key := strings.TrimSpace(opts.IssuerKey); key != "" {
		c.issuerKey = json.RawMessage(key)
	}
	c.pinned = len(c.issuerKey) > 0 && c.issuerDid != ""
	return c
}

// Pinned reports whether the configuration named the signing key and
// the DID. A pinned identity never changes at run time.
func (c *Client) Pinned() bool { return c.pinned }

// SetIssuer replaces the signing key, the DID, and the X.509 chain the
// issuance requests carry. The chain entries are base64 DER, leaf first.
func (c *Client) SetIssuer(key json.RawMessage, did string, x5c []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.issuerKey, c.issuerDid, c.x5c = key, did, x5c
}

// Issuer returns the signing key, the DID, and the X.509 chain.
func (c *Client) Issuer() (json.RawMessage, string, []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.issuerKey, c.issuerDid, c.x5c
}

// OnOnboard sets the function that receives a key EnsureIssuerKey
// onboards, so the caller can keep it.
func (c *Client) OnOnboard(fn func(key json.RawMessage, did string)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onboarded = fn
}

// HasIssuer reports whether the issuer role is configured.
func (c *Client) HasIssuer() bool { return c.issuer != nil }

// HasVerifier reports whether the verifier role is configured.
func (c *Client) HasVerifier() bool { return c.verifier != nil }

// HasVerifier2 reports whether the verifier-api2 is configured.
func (c *Client) HasVerifier2() bool { return c.verifier2 != nil }

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

// OnboardRequest is the body of POST /onboard/issuer.
type OnboardRequest struct {
	Key OnboardKey `json:"key"`
	Did OnboardDid `json:"did"`
}

// OnboardKey names the key walt.id makes: the key store, the type, and
// the settings of an external key store.
type OnboardKey struct {
	Backend string          `json:"backend"`
	KeyType string          `json:"keyType"`
	Config  json.RawMessage `json:"config,omitempty"`
}

// KeyStore is an external key store of walt.id, such as tse for the
// HashiCorp Vault transit engine. Config is the key store settings the
// onboarding endpoint takes: for tse the server, the auth object, and
// the namespace.
type KeyStore struct {
	Backend string
	Config  json.RawMessage
}

// OnboardDid names the DID method and, for did:web, the host and path.
type OnboardDid struct {
	Method string            `json:"method"`
	Config *OnboardDidConfig `json:"config,omitempty"`
}

// OnboardDidConfig is the configuration of a did:web, or the network of
// a did:cheqd.
type OnboardDidConfig struct {
	Domain  string `json:"domain,omitempty"`
	Path    string `json:"path,omitempty"`
	Network string `json:"network,omitempty"`
}

// Onboard asks walt.id to make a key and a DID. walt.id answers with the
// key, private part included, and the DID.
func (c *Client) Onboard(ctx context.Context, req OnboardRequest) (json.RawMessage, string, error) {
	if c.issuer == nil {
		return nil, "", ErrNoIssuer
	}
	var out onboardResponse
	if err := c.issuer.JSON(ctx, http.MethodPost, "/onboard/issuer", req, &out); err != nil {
		return nil, "", fmt.Errorf("waltid: onboard the issuer: %w", err)
	}
	if len(out.IssuerKey) == 0 || out.IssuerDid == "" {
		return nil, "", fmt.Errorf("waltid: the onboard answer has no key or no DID")
	}
	return out.IssuerKey, out.IssuerDid, nil
}

// EnsureIssuerKey returns the signing key and the DID. A key with an
// X.509 chain needs no DID. It onboards a new did:key at the first call
// when no identity exists, and hands it to the function of OnOnboard.
func (c *Client) EnsureIssuerKey(ctx context.Context) (json.RawMessage, string, error) {
	c.mu.Lock()
	key, did, chain := c.issuerKey, c.issuerDid, len(c.x5c) > 0
	c.mu.Unlock()
	if len(key) > 0 && (did != "" || chain) {
		return key, did, nil
	}
	key, did, err := c.Onboard(ctx, OnboardRequest{
		Key: OnboardKey{Backend: "jwk", KeyType: "secp256r1"},
		Did: OnboardDid{Method: "key"},
	})
	if err != nil {
		return nil, "", err
	}
	c.mu.Lock()
	c.issuerKey, c.issuerDid = key, did
	keep := c.onboarded
	c.mu.Unlock()
	if keep != nil {
		keep(key, did)
	}
	return key, did, nil
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
	// X5Chain is the X.509 chain of an imported identity, base64 DER,
	// leaf first. walt.id puts it in the x5c header.
	X5Chain []string `json:"x5Chain,omitempty"`
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
