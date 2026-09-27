// SPDX-License-Identifier: Apache-2.0

package credebl

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/internal/dpgclient"
)

// The OID4VC holder calls of the shared agent (P6-C7, ADR-062 decision
// 8). A tenant claims an OID4VCI offer with a pre-authorized code and
// answers an OID4VP request. The agent picks the credential of each
// query. The source is the holder controller and its service at the
// pinned release:
// https://raw.githubusercontent.com/credebl/agent-controller/v2.2.1-alpha-jsonld-vc.2.1/src/controllers/openid4vc/holder/holder.Controller.ts
// https://raw.githubusercontent.com/credebl/agent-controller/v2.2.1-alpha-jsonld-vc.2.1/src/controllers/openid4vc/holder/holder.service.ts

// The grant of a pre-authorized code offer.
const preAuthorizedGrant = "urn:ietf:params:oauth:grant-type:pre-authorized_code"

// The record types of the stored OID4VC credentials (Credo 0.6.2).
const (
	// RecordSdJwt is an SD-JWT VC.
	RecordSdJwt = "SdJwtVcRecord"
	// RecordMdoc is an ISO mdoc.
	RecordMdoc = "MdocRecord"
	// RecordW3c is a W3C credential.
	RecordW3c = "W3cCredentialRecord"
)

// The credential types of the remove call (CredentialType of
// holder.types.ts).
const (
	// HeldSdJwt removes an SD-JWT VC.
	HeldSdJwt = "sd-jwt-vc"
	// HeldMdoc removes an ISO mdoc.
	HeldMdoc = "mso_mdoc"
	// HeldW3c removes a W3C credential.
	HeldW3c = "w3c-vc"
)

// ResolvedOffer is what the agent reads in an OID4VCI offer.
type ResolvedOffer struct {
	// Payload is the offer.
	Payload struct {
		// Issuer is the credential issuer.
		Issuer string `json:"credential_issuer"`
		// ConfigurationIDs name the offered configurations.
		ConfigurationIDs []string `json:"credential_configuration_ids"`
		// Grants are the grants of the offer.
		Grants map[string]json.RawMessage `json:"grants"`
	} `json:"credentialOfferPayload"`
}

// PreAuthorized reports whether the offer carries a pre-authorized code
// grant, and whether that grant needs a transaction code.
func (o ResolvedOffer) PreAuthorized() (bool, bool) {
	raw, ok := o.Payload.Grants[preAuthorizedGrant]
	if !ok {
		return false, false
	}
	var grant struct {
		TxCode json.RawMessage `json:"tx_code"`
	}
	if json.Unmarshal(raw, &grant) != nil {
		return true, false
	}
	return true, len(grant.TxCode) > 0 && string(grant.TxCode) != "null"
}

// ResolveOffer reads an OID4VCI offer for a tenant.
func (a *Agent) ResolveOffer(ctx context.Context, tenant, offerURI string) (ResolvedOffer, error) {
	var got ResolvedOffer
	err := a.asTenant(ctx, tenant, func(c *dpgclient.Client) error {
		return c.JSON(ctx, http.MethodPost, "/openid4vc/holder/resolve-credential-offer", map[string]any{"credentialOfferUri": offerURI}, &got)
	})
	return got, err
}

// AgentStored is one stored OID4VC credential record: an SD-JWT VC, an
// ISO mdoc, or a W3C credential.
type AgentStored struct {
	// ID is the record id.
	ID string `json:"id"`
	// Type is the record type, such as SdJwtVcRecord.
	Type string `json:"type"`
	// CreatedAt is when the tenant stored it.
	CreatedAt time.Time `json:"createdAt"`
	// Tags are the tags of the record, such as vct or docType.
	Tags map[string]any `json:"_tags"`
	// Instances hold the credential.
	Instances []struct {
		// SdJwt is the compact SD-JWT VC.
		SdJwt string `json:"compactSdJwtVc"`
		// Mdoc is the issuer signed part of an mdoc, base64url.
		Mdoc string `json:"issuerSignedBase64Url"`
		// Credential is a W3C credential.
		Credential json.RawMessage `json:"credential"`
	} `json:"credentialInstances"`
}

// Compact returns the credential of the first instance as text: the
// compact SD-JWT VC, or the issuer signed part of an mdoc.
func (s AgentStored) Compact() string {
	if len(s.Instances) == 0 {
		return ""
	}
	if s.Instances[0].SdJwt != "" {
		return s.Instances[0].SdJwt
	}
	return s.Instances[0].Mdoc
}

// RequestCredential claims the offered configurations with the
// transaction code and returns the stored records.
func (a *Agent) RequestCredential(ctx context.Context, tenant, offerURI string, configurations []string, txCode string) ([]AgentStored, error) {
	body := map[string]any{"credentialOfferUri": offerURI, "credentialsToRequest": configurations}
	if txCode != "" {
		body["txCode"] = txCode
	}
	var got []AgentStored
	err := a.asTenant(ctx, tenant, func(c *dpgclient.Client) error {
		return c.JSON(ctx, http.MethodPost, "/openid4vc/holder/request-credential", body, &got)
	})
	return got, err
}

// SdJwtCredentials lists the SD-JWT VCs of a tenant.
func (a *Agent) SdJwtCredentials(ctx context.Context, tenant string) ([]AgentStored, error) {
	var got []AgentStored
	err := a.asTenant(ctx, tenant, func(c *dpgclient.Client) error {
		return c.JSON(ctx, http.MethodGet, "/openid4vc/holder/sd-jwt-vcs", nil, &got)
	})
	return got, err
}

// MdocCredentials lists the ISO mdocs of a tenant.
func (a *Agent) MdocCredentials(ctx context.Context, tenant string) ([]AgentStored, error) {
	var got []AgentStored
	err := a.asTenant(ctx, tenant, func(c *dpgclient.Client) error {
		return c.JSON(ctx, http.MethodGet, "/openid4vc/holder/mdoc-vcs", nil, &got)
	})
	return got, err
}

// DeleteHeld removes one stored credential of a tenant: kind is
// HeldSdJwt, HeldMdoc or HeldW3c.
func (a *Agent) DeleteHeld(ctx context.Context, tenant, kind, id string) error {
	body := map[string]any{"credentialType": kind, "credentialId": id}
	return a.asTenant(ctx, tenant, func(c *dpgclient.Client) error {
		return c.JSON(ctx, http.MethodDelete, "/openid4vc/holder/credential", body, nil)
	})
}

// ResolvedRequest is what the agent reads in an OID4VP request.
type ResolvedRequest struct {
	// Verifier names the verifier.
	Verifier struct {
		// ClientID is the effective client id of the verifier.
		ClientID string `json:"effectiveClientId"`
	} `json:"verifier"`
	// Dcql is the result of a DCQL query against the credentials of the
	// tenant.
	Dcql *struct {
		// QueryResult is the match of each credential query.
		QueryResult struct {
			// Matches are the matches by credential query id.
			Matches map[string]struct {
				// Success reports a query the tenant can answer.
				Success bool `json:"success"`
				// Valid are the credentials that answer the query, in
				// the order the agent picks from.
				Valid []struct {
					// Record is the stored credential.
					Record struct {
						// ID is the record id.
						ID string `json:"id"`
					} `json:"record"`
				} `json:"valid_credentials"`
			} `json:"credential_matches"`
		} `json:"queryResult"`
	} `json:"dcql"`
}

// Picks returns the record the agent answers each DCQL query with: the
// first valid credential of the query.
func (r ResolvedRequest) Picks() map[string]string {
	out := map[string]string{}
	if r.Dcql == nil {
		return out
	}
	for id, m := range r.Dcql.QueryResult.Matches {
		if m.Success && len(m.Valid) > 0 {
			out[id] = m.Valid[0].Record.ID
		}
	}
	return out
}

// ResolveProofRequest reads an OID4VP request for a tenant.
func (a *Agent) ResolveProofRequest(ctx context.Context, tenant, requestURI string) (ResolvedRequest, error) {
	var got ResolvedRequest
	err := a.asTenant(ctx, tenant, func(c *dpgclient.Client) error {
		return c.JSON(ctx, http.MethodPost, "/openid4vc/holder/resolve-proof-request", map[string]any{"proofRequestUri": requestURI}, &got)
	})
	return got, err
}

// Oid4vpAnswer is the answer of the verifier to the presentation.
type Oid4vpAnswer struct {
	// Status is the HTTP status of the verifier.
	Status int `json:"status"`
	// Body is the body of the verifier.
	Body json.RawMessage `json:"body"`
}

// Accepted reports whether the verifier took the presentation.
func (o Oid4vpAnswer) Accepted() bool { return o.Status >= 200 && o.Status < 300 }

// AcceptOid4vpRequest answers an OID4VP request with the credentials
// that the agent picks.
func (a *Agent) AcceptOid4vpRequest(ctx context.Context, tenant, requestURI string) (Oid4vpAnswer, error) {
	var got Oid4vpAnswer
	err := a.asTenant(ctx, tenant, func(c *dpgclient.Client) error {
		return c.JSON(ctx, http.MethodPost, "/openid4vc/holder/accept-proof-request", map[string]any{"proofRequestUri": requestURI}, &got)
	})
	return got, err
}
