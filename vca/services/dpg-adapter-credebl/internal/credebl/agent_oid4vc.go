// SPDX-License-Identifier: Apache-2.0

package credebl

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/dcql"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
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
	// Payload is the authorization request of the verifier.
	Payload struct {
		// Query is the DCQL query of the request.
		Query dcql.Query `json:"dcql_query"`
	} `json:"authorizationRequestPayload"`
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
			// Credentials are the credential queries the agent ran.
			Credentials []dcql.CredentialQuery `json:"credentials"`
			// Matches are the matches by credential query id.
			Matches map[string]dcqlMatch `json:"credential_matches"`
		} `json:"queryResult"`
	} `json:"dcql"`
	// PresentationExchange is the match of a Presentation Exchange
	// definition: DifPexCredentialsForRequest of Credo 0.6.2.
	PresentationExchange *struct {
		// CredentialsForRequest holds the requirements of the definition.
		CredentialsForRequest struct {
			// Requirements are the requirements, each with its entries.
			Requirements []pexRequirement `json:"requirements"`
		} `json:"credentialsForRequest"`
	} `json:"presentationExchange"`
}

// pexRequirement is one requirement of a Presentation Exchange match.
type pexRequirement struct {
	// NeedsCount is the number of entries the answer needs.
	NeedsCount int `json:"needsCount"`
	// Entries are the input descriptors, each with its credentials.
	Entries []pexEntry `json:"submissionEntry"`
}

// pexEntry is one input descriptor with the credentials that match it.
type pexEntry struct {
	// Descriptor is the id of the input descriptor.
	Descriptor string `json:"inputDescriptorId"`
	// Credentials match the descriptor, in the order the agent picks.
	Credentials []pexCredential `json:"verifiableCredentials"`
}

// pexCredential is one credential that matches an input descriptor.
type pexCredential struct {
	// Format is the claim format, for example dc+sd-jwt.
	Format string `json:"claimFormat"`
	// Record is the stored credential.
	Record struct {
		// ID is the record id.
		ID string `json:"id"`
		// Instances hold the stored credential.
		Instances []struct {
			// Compact is the compact SD-JWT VC.
			Compact string `json:"compactSdJwtVc"`
		} `json:"credentialInstances"`
	} `json:"credentialRecord"`
	// Disclosed is what an SD-JWT or an mDoc discloses for the
	// descriptor. A W3C credential has none and goes whole.
	Disclosed map[string]json.RawMessage `json:"disclosedPayload"`
}

// pexPicks returns the entries the agent answers with: the first
// needsCount entries of each requirement, each with its first
// credential (selectCredentialsForRequest of Credo 0.6.2).
func (r ResolvedRequest) pexPicks() []pexEntry {
	if r.PresentationExchange == nil {
		return nil
	}
	var out []pexEntry
	for _, req := range r.PresentationExchange.CredentialsForRequest.Requirements {
		entries := req.Entries
		if req.NeedsCount >= 0 && req.NeedsCount < len(entries) {
			entries = entries[:req.NeedsCount]
		}
		for _, e := range entries {
			if len(e.Credentials) > 0 {
				out = append(out, e)
			}
		}
	}
	return out
}

// dcqlMatch is the match of one credential query.
type dcqlMatch struct {
	// Success reports a query the tenant can answer.
	Success bool `json:"success"`
	// Valid are the credentials that answer the query, in the order the
	// agent picks from.
	Valid []dcqlValid `json:"valid_credentials"`
}

// dcqlValid is one credential that answers a query.
type dcqlValid struct {
	// Record is the stored credential.
	Record struct {
		// ID is the record id.
		ID string `json:"id"`
		// Instances hold the stored credential. An SD-JWT record keeps
		// the compact form with every disclosure.
		Instances []struct {
			// Compact is the compact SD-JWT VC.
			Compact string `json:"compactSdJwtVc"`
		} `json:"credentialInstances"`
	} `json:"record"`
	// Claims is the claims result of the DCQL library.
	Claims struct {
		// Sets are the claim sets the credential satisfies, in the order
		// of preference of the query.
		Sets []struct {
			// Index is the claim set of the query. Absent for a query
			// with no claim set.
			Index *int `json:"claim_set_index"`
			// Claims are the indexes of the claims of the query that the
			// set holds.
			Claims []int `json:"valid_claim_indexes"`
			// Output is what the credential discloses for the set.
			Output map[string]json.RawMessage `json:"output"`
		} `json:"valid_claim_sets"`
	} `json:"claims"`
}

// Picks returns the record the agent answers each DCQL query with: the
// first valid credential of the query.
func (r ResolvedRequest) Picks() map[string]string {
	out := map[string]string{}
	for _, e := range r.pexPicks() {
		out[e.Descriptor] = e.Credentials[0].Record.ID
	}
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

// Disclosure is what the agent sends for one credential query.
type Disclosure struct {
	// Query is the id of the credential query.
	Query string
	// Claims are the dotted claim paths the agent discloses. With Whole
	// they are the top level claims of the credential.
	Claims []string
	// Whole reports a query that names no claim, so the agent sends the
	// whole credential.
	Whole bool
}

// Disclosures returns what the agent sends for each query it answers,
// in query id order. The agent answers with the first valid credential
// and discloses the first valid claim set of it (selectCredentialsForRequest
// of Credo), so a claim that only a later claim set leaves out still
// travels.
func (r ResolvedRequest) Disclosures() []Disclosure {
	var out []Disclosure
	for _, e := range r.pexPicks() {
		out = append(out, pexDisclosure(e))
	}
	if r.Dcql == nil {
		return out
	}
	for _, id := range sortedIDs(r.Dcql.QueryResult.Matches) {
		m := r.Dcql.QueryResult.Matches[id]
		if !m.Success || len(m.Valid) == 0 {
			continue
		}
		q, ok := r.Payload.Query.Find(id)
		if !ok {
			q, _ = dcql.Query{Credentials: r.Dcql.QueryResult.Credentials}.Find(id)
		}
		d := disclosureOf(q, m.Valid[0])
		d.Query = id
		out = append(out, d)
	}
	return out
}

// disclosureOf returns what the agent sends of one valid credential:
// the claims of the first valid claim set, each top level claim of its
// output, and each claim of the stored SD-JWT outside a disclosure. The
// agent cannot leave those out (ADR-081 decision 5).
func disclosureOf(q dcql.CredentialQuery, v dcqlValid) Disclosure {
	d := disclosedClaims(q, v)
	if len(v.Claims.Sets) > 0 {
		d.Claims = withTopLevel(d.Claims, sortedIDs(v.Claims.Sets[0].Output))
	}
	if len(v.Record.Instances) > 0 {
		d.Claims = withTopLevel(d.Claims, PlainClaims(v.Record.Instances[0].Compact))
	}
	return d
}

// pexDisclosure returns what the agent sends for one input descriptor:
// the claims of the disclosed payload of an SD-JWT, with each claim the
// stored SD-JWT shows in the clear, or the elements of an mDoc. A W3C
// credential has no disclosed payload, so it goes whole.
func pexDisclosure(e pexEntry) Disclosure {
	c := e.Credentials[0]
	d := Disclosure{Query: e.Descriptor}
	if c.Disclosed == nil {
		d.Whole = true
		return d
	}
	for _, name := range sortedIDs(c.Disclosed) {
		var ns map[string]json.RawMessage
		switch {
		case sdJwtEnvelope[name]:
		case c.Format == "mso_mdoc" && json.Unmarshal(c.Disclosed[name], &ns) == nil:
			d.Claims = append(d.Claims, sortedIDs(ns)...)
		default:
			d.Claims = append(d.Claims, name)
		}
	}
	if len(c.Record.Instances) > 0 {
		d.Claims = withTopLevel(d.Claims, PlainClaims(c.Record.Instances[0].Compact))
	}
	return d
}

// withTopLevel adds each top level claim name that no claim path of
// claims already covers.
func withTopLevel(claims, names []string) []string {
	for _, n := range names {
		covered := false
		for _, c := range claims {
			covered = covered || c == n || strings.HasPrefix(c, n+".")
		}
		if !covered {
			claims = append(claims, n)
		}
	}
	return claims
}

// sdJwtEnvelope names the SD-JWT VC claims that say nothing of the holder.
var sdJwtEnvelope = map[string]bool{
	"iss": true, "iat": true, "nbf": true, "exp": true, "cnf": true, "vct": true,
	"vct#integrity": true, "status": true, "_sd": true, "_sd_alg": true, "sub": true,
}

// PlainClaims returns the payload claims of a compact SD-JWT that no
// disclosure hides, in name order. Every presentation shows them.
func PlainClaims(compact string) []string {
	jwt, _, _ := strings.Cut(compact, "~")
	payload, err := jose.PeekPayload(jwt)
	if err != nil {
		return nil
	}
	var out []string
	for name := range payload {
		if !sdJwtEnvelope[name] {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

// disclosedClaims returns the claims of the query that the first valid
// claim set of the credential names.
func disclosedClaims(q dcql.CredentialQuery, v dcqlValid) Disclosure {
	d := Disclosure{}
	if len(q.Claims) == 0 {
		d.Whole = true
		return d
	}
	if len(v.Claims.Sets) > 0 {
		set := v.Claims.Sets[0]
		for _, i := range set.Claims {
			if i >= 0 && i < len(q.Claims) {
				d.Claims = append(d.Claims, q.Claims[i].Path.String())
			}
		}
		if len(d.Claims) == 0 && set.Index != nil && *set.Index >= 0 && *set.Index < len(q.ClaimSets) {
			for _, c := range q.Claims {
				if slices.Contains(q.ClaimSets[*set.Index], c.ID) {
					d.Claims = append(d.Claims, c.Path.String())
				}
			}
		}
	}
	if len(d.Claims) == 0 {
		d.Claims = q.ClaimPaths()
	}
	return d
}

// sortedIDs returns the keys of a map in order.
func sortedIDs[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
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
