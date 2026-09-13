// SPDX-License-Identifier: Apache-2.0

package credebl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// DcqlQuery is the Digital Credentials Query Language body of a
// presentation request (ADR-022 decision 3).
type DcqlQuery struct {
	Query struct {
		Credentials []DcqlCredential `json:"credentials"`
	} `json:"query"`
}

// DcqlCredential is one credential a query asks for.
type DcqlCredential struct {
	// ID names the credential inside the query.
	ID string `json:"id"`
	// Format is the OID4VCI format identifier.
	Format string `json:"format"`
	// Claims lists the claims the verifier wants.
	Claims []DcqlClaim `json:"claims,omitempty"`
}

// DcqlClaim is one claim path of a query.
type DcqlClaim struct {
	// Path is the path of the claim inside the credential.
	Path []string `json:"path"`
}

// ParseDcql reads a DCQL document. It accepts the whole request body
// with its query member, and the bare query as well.
func ParseDcql(raw string) (DcqlQuery, error) {
	text := strings.TrimSpace(raw)
	if text == "" {
		return DcqlQuery{}, errors.New("credebl: the DCQL query is empty")
	}
	var wrapped DcqlQuery
	if err := json.Unmarshal([]byte(text), &wrapped); err != nil {
		return DcqlQuery{}, fmt.Errorf("credebl: read the DCQL query: %w", err)
	}
	if len(wrapped.Query.Credentials) > 0 {
		return wrapped, nil
	}
	var bare struct {
		Credentials []DcqlCredential `json:"credentials"`
	}
	if err := json.Unmarshal([]byte(text), &bare); err != nil {
		return DcqlQuery{}, fmt.Errorf("credebl: read the DCQL query: %w", err)
	}
	if len(bare.Credentials) == 0 {
		return DcqlQuery{}, errors.New("credebl: the DCQL query names no credential")
	}
	wrapped.Query.Credentials = bare.Credentials
	return wrapped, nil
}

// presentationRequest is the body of the presentation endpoint.
type presentationRequest struct {
	RequestSigner struct {
		Method string `json:"method"`
	} `json:"requestSigner"`
	ResponseMode string    `json:"responseMode"`
	Dcql         DcqlQuery `json:"dcql"`
}

// presentationResponse is the answer of the presentation endpoint.
type presentationResponse struct {
	Data struct {
		AuthorizationRequest string `json:"authorizationRequest"`
		VerificationSession  struct {
			ID string `json:"id"`
		} `json:"verificationSession"`
	} `json:"data"`
}

// Presentation is one started OID4VP transaction.
type Presentation struct {
	// RequestURI is the address the wallet opens.
	RequestURI string
	// State is the verification session of CREDEBL.
	State string
}

// CreatePresentation starts an OID4VP transaction with a DCQL query.
func (c *Client) CreatePresentation(ctx context.Context, verifierID string, query DcqlQuery) (Presentation, error) {
	if c == nil {
		return Presentation{}, ErrNoPlatform
	}
	var body presentationRequest
	body.RequestSigner.Method = "DID"
	body.ResponseMode = "direct_post"
	body.Dcql = query
	path := fmt.Sprintf("/v1/orgs/%s/oid4vp/presentation?verifierId=%s",
		c.orgID, url.QueryEscape(verifierID))
	var out presentationResponse
	if err := c.call(ctx, http.MethodPost, path, body, &out); err != nil {
		return Presentation{}, err
	}
	if out.Data.AuthorizationRequest == "" {
		return Presentation{}, errors.New("credebl: the presentation answer has no authorization request")
	}
	return Presentation{
		RequestURI: out.Data.AuthorizationRequest,
		State:      out.Data.VerificationSession.ID,
	}, nil
}

// SessionState names the phase of a CREDEBL verification session.
type SessionState string

// The session states the adapter acts on.
const (
	// StateVerified means the platform accepted the presentation.
	StateVerified SessionState = "ResponseVerified"
	// StateError means the platform rejected the presentation.
	StateError SessionState = "Error"
)

// sessionResponse is the answer of the verifier presentation endpoint.
type sessionResponse struct {
	Data struct {
		State                        string          `json:"state"`
		PresentationDocument         json.RawMessage `json:"presentationDocument"`
		AuthorizationResponsePayload struct {
			VPToken json.RawMessage `json:"vp_token"`
		} `json:"authorizationResponsePayload"`
	} `json:"data"`
}

// Session is the state of one OID4VP transaction.
type Session struct {
	// State is the phase of the session.
	State SessionState
	// Tokens holds the presented credentials.
	Tokens []string
}

// Presentation reads one verification session.
func (c *Client) Presentation(ctx context.Context, state string) (Session, error) {
	if c == nil {
		return Session{}, ErrNoPlatform
	}
	if strings.TrimSpace(state) == "" {
		return Session{}, errors.New("credebl: the session needs a state")
	}
	path := fmt.Sprintf("/v1/orgs/%s/oid4vp/verifier-presentation?id=%s", c.orgID, url.QueryEscape(state))
	var out sessionResponse
	if err := c.call(ctx, http.MethodGet, path, nil, &out); err != nil {
		return Session{}, err
	}
	return Session{
		State:  SessionState(out.Data.State),
		Tokens: Tokens(out.Data.AuthorizationResponsePayload.VPToken),
	}, nil
}

// Tokens reads a vp_token value. The value is one token, a list of
// tokens, or a map of lists, so the reader walks every shape.
func Tokens(raw json.RawMessage) []string {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil
	}
	var one string
	if json.Unmarshal(raw, &one) == nil {
		if one == "" {
			return nil
		}
		return []string{one}
	}
	var many []json.RawMessage
	if json.Unmarshal(raw, &many) == nil {
		var out []string
		for _, item := range many {
			out = append(out, Tokens(item)...)
		}
		return out
	}
	var grouped map[string]json.RawMessage
	if json.Unmarshal(raw, &grouped) == nil {
		keys := make([]string, 0, len(grouped))
		for k := range grouped {
			keys = append(keys, k)
		}
		sortStrings(keys)
		var out []string
		for _, k := range keys {
			out = append(out, Tokens(grouped[k])...)
		}
		return out
	}
	return nil
}

// sortStrings sorts the values in place.
func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

// verifierRequest is the body of the verifier endpoint.
type verifierRequest struct {
	VerifierID     string            `json:"verifierId"`
	ClientMetadata map[string]string `json:"clientMetadata"`
}

// verifierResponse is the answer of the verifier endpoint.
type verifierResponse struct {
	Data struct {
		ID string `json:"id"`
	} `json:"data"`
}

// verifierList is the listing of the verifier endpoint.
type verifierList struct {
	Data []struct {
		ID               string `json:"id"`
		PublicVerifierID string `json:"publicVerifierId"`
	} `json:"data"`
}

// EnsureVerifier returns the identifier of the OID4VP verifier. It
// creates one with the name when the platform has none.
//
// A restart of the adapter finds the verifier again: the create call
// then fails with the status conflict, and the adapter looks the
// verifier up by its public name.
func (c *Client) EnsureVerifier(ctx context.Context, name, logoURL string) (string, error) {
	if c == nil {
		return "", ErrNoPlatform
	}
	path := fmt.Sprintf("/v1/orgs/%s/oid4vp/verifier", c.orgID)
	body := verifierRequest{
		VerifierID: name,
		ClientMetadata: map[string]string{
			"client_name": name,
			"logo_uri":    logoURL,
		},
	}
	var created verifierResponse
	err := c.call(ctx, http.MethodPost, path, body, &created)
	if err == nil {
		if created.Data.ID == "" {
			return "", errors.New("credebl: the verifier answer has no identifier")
		}
		return created.Data.ID, nil
	}
	if !isConflict(err) {
		return "", err
	}
	var list verifierList
	if lerr := c.call(ctx, http.MethodGet, path, nil, &list); lerr != nil {
		return "", lerr
	}
	for _, entry := range list.Data {
		if entry.PublicVerifierID == name && entry.ID != "" {
			return entry.ID, nil
		}
	}
	return "", fmt.Errorf("credebl: the platform has a verifier named %q that it does not list", name)
}
