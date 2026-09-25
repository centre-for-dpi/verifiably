// SPDX-License-Identifier: Apache-2.0

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

// Verify calls one Inji Verify service.
//
// The service serves POST /v1/verify/vp-request to start a transaction
// and GET /v1/verify/vp-result/{id} to read the answer. Release 0.16.0
// returns no request URI in the start answer, so the adapter builds the
// wallet URI from the request identifier.
type Verify struct {
	client *dpgclient.Client
	// clientID is the DID the verifier presents to the wallet.
	clientID string
	// publicURL is the address the wallet reaches the service on.
	publicURL string
}

// NewVerify returns a Verify client. A nil client turns the verifier
// role off.
func NewVerify(client *dpgclient.Client, clientID, publicURL string) *Verify {
	if client == nil {
		return nil
	}
	if publicURL == "" {
		publicURL = client.BaseURL()
	}
	return &Verify{client: client, clientID: clientID, publicURL: strings.TrimRight(publicURL, "/")}
}

// ClientID returns the verifier identifier.
func (v *Verify) ClientID() string {
	if v == nil {
		return ""
	}
	return v.clientID
}

// requestCreate is the body of POST /v1/verify/vp-request.
type requestCreate struct {
	ClientID               string          `json:"clientId"`
	Nonce                  string          `json:"nonce,omitempty"`
	TransactionID          string          `json:"transactionId,omitempty"`
	PresentationDefinition json.RawMessage `json:"presentationDefinition,omitempty"`
}

// requestCreated is the answer of POST /v1/verify/vp-request.
type requestCreated struct {
	TransactionID string `json:"transactionId"`
	RequestID     string `json:"requestId"`
	ExpiresAt     int64  `json:"expiresAt"`
}

// Transaction is one started OID4VP transaction.
type Transaction struct {
	// RequestURI is the address the wallet opens.
	RequestURI string
	// State joins the transaction id and the request id.
	State string
	// ExpiresAt is the end of the transaction in seconds since the epoch.
	ExpiresAt int64
}

// CreateRequest starts an OID4VP transaction.
func (v *Verify) CreateRequest(ctx context.Context, definition, nonce string) (Transaction, error) {
	if v == nil {
		return Transaction{}, ErrNoVerify
	}
	body := requestCreate{ClientID: v.clientID, Nonce: nonce}
	if strings.TrimSpace(definition) != "" {
		if !json.Valid([]byte(definition)) {
			return Transaction{}, errors.New("inji: the presentation definition is not valid JSON")
		}
		body.PresentationDefinition = json.RawMessage(definition)
	}
	var out requestCreated
	if err := v.client.JSON(ctx, http.MethodPost, "/v1/verify/vp-request", body, &out); err != nil {
		return Transaction{}, err
	}
	if out.RequestID == "" {
		return Transaction{}, errors.New("inji: the verify answer has no request id")
	}
	requestURI := fmt.Sprintf("openid4vp://authorize?client_id=%s&request_uri=%s",
		url.QueryEscape(v.clientID),
		url.QueryEscape(v.publicURL+"/v1/verify/vp-request/"+out.RequestID))
	return Transaction{
		RequestURI: requestURI,
		State:      out.TransactionID + "|" + out.RequestID,
		ExpiresAt:  out.ExpiresAt,
	}, nil
}

// TransactionIDOf returns the transaction part of a state value.
func TransactionIDOf(state string) string {
	if i := strings.Index(state, "|"); i >= 0 {
		return state[:i]
	}
	return state
}

// Result is the answer of GET /v1/verify/vp-result/{id}.
type Result struct {
	// TransactionID names the transaction.
	TransactionID string `json:"transactionId"`
	// VPResultStatus is the verdict of Inji Verify. It is empty while no
	// wallet has answered.
	VPResultStatus string `json:"vpResultStatus"`
	// VCResults holds one entry per presented credential.
	VCResults []VCResult `json:"vcResults"`
}

// VCResult is the verdict of one presented credential.
type VCResult struct {
	// VC is the credential as the wallet sent it.
	VC json.RawMessage `json:"vc"`
	// VerificationStatus is the verdict of Inji Verify.
	VerificationStatus string `json:"verificationStatus"`
}

// Result reads the answer of one transaction.
func (v *Verify) Result(ctx context.Context, state string) (Result, error) {
	if v == nil {
		return Result{}, ErrNoVerify
	}
	id := TransactionIDOf(state)
	if id == "" {
		return Result{}, errors.New("inji: the state has no transaction id")
	}
	var out Result
	path := "/v1/verify/vp-result/" + url.PathEscape(id)
	if err := v.client.JSON(ctx, http.MethodGet, path, nil, &out); err != nil {
		return Result{}, err
	}
	return out, nil
}

// Succeeded reports whether Inji Verify accepted the presentation.
func (r Result) Succeeded() bool { return strings.EqualFold(r.VPResultStatus, "SUCCESS") }

// Answered reports whether a wallet has answered the transaction.
func (r Result) Answered() bool { return strings.TrimSpace(r.VPResultStatus) != "" }

// RequestedClaims returns the claim names of a Presentation Exchange
// definition. It reads the last part of every JSON path of every field.
func RequestedClaims(definition string) []string {
	var pd struct {
		InputDescriptors []struct {
			Constraints struct {
				Fields []struct {
					Path []string `json:"path"`
				} `json:"fields"`
			} `json:"constraints"`
		} `json:"input_descriptors"`
	}
	if err := json.Unmarshal([]byte(definition), &pd); err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, d := range pd.InputDescriptors {
		for _, f := range d.Constraints.Fields {
			for _, p := range f.Path {
				name := claimNameOf(p)
				if name == "" || seen[name] {
					continue
				}
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	return out
}

// claimNameOf returns the last name of a JSON path.
func claimNameOf(path string) string {
	path = strings.TrimSpace(path)
	path = strings.TrimSuffix(strings.TrimPrefix(path, "$."), "]")
	parts := strings.FieldsFunc(path, func(r rune) bool {
		return r == '.' || r == '[' || r == '\'' || r == '"'
	})
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}

// MatchesRequestedClaims reports whether at least one presented
// credential carries one of the claim names.
//
// Inji Verify can report success for a presentation that answers the
// request with the wrong credential. The adapter therefore checks the
// claims itself and lowers the verdict when nothing matches.
//
// The check needs a credential the adapter can read. An empty name list
// skips it. A presentation of compact tokens only also skips it, because
// the claim names live in the disclosures, which the policy service
// reads.
func MatchesRequestedClaims(results []VCResult, names []string) bool {
	if len(names) == 0 {
		return true
	}
	readable := 0
	for _, r := range results {
		claims, ok := claimNames(r.VC)
		if !ok {
			continue
		}
		readable++
		for _, name := range names {
			if claims[name] {
				return true
			}
		}
	}
	return readable == 0
}

// claimNames returns every key of a credential document. The second
// value is false when the credential is not a JSON object.
func claimNames(raw json.RawMessage) (map[string]bool, bool) {
	var doc map[string]any
	if len(raw) == 0 || json.Unmarshal(raw, &doc) != nil {
		return nil, false
	}
	out := map[string]bool{}
	collectKeys(doc, out)
	return out, true
}

func collectKeys(value any, out map[string]bool) {
	switch v := value.(type) {
	case map[string]any:
		for k, inner := range v {
			out[k] = true
			collectKeys(inner, out)
		}
	case []any:
		for _, inner := range v {
			collectKeys(inner, out)
		}
	}
}

// The verification statuses of the credential check of Inji Verify
// 0.16.0 (VerificationStatus of the MOSIP vc-verifier library).
const (
	StatusSuccess = "SUCCESS"
	StatusExpired = "EXPIRED"
	StatusRevoked = "REVOKED"
	StatusInvalid = "INVALID"
)

// verificationPath checks one credential. The Content-Type names the
// format: application/vc+sd-jwt or application/dc+sd-jwt selects SD-JWT,
// and every other type selects a JSON-LD credential.
const verificationPath = "/v1/verify/vc-verification"

// CheckCredential sends one credential to the credential check and
// returns its verification status.
func (v *Verify) CheckCredential(ctx context.Context, credential []byte, contentType string) (string, error) {
	if v == nil {
		return "", ErrNoVerify
	}
	resp, err := v.client.Do(ctx, dpgclient.Request{
		Method: http.MethodPost, Path: verificationPath, Body: credential, ContentType: contentType, Accept: "application/json",
	})
	if err != nil {
		return "", err
	}
	var out struct {
		VerificationStatus string `json:"verificationStatus"`
	}
	if err := json.Unmarshal(resp.Body, &out); err != nil {
		return "", fmt.Errorf("inji: read the credential check: %w", err)
	}
	if out.VerificationStatus == "" {
		return "", errors.New("inji: the credential check has no verification status")
	}
	return strings.ToUpper(out.VerificationStatus), nil
}
