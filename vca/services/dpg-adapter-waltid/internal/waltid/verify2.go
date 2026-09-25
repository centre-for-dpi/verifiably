// SPDX-License-Identifier: Apache-2.0

package waltid

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// ErrNoVerifier2 reports that the verifier-api2 is not configured.
var ErrNoVerifier2 = errors.New("waltid: no verifier-api2 URL")

// The flow types of POST /verification-session/create.
const (
	// FlowCrossDevice sends the request to a wallet on another device
	// through a QR code or a link.
	FlowCrossDevice = "cross_device"
)

// The session states of verifier 2 that end a session.
const (
	Status2Successful = "SUCCESSFUL"
	Status2Failed     = "FAILED"
	Status2Expired    = "EXPIRED"
)

// Session2Setup is the body of POST /verification-session/create.
type Session2Setup struct {
	// FlowType names the flow, for example cross_device.
	FlowType string `json:"flow_type"`
	// CoreFlow holds the query and the checks.
	CoreFlow CoreFlow `json:"core_flow"`
	// ExpectedOrigins lists the web origins that may call the Digital
	// Credentials API with the request.
	ExpectedOrigins []string `json:"expectedOrigins,omitempty"`
}

// CoreFlow is the query and the checks of one session.
type CoreFlow struct {
	// DcqlQuery is the DCQL query as the caller wrote it.
	DcqlQuery json.RawMessage `json:"dcql_query"`
	// Policies holds the checks walt.id runs.
	Policies *Policies2 `json:"policies,omitempty"`
}

// Policies2 holds the checks of verifier 2.
type Policies2 struct {
	// VCPolicies run on each credential.
	VCPolicies []map[string]any `json:"vc_policies,omitempty"`
}

// Session2Created is the answer of POST /verification-session/create.
type Session2Created struct {
	// SessionID names the session.
	SessionID string `json:"sessionId"`
	// BootstrapURL is the short request that points at the request
	// object. A QR code carries it.
	BootstrapURL string `json:"bootstrapAuthorizationRequestUrl"`
	// FullURL carries the whole request in the query.
	FullURL string `json:"fullAuthorizationRequestUrl"`
	// Data is the request object of a Digital Credentials API flow.
	Data json.RawMessage `json:"data,omitempty"`
}

// RequestURL returns the URL the wallet opens: the short one when walt.id
// sent it.
func (c Session2Created) RequestURL() string {
	if c.BootstrapURL != "" {
		return c.BootstrapURL
	}
	return c.FullURL
}

// Session2 is the part of GET /verification-session/{id}/info the adapter
// reads.
type Session2 struct {
	// ID names the session.
	ID string `json:"id"`
	// Status is ACTIVE, UNUSED, IN_USE, PROCESSING_FLOW, SUCCESSFUL,
	// FAILED, EXPIRED, or another state of walt.id.
	Status string `json:"status"`
	// StatusReason says why a session failed.
	StatusReason string `json:"statusReason"`
	// PolicyResults holds the verdict per check.
	PolicyResults *PolicyResults2 `json:"policy_results"`
	// Setup is the setup of the session, with the DCQL query.
	Setup struct {
		CoreFlow struct {
			DcqlQuery struct {
				Credentials []struct {
					ID     string `json:"id"`
					Format string `json:"format"`
				} `json:"credentials"`
			} `json:"dcql_query"`
		} `json:"core_flow"`
	} `json:"setup"`
	// PresentedRawData holds the vp_token as the wallet sent it.
	PresentedRawData *struct {
		VPToken map[string][]string `json:"vpToken"`
	} `json:"presented_raw_data"`
}

// PolicyResults2 is the verdict of verifier 2 per check.
type PolicyResults2 struct {
	// VPPolicies maps a query id onto the checks of its presentation.
	VPPolicies map[string]map[string]PolicyRun2 `json:"vp_policies"`
	// VCPolicies are the checks of the credentials.
	VCPolicies []PolicyRun2 `json:"vc_policies"`
	// SpecificVCPolicies maps a query id onto its own checks.
	SpecificVCPolicies map[string][]PolicyRun2 `json:"specific_vc_policies"`
}

// PolicyRun2 is one check result.
type PolicyRun2 struct {
	// Policy names the check. A vc policy carries it as an object.
	Policy json.RawMessage `json:"policy"`
	// Executed names the check of a vp policy.
	Executed json.RawMessage `json:"policy_executed"`
	// Success reports whether the check passed.
	Success bool `json:"success"`
	// Error is the failure text of a vc policy.
	Error json.RawMessage `json:"error"`
	// Errors are the failure texts of a vp policy.
	Errors []json.RawMessage `json:"errors"`
}

// CreateSession2 starts one verifier 2 session.
func (c *Client) CreateSession2(ctx context.Context, setup Session2Setup) (Session2Created, error) {
	if c.verifier2 == nil {
		return Session2Created{}, ErrNoVerifier2
	}
	var out Session2Created
	if err := c.verifier2.JSON(ctx, http.MethodPost, "/verification-session/create", setup, &out); err != nil {
		return Session2Created{}, err
	}
	if out.SessionID == "" {
		return Session2Created{}, errors.New("waltid: the verifier 2 answer has no session id")
	}
	return out, nil
}

// SessionInfo2 reads one verifier 2 session.
func (c *Client) SessionInfo2(ctx context.Context, id string) (Session2, error) {
	if c.verifier2 == nil {
		return Session2{}, ErrNoVerifier2
	}
	var out Session2
	path := "/verification-session/" + url.PathEscape(id) + "/info"
	if err := c.verifier2.JSON(ctx, http.MethodGet, path, nil, &out); err != nil {
		return Session2{}, err
	}
	return out, nil
}

// VCPolicies2 maps the check names of the caller onto the vc_policies of
// verifier 2 and adds the webhook policy when a URL is set. An unknown
// name, and status-list, are left out: the VCA policy service checks the
// status of every credential itself.
func VCPolicies2(names []string, webhookURL string) []map[string]any {
	out := []map[string]any{}
	for _, name := range names {
		switch name {
		case "signature", "not-before":
			out = append(out, map[string]any{"policy": name})
		case "expired":
			out = append(out, map[string]any{"policy": "expiration"})
		}
	}
	if u := strings.TrimSpace(webhookURL); u != "" {
		out = append(out, map[string]any{"policy": "webhook", "url": u})
	}
	return out
}

// Credentials returns the vp_token entries of a session, in query id
// order, with the query id of each.
func (s Session2) Credentials() (ids, tokens []string) {
	if s.PresentedRawData == nil {
		return nil, nil
	}
	keys := make([]string, 0, len(s.PresentedRawData.VPToken))
	for k := range s.PresentedRawData.VPToken {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, token := range s.PresentedRawData.VPToken[k] {
			ids = append(ids, k)
			tokens = append(tokens, token)
		}
	}
	return ids, tokens
}

// FormatOf returns the format the DCQL query of the session names for a
// query id, or an empty string.
func (s Session2) FormatOf(id string) string {
	for _, c := range s.Setup.CoreFlow.DcqlQuery.Credentials {
		if c.ID == id {
			return c.Format
		}
	}
	return ""
}

// Checks returns every check of a session: the presentation checks per
// query id in id order, then the credential checks, then the checks of
// one query id.
func (s Session2) Checks() []Check {
	if s.PolicyResults == nil {
		return nil
	}
	var out []Check
	queries := make([]string, 0, len(s.PolicyResults.VPPolicies))
	for k := range s.PolicyResults.VPPolicies {
		queries = append(queries, k)
	}
	sort.Strings(queries)
	for _, q := range queries {
		runs := s.PolicyResults.VPPolicies[q]
		names := make([]string, 0, len(runs))
		for n := range runs {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			out = append(out, runs[n].check(n))
		}
	}
	for _, run := range s.PolicyResults.VCPolicies {
		out = append(out, run.check(""))
	}
	specific := make([]string, 0, len(s.PolicyResults.SpecificVCPolicies))
	for k := range s.PolicyResults.SpecificVCPolicies {
		specific = append(specific, k)
	}
	sort.Strings(specific)
	for _, k := range specific {
		for _, run := range s.PolicyResults.SpecificVCPolicies[k] {
			out = append(out, run.check(""))
		}
	}
	return out
}

// check turns one run into a Check. fallback names a vp policy whose
// map key is its name.
func (r PolicyRun2) check(fallback string) Check {
	name := policyName(r.Policy)
	if name == "" {
		name = policyName(r.Executed)
	}
	if name == "" {
		name = fallback
	}
	out := Check{Name: name, Passed: r.Success}
	if !r.Success {
		out.Reason = failureText(r.Error, r.Errors)
		if out.Reason == "" {
			out.Reason = "the check failed"
		}
	}
	return out
}

// policyName reads a policy name from a string or from an object with a
// policy or an id field.
func policyName(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var name string
	if err := json.Unmarshal(raw, &name); err == nil {
		return name
	}
	var obj struct {
		Policy string `json:"policy"`
		ID     string `json:"id"`
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return ""
	}
	if obj.Policy != "" {
		return obj.Policy
	}
	return obj.ID
}

// failureText joins the failure texts of a run.
func failureText(one json.RawMessage, many []json.RawMessage) string {
	var parts []string
	for _, raw := range append([]json.RawMessage{one}, many...) {
		if text := errorText(raw); text != "" {
			parts = append(parts, text)
		}
	}
	return strings.Join(parts, "; ")
}

// errorText reads a failure from a string or from an object with an
// error or a message field.
func errorText(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return text
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return ""
	}
	for _, key := range []string{"error", "message", "reason"} {
		if s, ok := obj[key].(string); ok && s != "" {
			return s
		}
	}
	return fmt.Sprint(obj)
}
