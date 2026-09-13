// SPDX-License-Identifier: Apache-2.0

package waltid

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// RequestCredentialsFromDefinition turns a Presentation Exchange 2.0
// definition into the request_credentials list walt.id 0.18.2 wants.
// One input descriptor becomes one entry that carries the descriptor
// unchanged, so the wallet gets the constraints the caller wrote.
//
// A bare entry of the shape {format, vct} makes walt.id build its own
// definition, which the wallet cannot read. The adapter therefore always
// sends the full descriptor.
func RequestCredentialsFromDefinition(definition string) ([]map[string]any, error) {
	var pd struct {
		InputDescriptors []json.RawMessage `json:"input_descriptors"`
	}
	if err := json.Unmarshal([]byte(definition), &pd); err != nil {
		return nil, fmt.Errorf("waltid: read the presentation definition: %w", err)
	}
	if len(pd.InputDescriptors) == 0 {
		return nil, fmt.Errorf("waltid: the presentation definition has no input_descriptors")
	}
	out := make([]map[string]any, 0, len(pd.InputDescriptors))
	for i, raw := range pd.InputDescriptors {
		var descriptor map[string]any
		if err := json.Unmarshal(raw, &descriptor); err != nil {
			return nil, fmt.Errorf("waltid: read the input descriptor %d: %w", i, err)
		}
		entry := map[string]any{"input_descriptor": descriptor}
		if f := descriptorFormat(descriptor); f != "" {
			entry["format"] = f
		}
		out = append(out, entry)
	}
	return out, nil
}

// descriptorFormat returns the first format key of an input descriptor.
func descriptorFormat(descriptor map[string]any) string {
	formats, ok := descriptor["format"].(map[string]any)
	if !ok {
		return ""
	}
	best := ""
	for name := range formats {
		if best == "" || name < best {
			best = name
		}
	}
	return best
}

// VPPolicies returns the checks that always run on the presentation
// envelope. Making them optional would remove the point of the flow.
func VPPolicies() []any { return []any{"signature", "presentation-definition"} }

// VCPolicies maps the check names of the caller onto the walt.id
// vc_policies list. An unknown name is left out.
//
// The name status-list becomes the walt.id policy credential-status.
// That policy needs an args object with a discriminator: ietf for the
// IETF Token Status List of an SD-JWT, or w3c for the W3C Bitstring
// Status List of a VCDM credential. The w3c branch compares args.type
// with the type of the fetched list, which is BitstringStatusList, and
// not with the type of the entry in the credential.
func VCPolicies(names []string, format Format) []any {
	out := []any{}
	for _, name := range names {
		switch name {
		case "signature", "expired", "not-before":
			out = append(out, name)
		case "status-list":
			args := map[string]any{"value": 0}
			if IsSdJwt(format) {
				args["discriminator"] = "ietf"
			} else {
				args["discriminator"] = "w3c"
				args["purpose"] = "revocation"
				args["type"] = "BitstringStatusList"
			}
			out = append(out, map[string]any{"policy": "credential-status", "args": args})
		}
	}
	return out
}

// WebhookPolicy returns the walt.id policy that calls back a URL. An
// empty URL returns nothing.
func WebhookPolicy(webhookURL string) []any {
	if strings.TrimSpace(webhookURL) == "" {
		return nil
	}
	return []any{map[string]any{"policy": "webhook", "args": map[string]any{"url": webhookURL}}}
}

// StateFromAuthorizeURL returns the session id of a walt.id authorize
// URL. walt.id puts the id in the state query parameter, and in the last
// path part of the request_uri when the state is absent.
func StateFromAuthorizeURL(authorizeURL string) string {
	u, err := url.Parse(authorizeURL)
	if err != nil {
		return ""
	}
	if state := u.Query().Get("state"); state != "" {
		return state
	}
	requestURI := u.Query().Get("request_uri")
	if requestURI == "" {
		return ""
	}
	parts := strings.Split(strings.TrimRight(requestURI, "/"), "/")
	return parts[len(parts)-1]
}

// PresentedCredentials returns the credentials of a token response. The
// vp_token holds one string, an array of strings, or an object.
func PresentedCredentials(tokenResponse json.RawMessage) []string {
	if len(strings.TrimSpace(string(tokenResponse))) == 0 {
		return nil
	}
	var body struct {
		VPToken json.RawMessage `json:"vp_token"`
	}
	if err := json.Unmarshal(tokenResponse, &body); err != nil || len(body.VPToken) == 0 {
		return nil
	}
	return flattenTokens(body.VPToken)
}

// flattenTokens reads one token, a list of tokens, or a map of lists.
func flattenTokens(raw json.RawMessage) []string {
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		if one == "" {
			return nil
		}
		return []string{one}
	}
	var many []json.RawMessage
	if err := json.Unmarshal(raw, &many); err == nil {
		var out []string
		for _, item := range many {
			out = append(out, flattenTokens(item)...)
		}
		return out
	}
	var grouped map[string]json.RawMessage
	if err := json.Unmarshal(raw, &grouped); err == nil {
		keys := make([]string, 0, len(grouped))
		for k := range grouped {
			keys = append(keys, k)
		}
		sortStrings(keys)
		var out []string
		for _, k := range keys {
			out = append(out, flattenTokens(grouped[k])...)
		}
		return out
	}
	return nil
}

// sortStrings sorts the values in place. It avoids an import of sort in
// a file that needs nothing else from it.
func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

// Check is one policy verdict of walt.id.
type Check struct {
	// Name is the walt.id policy name.
	Name string
	// Passed reports whether the check passed.
	Passed bool
	// Reason is the walt.id text when the check failed.
	Reason string
}

// PolicyChecks reads the policy results of a session. walt.id nests the
// results per credential, so the reader walks the tree and collects every
// object that has a policy name.
func PolicyChecks(raw json.RawMessage) []Check {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil
	}
	var out []Check
	walkChecks(value, &out)
	return out
}

func walkChecks(value any, out *[]Check) {
	switch v := value.(type) {
	case map[string]any:
		if name, ok := v["policy"].(string); ok && name != "" {
			*out = append(*out, Check{
				Name:   name,
				Passed: checkPassed(v),
				Reason: checkReason(v),
			})
		}
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sortStrings(keys)
		for _, k := range keys {
			if k != "policy" {
				walkChecks(v[k], out)
			}
		}
	case []any:
		for _, item := range v {
			walkChecks(item, out)
		}
	}
}

// checkPassed reads the success flag of one policy result.
func checkPassed(v map[string]any) bool {
	for _, key := range []string{"is_success", "isSuccess", "success"} {
		if b, ok := v[key].(bool); ok {
			return b
		}
	}
	_, failed := v["error"]
	return !failed
}

// checkReason reads the failure text of one policy result.
func checkReason(v map[string]any) string {
	for _, key := range []string{"error", "reason", "message"} {
		if s, ok := v[key].(string); ok && s != "" {
			return s
		}
	}
	return ""
}
