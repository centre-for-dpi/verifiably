// SPDX-License-Identifier: Apache-2.0

package waltid

import (
	"encoding/json"
	"testing"
)

func TestRequestCredentialsFromDefinitionKeepsTheDescriptor(t *testing.T) {
	definition := `{"id":"x","input_descriptors":[
      {"id":"d1","format":{"vc+sd-jwt":{},"jwt_vc_json":{}},"constraints":{"limit_disclosure":"required"}},
      {"id":"d2","constraints":{}}]}`
	got, err := RequestCredentialsFromDefinition(definition)
	if err != nil {
		t.Fatalf("RequestCredentialsFromDefinition: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("entries = %d", len(got))
	}
	if got[0]["format"] != "jwt_vc_json" {
		t.Fatalf("format = %v, the first key in order wins", got[0]["format"])
	}
	if _, ok := got[1]["format"]; ok {
		t.Fatal("a descriptor without a format must add none")
	}
	descriptor := mustAs[map[string]any](t, got[0]["input_descriptor"])
	if descriptor["id"] != "d1" {
		t.Fatalf("descriptor = %v", descriptor)
	}
}

func TestRequestCredentialsFromDefinitionRejectsABadDocument(t *testing.T) {
	if _, err := RequestCredentialsFromDefinition("{"); err == nil {
		t.Fatal("a broken document was accepted")
	}
	if _, err := RequestCredentialsFromDefinition(`{"id":"x"}`); err == nil {
		t.Fatal("a document without descriptors was accepted")
	}
	if _, err := RequestCredentialsFromDefinition(`{"input_descriptors":[1]}`); err == nil {
		t.Fatal("a descriptor that is not an object was accepted")
	}
}

func TestVPPoliciesAlwaysRun(t *testing.T) {
	if got := VPPolicies(); len(got) != 2 {
		t.Fatalf("vp policies = %v", got)
	}
}

func TestVCPoliciesMapTheCheckNames(t *testing.T) {
	got := VCPolicies([]string{"signature", "expired", "not-before", "unknown"}, FormatJwtVcJSON)
	if len(got) != 3 {
		t.Fatalf("policies = %v, an unknown name drops out", got)
	}
	ietf := VCPolicies([]string{"status-list"}, FormatDcSdJwt)
	entry := mustAs[map[string]any](t, ietf[0])
	args := mustAs[map[string]any](t, entry["args"])
	if entry["policy"] != "credential-status" || args["discriminator"] != "ietf" {
		t.Fatalf("policy = %v", entry)
	}
	w3c := VCPolicies([]string{"status-list"}, FormatLdpVc)
	entry = mustAs[map[string]any](t, w3c[0])
	args = mustAs[map[string]any](t, entry["args"])
	if args["type"] != "BitstringStatusList" || args["purpose"] != "revocation" {
		t.Fatalf("args = %v", args)
	}
}

func TestWebhookPolicyNeedsAUrl(t *testing.T) {
	if got := WebhookPolicy("   "); got != nil {
		t.Fatalf("policy = %v, an empty URL adds none", got)
	}
	got := WebhookPolicy("https://vca.example/hook")
	entry := mustAs[map[string]any](t, got[0])
	args := mustAs[map[string]any](t, entry["args"])
	if args["url"] != "https://vca.example/hook" {
		t.Fatalf("args = %v", args)
	}
}

func TestStateFromAuthorizeURL(t *testing.T) {
	cases := map[string]string{
		"openid4vp://authorize?state=abc":                                     "abc",
		"openid4vp://authorize?request_uri=https%3A%2F%2Fv.example%2Fr%2Fxyz": "xyz",
		"openid4vp://authorize":                                               "",
		"://bad url":                                                          "",
	}
	for in, want := range cases {
		if got := StateFromAuthorizeURL(in); got != want {
			t.Fatalf("StateFromAuthorizeURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPresentedCredentialsReadsEveryTokenShape(t *testing.T) {
	cases := map[string]int{
		`{"vp_token":"one"}`:                     1,
		`{"vp_token":["one","two"]}`:             2,
		`{"vp_token":{"b":["two"],"a":["one"]}}`: 2,
		`{"vp_token":""}`:                        0,
		`{"vp_token":123}`:                       0,
		`{}`:                                     0,
		`not json`:                               0,
		``:                                       0,
	}
	for in, want := range cases {
		if got := PresentedCredentials(json.RawMessage(in)); len(got) != want {
			t.Fatalf("PresentedCredentials(%s) = %v, want %d", in, got, want)
		}
	}
	got := PresentedCredentials(json.RawMessage(`{"vp_token":{"b":["two"],"a":["one"]}}`))
	if got[0] != "one" || got[1] != "two" {
		t.Fatalf("the order must be stable, got %v", got)
	}
}

func TestPolicyChecksWalksTheTree(t *testing.T) {
	raw := json.RawMessage(`{"results":[{"policyResults":[
      {"policy":"signature","is_success":true},
      {"policy":"expired","success":false,"reason":"the credential expired"},
      {"policy":"credential-status","error":"the credential is revoked"},
      {"policy":"webhook","isSuccess":true}]}]}`)
	got := PolicyChecks(raw)
	if len(got) != 4 {
		t.Fatalf("checks = %v", got)
	}
	byName := map[string]Check{}
	for _, c := range got {
		byName[c.Name] = c
	}
	if !byName["signature"].Passed {
		t.Fatal("the signature check must pass")
	}
	if byName["expired"].Passed || byName["expired"].Reason == "" {
		t.Fatalf("expired = %+v", byName["expired"])
	}
	if byName["credential-status"].Passed {
		t.Fatal("an error entry means the check failed")
	}
	if !byName["webhook"].Passed {
		t.Fatal("the webhook check must pass")
	}
}

func TestPolicyChecksOfAnEmptyOrBrokenDocument(t *testing.T) {
	if got := PolicyChecks(nil); got != nil {
		t.Fatalf("checks = %v", got)
	}
	if got := PolicyChecks(json.RawMessage("not json")); got != nil {
		t.Fatalf("checks = %v", got)
	}
	if got := PolicyChecks(json.RawMessage(`{"policy":""}`)); got != nil {
		t.Fatalf("an entry without a name adds no check, got %v", got)
	}
}
