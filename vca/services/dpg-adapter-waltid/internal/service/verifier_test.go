// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"connectrpc.com/connect"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-waltid/internal/fake"
)

// sdJwtDefinition asks for one SD-JWT VC and one claim.
const sdJwtDefinition = `{
  "id": "age-check",
  "input_descriptors": [
    {
      "id": "identity",
      "format": {"vc+sd-jwt": {"sd-jwt_alg_values": ["ES256"]}},
      "constraints": {
        "limit_disclosure": "required",
        "fields": [
          {"path": ["$.vct"], "filter": {"type": "string", "const": "https://walt-issuer.example.org/identity_credential"}},
          {"path": ["$.age_over_18"]}
        ]
      }
    }
  ]
}`

func TestCreateRequestSendsTheInputDescriptorUnchanged(t *testing.T) {
	svc, f := newService(t, all)
	resp, err := svc.CreateRequest(context.Background(), connect.NewRequest(&backendv1.CreateRequestRequest{
		PresentationDefinition: sdJwtDefinition,
		DpgPolicies:            []string{"signature", "expired", "status-list", "unknown-check"},
		WebhookUrl:             "https://vca.example.org/hook",
	}))
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if !strings.HasPrefix(resp.Msg.GetRequestUri(), "openid4vp://") {
		t.Fatalf("request URI = %q", resp.Msg.GetRequestUri())
	}
	if resp.Msg.GetState() != "9c0e2f1b-77f4-4f2e-a0b1-6f6b2c1d8e55" {
		t.Fatalf("state = %q", resp.Msg.GetState())
	}
	var body struct {
		RequestCredentials []map[string]any `json:"request_credentials"`
		VPPolicies         []any            `json:"vp_policies"`
		VCPolicies         []any            `json:"vc_policies"`
	}
	if err := f.RequestJSON("/openid4vc/verify", &body); err != nil {
		t.Fatalf("read the verify request: %v", err)
	}
	if len(body.RequestCredentials) != 1 {
		t.Fatalf("request_credentials = %v", body.RequestCredentials)
	}
	entry := body.RequestCredentials[0]
	if entry["format"] != "vc+sd-jwt" {
		t.Fatalf("format = %v", entry["format"])
	}
	descriptor, _ := entry["input_descriptor"].(map[string]any)
	constraints, _ := descriptor["constraints"].(map[string]any)
	if constraints["limit_disclosure"] != "required" {
		t.Fatalf("the descriptor lost its constraints: %v", descriptor)
	}
	if len(body.VPPolicies) != 2 {
		t.Fatalf("vp_policies = %v, the envelope checks always run", body.VPPolicies)
	}
	statusArgs := findPolicyArgs(t, body.VCPolicies, "credential-status")
	if statusArgs["discriminator"] != "ietf" {
		t.Fatalf("an SD-JWT status check must use the IETF list, got %v", statusArgs)
	}
	if findPolicyArgs(t, body.VCPolicies, "webhook")["url"] != "https://vca.example.org/hook" {
		t.Fatal("the webhook policy is missing")
	}
}

func TestCreateRequestUsesTheW3cStatusArgumentsForAJwtCredential(t *testing.T) {
	svc, f := newService(t, all)
	definition := `{"id":"x","input_descriptors":[{"id":"d","format":{"jwt_vc_json":{}},"constraints":{}}]}`
	_, err := svc.CreateRequest(context.Background(), connect.NewRequest(&backendv1.CreateRequestRequest{
		PresentationDefinition: definition,
		DpgPolicies:            []string{"status-list"},
	}))
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	var body struct {
		VCPolicies []any `json:"vc_policies"`
	}
	if err := f.RequestJSON("/openid4vc/verify", &body); err != nil {
		t.Fatalf("read the verify request: %v", err)
	}
	args := findPolicyArgs(t, body.VCPolicies, "credential-status")
	if args["discriminator"] != "w3c" || args["type"] != "BitstringStatusList" {
		t.Fatalf("args = %v; walt.id compares the type of the list, not of the entry", args)
	}
}

// findPolicyArgs returns the args of one named policy.
func findPolicyArgs(t *testing.T, policies []any, name string) map[string]any {
	t.Helper()
	for _, p := range policies {
		entry, ok := p.(map[string]any)
		if !ok || entry["policy"] != name {
			continue
		}
		args, _ := entry["args"].(map[string]any)
		return args
	}
	return map[string]any{}
}

func TestCreateRequestRejectsADcqlOnlyRequest(t *testing.T) {
	svc, _ := newService(t, all)
	_, err := svc.CreateRequest(context.Background(), connect.NewRequest(&backendv1.CreateRequestRequest{
		Dcql: `{"credentials":[{"id":"vc-1","format":"dc+sd-jwt"}]}`,
	}))
	wantCode(t, err, connect.CodeInvalidArgument)
	if !strings.Contains(err.Error(), "presentation_definition") {
		t.Fatalf("the error %q does not say what to send", err)
	}
}

func TestCreateRequestRejectsABadDefinition(t *testing.T) {
	svc, _ := newService(t, all)
	ctx := context.Background()
	_, err := svc.CreateRequest(ctx, connect.NewRequest(&backendv1.CreateRequestRequest{
		PresentationDefinition: "{",
	}))
	wantCode(t, err, connect.CodeInvalidArgument)
	_, err = svc.CreateRequest(ctx, connect.NewRequest(&backendv1.CreateRequestRequest{
		PresentationDefinition: `{"id":"x"}`,
	}))
	wantCode(t, err, connect.CodeInvalidArgument)
	_, err = svc.CreateRequest(ctx, connect.NewRequest(&backendv1.CreateRequestRequest{
		PresentationDefinition: `{"id":"x","input_descriptors":["not an object"]}`,
	}))
	wantCode(t, err, connect.CodeInvalidArgument)
}

func TestCreateRequestReportsAFailure(t *testing.T) {
	svc, f := newService(t, all)
	f.SetStatus("/openid4vc/verify", http.StatusBadGateway)
	_, err := svc.CreateRequest(context.Background(), connect.NewRequest(&backendv1.CreateRequestRequest{
		PresentationDefinition: sdJwtDefinition,
	}))
	wantCode(t, err, connect.CodeUnavailable)
}

func TestGetResultReportsAPendingTransaction(t *testing.T) {
	svc, f := newService(t, all)
	f.SetSession(fake.SessionPending)
	resp, err := svc.GetResult(context.Background(),
		connect.NewRequest(&backendv1.GetResultRequest{State: "9c0e2f1b"}))
	if err != nil {
		t.Fatalf("GetResult: %v", err)
	}
	if resp.Msg.GetState() != backendv1.GetResultResponse_STATE_PENDING {
		t.Fatalf("state = %v", resp.Msg.GetState())
	}
	if resp.Msg.GetReceivedAt() != nil {
		t.Fatal("a pending transaction has no answer time")
	}
}

func TestGetResultReportsAnAcceptedTransaction(t *testing.T) {
	svc, f := newService(t, all)
	f.SetSession(fake.SessionAccepted)
	resp, err := svc.GetResult(context.Background(),
		connect.NewRequest(&backendv1.GetResultRequest{State: "9c0e2f1b"}))
	if err != nil {
		t.Fatalf("GetResult: %v", err)
	}
	if resp.Msg.GetState() != backendv1.GetResultResponse_STATE_ACCEPTED {
		t.Fatalf("state = %v", resp.Msg.GetState())
	}
	if len(resp.Msg.GetPresented()) != 1 {
		t.Fatalf("presented = %d", len(resp.Msg.GetPresented()))
	}
	if !strings.Contains(string(resp.Msg.GetPresented()[0].GetPayload()), "~") {
		t.Fatal("the SD-JWT payload must reach the caller unchanged")
	}
	checks := resp.Msg.GetDpgChecks()
	if len(checks) != 3 {
		t.Fatalf("checks = %v", checks)
	}
	if resp.Msg.GetReceivedAt() == nil {
		t.Fatal("the answer time is missing")
	}
}

func TestGetResultReportsARejectedTransaction(t *testing.T) {
	svc, f := newService(t, all)
	f.SetSession(fake.SessionRejected)
	resp, err := svc.GetResult(context.Background(),
		connect.NewRequest(&backendv1.GetResultRequest{State: "9c0e2f1b"}))
	if err != nil {
		t.Fatalf("GetResult: %v", err)
	}
	if resp.Msg.GetState() != backendv1.GetResultResponse_STATE_REJECTED {
		t.Fatalf("state = %v", resp.Msg.GetState())
	}
	var failed *backendv1.GetResultResponse_DpgCheck
	for _, c := range resp.Msg.GetDpgChecks() {
		if !c.GetPassed() {
			failed = c
		}
	}
	if failed == nil || failed.GetReason() == "" {
		t.Fatalf("the failed check has no reason: %v", resp.Msg.GetDpgChecks())
	}
}

func TestGetResultChecksItsInput(t *testing.T) {
	svc, _ := newService(t, all)
	_, err := svc.GetResult(context.Background(), connect.NewRequest(&backendv1.GetResultRequest{}))
	wantCode(t, err, connect.CodeInvalidArgument)
}

func TestGetResultReportsAFailure(t *testing.T) {
	svc, f := newService(t, all)
	f.SetStatus("/openid4vc/session/9c0e2f1b", http.StatusNotFound)
	_, err := svc.GetResult(context.Background(),
		connect.NewRequest(&backendv1.GetResultRequest{State: "9c0e2f1b"}))
	wantCode(t, err, connect.CodeNotFound)
}

func TestRecordedSessionsAreValidJson(t *testing.T) {
	for _, name := range []string{
		"session-pending.json", "session-accepted.json", "session-rejected.json",
		"issuer-metadata.json", "onboard-issuer.json", "wallet-login.json",
		"wallet-wallets.json", "wallet-credentials.json", "wallet-credentials-after.json",
		"resolve-offer.json", "present-result.json",
	} {
		raw := readFixture(t, name)
		if !json.Valid(raw) {
			t.Fatalf("%s is not valid JSON", name)
		}
	}
}
