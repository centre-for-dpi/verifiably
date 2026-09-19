// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/fake"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/service"
)

// farmerDefinition asks for the full name of a farmer credential.
const farmerDefinition = `{
  "id": "farmer-check",
  "input_descriptors": [
    {
      "id": "farmer",
      "format": {"ldp_vc": {"proof_type": ["Ed25519Signature2020"]}},
      "constraints": {"fields": [{"path": ["$.credentialSubject.fullName"]}]}
    }
  ]
}`

// startRequest creates one transaction and returns its state.
func startRequest(t *testing.T, svc *service.Service) string {
	t.Helper()
	resp, err := svc.CreateRequest(context.Background(), connect.NewRequest(&backendv1.CreateRequestRequest{
		PresentationDefinition: farmerDefinition,
	}))
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	return resp.Msg.GetState()
}

func TestCreateRequestBuildsTheWalletUri(t *testing.T) {
	svc, f := newService(t, both)
	resp, err := svc.CreateRequest(context.Background(), connect.NewRequest(&backendv1.CreateRequestRequest{
		PresentationDefinition: farmerDefinition,
		Nonce:                  "nonce-1",
	}))
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if !strings.HasPrefix(resp.Msg.GetRequestUri(), "openid4vp://") {
		t.Fatalf("request URI = %q", resp.Msg.GetRequestUri())
	}
	if resp.Msg.GetState() != "c1d2e3f4-a5b6-4c7d-8e9f-0a1b2c3d4e5f|9b8a7c6d-5e4f-4a3b-2c1d-0e9f8a7b6c5d" {
		t.Fatalf("state = %q", resp.Msg.GetState())
	}
	if resp.Msg.GetExpiresAt() == nil {
		t.Fatal("the transaction has no end time")
	}
	var body map[string]any
	if err := f.RequestJSON("/v1/verify/vp-request", &body); err != nil {
		t.Fatalf("read the request: %v", err)
	}
	if body["nonce"] != "nonce-1" {
		t.Fatalf("nonce = %v", body["nonce"])
	}
	if body["clientId"] != "did:web:verify.example:v1:verify" {
		t.Fatalf("client id = %v", body["clientId"])
	}
}

func TestCreateRequestMakesANonceWhenTheCallerSendsNone(t *testing.T) {
	svc, f := newService(t, both)
	if _, err := svc.CreateRequest(context.Background(),
		connect.NewRequest(&backendv1.CreateRequestRequest{PresentationDefinition: farmerDefinition})); err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	var body map[string]any
	if err := f.RequestJSON("/v1/verify/vp-request", &body); err != nil {
		t.Fatalf("read the request: %v", err)
	}
	if body["nonce"] == "" || body["nonce"] == nil {
		t.Fatal("the request carries no nonce")
	}
}

func TestCreateRequestRejectsADcqlOnlyRequest(t *testing.T) {
	svc, _ := newService(t, both)
	_, err := svc.CreateRequest(context.Background(), connect.NewRequest(&backendv1.CreateRequestRequest{
		Dcql: `{"credentials":[]}`,
	}))
	wantCode(t, err, connect.CodeInvalidArgument)
	if !strings.Contains(err.Error(), "presentation_definition") {
		t.Fatalf("the error %q does not say what to send", err)
	}
}

func TestCreateRequestReportsAFailure(t *testing.T) {
	svc, f := newService(t, both)
	f.SetStatus("/v1/verify/vp-request", http.StatusInternalServerError)
	_, err := svc.CreateRequest(context.Background(), connect.NewRequest(&backendv1.CreateRequestRequest{
		PresentationDefinition: farmerDefinition,
	}))
	wantCode(t, err, connect.CodeUnavailable)
}

func TestGetResultReportsAPendingTransaction(t *testing.T) {
	svc, f := newService(t, both)
	state := startRequest(t, svc)
	f.SetResult(fake.ResultPending)
	resp, err := svc.GetResult(context.Background(),
		connect.NewRequest(&backendv1.GetResultRequest{State: state}))
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

func TestGetResultAcceptsAMatchingPresentation(t *testing.T) {
	svc, f := newService(t, both)
	state := startRequest(t, svc)
	f.SetResult(fake.ResultSuccess)
	resp, err := svc.GetResult(context.Background(),
		connect.NewRequest(&backendv1.GetResultRequest{State: state}))
	if err != nil {
		t.Fatalf("GetResult: %v", err)
	}
	if resp.Msg.GetState() != backendv1.GetResultResponse_STATE_ACCEPTED {
		t.Fatalf("state = %v", resp.Msg.GetState())
	}
	if len(resp.Msg.GetPresented()) != 1 {
		t.Fatalf("presented = %d", len(resp.Msg.GetPresented()))
	}
	if len(resp.Msg.GetDpgChecks()) != 1 || !resp.Msg.GetDpgChecks()[0].GetPassed() {
		t.Fatalf("checks = %v", resp.Msg.GetDpgChecks())
	}
	if resp.Msg.GetReceivedAt() == nil {
		t.Fatal("the answer time is missing")
	}
}

func TestGetResultLowersASuccessWithTheWrongCredential(t *testing.T) {
	svc, f := newService(t, both)
	state := startRequest(t, svc)
	f.SetResult(fake.ResultWrongCredential)
	resp, err := svc.GetResult(context.Background(),
		connect.NewRequest(&backendv1.GetResultRequest{State: state}))
	if err != nil {
		t.Fatalf("GetResult: %v", err)
	}
	if resp.Msg.GetState() != backendv1.GetResultResponse_STATE_REJECTED {
		t.Fatalf("state = %v; Inji Verify can accept the wrong credential", resp.Msg.GetState())
	}
	var guard *backendv1.GetResultResponse_DpgCheck
	for _, c := range resp.Msg.GetDpgChecks() {
		if c.GetName() == "requested-claims" {
			guard = c
		}
	}
	if guard == nil || guard.GetPassed() || guard.GetReason() == "" {
		t.Fatalf("checks = %v", resp.Msg.GetDpgChecks())
	}
}

func TestGetResultReportsARejectedPresentation(t *testing.T) {
	svc, f := newService(t, both)
	state := startRequest(t, svc)
	f.SetResult(fake.ResultInvalid)
	resp, err := svc.GetResult(context.Background(),
		connect.NewRequest(&backendv1.GetResultRequest{State: state}))
	if err != nil {
		t.Fatalf("GetResult: %v", err)
	}
	if resp.Msg.GetState() != backendv1.GetResultResponse_STATE_REJECTED {
		t.Fatalf("state = %v", resp.Msg.GetState())
	}
	checks := resp.Msg.GetDpgChecks()
	if len(checks) != 1 || checks[0].GetPassed() || checks[0].GetReason() != "EXPIRED" {
		t.Fatalf("checks = %v", checks)
	}
}

func TestGetResultWithoutAStoredRequestSkipsTheGuard(t *testing.T) {
	svc, f := newService(t, both)
	f.SetResult(fake.ResultWrongCredential)
	resp, err := svc.GetResult(context.Background(),
		connect.NewRequest(&backendv1.GetResultRequest{State: "unknown-transaction"}))
	if err != nil {
		t.Fatalf("GetResult: %v", err)
	}
	if resp.Msg.GetState() != backendv1.GetResultResponse_STATE_ACCEPTED {
		t.Fatalf("state = %v; without a stored request there is nothing to compare", resp.Msg.GetState())
	}
}

func TestGetResultChecksItsInput(t *testing.T) {
	svc, _ := newService(t, both)
	_, err := svc.GetResult(context.Background(), connect.NewRequest(&backendv1.GetResultRequest{}))
	wantCode(t, err, connect.CodeInvalidArgument)
}

func TestGetResultReportsAFailure(t *testing.T) {
	svc, f := newService(t, both)
	f.SetStatus("/v1/verify/vp-result/tx", http.StatusNotFound)
	_, err := svc.GetResult(context.Background(),
		connect.NewRequest(&backendv1.GetResultRequest{State: "tx"}))
	wantCode(t, err, connect.CodeNotFound)
}

func TestRecordedAnswersAreValidJson(t *testing.T) {
	entries, err := os.ReadDir(testdata)
	if err != nil {
		t.Fatalf("read the testdata directory: %v", err)
	}
	count := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(testdata, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		if !json.Valid(raw) {
			t.Fatalf("%s is not valid JSON", e.Name())
		}
		count++
	}
	if count < 10 {
		t.Fatalf("the recorded answers are %d, want at least 10", count)
	}
}
