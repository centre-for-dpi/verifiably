// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"connectrpc.com/connect"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/fake"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/service"
)

// farmerQuery asks for one claim of a farmer credential.
const farmerQuery = `{"credentials":[{"id":"vc-1","format":"dc+sd-jwt",
  "claims":[{"path":["fullName"]}]}]}`

func TestCreateRequestProvisionsTheVerifierOnce(t *testing.T) {
	svc, f := newService(t, nil)
	ctx := context.Background()
	resp, err := svc.CreateRequest(ctx, connect.NewRequest(&backendv1.CreateRequestRequest{
		Dcql: farmerQuery,
	}))
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if !strings.HasPrefix(resp.Msg.GetRequestUri(), "openid4vp://") {
		t.Fatalf("request URI = %q", resp.Msg.GetRequestUri())
	}
	if resp.Msg.GetState() != "2d7f8a91-5c30-4e17-9b62-0a4d8f1e3c75" {
		t.Fatalf("state = %q", resp.Msg.GetState())
	}
	// The second call reuses the stored verifier.
	f.SetStatus("/v1/orgs/org-1/oid4vp/verifier", http.StatusInternalServerError)
	if _, err := svc.CreateRequest(ctx, connect.NewRequest(&backendv1.CreateRequestRequest{
		Dcql: farmerQuery,
	})); err != nil {
		t.Fatalf("the second call did not reuse the verifier: %v", err)
	}
}

func TestCreateRequestUsesThePinnedVerifier(t *testing.T) {
	svc, f := newService(t, func(o *service.Options) { o.VerifierID = "v-pinned" })
	f.SetStatus("/v1/orgs/org-1/oid4vp/verifier", http.StatusInternalServerError)
	if _, err := svc.CreateRequest(context.Background(),
		connect.NewRequest(&backendv1.CreateRequestRequest{Dcql: farmerQuery})); err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	query := string(f.Request("/v1/orgs/org-1/oid4vp/presentation"))
	if query == "" {
		t.Fatal("the presentation request is missing")
	}
}

func TestCreateRequestRejectsAPresentationExchangeOnlyRequest(t *testing.T) {
	svc, _ := newService(t, nil)
	_, err := svc.CreateRequest(context.Background(), connect.NewRequest(&backendv1.CreateRequestRequest{
		PresentationDefinition: `{"id":"x","input_descriptors":[]}`,
	}))
	wantCode(t, err, connect.CodeInvalidArgument)
	if !strings.Contains(err.Error(), "dcql") {
		t.Fatalf("the error %q does not say what to send", err)
	}
}

func TestCreateRequestRejectsABadQuery(t *testing.T) {
	svc, _ := newService(t, nil)
	_, err := svc.CreateRequest(context.Background(),
		connect.NewRequest(&backendv1.CreateRequestRequest{Dcql: "{"}))
	wantCode(t, err, connect.CodeInvalidArgument)
}

func TestCreateRequestReportsAFailure(t *testing.T) {
	svc, f := newService(t, nil)
	f.SetStatus("/v1/orgs/org-1/oid4vp/verifier", http.StatusBadGateway)
	_, err := svc.CreateRequest(context.Background(),
		connect.NewRequest(&backendv1.CreateRequestRequest{Dcql: farmerQuery}))
	wantCode(t, err, connect.CodeUnavailable)
	f.SetStatus("/v1/orgs/org-1/oid4vp/verifier", 0)
	f.SetStatus("/v1/orgs/org-1/oid4vp/presentation", http.StatusBadGateway)
	_, err = svc.CreateRequest(context.Background(),
		connect.NewRequest(&backendv1.CreateRequestRequest{Dcql: farmerQuery}))
	wantCode(t, err, connect.CodeUnavailable)
}

func TestGetResultReportsAPendingTransaction(t *testing.T) {
	svc, f := newService(t, nil)
	f.SetSession(fake.SessionPending)
	resp, err := svc.GetResult(context.Background(),
		connect.NewRequest(&backendv1.GetResultRequest{State: "s-1"}))
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
	svc, f := newService(t, nil)
	f.SetSession(fake.SessionVerified)
	resp, err := svc.GetResult(context.Background(),
		connect.NewRequest(&backendv1.GetResultRequest{State: "s-1"}))
	if err != nil {
		t.Fatalf("GetResult: %v", err)
	}
	if resp.Msg.GetState() != backendv1.GetResultResponse_STATE_ACCEPTED {
		t.Fatalf("state = %v", resp.Msg.GetState())
	}
	if len(resp.Msg.GetPresented()) != 1 {
		t.Fatalf("presented = %d", len(resp.Msg.GetPresented()))
	}
	if resp.Msg.GetPresented()[0].GetFormat() != commonv1.Format_FORMAT_DC_SD_JWT {
		t.Fatalf("format = %v", resp.Msg.GetPresented()[0].GetFormat())
	}
	if !strings.Contains(string(resp.Msg.GetPresented()[0].GetPayload()), "~") {
		t.Fatal("the SD-JWT payload must reach the caller unchanged")
	}
	if len(resp.Msg.GetDpgChecks()) != 1 || !resp.Msg.GetDpgChecks()[0].GetPassed() {
		t.Fatalf("checks = %v", resp.Msg.GetDpgChecks())
	}
	if resp.Msg.GetReceivedAt() == nil {
		t.Fatal("the answer time is missing")
	}
}

func TestGetResultReportsARejectedTransaction(t *testing.T) {
	svc, f := newService(t, nil)
	f.SetSession(fake.SessionError)
	resp, err := svc.GetResult(context.Background(),
		connect.NewRequest(&backendv1.GetResultRequest{State: "s-1"}))
	if err != nil {
		t.Fatalf("GetResult: %v", err)
	}
	if resp.Msg.GetState() != backendv1.GetResultResponse_STATE_REJECTED {
		t.Fatalf("state = %v", resp.Msg.GetState())
	}
	if resp.Msg.GetDpgChecks()[0].GetPassed() {
		t.Fatal("the check must fail")
	}
}

func TestGetResultChecksItsInput(t *testing.T) {
	svc, _ := newService(t, nil)
	_, err := svc.GetResult(context.Background(), connect.NewRequest(&backendv1.GetResultRequest{}))
	wantCode(t, err, connect.CodeInvalidArgument)
}

func TestGetResultReportsAFailure(t *testing.T) {
	svc, f := newService(t, nil)
	f.SetStatus("/v1/orgs/org-1/oid4vp/verifier-presentation", http.StatusNotFound)
	_, err := svc.GetResult(context.Background(),
		connect.NewRequest(&backendv1.GetResultRequest{State: "s-1"}))
	wantCode(t, err, connect.CodeNotFound)
}
