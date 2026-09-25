// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-waltid/internal/fake"
)

// dcqlQuery asks for one SD-JWT VC with one claim.
const dcqlQuery = `{"credentials":[{"id":"credential_1","format":"dc+sd-jwt",` +
	`"meta":{"vct_values":["https://walt-issuer.example.org/identity_credential"]},` +
	`"claims":[{"path":["age_over_18"]}]}]}`

// withV2 wires both verifiers of the stack.
var withV2 = roles{verifier: true, verifier2: true}

func TestCreateDcqlSession(t *testing.T) {
	svc, f := newService(t, withV2)
	resp, err := svc.CreateRequest(context.Background(), connect.NewRequest(&backendv1.CreateRequestRequest{
		Dcql:        dcqlQuery,
		DpgPolicies: []string{"signature", "expired", "not-before", "status-list", "unknown-check"},
		WebhookUrl:  "https://vca.example.org/hook",
	}))
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if !strings.HasPrefix(resp.Msg.GetRequestUri(), "openid4vp://authorize?client_id=verifier2&request_uri=") {
		t.Fatalf("request URI = %q, want the bootstrap URL of verifier 2", resp.Msg.GetRequestUri())
	}
	if resp.Msg.GetState() != "v2:14d60fa2-4e7d-4a34-a291-80da0e053fab" {
		t.Fatalf("state = %q", resp.Msg.GetState())
	}
	if len(f.Request("/openid4vc/verify")) != 0 {
		t.Fatal("a DCQL request went to the Presentation Exchange verifier")
	}
	var body struct {
		FlowType string `json:"flow_type"`
		Core     struct {
			Dcql     map[string]any `json:"dcql_query"`
			Policies struct {
				VC []map[string]any `json:"vc_policies"`
			} `json:"policies"`
		} `json:"core_flow"`
	}
	if err := f.RequestJSON("/verification-session/create", &body); err != nil {
		t.Fatalf("read the create request: %v", err)
	}
	if body.FlowType != "cross_device" {
		t.Errorf("flow_type = %q", body.FlowType)
	}
	creds := mustAs[[]any](t, body.Core.Dcql["credentials"])
	if len(creds) != 1 || mustAs[map[string]any](t, creds[0])["id"] != "credential_1" {
		t.Errorf("the DCQL query changed on the way: %v", body.Core.Dcql)
	}
	var names []string
	for _, p := range body.Core.Policies.VC {
		names = append(names, mustAs[string](t, p["policy"]))
	}
	if got := strings.Join(names, ","); got != "signature,expiration,not-before,webhook" {
		t.Errorf("vc_policies = %s", got)
	}
	if body.Core.Policies.VC[3]["url"] != "https://vca.example.org/hook" {
		t.Errorf("the webhook policy has no URL: %v", body.Core.Policies.VC[3])
	}
}

func TestCreateDcqlSessionChecksTheQuery(t *testing.T) {
	svc, _ := newService(t, withV2)
	_, err := svc.CreateRequest(context.Background(), connect.NewRequest(&backendv1.CreateRequestRequest{Dcql: "{not json"}))
	wantCode(t, err, connect.CodeInvalidArgument)
}

func TestCreateDcqlSessionReportsAFailureOfVerifier2(t *testing.T) {
	svc, f := newService(t, withV2)
	f.SetStatus("/verification-session/create", 500)
	_, err := svc.CreateRequest(context.Background(), connect.NewRequest(&backendv1.CreateRequestRequest{Dcql: dcqlQuery}))
	wantCode(t, err, connect.CodeUnavailable)
}

func TestDcqlWithoutVerifier2IsABadRequest(t *testing.T) {
	svc, _ := newService(t, roles{verifier: true})
	_, err := svc.CreateRequest(context.Background(), connect.NewRequest(&backendv1.CreateRequestRequest{Dcql: dcqlQuery}))
	wantCode(t, err, connect.CodeInvalidArgument)
}

func TestPresentationExchangeWithoutVerifier1IsABadRequest(t *testing.T) {
	svc, _ := newService(t, roles{verifier2: true})
	_, err := svc.CreateRequest(context.Background(), connect.NewRequest(&backendv1.CreateRequestRequest{
		PresentationDefinition: sdJwtDefinition,
	}))
	wantCode(t, err, connect.CodeInvalidArgument)
}

func TestGetResultV2States(t *testing.T) {
	table := []struct {
		session  fake.Session2State
		want     backendv1.GetResultResponse_State
		creds    int
		checks   int
		failures int
	}{
		{fake.Session2Active, backendv1.GetResultResponse_STATE_PENDING, 0, 0, 0},
		{fake.Session2Successful, backendv1.GetResultResponse_STATE_ACCEPTED, 1, 3, 0},
		{fake.Session2Failed, backendv1.GetResultResponse_STATE_REJECTED, 1, 4, 2},
		{fake.Session2Expired, backendv1.GetResultResponse_STATE_EXPIRED, 0, 0, 0},
	}
	for _, row := range table {
		t.Run(string(row.session), func(t *testing.T) {
			svc, f := newService(t, withV2)
			f.SetSession2(row.session)
			resp, err := svc.GetResult(context.Background(), connect.NewRequest(&backendv1.GetResultRequest{
				State: "v2:14d60fa2-4e7d-4a34-a291-80da0e053fab",
			}))
			if err != nil {
				t.Fatalf("GetResult: %v", err)
			}
			if resp.Msg.GetState() != row.want {
				t.Fatalf("state = %v, want %v", resp.Msg.GetState(), row.want)
			}
			if len(resp.Msg.GetPresented()) != row.creds {
				t.Fatalf("presented = %d, want %d", len(resp.Msg.GetPresented()), row.creds)
			}
			if len(resp.Msg.GetDpgChecks()) != row.checks {
				t.Fatalf("checks = %v, want %d", resp.Msg.GetDpgChecks(), row.checks)
			}
			failures := 0
			for _, c := range resp.Msg.GetDpgChecks() {
				if !c.GetPassed() {
					failures++
					if c.GetReason() == "" {
						t.Errorf("the failed check %q has no reason", c.GetName())
					}
				}
			}
			if failures != row.failures {
				t.Errorf("failed checks = %d, want %d", failures, row.failures)
			}
			if row.creds > 0 {
				if !strings.HasPrefix(string(resp.Msg.GetPresented()[0].GetPayload()), "eyJ") {
					t.Error("the presented credential is not the vp_token entry")
				}
				if resp.Msg.GetPresented()[0].GetFormat() != commonv1.Format_FORMAT_DC_SD_JWT {
					t.Errorf("format = %v", resp.Msg.GetPresented()[0].GetFormat())
				}
				if resp.Msg.GetReceivedAt() == nil {
					t.Error("an answered session has no time")
				}
			}
			if !strings.HasSuffix(f.LastPath(), "/verification-session/14d60fa2-4e7d-4a34-a291-80da0e053fab/info") {
				t.Errorf("the adapter read %q", f.LastPath())
			}
		})
	}
}

func TestGetResultV2ReportsAMissingSession(t *testing.T) {
	svc, f := newService(t, withV2)
	f.SetStatus("/verification-session/gone/info", 404)
	_, err := svc.GetResult(context.Background(), connect.NewRequest(&backendv1.GetResultRequest{State: "v2:gone"}))
	wantCode(t, err, connect.CodeNotFound)
}

func TestGetResultV2WithoutVerifier2(t *testing.T) {
	svc, _ := newService(t, roles{verifier: true})
	_, err := svc.GetResult(context.Background(), connect.NewRequest(&backendv1.GetResultRequest{State: "v2:any"}))
	wantCode(t, err, connect.CodeFailedPrecondition)
}

func TestCapabilitiesListDcqlWhenV2Configured(t *testing.T) {
	ctx := context.Background()
	for _, row := range []struct {
		name       string
		r          roles
		dcql, pex  bool
		component  bool
		isVerifier bool
	}{
		{"verifier 1 only", roles{verifier: true}, false, true, false, true},
		{"both verifiers", withV2, true, true, true, true},
		{"verifier 2 only", roles{verifier2: true}, true, false, true, true},
		{"no verifier", roles{issuer: true}, false, false, false, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			svc, _ := newService(t, row.r)
			resp, err := svc.GetCapabilities(ctx, connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
			if err != nil {
				t.Fatalf("GetCapabilities: %v", err)
			}
			if got := hasProtocol(resp.Msg.GetProtocols(), backendv1.Protocol_PROTOCOL_OID4VP_DCQL); got != row.dcql {
				t.Errorf("DCQL listed = %v, want %v", got, row.dcql)
			}
			if got := hasProtocol(resp.Msg.GetProtocols(), backendv1.Protocol_PROTOCOL_OID4VP_PEX); got != row.pex {
				t.Errorf("PE listed = %v, want %v", got, row.pex)
			}
			verifier := 0
			for _, r := range resp.Msg.GetRoles() {
				if r == commonv1.Role_ROLE_VERIFIER {
					verifier++
				}
			}
			if (verifier == 1) != row.isVerifier || verifier > 1 {
				t.Errorf("verifier role listed %d times", verifier)
			}
			found := false
			for _, c := range resp.Msg.GetDpgInfo().GetComponents() {
				if c.GetName() == "verifier-api2" {
					found = c.GetVersion() == "0.18.2"
				}
			}
			if found != row.component {
				t.Errorf("verifier-api2 component = %v, want %v", found, row.component)
			}
		})
	}
}

func TestDcApiRequestCreated(t *testing.T) {
	svc, f := newService(t, withV2)
	ctx := context.Background()
	resp, err := svc.CreateRequest(ctx, connect.NewRequest(&backendv1.CreateRequestRequest{
		Dcql: dcqlQuery, DcApi: true, ExpectedOrigins: []string{"https://verifier-waltid.labs.example"},
		DpgPolicies: []string{"signature"},
	}))
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	var request struct {
		Protocol string         `json:"protocol"`
		Data     map[string]any `json:"data"`
	}
	if uerr := json.Unmarshal([]byte(resp.Msg.GetDcApiRequest()), &request); uerr != nil {
		t.Fatalf("the DC API request is not JSON: %v", uerr)
	}
	if request.Protocol != "openid4vp-v1-unsigned" || request.Data["response_mode"] != "dc_api" {
		t.Errorf("DC API request = %+v", request)
	}
	if !strings.HasPrefix(resp.Msg.GetRequestUri(), "openid4vp://authorize?client_id=verifier2") {
		t.Errorf("the QR fallback has no request URI: %q", resp.Msg.GetRequestUri())
	}
	if resp.Msg.GetState() != "v2:ff4f0c86-56ce-4e4a-a137-dd5569049ff3,14d60fa2-4e7d-4a34-a291-80da0e053fab" {
		t.Errorf("state = %q", resp.Msg.GetState())
	}
	bodies := f.Bodies("/verification-session/create")
	if len(bodies) != 2 {
		t.Fatalf("created %d sessions, want a DC API session and a cross device session", len(bodies))
	}
	var dc struct {
		FlowType string   `json:"flow_type"`
		Origins  []string `json:"expectedOrigins"`
		Core     struct {
			Dcql json.RawMessage `json:"dcql_query"`
		} `json:"core_flow"`
	}
	if uerr := json.Unmarshal(bodies[0], &dc); uerr != nil {
		t.Fatal(uerr)
	}
	if dc.FlowType != "dc_api_openid4vp" || len(dc.Origins) != 1 || dc.Origins[0] != "https://verifier-waltid.labs.example" || len(dc.Core.Dcql) == 0 {
		t.Errorf("DC API session body = %s", bodies[0])
	}

	// The browser answer goes to the DC API session.
	if _, serr := svc.SubmitBrowserAnswer(ctx, connect.NewRequest(&backendv1.SubmitBrowserAnswerRequest{
		State: resp.Msg.GetState(), Response: `{"protocol":"openid4vp-v1-unsigned","data":{"vp_token":{"credential_1":["eyJ"]}}}`,
	})); serr != nil {
		t.Fatalf("SubmitBrowserAnswer: %v", serr)
	}
	var answer map[string]any
	if rerr := f.RequestJSON("/verification-session/ff4f0c86-56ce-4e4a-a137-dd5569049ff3/response", &answer); rerr != nil {
		t.Fatalf("the answer did not reach verifier 2: %v", rerr)
	}
	if answer["protocol"] != "openid4vp-v1-unsigned" {
		t.Errorf("answer = %v", answer)
	}

	// Either session answers the result.
	f.SetSession2(fake.Session2Successful)
	result, err := svc.GetResult(ctx, connect.NewRequest(&backendv1.GetResultRequest{State: resp.Msg.GetState()}))
	if err != nil || result.Msg.GetState() != backendv1.GetResultResponse_STATE_ACCEPTED {
		t.Fatalf("GetResult = %v %v", result, err)
	}
}

func TestDcApiNeedsOriginsAndQuery(t *testing.T) {
	svc, _ := newService(t, withV2)
	ctx := context.Background()
	_, err := svc.CreateRequest(ctx, connect.NewRequest(&backendv1.CreateRequestRequest{Dcql: dcqlQuery, DcApi: true}))
	wantCode(t, err, connect.CodeInvalidArgument)
	_, err = svc.CreateRequest(ctx, connect.NewRequest(&backendv1.CreateRequestRequest{
		PresentationDefinition: sdJwtDefinition, DcApi: true, ExpectedOrigins: []string{"https://v.example"},
	}))
	wantCode(t, err, connect.CodeInvalidArgument)
	v1, _ := newService(t, roles{verifier: true})
	_, err = v1.CreateRequest(ctx, connect.NewRequest(&backendv1.CreateRequestRequest{
		Dcql: dcqlQuery, DcApi: true, ExpectedOrigins: []string{"https://v.example"},
	}))
	wantCode(t, err, connect.CodeInvalidArgument)
}

func TestSubmitBrowserAnswerChecksItsInput(t *testing.T) {
	ctx := context.Background()
	v1, _ := newService(t, roles{verifier: true})
	_, err := v1.SubmitBrowserAnswer(ctx, connect.NewRequest(&backendv1.SubmitBrowserAnswerRequest{State: "v2:a", Response: "{}"}))
	wantCode(t, err, connect.CodeUnimplemented)
	svc, f := newService(t, withV2)
	for _, req := range []*backendv1.SubmitBrowserAnswerRequest{
		{State: "plain", Response: "{}"},
		{State: "v2:a", Response: "not json"},
		{State: "v2:a", Response: "[1]"},
	} {
		_, serr := svc.SubmitBrowserAnswer(ctx, connect.NewRequest(req))
		wantCode(t, serr, connect.CodeInvalidArgument)
	}
	f.SetStatus("/verification-session/a/response", 400)
	_, err = svc.SubmitBrowserAnswer(ctx, connect.NewRequest(&backendv1.SubmitBrowserAnswerRequest{State: "v2:a", Response: "{}"}))
	wantCode(t, err, connect.CodeInvalidArgument)
}

func TestGetResultOfTwoSessionsWaitsForBoth(t *testing.T) {
	svc, f := newService(t, withV2)
	ctx := context.Background()
	for session, want := range map[fake.Session2State]backendv1.GetResultResponse_State{
		fake.Session2Active:  backendv1.GetResultResponse_STATE_PENDING,
		fake.Session2Expired: backendv1.GetResultResponse_STATE_EXPIRED,
		fake.Session2Failed:  backendv1.GetResultResponse_STATE_REJECTED,
	} {
		f.SetSession2(session)
		resp, err := svc.GetResult(ctx, connect.NewRequest(&backendv1.GetResultRequest{State: "v2:a,b"}))
		if err != nil || resp.Msg.GetState() != want {
			t.Errorf("%s: %v %v", session, resp, err)
		}
	}
}

func TestCapabilitiesListDcApiWithVerifier2(t *testing.T) {
	for _, row := range []struct {
		r    roles
		want bool
	}{{withV2, true}, {roles{verifier: true}, false}} {
		svc, _ := newService(t, row.r)
		resp, err := svc.GetCapabilities(context.Background(), connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		listed := false
		for _, f := range resp.Msg.GetFeatures() {
			listed = listed || f == backendv1.Feature_FEATURE_DC_API_VERIFY
		}
		if listed != row.want || hasProtocol(resp.Msg.GetProtocols(), backendv1.Protocol_PROTOCOL_DC_API) != row.want {
			t.Errorf("%+v: DC API listed = %v", row.r, listed)
		}
	}
}
