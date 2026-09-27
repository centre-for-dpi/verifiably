// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/fake"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/service"
)

// P6-C6: the platform asks for a proof over DIDComm: an AnonCreds proof
// request with predicates, or a DIF Presentation Exchange request, as an
// out of band invitation or over a connection. The agent verifies the
// proof, and the platform reads the revealed values.

const (
	proofSchemaID = "did:indy:bcovrin:testnet:Ra8FGb2mXsTg1d4VqVnYpS/anoncreds/v0/SCHEMA/Farmer/1.0"
	proofCredDef  = "did:indy:bcovrin:testnet:Ra8FGb2mXsTg1d4VqVnYpS/anoncreds/v0/CLAIM_DEF/2107/default" //nolint:gosec // G101: a credential definition id, not a credential.
	proofIssuer   = "did:indy:bcovrin:testnet:Ra8FGb2mXsTg1d4VqVnYpS"
	oobProofID    = "5e6f7a8b-9c0d-4e1f-8a2b-3c4d5e6f7a8b"
	connProofID   = "7a8b9c0d-1e2f-4a3b-9c4d-5e6f7a8b9c0d"
	holderConn    = "6e7f8a9b-0c1d-4e2f-9a3b-4c5d6e7f8a9b"
)

// anonCredsRequest is a proof request of the AnonCreds specification:
// the name of the holder, and the proof that the farm has at least 10
// acres without the number.
const anonCredsRequest = `{
  "name": "Farmer check",
  "version": "1.0",
  "requested_attributes": {
    "attr1": {"name": "fullName", "restrictions": [{"schema_id": "` + proofSchemaID + `", "cred_def_id": "` + proofCredDef + `"}]}
  },
  "requested_predicates": {
    "pred1": {"name": "acres", "p_type": ">=", "p_value": 10, "restrictions": [{"schema_id": "` + proofSchemaID + `"}]}
  }
}`

// peDefinition asks for the full name of a W3C JSON-LD credential of
// the type FarmerCredential.
const peDefinition = `{
  "id": "farmer-check",
  "name": "Farmer check",
  "purpose": "Check the farmer.",
  "input_descriptors": [{
    "id": "farmer",
    "constraints": {"fields": [
      {"path": ["$.type"], "filter": {"type": "array", "contains": {"const": "FarmerCredential"}}},
      {"path": ["$.credentialSubject.fullName"]}
    ]}
  }]
}`

// TestOobProofRequest is P6-C6: an AnonCreds proof request becomes an
// out of band invitation of the agent that carries the request. The
// request travels as the Indy proof format of the platform, and the
// state names the proof exchange.
func TestOobProofRequest(t *testing.T) {
	svc, f := newService(t, nil)
	resp, err := svc.CreateRequest(context.Background(), connect.NewRequest(&backendv1.CreateRequestRequest{
		AnoncredsRequest: anonCredsRequest,
	}))
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if !strings.Contains(resp.Msg.GetRequestUri(), "?oob=") || resp.Msg.GetState() != service.DidcommProofPrefix+oobProofID {
		t.Fatalf("request = %+v", resp.Msg)
	}
	path := "/v1/orgs/org-1/proofs/oob"
	if q := f.Query(path); q != "requestType=indy" {
		t.Errorf("query = %q", q)
	}
	var body struct {
		Protocol string `json:"protocolVersion"`
		Accept   string `json:"autoAcceptProof"`
		Shorten  *bool  `json:"isShortenUrl"`
		Reuse    bool   `json:"reuseConnection"`
		Formats  struct {
			Indy struct {
				Name       string                     `json:"name"`
				Version    string                     `json:"version"`
				Attributes map[string]json.RawMessage `json:"requested_attributes"`
				Predicates map[string]struct {
					Name  string `json:"name"`
					Type  string `json:"p_type"`
					Value int64  `json:"p_value"`
				} `json:"requested_predicates"`
			} `json:"indy"`
		} `json:"proofFormats"`
	}
	if err := f.RequestJSON(path, &body); err != nil {
		t.Fatal(err)
	}
	indy := body.Formats.Indy
	if body.Protocol != "v2" || body.Accept != "always" || body.Shorten == nil || *body.Shorten || !body.Reuse {
		t.Errorf("body = %+v", body)
	}
	if indy.Name != "Farmer check" || indy.Version != "1.0" || len(indy.Attributes) != 1 {
		t.Errorf("indy = %+v", indy)
	}
	if p := indy.Predicates["pred1"]; p.Name != "acres" || p.Type != ">=" || p.Value != 10 {
		t.Errorf("predicates = %+v", indy.Predicates)
	}
}

// TestPeProofRequestOverDidcomm: a DIF PE definition over DIDComm goes
// out as a request of the type presentationExchange. The platform needs
// the schema of each input descriptor, which the adapter reads from the
// type filter of the descriptor.
func TestPeProofRequestOverDidcomm(t *testing.T) {
	svc, f := newService(t, nil)
	resp, err := svc.CreateRequest(context.Background(), connect.NewRequest(&backendv1.CreateRequestRequest{
		Didcomm: true, PresentationDefinition: peDefinition,
	}))
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if resp.Msg.GetState() != service.DidcommProofPrefix+oobProofID {
		t.Errorf("state = %q", resp.Msg.GetState())
	}
	path := "/v1/orgs/org-1/proofs/oob"
	if q := f.Query(path); q != "requestType=presentationExchange" {
		t.Errorf("query = %q", q)
	}
	var body struct {
		Definition struct {
			ID          string `json:"id"`
			Descriptors []struct {
				ID     string `json:"id"`
				Schema []struct {
					URI string `json:"uri"`
				} `json:"schema"`
				Constraints struct {
					Fields []struct {
						Path []string `json:"path"`
					} `json:"fields"`
				} `json:"constraints"`
			} `json:"input_descriptors"`
		} `json:"presentationDefinition"`
	}
	if err := f.RequestJSON(path, &body); err != nil {
		t.Fatal(err)
	}
	d := body.Definition
	if d.ID != "farmer-check" || len(d.Descriptors) != 1 || len(d.Descriptors[0].Schema) != 1 ||
		d.Descriptors[0].Schema[0].URI != "FarmerCredential" || len(d.Descriptors[0].Constraints.Fields) != 2 {
		t.Errorf("definition = %+v", d)
	}
}

// TestConnectionProofRequest is P6-C6: with a connection the request
// goes over that connection in the attribute list of the platform, and
// no invitation comes back.
func TestConnectionProofRequest(t *testing.T) {
	svc, f := newService(t, nil)
	resp, err := svc.CreateRequest(context.Background(), connect.NewRequest(&backendv1.CreateRequestRequest{
		AnoncredsRequest: anonCredsRequest, ConnectionId: holderConn,
	}))
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if resp.Msg.GetRequestUri() != "" || resp.Msg.GetState() != service.DidcommProofPrefix+connProofID {
		t.Fatalf("request = %+v", resp.Msg)
	}
	path := "/v1/orgs/org-1/proofs"
	if q := f.Query(path); q != "requestType=indy" {
		t.Errorf("query = %q", q)
	}
	var body struct {
		Connection string `json:"connectionId"`
		Accept     string `json:"autoAcceptProof"`
		Formats    struct {
			Indy struct {
				Attributes []struct {
					Name      string `json:"attributeName"`
					Condition string `json:"condition"`
					Value     string `json:"value"`
					CredDef   string `json:"credDefId"`
					Schema    string `json:"schemaId"`
				} `json:"attributes"`
			} `json:"indy"`
		} `json:"proofFormats"`
	}
	if err := f.RequestJSON(path, &body); err != nil {
		t.Fatal(err)
	}
	a := body.Formats.Indy.Attributes
	if body.Connection != holderConn || body.Accept != "always" || len(a) != 2 {
		t.Fatalf("body = %+v", body)
	}
	if a[0].Name != "fullName" || a[0].CredDef != proofCredDef || a[0].Schema != proofSchemaID || a[0].Condition != "" {
		t.Errorf("attribute = %+v", a[0])
	}
	if a[1].Name != "acres" || a[1].Condition != ">=" || a[1].Value != "10" || a[1].Schema != proofSchemaID {
		t.Errorf("predicate = %+v", a[1])
	}
}

// TestConnectionProofRequestWithPe: a DIF PE request goes over a
// connection too.
func TestConnectionProofRequestWithPe(t *testing.T) {
	svc, f := newService(t, nil)
	if _, err := svc.CreateRequest(context.Background(), connect.NewRequest(&backendv1.CreateRequestRequest{
		Didcomm: true, PresentationDefinition: peDefinition, ConnectionId: holderConn,
	})); err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if q := f.Query("/v1/orgs/org-1/proofs"); q != "requestType=presentationExchange" {
		t.Errorf("query = %q", q)
	}
	var body struct {
		Connection string          `json:"connectionId"`
		Definition json.RawMessage `json:"presentationDefinition"`
	}
	if err := f.RequestJSON("/v1/orgs/org-1/proofs", &body); err != nil {
		t.Fatal(err)
	}
	if body.Connection != holderConn || !strings.Contains(string(body.Definition), `"uri":"FarmerCredential"`) {
		t.Errorf("body = %s", f.Request("/v1/orgs/org-1/proofs"))
	}
}

// TestProofRequestRefusesWhatItCannotAsk: a request needs an AnonCreds
// request or a PE definition, a PE descriptor needs a type, and an
// AnonCreds request must parse.
func TestProofRequestRefusesWhatItCannotAsk(t *testing.T) {
	svc, _ := newService(t, nil)
	for name, req := range map[string]*backendv1.CreateRequestRequest{
		"didcomm with no query":  {Didcomm: true},
		"bad anoncreds":          {AnoncredsRequest: "{"},
		"anoncreds asks nothing": {AnoncredsRequest: `{"name":"x","requested_attributes":{},"requested_predicates":{}}`},
		"bad predicate":          {AnoncredsRequest: `{"requested_predicates":{"p":{"name":"acres","p_type":"==","p_value":1}}}`},
		"attribute with no name": {AnoncredsRequest: `{"requested_attributes":{"a":{"restrictions":[]}}}`},
		"bad definition":         {Didcomm: true, PresentationDefinition: "["},
		"no descriptor":          {Didcomm: true, PresentationDefinition: `{"id":"x","input_descriptors":[]}`},
		"descriptor with no type": {Didcomm: true, PresentationDefinition: `{"id":"x","input_descriptors":[{"id":"a",` +
			`"constraints":{"fields":[{"path":["$.credentialSubject.fullName"]}]}}]}`},
	} {
		_, err := svc.CreateRequest(context.Background(), connect.NewRequest(req))
		if connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// getResult reads the result of one DIDComm proof request.
func getResult(t *testing.T, svc *service.Service, id string) *backendv1.GetResultResponse {
	t.Helper()
	resp, err := svc.GetResult(context.Background(), connect.NewRequest(&backendv1.GetResultRequest{State: service.DidcommProofPrefix + id}))
	if err != nil {
		t.Fatalf("GetResult: %v", err)
	}
	return resp.Msg
}

// TestProofResultVerified is P6-C6: a proof the agent verified reads as
// accepted, with the check of the stack and the revealed values: the
// name, and the predicate the holder proved without the number.
func TestProofResultVerified(t *testing.T) {
	svc, f := newService(t, nil)
	f.SetProof(fake.ProofDone)
	m := getResult(t, svc, oobProofID)
	if m.GetState() != backendv1.GetResultResponse_STATE_ACCEPTED || m.GetReceivedAt() == nil {
		t.Fatalf("result = %+v", m)
	}
	if len(m.GetDpgChecks()) != 1 || !m.GetDpgChecks()[0].GetPassed() || m.GetDpgChecks()[0].GetName() != service.ProofCheckName {
		t.Errorf("checks = %v", m.GetDpgChecks())
	}
	if len(m.GetPresented()) != 1 || m.GetPresented()[0].GetFormat() != commonv1.Format_FORMAT_ANONCREDS {
		t.Fatalf("presented = %v", m.GetPresented())
	}
	var view struct {
		Type    []string          `json:"type"`
		Issuer  string            `json:"issuer"`
		Schema  map[string]string `json:"credentialSchema"`
		CredDef string            `json:"credentialDefinitionId"`
		Subject map[string]string `json:"credentialSubject"`
		Context any               `json:"@context"`
	}
	if err := json.Unmarshal(m.GetPresented()[0].GetPayload(), &view); err != nil {
		t.Fatal(err)
	}
	if view.Subject["fullName"] != "[holder]" || view.Subject["acres"] != ">=10" || view.Schema["id"] != proofSchemaID ||
		view.CredDef != proofCredDef || view.Issuer != proofIssuer || !slices.Contains(view.Type, "Farmer") || view.Context != nil {
		t.Errorf("view = %+v", view)
	}
	for _, call := range f.Calls() {
		if strings.HasSuffix(call, "/verify") {
			t.Errorf("a done exchange needs no verify call: %v", f.Calls())
		}
	}
}

// TestProofResultOfPe: the revealed values of a DIF PE proof carry the
// schema of the descriptor and no credential definition.
func TestProofResultOfPe(t *testing.T) {
	svc, f := newService(t, nil)
	f.SetProof(fake.ProofDone)
	f.SetVerified(fake.VerifiedPE)
	m := getResult(t, svc, oobProofID)
	if len(m.GetPresented()) != 1 || m.GetPresented()[0].GetFormat() != commonv1.Format_FORMAT_UNSPECIFIED {
		t.Fatalf("presented = %v", m.GetPresented())
	}
	if p := string(m.GetPresented()[0].GetPayload()); !strings.Contains(p, `"fullName":"[holder]"`) || strings.Contains(p, "credentialDefinitionId") {
		t.Errorf("view = %s", p)
	}
}

// TestProofVerifiedAfterPresentation: a presentation that waits for the
// verifier gets the verify call of the platform, and then reads as
// accepted.
func TestProofVerifiedAfterPresentation(t *testing.T) {
	svc, f := newService(t, nil)
	f.SetProof(fake.ProofPresentationReceived)
	m := getResult(t, svc, connProofID)
	if m.GetState() != backendv1.GetResultResponse_STATE_ACCEPTED {
		t.Fatalf("result = %+v", m)
	}
	if !slices.Contains(f.Calls(), "POST /v1/orgs/org-1/proofs/"+connProofID+"/verify") {
		t.Errorf("calls = %v", f.Calls())
	}
}

// TestProofResultStates: no answer is pending, a proof that did not
// verify and a declined request read as rejected with no credential,
// and the reason of the agent reaches the checks.
func TestProofResultStates(t *testing.T) {
	svc, f := newService(t, nil)
	f.SetProof(fake.ProofRequestSent)
	if m := getResult(t, svc, oobProofID); m.GetState() != backendv1.GetResultResponse_STATE_PENDING || len(m.GetPresented()) != 0 {
		t.Errorf("pending = %+v", m)
	}
	for answer, reason := range map[fake.Answer]string{fake.ProofDoneUnverified: "not valid", fake.ProofAbandoned: "declined"} {
		f.SetProof(answer)
		m := getResult(t, svc, oobProofID)
		if m.GetState() != backendv1.GetResultResponse_STATE_REJECTED || len(m.GetPresented()) != 0 ||
			len(m.GetDpgChecks()) != 1 || m.GetDpgChecks()[0].GetPassed() || !strings.Contains(m.GetDpgChecks()[0].GetReason(), reason) {
			t.Errorf("%s: %+v", answer, m)
		}
	}
}

// TestProofResultNeedsAKnownState: a state with the prefix and no id is
// a bad request.
func TestProofResultNeedsAKnownState(t *testing.T) {
	svc, _ := newService(t, nil)
	_, err := svc.GetResult(context.Background(), connect.NewRequest(&backendv1.GetResultRequest{State: service.DidcommProofPrefix}))
	wantCode(t, err, connect.CodeInvalidArgument)
}

// TestListProofRequests is P6-C6: the proof requests of the
// organisation, with the label of the wallet, and an empty list when the
// platform knows none.
func TestListProofRequests(t *testing.T) {
	svc, f := newService(t, nil)
	resp, err := svc.ListProofRequests(context.Background(), connect.NewRequest(&backendv1.ListProofRequestsRequest{
		Page: &commonv1.Pagination{PageSize: 10},
	}))
	if err != nil {
		t.Fatalf("ListProofRequests: %v", err)
	}
	got := resp.Msg.GetRequests()
	if len(got) != 2 || resp.Msg.GetPage().GetTotalSize() != 2 {
		t.Fatalf("requests = %v", resp.Msg)
	}
	first := got[0]
	if first.GetId() != oobProofID || first.GetResultState() != service.DidcommProofPrefix+oobProofID ||
		first.GetConnectionLabel() != "[wallet one]" || first.GetState() != "done" || first.GetCreatedAt() == nil {
		t.Errorf("first = %v", first)
	}
	if !strings.Contains(got[1].GetError(), "declined") {
		t.Errorf("second = %v", got[1])
	}
	if q := f.Query("/v1/orgs/org-1/proofs"); !strings.Contains(q, "pageSize=10") || !strings.Contains(q, "pageNumber=1") {
		t.Errorf("query = %q", q)
	}
	f.SetProofs(fake.NoProofs)
	none, err := svc.ListProofRequests(context.Background(), connect.NewRequest(&backendv1.ListProofRequestsRequest{}))
	if err != nil || len(none.Msg.GetRequests()) != 0 {
		t.Errorf("none = %v, %v", none, err)
	}
	_, err = svc.ListProofRequests(context.Background(), connect.NewRequest(&backendv1.ListProofRequestsRequest{
		Page: &commonv1.Pagination{PageToken: "x"},
	}))
	wantCode(t, err, connect.CodeInvalidArgument)
}

// TestListProofSchemas is P6-C6: the AnonCreds schemas of the platform,
// with their attributes and the credential definitions of each.
func TestListProofSchemas(t *testing.T) {
	svc, f := newService(t, nil)
	resp, err := svc.ListProofSchemas(context.Background(), connect.NewRequest(&backendv1.ListProofSchemasRequest{}))
	if err != nil {
		t.Fatalf("ListProofSchemas: %v", err)
	}
	got := resp.Msg.GetSchemas()
	if len(got) != 1 {
		t.Fatalf("schemas = %v", resp.Msg)
	}
	s := got[0]
	if s.GetId() != proofSchemaID || s.GetName() != "Farmer" || s.GetVersion() != "1.0" ||
		!slices.Equal(s.GetAttributes(), []string{"fullName", "acres"}) || s.GetOrganisation() != "[organisation]" ||
		!slices.Equal(s.GetCredentialDefinitions(), []string{proofCredDef}) || s.GetIssuerDid() != proofIssuer {
		t.Errorf("schema = %v", s)
	}
	if q := f.Query("/v1/platform/schemas"); !strings.Contains(q, "schemaType=indy") {
		t.Errorf("query = %q", q)
	}
	f.SetPlatformSchemas(fake.NoPlatformSchemas)
	none, err := svc.ListProofSchemas(context.Background(), connect.NewRequest(&backendv1.ListProofSchemasRequest{}))
	if err != nil || len(none.Msg.GetSchemas()) != 0 {
		t.Errorf("none = %v, %v", none, err)
	}
}

// TestListVerifierConnections: the verifier reads the connections of the
// organisation, as the issuer does.
func TestListVerifierConnections(t *testing.T) {
	svc, _ := newService(t, nil)
	resp, err := svc.ListVerifierConnections(context.Background(), connect.NewRequest(&backendv1.ListVerifierConnectionsRequest{
		Page: &commonv1.Pagination{PageSize: 10},
	}))
	if err != nil {
		t.Fatalf("ListVerifierConnections: %v", err)
	}
	if len(resp.Msg.GetConnections()) != 2 || resp.Msg.GetPage().GetTotalSize() != 2 {
		t.Errorf("connections = %v", resp.Msg)
	}
}

// TestCapabilitiesListDidcommProofs is P6-C6: the answer names the
// DIDComm present proof protocol and the AnonCreds proof feature.
func TestCapabilitiesListDidcommProofs(t *testing.T) {
	svc, _ := newService(t, nil)
	resp, err := svc.GetCapabilities(context.Background(), connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(resp.Msg.GetProtocols(), backendv1.Protocol_PROTOCOL_DIDCOMM_PRESENT_V2) ||
		!slices.Contains(resp.Msg.GetFeatures(), backendv1.Feature_FEATURE_ANONCREDS_PROOF) {
		t.Errorf("protocols %v features %v", resp.Msg.GetProtocols(), resp.Msg.GetFeatures())
	}
}

// TestProofCallsReportAPlatformThatFails: each DIDComm proof call names
// the step that failed when the platform does not answer.
func TestProofCallsReportAPlatformThatFails(t *testing.T) {
	ctx := context.Background()
	id := service.DidcommProofPrefix + oobProofID
	for path, call := range map[string]func(*service.Service) error{
		"/v1/orgs/org-1/proofs/oob": func(s *service.Service) error {
			_, err := s.CreateRequest(ctx, connect.NewRequest(&backendv1.CreateRequestRequest{AnoncredsRequest: anonCredsRequest}))
			return err
		},
		"/v1/orgs/org-1/proofs": func(s *service.Service) error {
			_, err := s.CreateRequest(ctx, connect.NewRequest(&backendv1.CreateRequestRequest{AnoncredsRequest: anonCredsRequest, ConnectionId: holderConn}))
			return err
		},
		"/v1/orgs/org-1/proofs/" + oobProofID: func(s *service.Service) error {
			_, err := s.GetResult(ctx, connect.NewRequest(&backendv1.GetResultRequest{State: id}))
			return err
		},
		"/v1/orgs/org-1/verified-proofs/" + oobProofID: func(s *service.Service) error {
			_, err := s.GetResult(ctx, connect.NewRequest(&backendv1.GetResultRequest{State: id}))
			return err
		},
		"/v1/orgs/org-1/proofs/" + oobProofID + "/verify": func(s *service.Service) error {
			_, err := s.GetResult(ctx, connect.NewRequest(&backendv1.GetResultRequest{State: id}))
			return err
		},
		"/v1/platform/schemas": func(s *service.Service) error {
			_, err := s.ListProofSchemas(ctx, connect.NewRequest(&backendv1.ListProofSchemasRequest{}))
			return err
		},
		"/v1/platform/cred-defs": func(s *service.Service) error {
			_, err := s.ListProofSchemas(ctx, connect.NewRequest(&backendv1.ListProofSchemasRequest{}))
			return err
		},
		"/v1/orgs/org-1/connections": func(s *service.Service) error {
			_, err := s.ListVerifierConnections(ctx, connect.NewRequest(&backendv1.ListVerifierConnectionsRequest{}))
			return err
		},
	} {
		svc, f := newService(t, nil)
		f.SetProof(fake.ProofDone)
		if strings.HasSuffix(path, "/verify") {
			f.SetProof(fake.ProofPresentationReceived)
		}
		f.SetStatus(path, 502)
		if code := connect.CodeOf(call(svc)); code != connect.CodeUnavailable {
			t.Errorf("%s: code = %v", path, code)
		}
	}
	svc, f := newService(t, nil)
	f.SetStatus("/v1/orgs/org-1/proofs", 502)
	_, err := svc.ListProofRequests(ctx, connect.NewRequest(&backendv1.ListProofRequestsRequest{}))
	wantCode(t, err, connect.CodeUnavailable)
	_, err = svc.ListProofSchemas(ctx, connect.NewRequest(&backendv1.ListProofSchemasRequest{Page: &commonv1.Pagination{PageToken: "0"}}))
	wantCode(t, err, connect.CodeInvalidArgument)
}
