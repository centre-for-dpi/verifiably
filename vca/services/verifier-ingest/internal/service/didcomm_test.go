// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	discoveryv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1"
	ingestv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/ingest/v1"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/service"
)

// P6-C6: a request through a stack that asks over DIDComm (ADR-061
// decision 5).

// didcommStack reads DCQL over OID4VP, and AnonCreds and PE over DIDComm.
var didcommStack = service.Stack{Pair: "verifier-credebl", Name: "CREDEBL", Adapter: "http://credebl",
	Protocols: []backendv1.Protocol{backendv1.Protocol_PROTOCOL_OID4VP_DCQL, backendv1.Protocol_PROTOCOL_DIDCOMM_PRESENT_V2},
	Features:  []backendv1.Feature{backendv1.Feature_FEATURE_ANONCREDS_PROOF}}

// anonTemplate reveals the name of a farmer and proves at least 10 acres.
func anonTemplate() *discoveryv1.PresentationTemplate {
	restriction := &discoveryv1.AnonCredsRequest_Restriction{SchemaId: "did:indy:bcovrin:testnet:Ra8F/anoncreds/v0/SCHEMA/Farmer/1.0"}
	return &discoveryv1.PresentationTemplate{Id: "farmer-check", Version: 1, Kind: discoveryv1.TemplateKind_TEMPLATE_KIND_NATIVE,
		PolicySetId: "query-farmer-check",
		Anoncreds: &discoveryv1.AnonCredsRequest{Name: "Farmer check", Version: "1.0",
			Attributes: []*discoveryv1.AnonCredsRequest_Attribute{{Names: []string{"fullName"}, Restriction: restriction}},
			Predicates: []*discoveryv1.AnonCredsRequest_Predicate{{Name: "acres", Op: ">=", Value: 10, Restriction: restriction}}}}
}

// didcommService wires the service with the DIDComm stack and a DCQL
// stack without DIDComm.
func didcommService(t *testing.T, tpl *discoveryv1.PresentationTemplate, a *adapter, res service.ResultStore) *service.Service {
	t.Helper()
	svc, _ := build(t, service.Options{
		Discovery: templateOf{t: tpl}, Policy: &evaluator{}, Results: res, RequestTTL: time.Minute,
		Stacks: func(context.Context) []service.Stack {
			return []service.Stack{didcommStack, {Pair: "verifier-waltid", Name: "walt.id", Adapter: "http://waltid",
				Protocols: []backendv1.Protocol{backendv1.Protocol_PROTOCOL_OID4VP_DCQL}}}
		},
		StackClient: func(string) service.StackVerifier { return a },
	})
	return svc
}

// TestDidcommQueryFor is ADR-061 decision 5: a stack that speaks
// DIDComm present proof reads an AnonCreds template when it lists
// FEATURE_ANONCREDS_PROOF, a PE template, and a DCQL template whose PE
// form loses nothing.
func TestDidcommQueryFor(t *testing.T) {
	pe, anon, ok := service.DidcommQueryFor(anonTemplate(), didcommStack)
	if !ok || pe != "" || !strings.Contains(anon, `"requested_predicates"`) || !strings.Contains(anon, `"p_value":10`) {
		t.Errorf("anoncreds: %q %q %v", pe, anon, ok)
	}
	if pe, anon, ok = service.DidcommQueryFor(licenceTemplate(), didcommStack); !ok || anon != "" || !strings.Contains(pe, `"input_descriptors"`) {
		t.Errorf("dcql: %q %q %v", pe, anon, ok)
	}
	stored := &discoveryv1.PresentationTemplate{Kind: discoveryv1.TemplateKind_TEMPLATE_KIND_PE, PresentationDefinition: `{"id":"x"}`}
	if pe, _, ok = service.DidcommQueryFor(stored, didcommStack); !ok || pe != `{"id":"x"}` {
		t.Errorf("pe: %q %v", pe, ok)
	}
	noFeature := didcommStack
	noFeature.Features = nil
	if _, _, ok = service.DidcommQueryFor(anonTemplate(), noFeature); ok {
		t.Error("a stack without AnonCreds proofs reads an AnonCreds template")
	}
	if _, _, ok = service.DidcommQueryFor(licenceTemplate(), dcqlStack); ok {
		t.Error("a stack without DIDComm reads a DIDComm request")
	}
	if _, _, ok = service.DidcommQueryFor(&discoveryv1.PresentationTemplate{Dcql: "{"}, didcommStack); ok {
		t.Error("a bad DCQL query has a PE form")
	}
	if !didcommStack.Didcomm() || !didcommStack.AnonCreds() || dcqlStack.Didcomm() {
		t.Error("the stack helpers")
	}
	if d, p, ok := service.QueryFor(anonTemplate(), didcommStack.Protocols); ok || d != "" || p != "" {
		t.Error("an AnonCreds template has an OID4VP form")
	}
}

// TestAnonCredsRequestGoesOverDidcomm: an AnonCreds template goes to the
// stack as a DIDComm request with the proof request of the
// specification, and the transaction says so.
func TestAnonCredsRequestGoesOverDidcomm(t *testing.T) {
	ctx := context.Background()
	a := &adapter{}
	svc := didcommService(t, anonTemplate(), a, &keeper{})
	created, err := svc.CreateOid4VpRequest(ctx, connect.NewRequest(&ingestv1.CreateOid4VpRequestRequest{
		TemplateId: "farmer-check", Stack: "verifier-credebl",
	}))
	if err != nil {
		t.Fatalf("CreateOid4VpRequest: %v", err)
	}
	if len(a.created) != 1 || !a.created[0].GetDidcomm() || !strings.Contains(a.created[0].GetAnoncredsRequest(), `"acres"`) ||
		a.created[0].GetDcql() != "" || a.created[0].GetPresentationDefinition() != "" {
		t.Fatalf("sent %+v", a.created)
	}
	got, err := svc.GetTransaction(ctx, connect.NewRequest(&ingestv1.GetTransactionRequest{TransactionId: created.Msg.GetTransactionId()}))
	if err != nil || !got.Msg.GetDidcomm() || got.Msg.GetRequestUri() == "" {
		t.Fatalf("transaction %+v, %v", got, err)
	}
	list, err := svc.ListTransactions(ctx, connect.NewRequest(&ingestv1.ListTransactionsRequest{}))
	if err != nil || len(list.Msg.GetTransactions()) != 1 || !list.Msg.GetTransactions()[0].GetDidcomm() {
		t.Errorf("list %+v, %v", list, err)
	}
}

// TestDidcommRequestOverAConnection: a DCQL template goes to a connected
// wallet as a DIF PE request over DIDComm.
func TestDidcommRequestOverAConnection(t *testing.T) {
	ctx := context.Background()
	a := &adapter{}
	svc := didcommService(t, licenceTemplate(), a, &keeper{})
	created, err := svc.CreateOid4VpRequest(ctx, connect.NewRequest(&ingestv1.CreateOid4VpRequestRequest{
		TemplateId: "pid", Stack: "verifier-credebl", Didcomm: true, ConnectionId: "conn-1",
	}))
	if err != nil {
		t.Fatalf("CreateOid4VpRequest: %v", err)
	}
	sent := a.created[0]
	if !sent.GetDidcomm() || sent.GetConnectionId() != "conn-1" || !strings.Contains(sent.GetPresentationDefinition(), `"input_descriptors"`) || sent.GetDcql() != "" {
		t.Fatalf("sent %+v", sent)
	}
	got, err := svc.GetTransaction(ctx, connect.NewRequest(&ingestv1.GetTransactionRequest{TransactionId: created.Msg.GetTransactionId()}))
	if err != nil || got.Msg.GetConnectionId() != "conn-1" || !got.Msg.GetDidcomm() {
		t.Errorf("transaction %+v, %v", got, err)
	}
}

// TestDidcommRequestRefusals: an AnonCreds template needs a DIDComm
// stack, a connection needs DIDComm, and DIDComm has no Digital
// Credentials API request.
func TestDidcommRequestRefusals(t *testing.T) {
	ctx := context.Background()
	for name, c := range map[string]struct {
		tpl  *discoveryv1.PresentationTemplate
		req  *ingestv1.CreateOid4VpRequestRequest
		code connect.Code
	}{
		"anoncreds through vca":     {anonTemplate(), &ingestv1.CreateOid4VpRequestRequest{TemplateId: "farmer-check"}, connect.CodeFailedPrecondition},
		"anoncreds over oid4vp":     {anonTemplate(), &ingestv1.CreateOid4VpRequestRequest{TemplateId: "farmer-check", Stack: "verifier-waltid"}, connect.CodeFailedPrecondition},
		"didcomm on an oid4vp only": {licenceTemplate(), &ingestv1.CreateOid4VpRequestRequest{TemplateId: "pid", Stack: "verifier-waltid", Didcomm: true}, connect.CodeFailedPrecondition},
		"connection without didcomm": {licenceTemplate(), &ingestv1.CreateOid4VpRequestRequest{TemplateId: "pid", Stack: "verifier-credebl",
			ConnectionId: "conn-1"}, connect.CodeInvalidArgument},
		"didcomm with dc api": {licenceTemplate(), &ingestv1.CreateOid4VpRequestRequest{TemplateId: "pid", Stack: "verifier-credebl",
			Didcomm: true, DcApi: true}, connect.CodeFailedPrecondition},
	} {
		svc := didcommService(t, c.tpl, &adapter{}, &keeper{})
		_, err := svc.CreateOid4VpRequest(ctx, connect.NewRequest(c.req))
		if connect.CodeOf(err) != c.code {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestDidcommAnswerIsStoredWithItsCarrier: the revealed values of a
// proof that the stack checked go to the policy service with the
// AnonCreds format, and the result names the carrier didcomm.
func TestDidcommAnswerIsStoredWithItsCarrier(t *testing.T) {
	ctx := context.Background()
	view := `{"type":["Farmer"],"issuer":"did:indy:bcovrin:testnet:Ra8F","credentialSubject":{"fullName":"[holder]","acres":">=10"}}`
	a := &adapter{answer: &backendv1.GetResultResponse{State: backendv1.GetResultResponse_STATE_ACCEPTED,
		Presented: []*commonv1.Credential{{Format: commonv1.Format_FORMAT_ANONCREDS, Payload: []byte(view)}},
		DpgChecks: []*backendv1.GetResultResponse_DpgCheck{{Name: "credebl-proof-verified", Passed: true}}}}
	res := &keeper{}
	svc := didcommService(t, anonTemplate(), a, res)
	created, err := svc.CreateOid4VpRequest(ctx, connect.NewRequest(&ingestv1.CreateOid4VpRequestRequest{
		TemplateId: "farmer-check", Stack: "verifier-credebl",
	}))
	if err != nil {
		t.Fatal(err)
	}
	got, err := svc.GetTransaction(ctx, connect.NewRequest(&ingestv1.GetTransactionRequest{TransactionId: created.Msg.GetTransactionId()}))
	if err != nil || got.Msg.GetResultId() != "res-7" {
		t.Fatalf("transaction %+v, %v", got, err)
	}
	creds := got.Msg.GetPresentation().GetCredentials()
	if len(creds) != 1 || creds[0].GetFormat() != commonv1.Format_FORMAT_ANONCREDS {
		t.Errorf("credentials %+v", creds)
	}
	if res.kept.GetCarrier() != service.DidcommCarrierName || len(res.kept.GetCredentials()) != 1 ||
		res.kept.GetCredentials()[0].GetDisplayFields()["acres"] != ">=10" || res.kept.GetStack() != "CREDEBL" {
		t.Errorf("kept %+v", res.kept)
	}
	if service.ProtoFormat("anoncreds") != commonv1.Format_FORMAT_ANONCREDS {
		t.Error("the AnonCreds format word")
	}
}
