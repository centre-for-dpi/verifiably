// SPDX-License-Identifier: Apache-2.0

package credebl

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/internal/dpgclient"
)

// P6-C7: the holder calls of the shared agent (ADR-062).

const (
	testTenant = "5f3c6a1e-8b2d-4c7a-9e1f-2a3b4c5d6e7f"
	testAPIKey = "agent-api-key" //nolint:gosec // G101: the key of the test server, not a credential.
)

// agentServer answers the agent calls from the fixtures of testdata/doc
// and records each request.
type agentServer struct {
	srv *httptest.Server

	mu      sync.Mutex
	bodies  map[string][]byte
	queries map[string]string
	auth    map[string]string
	status  map[string][]int
	answers map[string]string
}

func newAgentServer(t *testing.T) *agentServer {
	t.Helper()
	a := &agentServer{bodies: map[string][]byte{}, queries: map[string]string{}, auth: map[string]string{},
		status: map[string][]int{}, answers: map[string]string{}}
	files := map[string]string{
		"POST /agent/token":                                             "agent-token.json",
		"POST /multi-tenancy/create-tenant":                             "agent-tenant-created.json",
		"POST /multi-tenancy/get-token/" + testTenant:                   "agent-tenant-token.json",
		"POST /dids/write":                                              "agent-did-created.json",
		"GET /dids":                                                     "agent-dids.json",
		"POST /didcomm/oob/receive-invitation-url":                      "agent-oob-received-offer.json",
		"GET /didcomm/credentials":                                      "agent-credentials-offer-received.json",
		"GET /didcomm/credentials/c-1":                                  "agent-credential-done.json",
		"POST /didcomm/credentials/accept-offer":                        "agent-credential-request-sent.json",
		"GET /didcomm/credentials/c-1/form-data":                        "agent-credential-form-data.json",
		"GET /didcomm/credentials/w3c":                                  "agent-w3c-credentials.json",
		"DELETE /openid4vc/holder/credential":                           "",
		"GET /didcomm/proofs":                                           "agent-proofs-request-received.json",
		"GET /didcomm/proofs/p-1":                                       "agent-proof-done.json",
		"POST /didcomm/proofs/p-1/accept-request":                       "agent-proof-presentation-sent.json",
		"GET /didcomm/proofs/p-1/form-data":                             "agent-proof-form-data.json",
		"GET /didcomm/connections":                                      "agent-connections.json",
		"GET /didcomm/connections/8a9b0c1d-2e3f-4a5b-9c6d-7e8f9a0b1c2d": "",
	}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Method + " " + r.URL.Path
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read the body: %v", err)
		}
		a.mu.Lock()
		a.bodies[key], a.queries[key], a.auth[key] = raw, r.URL.RawQuery, r.Header.Get("Authorization")
		var code int
		if list := a.status[key]; len(list) > 0 {
			code, a.status[key] = list[0], list[1:]
		}
		body, set := a.answers[key]
		a.mu.Unlock()
		if code != 0 {
			w.WriteHeader(code)
			return
		}
		if set {
			mustWrite(t, w, []byte(body))
			return
		}
		name, ok := files[key]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if name == "" {
			mustWrite(t, w, []byte("{}"))
			return
		}
		data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "doc", name)) //nolint:gosec // G304: a fixed fixture name
		if err != nil {
			t.Errorf("read %s: %v", name, err)
		}
		mustWrite(t, w, data)
	}))
	t.Cleanup(a.srv.Close)
	return a
}

// agent returns a client of the server.
func (a *agentServer) agent() *Agent {
	return NewAgent(AgentOptions{
		HTTP:   dpgclient.New(dpgclient.Options{BaseURL: a.srv.URL, HTTP: a.srv.Client(), Retries: -1, Sleep: func(time.Duration) {}}),
		APIKey: testAPIKey,
	})
}

// fail makes the server answer the call with the statuses in order.
func (a *agentServer) fail(key string, codes ...int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.status[key] = codes
}

// answer makes the server answer the call with the body.
func (a *agentServer) answer(key, body string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.answers[key] = body
}

// forget drops the body that answer set.
func (a *agentServer) forget(key string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.answers, key)
}

// seen returns what the server recorded for a call.
func (a *agentServer) seen(key string) (body []byte, query, auth string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.bodies[key], a.queries[key], a.auth[key]
}

// TestNewAgentNeedsAddressAndKey: without the address or the API key
// of the agent the adapter has no agent, so it serves no holder role.
func TestNewAgentNeedsAddressAndKey(t *testing.T) {
	if NewAgent(AgentOptions{APIKey: testAPIKey}) != nil {
		t.Error("an agent with no address")
	}
	if NewAgent(AgentOptions{HTTP: dpgclient.New(dpgclient.Options{BaseURL: "http://agent"})}) != nil {
		t.Error("an agent with no API key")
	}
}

// TestAgentTenantAndTokens: the API key buys the token of the base
// wallet, which makes a tenant. A later call asks for the token of the
// tenant with the base token, and a refused token is asked for again.
func TestAgentTenantAndTokens(t *testing.T) {
	a := newAgentServer(t)
	ctx := context.Background()
	agent := a.agent()
	id, err := agent.CreateTenant(ctx, "[holder wallet]")
	if err != nil || id != testTenant {
		t.Fatalf("CreateTenant = %q, %v", id, err)
	}
	body, _, auth := a.seen("POST /multi-tenancy/create-tenant")
	if auth != "Bearer [base wallet token]" || !strings.Contains(string(body), `"config":{"label":"[holder wallet]"}`) {
		t.Errorf("create-tenant: %s %s", auth, body)
	}
	if _, _, auth = a.seen("POST /agent/token"); auth != testAPIKey {
		t.Errorf("the token call sent %q, want the bare API key", auth)
	}
	// The tenant token of the create answer serves the first call.
	did, err := agent.CreateDidKey(ctx, testTenant)
	if err != nil || did != "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK" {
		t.Fatalf("CreateDidKey = %q, %v", did, err)
	}
	body, _, auth = a.seen("POST /dids/write")
	if auth != "Bearer [tenant token]" || string(body) != `{"keyType":"ed25519","method":"key"}` {
		t.Errorf("dids/write: %s %s", auth, body)
	}
	if _, _, got := a.seen("POST /multi-tenancy/get-token/" + testTenant); got != "" {
		t.Error("the adapter asked for a token it held")
	}
	// A new client asks for the tenant token, and asks again after a 401.
	fresh := a.agent()
	a.fail("GET /dids", http.StatusUnauthorized)
	dids, err := fresh.Dids(ctx, testTenant)
	if err != nil || len(dids) != 2 || dids[0].Did != did || dids[0].CreatedAt.IsZero() || len(dids[0].Keys) != 1 {
		t.Fatalf("Dids = %+v, %v", dids, err)
	}
	if _, _, got := a.seen("POST /multi-tenancy/get-token/" + testTenant); got != "Bearer [base wallet token]" {
		t.Errorf("get-token sent %q", got)
	}
	a.fail("GET /dids", http.StatusUnauthorized, http.StatusUnauthorized)
	if _, err = fresh.Dids(ctx, testTenant); !dpgclient.IsStatus(err, http.StatusUnauthorized) {
		t.Errorf("a second refusal: %v", err)
	}
}

// TestAgentTokenFailures: a refused API key or a token answer with no
// token stops the call.
func TestAgentTokenFailures(t *testing.T) {
	a := newAgentServer(t)
	ctx := context.Background()
	a.fail("POST /agent/token", http.StatusUnauthorized)
	if _, err := a.agent().CreateTenant(ctx, "x"); err == nil {
		t.Error("a refused API key")
	}
	a.answer("POST /agent/token", `{}`)
	if _, err := a.agent().CreateTenant(ctx, "x"); err == nil {
		t.Error("a token answer with no token")
	}
	a.forget("POST /agent/token")
	a.answer("POST /multi-tenancy/get-token/"+testTenant, `{}`)
	if _, err := a.agent().Dids(ctx, testTenant); err == nil {
		t.Error("a tenant token answer with no token")
	}
	a.answer("POST /multi-tenancy/create-tenant", `{"token":"t"}`)
	if _, err := a.agent().CreateTenant(ctx, "x"); err == nil {
		t.Error("a tenant with no id")
	}
	a.answer("POST /dids/write", `{}`)
	if _, err := a.agent().CreateDidKey(ctx, "t-2"); err == nil {
		t.Error("a DID answer with no DID")
	}
	a.fail("POST /multi-tenancy/get-token/t-3", http.StatusNotFound)
	if _, err := a.agent().Dids(ctx, "t-3"); err == nil {
		t.Error("an unknown tenant")
	}
}

// TestAgentReceivesAnInvitation: the agent takes the invitation URL
// and the label of the wallet. The answer names the message it carries
// and its thread.
func TestAgentReceivesAnInvitation(t *testing.T) {
	a := newAgentServer(t)
	ctx := context.Background()
	got, err := a.agent().ReceiveInvitation(ctx, testTenant, "http://agent?oob=abc", "[holder wallet]")
	if err != nil {
		t.Fatal(err)
	}
	body, _, _ := a.seen("POST /didcomm/oob/receive-invitation-url")
	var sent map[string]any
	if err := json.Unmarshal(body, &sent); err != nil || sent["invitationUrl"] != "http://agent?oob=abc" || sent["label"] != "[holder wallet]" ||
		sent["reuseConnection"] != true || sent["autoAcceptConnection"] != true || sent["autoAcceptInvitation"] != true {
		t.Errorf("sent %s", body)
	}
	msgs := got.Attached()
	if len(msgs) != 1 || !msgs[0].IsOffer() || msgs[0].IsProofRequest() || msgs[0].ThreadID != "9c8d7e6f-5a4b-4c3d-9e2f-1a0b9c8d7e6f" {
		t.Fatalf("attached %+v", msgs)
	}
	if got.Connection == nil || got.Connection.TheirLabel != "[issuer organisation]" || got.Label() != "[issuer organisation]" {
		t.Errorf("connection %+v", got.Connection)
	}
}

// TestAttachedMessages reads the messages of an invitation: base64 or
// JSON data, a thread of its own or of the message id, and nothing from
// an attachment it cannot read.
func TestAttachedMessages(t *testing.T) {
	inv := `{"label":"L","requests~attach":[
		{"data":{"json":{"@type":"https://didcomm.org/present-proof/2.0/request-presentation","@id":"m-1","~thread":{"thid":"t-9"}}}},
		{"data":{"base64":"%%%"}},
		{"data":{"base64":"bm90IGpzb24="}},
		{"data":{}}]}`
	r := Received{}
	r.OutOfBand.Invitation = json.RawMessage(inv)
	msgs := r.Attached()
	if len(msgs) != 1 || !msgs[0].IsProofRequest() || msgs[0].ThreadID != "t-9" || r.Label() != "L" {
		t.Errorf("attached %+v", msgs)
	}
	r.OutOfBand.Invitation = json.RawMessage(`[`)
	if len(r.Attached()) != 0 || r.Label() != "" {
		t.Error("a bad invitation")
	}
}

// TestAgentCredentialCalls: the list asks for the holder records of a
// thread or a state, the accept names the record, and the form data
// and the W3C list read as the agent writes them.
func TestAgentCredentialCalls(t *testing.T) {
	a := newAgentServer(t)
	ctx := context.Background()
	agent := a.agent()
	list, err := agent.Credentials(ctx, testTenant, CredentialQuery{ThreadID: "th-1", State: "offer-received"})
	if err != nil || len(list) != 1 || list[0].State != "offer-received" || len(list[0].Attributes) != 2 {
		t.Fatalf("Credentials = %+v, %v", list, err)
	}
	if _, q, _ := a.seen("GET /didcomm/credentials"); q != "role=holder&state=offer-received&threadId=th-1" {
		t.Errorf("query %q", q)
	}
	one, err := agent.Credential(ctx, testTenant, "c-1")
	if err != nil || one.State != "done" || one.AnonCreds() == nil || one.AnonCreds().CredDefID == "" || one.RecordOf("anoncreds") == "" ||
		one.RecordOf("w3c") != "" || one.UpdatedAt.IsZero() {
		t.Fatalf("Credential = %+v, %v", one, err)
	}
	if _, err = agent.AcceptOffer(ctx, testTenant, "c-1"); err != nil {
		t.Fatal(err)
	}
	if body, _, _ := a.seen("POST /didcomm/credentials/accept-offer"); string(body) != `{"credentialExchangeRecordId":"c-1"}` {
		t.Errorf("accept-offer %s", body)
	}
	form, err := agent.CredentialFormData(ctx, testTenant, "c-1")
	if err != nil || len(form.OfferAttributes) != 2 || form.Offer.AnonCreds == nil || form.Offer.AnonCreds.SchemaID == "" {
		t.Fatalf("form %+v, %v", form, err)
	}
	w3c, err := agent.W3cCredentials(ctx, testTenant)
	if err != nil || len(w3c) != 1 || !strings.Contains(string(w3c[0].Credential()), `"PermanentResidentCard"`) {
		t.Fatalf("w3c %+v, %v", w3c, err)
	}
	legacy := AgentW3c{Legacy: json.RawMessage(`{"a":1}`)}
	if string(legacy.Credential()) != `{"a":1}` {
		t.Error("the credential of a record from before 0.6")
	}
	if err = agent.DeleteW3c(ctx, testTenant, "w-1"); err != nil {
		t.Fatal(err)
	}
	if body, _, _ := a.seen("DELETE /openid4vc/holder/credential"); string(body) != `{"credentialId":"w-1","credentialType":"w3c-vc"}` {
		t.Errorf("delete %s", body)
	}
}

// TestAgentProofAndConnectionCalls: the proof list asks for a thread,
// the accept names the record, and the request reads as plain text.
func TestAgentProofAndConnectionCalls(t *testing.T) {
	a := newAgentServer(t)
	ctx := context.Background()
	agent := a.agent()
	list, err := agent.Proofs(ctx, testTenant, "th-2")
	if err != nil || len(list) != 1 || list[0].State != "request-received" {
		t.Fatalf("Proofs = %+v, %v", list, err)
	}
	if _, q, _ := a.seen("GET /didcomm/proofs"); q != "threadId=th-2" {
		t.Errorf("query %q", q)
	}
	if _, err = agent.Proofs(ctx, testTenant, ""); err != nil {
		t.Fatal(err)
	}
	if _, q, _ := a.seen("GET /didcomm/proofs"); q != "" {
		t.Errorf("query %q", q)
	}
	if one, perr := agent.Proof(ctx, testTenant, "p-1"); perr != nil || one.State != "done" {
		t.Fatalf("Proof = %+v, %v", one, perr)
	}
	if _, err = agent.AcceptProofRequest(ctx, testTenant, "p-1"); err != nil {
		t.Fatal(err)
	}
	if body, _, _ := a.seen("POST /didcomm/proofs/p-1/accept-request"); string(body) != `{}` {
		t.Errorf("accept-request %s", body)
	}
	form, err := agent.ProofFormData(ctx, testTenant, "p-1")
	if err != nil {
		t.Fatal(err)
	}
	if name, asked := form.Asked(); name != "Farmer check" || strings.Join(asked, "|") != "fullName|acres >= 10" {
		t.Errorf("asked %q %v", name, asked)
	}
	conns, err := agent.Connections(ctx, testTenant)
	if err != nil || len(conns) != 2 || conns[0].TheirLabel != "[issuer organisation]" || conns[0].State != "completed" {
		t.Fatalf("Connections = %+v, %v", conns, err)
	}
	a.answer("GET /didcomm/connections/8a9b0c1d-2e3f-4a5b-9c6d-7e8f9a0b1c2d", `{"id":"8a9b0c1d-2e3f-4a5b-9c6d-7e8f9a0b1c2d","state":"completed"}`)
	if c, cerr := agent.Connection(ctx, testTenant, "8a9b0c1d-2e3f-4a5b-9c6d-7e8f9a0b1c2d"); cerr != nil || c.State != "completed" {
		t.Errorf("Connection = %+v, %v", c, cerr)
	}
}

// TestProofFormDataAsked reads each form of a proof request: AnonCreds,
// the legacy Indy form, a group of names, and DIF PE.
func TestProofFormDataAsked(t *testing.T) {
	var indy ProofFormData
	if err := json.Unmarshal([]byte(`{"request":{"indy":{"name":"n","requested_attributes":{"b":{"names":["x","y"]},"a":{"name":"w"}},
		"requested_predicates":{"p":{"name":"age","p_type":">","p_value":17}}}}}`), &indy); err != nil {
		t.Fatal(err)
	}
	if name, asked := indy.Asked(); name != "n" || strings.Join(asked, "|") != "w|x|y|age > 17" {
		t.Errorf("indy %q %v", name, asked)
	}
	var pe ProofFormData
	if err := json.Unmarshal([]byte(`{"request":{"presentationExchange":{"presentation_definition":{"name":"Licence","input_descriptors":[
		{"id":"d1","constraints":{"fields":[{"path":["$.credentialSubject.licenceNumber"]},{"path":["$.vc.type"]}]}},
		{"id":"d2","name":"Photo"}]}}}}`), &pe); err != nil {
		t.Fatal(err)
	}
	if name, asked := pe.Asked(); name != "Licence" || strings.Join(asked, "|") != "licenceNumber|type|Photo" {
		t.Errorf("pe %q %v", name, asked)
	}
	var none ProofFormData
	if name, asked := none.Asked(); name != "" || asked != nil {
		t.Errorf("none %q %v", name, asked)
	}
}

// TestAgentCallsReportFailures: a call the agent refuses returns the
// status.
func TestAgentCallsReportFailures(t *testing.T) {
	a := newAgentServer(t)
	ctx := context.Background()
	agent := a.agent()
	for key, call := range map[string]func() error{
		"GET /didcomm/credentials": func() error { _, err := agent.Credentials(ctx, testTenant, CredentialQuery{}); return err },
		"POST /didcomm/oob/receive-invitation-url": func() error {
			_, err := agent.ReceiveInvitation(ctx, testTenant, "u", "l")
			return err
		},
		"GET /didcomm/proofs":      func() error { _, err := agent.Proofs(ctx, testTenant, ""); return err },
		"GET /didcomm/connections": func() error { _, err := agent.Connections(ctx, testTenant); return err },
	} {
		a.fail(key, http.StatusBadRequest)
		if err := call(); !dpgclient.IsStatus(err, http.StatusBadRequest) {
			t.Errorf("%s: %v", key, err)
		}
	}
	var nilAgent *Agent
	if _, err := nilAgent.Dids(ctx, testTenant); !errors.Is(err, ErrNoAgent) {
		t.Errorf("a nil agent: %v", err)
	}
}
