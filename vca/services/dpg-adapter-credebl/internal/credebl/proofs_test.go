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
	"testing"
)

// proofServer answers the proof calls of P6-C6 from the fixtures of
// testdata/doc, or from a body a test sets, and records each request.
type proofServer struct {
	srv     *httptest.Server
	bodies  map[string][]byte
	queries map[string]string
	answers map[string]string
	status  map[string]int
}

func newProofServer(t *testing.T) *proofServer {
	t.Helper()
	p := &proofServer{bodies: map[string][]byte{}, queries: map[string]string{}, answers: map[string]string{}, status: map[string]int{}}
	files := map[string]string{
		"POST /v1/orgs/org-1/proofs/oob":           "proof-oob-created.json",
		"POST /v1/orgs/org-1/proofs":               "proof-connection-created.json",
		"GET /v1/orgs/org-1/proofs":                "proofs.json",
		"GET /v1/orgs/org-1/proofs/p-1":            "proof-record-done.json",
		"POST /v1/orgs/org-1/proofs/p-1/verify":    "proof-verified.json",
		"GET /v1/orgs/org-1/verified-proofs/p-1":   "verified-proof-indy.json",
		"GET /v1/platform/schemas":                 "platform-schemas.json",
		"GET /v1/platform/cred-defs":               "platform-cred-defs.json",
		"GET /v1/orgs/org-1/verified-proofs/p-odd": "",
	}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/signin" {
			mustWrite(t, w, []byte(`{"data":{"access_token":"t"}}`))
			return
		}
		key := r.Method + " " + r.URL.Path
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read the body: %v", err)
		}
		p.bodies[key], p.queries[key] = raw, r.URL.RawQuery
		if code := p.status[key]; code != 0 {
			w.WriteHeader(code)
			return
		}
		if body, ok := p.answers[key]; ok {
			mustWrite(t, w, []byte(body))
			return
		}
		name, ok := files[key]
		if !ok || name == "" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "doc", name)) // #nosec G304 -- a fixed test path
		if err != nil {
			t.Fatal(err)
		}
		mustWrite(t, w, data)
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *proofServer) client() *Client { return newClient(p.srv, nil) }

// TestCreateOOBProofSendsTheIndyFormat is P6-C6: an AnonCreds request
// goes out as the Indy proof format of the platform, and the answer
// names the invitation and the proof exchange.
func TestCreateOOBProofSendsTheIndyFormat(t *testing.T) {
	p := newProofServer(t)
	got, err := p.client().CreateOOBProof(context.Background(), ProofRequest{
		Type: ProofTypeIndy, Indy: json.RawMessage(`{"name":"x","version":"1.0","requested_attributes":{},"requested_predicates":{}}`), Comment: "c",
	})
	if err != nil {
		t.Fatalf("CreateOOBProof: %v", err)
	}
	if !strings.Contains(got.InvitationURL, "?oob=") || got.RecordID != "5e6f7a8b-9c0d-4e1f-8a2b-3c4d5e6f7a8b" || got.ThreadID == "" {
		t.Errorf("proof = %+v", got)
	}
	key := "POST /v1/orgs/org-1/proofs/oob"
	if p.queries[key] != "requestType=indy" || !strings.Contains(string(p.bodies[key]), `"proofFormats":{"indy":{"name":"x"`) {
		t.Errorf("query %q body %s", p.queries[key], p.bodies[key])
	}
}

// TestSendConnectionProofSendsTheDefinition: a DIF PE request over a
// connection carries the definition and the connection.
func TestSendConnectionProofSendsTheDefinition(t *testing.T) {
	p := newProofServer(t)
	got, err := p.client().SendConnectionProof(context.Background(), "conn-1", ProofRequest{
		Type: ProofTypePE, Definition: json.RawMessage(`{"id":"d"}`),
	})
	if err != nil {
		t.Fatalf("SendConnectionProof: %v", err)
	}
	if got.ID != "7a8b9c0d-1e2f-4a3b-9c4d-5e6f7a8b9c0d" || got.State != "request-sent" {
		t.Errorf("record = %+v", got)
	}
	key := "POST /v1/orgs/org-1/proofs"
	body := string(p.bodies[key])
	if p.queries[key] != "requestType=presentationExchange" || !strings.Contains(body, `"connectionId":"conn-1"`) ||
		!strings.Contains(body, `"presentationDefinition":{"id":"d"}`) {
		t.Errorf("query %q body %s", p.queries[key], body)
	}
}

// TestProofCallsRefuseWhatThePlatformRefuses: an unknown type, a
// connection request with no connection, and answers with no record.
func TestProofCallsRefuseWhatThePlatformRefuses(t *testing.T) {
	p := newProofServer(t)
	c, ctx := p.client(), context.Background()
	if _, err := c.CreateOOBProof(ctx, ProofRequest{Type: "x"}); err == nil {
		t.Error("an unknown type went out")
	}
	if _, err := c.SendConnectionProof(ctx, "conn-1", ProofRequest{Type: "x"}); err == nil {
		t.Error("an unknown type went over the connection")
	}
	if _, err := c.SendConnectionProof(ctx, " ", ProofRequest{Type: ProofTypeIndy}); err == nil {
		t.Error("a request went over no connection")
	}
	p.answers["POST /v1/orgs/org-1/proofs/oob"] = `{"data":{}}`
	p.answers["POST /v1/orgs/org-1/proofs"] = `{"data":{}}`
	if _, err := c.CreateOOBProof(ctx, ProofRequest{Type: ProofTypeIndy}); err == nil {
		t.Error("an answer with no invitation passed")
	}
	if _, err := c.SendConnectionProof(ctx, "conn-1", ProofRequest{Type: ProofTypeIndy}); err == nil {
		t.Error("an answer with no record passed")
	}
	p.status["POST /v1/orgs/org-1/proofs/oob"] = http.StatusBadRequest
	p.status["POST /v1/orgs/org-1/proofs"] = http.StatusBadRequest
	if _, err := c.CreateOOBProof(ctx, ProofRequest{Type: ProofTypeIndy}); err == nil {
		t.Error("a refused request passed")
	}
	if _, err := c.SendConnectionProof(ctx, "conn-1", ProofRequest{Type: ProofTypeIndy}); err == nil {
		t.Error("a refused request passed")
	}
}

// TestProofRecordAndVerify: the record of an exchange, the verify call,
// and the revealed values of the proof.
func TestProofRecordAndVerify(t *testing.T) {
	p := newProofServer(t)
	c, ctx := p.client(), context.Background()
	rec, err := c.ProofRecord(ctx, "p-1")
	if err != nil || rec.State != ProofStateDone || rec.IsVerified == nil || !*rec.IsVerified || rec.UpdatedAt.IsZero() {
		t.Fatalf("record = %+v, %v", rec, err)
	}
	after, err := c.VerifyProof(ctx, "p-1")
	if err != nil || after.State != ProofStateDone {
		t.Fatalf("verify = %+v, %v", after, err)
	}
	values, err := c.VerifiedProof(ctx, "p-1")
	if err != nil || len(values) != 2 {
		t.Fatalf("values = %+v, %v", values, err)
	}
	if values[0].Name != "fullName" || values[0].Value != "[holder]" || values[0].CredDefID == "" || values[1].Value != ">=10" {
		t.Errorf("values = %+v", values)
	}
	if _, err := c.ProofRecord(ctx, "missing"); err == nil {
		t.Error("a missing record passed")
	}
	if _, err := c.VerifyProof(ctx, "missing"); err == nil {
		t.Error("a missing verify passed")
	}
	if _, err := c.VerifiedProof(ctx, "missing"); err == nil {
		t.Error("missing values passed")
	}
}

// TestVerifiedProofReadsEachValue: a number or an object keeps its JSON
// form, and an entry with no attribute is left out.
func TestVerifiedProofReadsEachValue(t *testing.T) {
	p := newProofServer(t)
	p.answers["GET /v1/orgs/org-1/verified-proofs/p-odd"] = `{"data":[{"acres":12,"schemaId":null},{"schemaId":"s"},{"land":{"a":1}}]}`
	values, err := p.client().VerifiedProof(context.Background(), "p-odd")
	if err != nil || len(values) != 2 {
		t.Fatalf("values = %+v, %v", values, err)
	}
	if values[0].Value != "12" || values[0].SchemaID != "" || values[1].Value != `{"a":1}` {
		t.Errorf("values = %+v", values)
	}
}

// TestProofListsReadNotFoundAsEmpty: the platform answers the status not
// found for an empty list, and another failure stays an error.
func TestProofListsReadNotFoundAsEmpty(t *testing.T) {
	p := newProofServer(t)
	c, ctx := p.client(), context.Background()
	list, total, err := c.ProofRequests(ctx, 1, 10)
	if err != nil || total != 2 || len(list) != 2 || list[0].Connection == nil || list[0].Connection.Label != "[wallet one]" {
		t.Fatalf("list = %+v %d %v", list, total, err)
	}
	if q := p.queries["GET /v1/orgs/org-1/proofs"]; !strings.Contains(q, "sortBy=desc") || !strings.Contains(q, "search=") {
		t.Errorf("query = %q", q)
	}
	schemas, n, err := c.PlatformSchemas(ctx, 1, 10)
	if err != nil || n != 1 || len(schemas) != 1 || len(schemas[0].Attributes) != 2 {
		t.Fatalf("schemas = %+v %d %v", schemas, n, err)
	}
	defs, err := c.PlatformCredDefs(ctx)
	if err != nil || len(defs[schemas[0].ID]) != 1 {
		t.Fatalf("definitions = %v, %v", defs, err)
	}
	for _, key := range []string{"GET /v1/orgs/org-1/proofs", "GET /v1/platform/schemas", "GET /v1/platform/cred-defs"} {
		p.status[key] = http.StatusNotFound
	}
	if list, _, err := c.ProofRequests(ctx, 1, 10); err != nil || len(list) != 0 {
		t.Errorf("no proofs = %v, %v", list, err)
	}
	if list, _, err := c.PlatformSchemas(ctx, 1, 10); err != nil || len(list) != 0 {
		t.Errorf("no schemas = %v, %v", list, err)
	}
	if defs, err := c.PlatformCredDefs(ctx); err != nil || len(defs) != 0 {
		t.Errorf("no definitions = %v, %v", defs, err)
	}
	for _, key := range []string{"GET /v1/orgs/org-1/proofs", "GET /v1/platform/schemas", "GET /v1/platform/cred-defs"} {
		p.status[key] = http.StatusBadGateway
	}
	if _, _, err := c.ProofRequests(ctx, 1, 10); err == nil {
		t.Error("a failed list passed")
	}
	if _, _, err := c.PlatformSchemas(ctx, 1, 10); err == nil {
		t.Error("a failed list passed")
	}
	if _, err := c.PlatformCredDefs(ctx); err == nil {
		t.Error("a failed list passed")
	}
}

// TestProofCallsNeedAPlatform: a client with no platform refuses every
// proof call.
func TestProofCallsNeedAPlatform(t *testing.T) {
	var c *Client
	ctx := context.Background()
	_, e1 := c.CreateOOBProof(ctx, ProofRequest{})
	_, e2 := c.SendConnectionProof(ctx, "c", ProofRequest{})
	_, e3 := c.ProofRecord(ctx, "p")
	_, e4 := c.VerifyProof(ctx, "p")
	_, e5 := c.VerifiedProof(ctx, "p")
	_, _, e6 := c.ProofRequests(ctx, 1, 1)
	_, _, e7 := c.PlatformSchemas(ctx, 1, 1)
	_, e8 := c.PlatformCredDefs(ctx)
	for i, err := range []error{e1, e2, e3, e4, e5, e6, e7, e8} {
		if !errors.Is(err, ErrNoPlatform) {
			t.Errorf("call %d: %v", i+1, err)
		}
	}
}
