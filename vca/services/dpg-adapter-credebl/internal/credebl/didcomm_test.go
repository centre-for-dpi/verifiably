// SPDX-License-Identifier: Apache-2.0

package credebl

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// didcommServer answers the DIDComm issuance calls of the api gateway
// from the fixtures of testdata/doc and records each request.
type didcommServer struct {
	t       *testing.T
	srv     *httptest.Server
	paths   []string
	queries []string
	bodies  map[string]map[string]any
	status  map[string]int
}

func newDidcommServer(t *testing.T) *didcommServer {
	t.Helper()
	d := &didcommServer{t: t, bodies: map[string]map[string]any{}, status: map[string]int{}}
	files := map[string]string{
		"/v1/orgs/org-1/credentials/oob/offer":  "oob-offer-created.json",
		"/v1/orgs/org-1/credentials/offer":      "connection-offer-created.json",
		"/v1/orgs/org-1/credentials/oob/email":  "oob-email-sent.json",
		"/v1/orgs/org-1/connections":            "connections.json",
		"/v1/orgs/org-1/credentials/rec-done":   "credential-record-done.json",
		"/v1/orgs/org-1/credentials/rec-sent":   "credential-record-offer-sent.json",
		"/v1/orgs/org-1/credentials/rec-failed": "credential-record-abandoned.json",
	}
	d.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/signin" {
			mustWrite(t, w, []byte(`{"data":{"access_token":"t"}}`))
			return
		}
		d.paths = append(d.paths, r.Method+" "+r.URL.Path)
		d.queries = append(d.queries, r.URL.RawQuery)
		if r.Body != nil {
			raw, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("read the body: %v", err)
			}
			if len(raw) > 0 {
				var body map[string]any
				if err := json.Unmarshal(raw, &body); err != nil {
					t.Errorf("the body of %s: %v", r.URL.Path, err)
				}
				d.bodies[r.URL.Path] = body
			}
		}
		if code := d.status[r.URL.Path]; code != 0 {
			w.WriteHeader(code)
			mustWrite(t, w, []byte(`{"statusCode":`+http.StatusText(code)+`}`))
			return
		}
		name, ok := files[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "doc", name)) // #nosec G304 -- a fixed test path
		if err != nil {
			t.Fatal(err)
		}
		mustWrite(t, w, data)
	}))
	t.Cleanup(d.srv.Close)
	return d
}

func (d *didcommServer) client() *Client { return newClient(d.srv, nil) }

func anoncredsOffer() DidcommOffer {
	return DidcommOffer{
		Type:                   CredentialTypeIndy,
		CredentialDefinitionID: "Ra8F7Qx1:3:CL:Ra8F7Qx1:2:Farmer:1.0:default",
		Attributes:             map[string]string{"fullName": "[holder]", "acres": "12"},
	}
}

// TestOobOfferGivesInvitation is P6-C3: an out of band offer of an
// AnonCreds credential gives the invitation of the agent, the id of the
// credential exchange, and the thread.
func TestOobOfferGivesInvitation(t *testing.T) {
	d := newDidcommServer(t)
	got, err := d.client().CreateOOBOffer(context.Background(), anoncredsOffer())
	if err != nil {
		t.Fatalf("CreateOOBOffer: %v", err)
	}
	if !strings.Contains(got.InvitationURL, "?oob=") || got.RecordID != "0a1b2c3d-4e5f-4a6b-9c7d-8e9f0a1b2c3d" ||
		got.ThreadID != "9c8d7e6f-5a4b-4c3d-9e2f-1a0b9c8d7e6f" {
		t.Errorf("offer = %+v", got)
	}
	if d.queries[0] != "credentialType=indy" {
		t.Errorf("query = %q", d.queries[0])
	}
	body := d.bodies["/v1/orgs/org-1/credentials/oob/offer"]
	if body["credentialDefinitionId"] != "Ra8F7Qx1:3:CL:Ra8F7Qx1:2:Farmer:1.0:default" || body["protocolVersion"] != "v2" ||
		body["isShortenUrl"] != false || body["reuseConnection"] != true {
		t.Errorf("body = %v", body)
	}
	attrs, ok := body["attributes"].([]any)
	if !ok || len(attrs) != 2 {
		t.Fatalf("attributes = %v", body["attributes"])
	}
	// The attributes come in name order, each with a name and a value.
	first, ok := attrs[0].(map[string]any)
	if !ok || first["name"] != "acres" || first["value"] != "12" {
		t.Errorf("first attribute = %v", attrs[0])
	}
}

// TestJsonLdOfferCarriesTheCredential: a W3C JSON-LD offer carries the
// credential with the context of the schema and the proof options.
func TestJsonLdOfferCarriesTheCredential(t *testing.T) {
	d := newDidcommServer(t)
	offer := DidcommOffer{
		Type: CredentialTypeJSONLD,
		Credential: map[string]any{
			"@context": []string{W3CContext, "http://credebl-schema-file-server:4000/schemas/s-1"},
			"type":     []string{"VerifiableCredential"}, "issuer": map[string]string{"id": "did:key:z6Mk"},
			"issuanceDate": "2026-09-27T09:00:00Z", "credentialSubject": map[string]any{"fullName": "[holder]"},
		},
		Options: JSONLDOptions(),
	}
	if _, err := d.client().CreateOOBOffer(context.Background(), offer); err != nil {
		t.Fatalf("CreateOOBOffer: %v", err)
	}
	if d.queries[0] != "credentialType=jsonld" {
		t.Errorf("query = %q", d.queries[0])
	}
	body := d.bodies["/v1/orgs/org-1/credentials/oob/offer"]
	if _, ok := body["credential"].(map[string]any); !ok || body["attributes"] != nil {
		t.Errorf("body = %v", body)
	}
	options, ok := body["options"].(map[string]any)
	if !ok || options["proofType"] != "Ed25519Signature2018" || options["proofPurpose"] != "assertionMethod" {
		t.Errorf("options = %v", body["options"])
	}
}

// TestConnectionOfferGoesOverTheConnection: an offer to a connection of
// the organisation returns the record the agent made.
func TestConnectionOfferGoesOverTheConnection(t *testing.T) {
	d := newDidcommServer(t)
	got, err := d.client().SendConnectionOffer(context.Background(), "6e7f8a9b-0c1d-4e2f-9a3b-4c5d6e7f8a9b", anoncredsOffer())
	if err != nil {
		t.Fatalf("SendConnectionOffer: %v", err)
	}
	if got.ID != "3c4d5e6f-7a8b-4c9d-8e0f-1a2b3c4d5e6f" || got.State != "offer-sent" {
		t.Errorf("record = %+v", got)
	}
	body := d.bodies["/v1/orgs/org-1/credentials/offer"]
	data, ok := body["credentialData"].([]any)
	if !ok || len(data) != 1 {
		t.Fatalf("credentialData = %v", body["credentialData"])
	}
	entry, ok := data[0].(map[string]any)
	if !ok || entry["connectionId"] != "6e7f8a9b-0c1d-4e2f-9a3b-4c5d6e7f8a9b" || entry["attributes"] == nil {
		t.Errorf("entry = %v", data[0])
	}
	if _, err := d.client().SendConnectionOffer(context.Background(), " ", anoncredsOffer()); err == nil {
		t.Error("an offer without a connection passed")
	}
}

// TestOobEmailSendsThroughPlatform is P6-C3: the platform mails the out
// of band invitation to the address.
func TestOobEmailSendsThroughPlatform(t *testing.T) {
	d := newDidcommServer(t)
	if err := d.client().SendOOBEmail(context.Background(), "holder@registry.gov.test", anoncredsOffer()); err != nil {
		t.Fatalf("SendOOBEmail: %v", err)
	}
	body := d.bodies["/v1/orgs/org-1/credentials/oob/email"]
	offers, ok := body["credentialOffer"].([]any)
	if !ok || len(offers) != 1 {
		t.Fatalf("credentialOffer = %v", body["credentialOffer"])
	}
	entry, ok := offers[0].(map[string]any)
	if !ok || entry["emailId"] != "holder@registry.gov.test" || entry["attributes"] == nil {
		t.Errorf("entry = %v", offers[0])
	}
	if body["credentialDefinitionId"] == nil || body["isReuseConnection"] != true {
		t.Errorf("body = %v", body)
	}
	if err := d.client().SendOOBEmail(context.Background(), "", anoncredsOffer()); err == nil {
		t.Error("an email offer without an address passed")
	}
	// The platform answers false when the mail provider failed.
	d.status["/v1/orgs/org-1/credentials/oob/email"] = http.StatusInternalServerError
	if err := d.client().SendOOBEmail(context.Background(), "holder@registry.gov.test", anoncredsOffer()); err == nil {
		t.Error("a failed mail passed")
	}
}

// TestConnectionsListed: the platform lists the connections newest
// first, and answers not found for none.
func TestConnectionsListed(t *testing.T) {
	d := newDidcommServer(t)
	got, total, err := d.client().Connections(context.Background(), 1, 20)
	if err != nil || total != 2 || len(got) != 2 {
		t.Fatalf("Connections = %v, %d, %v", got, total, err)
	}
	if got[0].ID != "6e7f8a9b-0c1d-4e2f-9a3b-4c5d6e7f8a9b" || got[0].Label != "[wallet one]" || got[0].State != "completed" || got[0].CreatedAt.IsZero() {
		t.Errorf("first = %+v", got[0])
	}
	if !strings.Contains(d.queries[0], "pageNumber=1") || !strings.Contains(d.queries[0], "pageSize=20") {
		t.Errorf("query = %q", d.queries[0])
	}
	d.status["/v1/orgs/org-1/connections"] = http.StatusNotFound
	none, total, err := d.client().Connections(context.Background(), 1, 20)
	if err != nil || total != 0 || len(none) != 0 {
		t.Errorf("an empty list = %v, %d, %v", none, total, err)
	}
}

// TestCredentialRecordReadsTheState: the record of a DIDComm exchange
// carries its state and the error of the agent.
func TestCredentialRecordReadsTheState(t *testing.T) {
	d := newDidcommServer(t)
	for id, want := range map[string]string{"rec-done": "done", "rec-sent": "offer-sent", "rec-failed": "abandoned"} {
		got, err := d.client().CredentialRecord(context.Background(), id)
		if err != nil || got.State != want || got.UpdatedAt.IsZero() {
			t.Errorf("%s = %+v, %v", id, got, err)
		}
	}
	failed, err := d.client().CredentialRecord(context.Background(), "rec-failed")
	if err != nil || !strings.Contains(failed.ErrorMessage, "declined") {
		t.Errorf("failed = %+v, %v", failed, err)
	}
}

func TestDidcommCallsNeedAPlatform(t *testing.T) {
	var c *Client
	ctx := context.Background()
	if _, err := c.CreateOOBOffer(ctx, anoncredsOffer()); err == nil {
		t.Error("CreateOOBOffer on no platform")
	}
	if _, err := c.SendConnectionOffer(ctx, "c", anoncredsOffer()); err == nil {
		t.Error("SendConnectionOffer on no platform")
	}
	if err := c.SendOOBEmail(ctx, "a@b.test", anoncredsOffer()); err == nil {
		t.Error("SendOOBEmail on no platform")
	}
	if _, _, err := c.Connections(ctx, 1, 1); err == nil {
		t.Error("Connections on no platform")
	}
	if _, err := c.CredentialRecord(ctx, "r"); err == nil {
		t.Error("CredentialRecord on no platform")
	}
}
