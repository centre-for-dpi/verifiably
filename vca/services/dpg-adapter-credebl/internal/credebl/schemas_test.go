// SPDX-License-Identifier: Apache-2.0

package credebl

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/fake"
	"github.com/centre-for-dpi/vc-adapters/services/internal/dpgclient"
)

func TestSchemaCallsReadTheDocumentedAnswers(t *testing.T) {
	f := fake.New("../../testdata")
	t.Cleanup(f.Close)
	c := New(Options{
		HTTP:       dpgclient.New(dpgclient.Options{BaseURL: f.URL(), HTTP: f.Client(), Retries: -1, Sleep: func(time.Duration) {}}),
		Account:    Account{Email: "e", Password: "p", CryptoKey: "k"},
		OrgID:      "org-1",
		RandomSalt: func() ([]byte, error) { return fixedSalt, nil },
	})
	ctx := context.Background()
	attrs := []SchemaAttribute{{AttributeName: "a", SchemaDataType: "string", DisplayName: "a", IsRequired: true}}
	schemaID, err := c.CreateIndySchema(ctx, "RegistrationCertificate", "1.0", "did:indy:bcovrin:testnet:Ra8F", attrs)
	if err != nil || !strings.Contains(schemaID, "/SCHEMA/") {
		t.Errorf("CreateIndySchema = %q, %v", schemaID, err)
	}
	credDef, err := c.CreateCredentialDefinition(ctx, schemaID, "did:indy:bcovrin:testnet:Ra8F", "default")
	if err != nil || !strings.Contains(credDef, "/CLAIM_DEF/") {
		t.Errorf("CreateCredentialDefinition = %q, %v", credDef, err)
	}
	w3c, err := c.CreateW3CSchema(ctx, "RegistrationCertificate", "d", attrs)
	if err != nil || !strings.Contains(w3c, "/schemas/") {
		t.Errorf("CreateW3CSchema = %q, %v", w3c, err)
	}
	ledgers, err := c.Ledgers(ctx)
	if err != nil || len(ledgers) != 4 || ledgers[0].Namespace != "bcovrin:testnet" || ledgers[0].Name != "Bcovrin Testnet" {
		t.Errorf("Ledgers = %v, %v", ledgers, err)
	}
}

func TestSchemaCallsWithoutAPlatform(t *testing.T) {
	var c *Client
	ctx := context.Background()
	for i, err := range []error{
		func() error { _, err := c.CreateIndySchema(ctx, "n", "1.0", "d", nil); return err }(),
		func() error { _, err := c.CreateW3CSchema(ctx, "n", "d", nil); return err }(),
		func() error { _, err := c.CreateCredentialDefinition(ctx, "s", "d", "t"); return err }(),
		func() error { _, err := c.Ledgers(ctx); return err }(),
		func() error { _, err := c.OrgSchemas(ctx, "n"); return err }(),
		func() error { _, err := c.SchemaCredDefs(ctx, "s"); return err }(),
	} {
		if !errors.Is(err, ErrNoPlatform) {
			t.Errorf("call %d: err = %v", i, err)
		}
	}
}

func TestSchemaAnswersWithoutTheirIds(t *testing.T) {
	srv := orgServer(t, func(w http.ResponseWriter, _ *http.Request) { mustWrite(t, w, []byte(`{"data":{}}`)) })
	c := newClient(srv, nil)
	ctx := context.Background()
	if _, err := c.CreateIndySchema(ctx, "n", "1.0", "d", nil); err == nil {
		t.Error("a schema answer with no ledger id passed")
	}
	if _, err := c.CreateW3CSchema(ctx, "n", "d", nil); err == nil {
		t.Error("a schema answer with no address passed")
	}
	if _, err := c.CreateCredentialDefinition(ctx, "s", "d", "t"); err == nil {
		t.Error("a credential definition answer with no id passed")
	}
	failing := orgServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadRequest) })
	fc := newClient(failing, nil)
	for i, err := range []error{
		func() error { _, err := fc.CreateIndySchema(ctx, "n", "1.0", "d", nil); return err }(),
		func() error { _, err := fc.CreateW3CSchema(ctx, "n", "d", nil); return err }(),
		func() error { _, err := fc.CreateCredentialDefinition(ctx, "s", "d", "t"); return err }(),
		func() error { _, err := fc.Ledgers(ctx); return err }(),
	} {
		if err == nil {
			t.Errorf("call %d passed", i)
		}
	}
}

func TestIndyNamespace(t *testing.T) {
	cases := map[string]string{
		"did:indy:bcovrin:testnet:Ra8F": "bcovrin:testnet",
		"did:indy:indicio:demonet:Xy":   "indicio:demonet",
		"did:key:z6Mk":                  "",
		"did:indy:sovrin:Xy":            "",
	}
	for did, want := range cases {
		got, ok := IndyNamespace(did)
		if got != want || ok != (want != "") {
			t.Errorf("%s: %q %v", did, got, ok)
		}
	}
}

// TestSchemaListsReadEveryPage: the schema and credential definition
// lists of the platform come in pages. The client reads each page until
// the answer says no page follows, and keeps the slash of a ledger id in
// one path segment.
func TestSchemaListsReadEveryPage(t *testing.T) {
	const schemaID = "did:indy:bcovrin:testnet:Ra8F/anoncreds/v0/SCHEMA/Degree/1.0"
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.EscapedPath()+"?"+r.URL.RawQuery)
		page := r.URL.Query().Get("pageNumber")
		switch {
		case r.URL.Path == "/v1/auth/signin":
			mustWrite(t, w, []byte(`{"data":{"access_token":"t","expires_in":3600}}`))
		case strings.HasSuffix(r.URL.Path, "/cred-defs") && page == "1":
			mustWrite(t, w, []byte(`{"data":{"hasNextPage":true,"data":[{"tag":"other","credentialDefinitionId":"a"}]}}`))
		case strings.HasSuffix(r.URL.Path, "/cred-defs"):
			mustWrite(t, w, []byte(`{"data":{"hasNextPage":false,"data":[{"tag":"default","credentialDefinitionId":"b"}]}}`))
		case page == "1":
			mustWrite(t, w, []byte(`{"data":{"hasNextPage":true,"data":[{"name":"Degree","version":"1.0","schemaLedgerId":"x"}]}}`))
		case page == "2":
			mustWrite(t, w, []byte(`{"data":{"hasNextPage":true,"data":[]}}`))
		}
	}))
	t.Cleanup(srv.Close)
	c := New(Options{
		HTTP:       dpgclient.New(dpgclient.Options{BaseURL: srv.URL, HTTP: srv.Client(), Retries: -1, Sleep: func(time.Duration) {}}),
		Account:    Account{Email: "e", Password: "p", CryptoKey: "k"},
		OrgID:      "org-1",
		RandomSalt: func() ([]byte, error) { return fixedSalt, nil },
	})
	ctx := context.Background()
	schemas, err := c.OrgSchemas(ctx, "Degree")
	if err != nil || len(schemas) != 1 || schemas[0].NoLedger() {
		t.Fatalf("OrgSchemas = %v, %v", schemas, err)
	}
	defs, err := c.SchemaCredDefs(ctx, schemaID)
	if err != nil || len(defs) != 2 || defs[1].Tag != "default" || defs[1].ID != "b" {
		t.Fatalf("SchemaCredDefs = %v, %v", defs, err)
	}
	joined := strings.Join(paths, "\n")
	if !strings.Contains(joined, "/v1/orgs/org-1/schemas/did:indy:bcovrin:testnet:Ra8F%2Fanoncreds%2Fv0%2FSCHEMA%2FDegree%2F1.0/cred-defs") {
		t.Errorf("the ledger id left its path segment:\n%s", joined)
	}
	if !strings.Contains(joined, "searchByText=Degree") {
		t.Errorf("the list carries no search text:\n%s", joined)
	}
	if !(OrgSchema{LedgerID: "https://files/schemas/1"}).NoLedger() {
		t.Error("an address of the schema file server has a ledger")
	}
}
