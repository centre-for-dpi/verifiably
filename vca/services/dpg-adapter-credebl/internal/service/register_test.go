// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"strings"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
)

// P6-C2: AnonCreds schemas and credential definitions on a ledger, and
// W3C JSON-LD schemas that the schema file server keeps. The answers
// come from the platform sources in testdata/doc.

// registrationSchema is the JSON Schema of the configurations the tests
// register.
const registrationSchema = `{"type":"object","properties":{"registration_number":{"type":"string"},` +
	`"holder_name":{"type":"string"},"issued_on":{"type":"string","format":"date"},"active":{"type":"boolean"},` +
	`"employees":{"type":"integer"}},"required":["registration_number"]}`

// register calls RegisterCredentialConfiguration with one configuration.
func register(t *testing.T, svc interface {
	RegisterCredentialConfiguration(context.Context, *connect.Request[backendv1.RegisterCredentialConfigurationRequest]) (*connect.Response[backendv1.RegisterCredentialConfigurationResponse], error)
}, format commonv1.Format, ledger string) (string, error) {
	t.Helper()
	res, err := svc.RegisterCredentialConfiguration(context.Background(), connect.NewRequest(&backendv1.RegisterCredentialConfigurationRequest{
		Configuration: &backendv1.CredentialConfiguration{
			Id: "RegistrationCertificate_anoncreds", Format: format, Type: "RegistrationCertificate",
			JsonSchema: registrationSchema, Ledger: ledger,
		},
	}))
	if err != nil {
		return "", err
	}
	return res.Msg.GetId(), nil
}

// TestRegisterAnonCredsCreatesSchemaAndCredDef: an AnonCreds
// configuration writes the schema on the ledger with the DID the
// organisation holds there, and then its credential definition. The
// configuration id is the credential definition id.
func TestRegisterAnonCredsCreatesSchemaAndCredDef(t *testing.T) {
	svc, f := newService(t, nil)
	id, err := register(t, svc, commonv1.Format_FORMAT_ANONCREDS, "bcovrin:testnet")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if !strings.Contains(id, "/anoncreds/v0/CLAIM_DEF/") {
		t.Errorf("id = %q, want the credential definition id", id)
	}
	var schema struct {
		Type    string `json:"type"`
		Payload struct {
			SchemaName    string `json:"schemaName"`
			SchemaVersion string `json:"schemaVersion"`
			OrgDid        string `json:"orgDid"`
			Attributes    []struct {
				AttributeName  string `json:"attributeName"`
				SchemaDataType string `json:"schemaDataType"`
				DisplayName    string `json:"displayName"`
				IsRequired     bool   `json:"isRequired"`
			} `json:"attributes"`
		} `json:"schemaPayload"`
	}
	if err := f.RequestJSON("/v1/orgs/org-1/schemas", &schema); err != nil {
		t.Fatalf("the schema request: %v", err)
	}
	if schema.Type != "indy" || schema.Payload.SchemaName != "RegistrationCertificate" || schema.Payload.SchemaVersion != "1.0" ||
		schema.Payload.OrgDid != fixtureIndyDid {
		t.Errorf("schema request = %+v", schema)
	}
	types := map[string]string{}
	required := map[string]bool{}
	for _, a := range schema.Payload.Attributes {
		types[a.AttributeName] = a.SchemaDataType
		required[a.AttributeName] = a.IsRequired
	}
	for name, want := range map[string]string{
		"registration_number": "string", "holder_name": "string", "issued_on": "datetime-local", "active": "boolean", "employees": "number",
	} {
		if types[name] != want {
			t.Errorf("%s has the type %q, want %q", name, types[name], want)
		}
	}
	if !required["registration_number"] || required["holder_name"] {
		t.Errorf("required = %v", required)
	}
	var credDef map[string]any
	if err := f.RequestJSON("/v1/orgs/org-1/cred-defs", &credDef); err != nil {
		t.Fatalf("the credential definition request: %v", err)
	}
	if credDef["schemaLedgerId"] != "did:indy:bcovrin:testnet:Ra8FGb2mXsTg1d4VqVnYpS/anoncreds/v0/SCHEMA/RegistrationCertificate/1.0" ||
		credDef["orgDid"] != fixtureIndyDid || credDef["tag"] != "default" || credDef["revocable"] != false {
		t.Errorf("credential definition request = %v", credDef)
	}
	calls := strings.Join(f.Calls(), "\n")
	if strings.Index(calls, "POST /v1/orgs/org-1/schemas") > strings.Index(calls, "POST /v1/orgs/org-1/cred-defs") {
		t.Errorf("the credential definition came first:\n%s", calls)
	}
	if strings.Contains(calls, "/template") {
		t.Errorf("an AnonCreds configuration made an OID4VC template:\n%s", calls)
	}
}

// TestRegisterAnonCredsNeedsALedgerOfTheOrganisation: the ledger must be
// one where the organisation holds a DID.
func TestRegisterAnonCredsNeedsALedgerOfTheOrganisation(t *testing.T) {
	svc, f := newService(t, nil)
	_, err := register(t, svc, commonv1.Format_FORMAT_ANONCREDS, "")
	wantCode(t, err, connect.CodeInvalidArgument)
	_, err = register(t, svc, commonv1.Format_FORMAT_ANONCREDS, "indicio:testnet")
	wantCode(t, err, connect.CodeFailedPrecondition)
	if strings.Contains(strings.Join(f.Calls(), " "), "/schemas") {
		t.Errorf("a refused configuration wrote a schema: %v", f.Calls())
	}
	f.SetStatus("/v1/orgs/org-1/cred-defs", 400)
	_, err = register(t, svc, commonv1.Format_FORMAT_ANONCREDS, "bcovrin:testnet")
	wantCode(t, err, connect.CodeInvalidArgument)
}

// TestRegisterJsonLd: a W3C JSON-LD configuration writes a schema with
// no ledger, which the schema file server keeps. The configuration id
// is the address of the schema.
func TestRegisterJsonLd(t *testing.T) {
	svc, f := newService(t, nil)
	id, err := register(t, svc, commonv1.Format_FORMAT_LDP_VC, "")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if !strings.HasPrefix(id, "http://credebl-schema-file-server:4000/schemas/") {
		t.Errorf("id = %q, want the schema address", id)
	}
	var schema struct {
		Type    string `json:"type"`
		Payload struct {
			SchemaName  string `json:"schemaName"`
			SchemaType  string `json:"schemaType"`
			Description string `json:"description"`
			Attributes  []struct {
				AttributeName  string `json:"attributeName"`
				SchemaDataType string `json:"schemaDataType"`
			} `json:"attributes"`
		} `json:"schemaPayload"`
	}
	if reqErr := f.RequestJSON("/v1/orgs/org-1/schemas", &schema); reqErr != nil {
		t.Fatalf("the schema request: %v", reqErr)
	}
	if schema.Type != "json" || schema.Payload.SchemaType != "no_ledger" || schema.Payload.SchemaName != "RegistrationCertificate" ||
		len(schema.Payload.Attributes) != 5 {
		t.Errorf("schema request = %+v", schema)
	}
	for _, a := range schema.Payload.Attributes {
		if a.AttributeName == "employees" && a.SchemaDataType != "integer" {
			t.Errorf("employees has the type %q", a.SchemaDataType)
		}
	}
	if strings.Contains(strings.Join(f.Calls(), " "), "/template") {
		t.Errorf("a JSON-LD configuration made an OID4VC template: %v", f.Calls())
	}
	_, err = register(t, svc, commonv1.Format_FORMAT_LDP_VC, "bcovrin:testnet")
	wantCode(t, err, connect.CodeInvalidArgument)
}

// TestLedgersListed: the capability answer lists the ledgers the
// organisation holds a DID on, with the names the platform gives them,
// and the schema formats they allow. The answer reads the platform once
// a minute at most.
func TestLedgersListed(t *testing.T) {
	svc, f := newService(t, nil)
	ctx := context.Background()
	caps, err := svc.GetCapabilities(ctx, connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	ledgers := caps.Msg.GetLedgers()
	if len(ledgers) != 1 || ledgers[0].GetNamespace() != "bcovrin:testnet" || ledgers[0].GetName() != "Bcovrin Testnet" {
		t.Errorf("ledgers = %v", ledgers)
	}
	if got := caps.Msg.GetSchemaFormats(); len(got) != 2 || got[0] != commonv1.Format_FORMAT_ANONCREDS || got[1] != commonv1.Format_FORMAT_LDP_VC {
		t.Errorf("schema formats = %v", got)
	}
	// The adapter issues both over DIDComm (P6-C3), so they are issue
	// formats too.
	issue := map[commonv1.Format]bool{}
	for _, fm := range caps.Msg.GetFormats() {
		issue[fm] = true
	}
	if !issue[commonv1.Format_FORMAT_ANONCREDS] || !issue[commonv1.Format_FORMAT_LDP_VC] {
		t.Errorf("issue formats = %v", caps.Msg.GetFormats())
	}
	if _, againErr := svc.GetCapabilities(ctx, connect.NewRequest(&backendv1.GetCapabilitiesRequest{})); againErr != nil {
		t.Fatal(againErr)
	}
	if n := strings.Count(strings.Join(f.Calls(), "\n"), "GET /v1/orgs/org-1/dids"); n != 1 {
		t.Errorf("two answers read the DIDs %d times, want once", n)
	}
	// A platform that does not answer leaves the ledgers out, and the
	// answer still comes.
	down, fd := newService(t, nil)
	fd.SetStatus("/v1/orgs/org-1/dids", 500)
	caps, err = down.GetCapabilities(ctx, connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(caps.Msg.GetLedgers()) != 0 || len(caps.Msg.GetSchemaFormats()) != 1 {
		t.Errorf("a platform that is down gave ledgers %v and schema formats %v", caps.Msg.GetLedgers(), caps.Msg.GetSchemaFormats())
	}
}

// TestARegistrationAgainFindsTheSchemaOfThePlatform is ADR-077 decision
// 2: the schema registry registers every published version again at
// each start. The adapter finds the AnonCreds schema, its credential
// definition and the W3C schema of the same name, and answers with
// their ids. It writes nothing twice, so the ledger sees one write each.
func TestARegistrationAgainFindsTheSchemaOfThePlatform(t *testing.T) {
	svc, f := newService(t, nil)
	first := map[commonv1.Format]string{}
	for run := 1; run <= 2; run++ {
		for _, c := range []struct {
			format commonv1.Format
			ledger string
		}{{commonv1.Format_FORMAT_ANONCREDS, "bcovrin:testnet"}, {commonv1.Format_FORMAT_LDP_VC, ""}} {
			id, err := register(t, svc, c.format, c.ledger)
			if err != nil {
				t.Fatalf("run %d: register %v: %v", run, c.format, err)
			}
			if run == 1 {
				first[c.format] = id
			} else if id != first[c.format] {
				t.Errorf("run 2 of %v answered %q, want the id of run 1 %q", c.format, id, first[c.format])
			}
		}
	}
	calls := f.Calls()
	if n := count(calls, "POST /v1/orgs/org-1/schemas"); n != 2 {
		t.Errorf("%d schema writes for one AnonCreds and one W3C schema, want 2:\n%s", n, strings.Join(calls, "\n"))
	}
	if n := count(calls, "POST /v1/orgs/org-1/cred-defs"); n != 1 {
		t.Errorf("%d credential definition writes, want 1:\n%s", n, strings.Join(calls, "\n"))
	}
}

// TestARegistrationAgainWritesOnlyTheMissingCredDef: a first run that
// wrote the schema and failed on the credential definition leaves the
// schema on the ledger. The next run writes the credential definition
// only.
func TestARegistrationAgainWritesOnlyTheMissingCredDef(t *testing.T) {
	svc, f := newService(t, nil)
	f.SetStatus("/v1/orgs/org-1/cred-defs", 502)
	if _, err := register(t, svc, commonv1.Format_FORMAT_ANONCREDS, "bcovrin:testnet"); err == nil {
		t.Fatal("the failed credential definition gave no error")
	}
	id, err := register(t, svc, commonv1.Format_FORMAT_ANONCREDS, "bcovrin:testnet")
	if err != nil {
		t.Fatalf("register again: %v", err)
	}
	if !strings.Contains(id, "/anoncreds/v0/CLAIM_DEF/") {
		t.Errorf("id = %q, want the credential definition id", id)
	}
	calls := f.Calls()
	if n := count(calls, "POST /v1/orgs/org-1/schemas"); n != 1 {
		t.Errorf("%d schema writes, want 1:\n%s", n, strings.Join(calls, "\n"))
	}
	if n := count(calls, "POST /v1/orgs/org-1/cred-defs"); n != 2 {
		t.Errorf("%d credential definition writes, want the failed one and one more:\n%s", n, strings.Join(calls, "\n"))
	}
}

// TestARegistrationAgainOfATemplateWritesOneSchema: a first run that
// stored the schema of a template and failed on the template stores no
// second schema on the next run.
func TestARegistrationAgainOfATemplateWritesOneSchema(t *testing.T) {
	svc, f := newService(t, nil)
	f.SetStatus("/v1/orgs/org-1/oid4vc/issuer-1/template", 0, 502)
	request := connect.NewRequest(&backendv1.RegisterCredentialConfigurationRequest{
		Configuration: &backendv1.CredentialConfiguration{
			Id: "NewCredential", Format: commonv1.Format_FORMAT_DC_SD_JWT, JsonSchema: registrationSchema,
		},
	})
	if _, err := svc.RegisterCredentialConfiguration(context.Background(), request); err == nil {
		t.Fatal("the failed template gave no error")
	}
	if _, err := svc.RegisterCredentialConfiguration(context.Background(), request); err != nil {
		t.Fatalf("register again: %v", err)
	}
	if n := count(f.Calls(), "POST /v1/orgs/org-1/schemas"); n != 1 {
		t.Errorf("%d schema writes, want 1:\n%s", n, strings.Join(f.Calls(), "\n"))
	}
}

// TestAnAnonCredsNameOfAnotherOrganisationIsRefused: the platform keeps
// one AnonCreds schema per name and version across every organisation.
// A name that another organisation holds answers the code
// already_exists, which no later try changes.
func TestAnAnonCredsNameOfAnotherOrganisationIsRefused(t *testing.T) {
	svc, f := newService(t, nil)
	f.AddForeignSchema("RegistrationCertificate", "1.0")
	_, err := register(t, svc, commonv1.Format_FORMAT_ANONCREDS, "bcovrin:testnet")
	wantCode(t, err, connect.CodeAlreadyExists)
	if n := count(f.Calls(), "POST /v1/orgs/org-1/cred-defs"); n != 0 {
		t.Errorf("a refused schema wrote %d credential definitions", n)
	}
}

// TestARegistrationReportsAListThatFails: a schema or credential
// definition list that fails stops the registration before a write.
func TestARegistrationReportsAListThatFails(t *testing.T) {
	svc, f := newService(t, nil)
	f.SetStatus("/v1/orgs/org-1/schemas", 503)
	_, err := register(t, svc, commonv1.Format_FORMAT_ANONCREDS, "bcovrin:testnet")
	wantCode(t, err, connect.CodeUnavailable)
	f.SetStatus("/v1/orgs/org-1/schemas", 503)
	_, err = register(t, svc, commonv1.Format_FORMAT_LDP_VC, "")
	wantCode(t, err, connect.CodeUnavailable)
	f.SetStatus("/v1/orgs/org-1/schemas/"+fixtureIndyDid+"/anoncreds/v0/SCHEMA/RegistrationCertificate/1.0/cred-defs", 503)
	_, err = register(t, svc, commonv1.Format_FORMAT_ANONCREDS, "bcovrin:testnet")
	wantCode(t, err, connect.CodeUnavailable)
	f.SetStatus("/v1/orgs/org-1/schemas", 503)
	_, err = svc.RegisterCredentialConfiguration(context.Background(), connect.NewRequest(&backendv1.RegisterCredentialConfigurationRequest{
		Configuration: &backendv1.CredentialConfiguration{
			Id: "NewCredential", Format: commonv1.Format_FORMAT_DC_SD_JWT, JsonSchema: registrationSchema,
		},
	}))
	wantCode(t, err, connect.CodeUnavailable)
	if n := count(f.Calls(), "POST /v1/orgs/org-1/cred-defs"); n != 0 {
		t.Errorf("a failed list wrote %d credential definitions", n)
	}
}
