// SPDX-License-Identifier: Apache-2.0

package fake_test

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/fake"
)

const testdata = "../../testdata"

func TestFakeServesTheRecordedAnswers(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	cases := map[string]string{
		"/v1/auth/signin":                             "access_token",
		"/v1/orgs/org-1/oid4vc/issuer-1/template":     "FarmerCredential",
		"/v1/orgs/org-1/oid4vp/verifier":              "publicVerifierId",
		"/v1/orgs/org-1/oid4vp/verifier-presentation": "state",
	}
	for path, want := range cases {
		if body := get(t, f, path); !strings.Contains(body, want) {
			t.Fatalf("%s returned %q, want a body with %q", path, body, want)
		}
	}
	posts := map[string]string{
		"/v1/orgs/org-1/schemas":                      "schemaLedgerId",
		"/v1/orgs/org-1/oid4vc/issuer-1/create-offer": "credentialOffer",
		"/v1/orgs/org-1/oid4vp/presentation":          "authorizationRequest",
		"/v1/orgs/org-1/oid4vc/issuer-1/template":     "d4e8a1f7",
	}
	for path, want := range posts {
		if body := post(t, f, path, "{}"); !strings.Contains(body, want) {
			t.Fatalf("%s returned %q, want a body with %q", path, body, want)
		}
	}
}

func TestFakeCountsTheSignins(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	post(t, f, "/v1/auth/signin", "{}")
	post(t, f, "/v1/auth/signin", "{}")
	if f.Signins() != 2 {
		t.Fatalf("sign ins = %d", f.Signins())
	}
}

func TestFakeSwitchesTheAnswers(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	f.SetSession(fake.SessionVerified)
	if !strings.Contains(get(t, f, "/v1/orgs/org-1/oid4vp/verifier-presentation"), "ResponseVerified") {
		t.Fatal("the verified session is missing")
	}
	f.SetSession(fake.SessionError)
	if !strings.Contains(get(t, f, "/v1/orgs/org-1/oid4vp/verifier-presentation"), "Error") {
		t.Fatal("the failed session is missing")
	}
	f.SetTemplates(fake.Templates)
	if !strings.Contains(get(t, f, "/v1/orgs/org-1/oid4vc/issuer-1/template"), "IdentityCredential") {
		t.Fatal("the template listing is missing")
	}
}

func TestFakeServesTheStatusesInOrder(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	f.SetStatus("/v1/auth/signin", http.StatusTeapot, http.StatusForbidden)
	if code := status(t, f, "/v1/auth/signin"); code != http.StatusTeapot {
		t.Fatalf("first status = %d", code)
	}
	if code := status(t, f, "/v1/auth/signin"); code != http.StatusForbidden {
		t.Fatalf("second status = %d", code)
	}
	if code := status(t, f, "/v1/auth/signin"); code != http.StatusOK {
		t.Fatalf("third status = %d, the list is empty", code)
	}
	f.SetStatus("/v1/auth/signin", http.StatusTeapot)
	f.SetStatus("/v1/auth/signin")
	if code := status(t, f, "/v1/auth/signin"); code != http.StatusOK {
		t.Fatalf("status = %d, an empty list removes the setting", code)
	}
}

func TestFakeReportsAMissingRecording(t *testing.T) {
	f := fake.New("testdata-that-does-not-exist")
	defer f.Close()
	if code := status(t, f, "/v1/auth/signin"); code != http.StatusInternalServerError {
		t.Fatalf("status = %d", code)
	}
}

func TestFakeAnswersAnUnknownPathWithNotFound(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	if code := status(t, f, "/unknown"); code != http.StatusNotFound {
		t.Fatalf("status = %d", code)
	}
}

func TestFakeRecordsTheRequestBody(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	post(t, f, "/v1/auth/signin", `{"email":"admin@example.org"}`)
	var body map[string]any
	if err := f.RequestJSON("/v1/auth/signin", &body); err != nil {
		t.Fatalf("RequestJSON: %v", err)
	}
	if body["email"] != "admin@example.org" {
		t.Fatalf("body = %v", body)
	}
	if len(f.Request("/v1/auth/signin")) == 0 {
		t.Fatal("the fake recorded no body")
	}
}

func get(t *testing.T, f *fake.Server, path string) string {
	t.Helper()
	resp, err := f.Client().Get(f.URL() + path)
	if err != nil {
		t.Fatalf("get %s: %v", path, err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Errorf("the close failed: %v", cerr)
		}
	}()
	body, verr := io.ReadAll(resp.Body)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	return string(body)
}

func post(t *testing.T, f *fake.Server, path, request string) string {
	t.Helper()
	resp, err := f.Client().Post(f.URL()+path, "application/json", strings.NewReader(request))
	if err != nil {
		t.Fatalf("post %s: %v", path, err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Errorf("the close failed: %v", cerr)
		}
	}()
	body, verr := io.ReadAll(resp.Body)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	return string(body)
}

func status(t *testing.T, f *fake.Server, path string) int {
	t.Helper()
	resp, err := f.Client().Get(f.URL() + path)
	if err != nil {
		t.Fatalf("get %s: %v", path, err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Errorf("the close failed: %v", cerr)
		}
	}()
	return resp.StatusCode
}

// call sends one request and returns the status and the body.
func call(t *testing.T, f *fake.Server, method, path string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, f.URL()+path, strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := f.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Errorf("the close failed: %v", cerr)
		}
	}()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(body)
}

// TestFakeServesTheOrganisationCalls covers the answers written from
// the platform sources (P6-C1).
func TestFakeServesTheOrganisationCalls(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	org := "/v1/orgs/0b6c2f0e-5a38-4a1e-9d2b-3f7c1e6a9d41"
	cases := []struct {
		method, path string
		status       int
		want         string
	}{
		{http.MethodGet, "/v1/orgs", 200, "Platform-admin"},
		{http.MethodPost, "/v1/orgs", 201, "[ORGANISATION]"},
		{http.MethodGet, org, 200, "SHARED"},
		{http.MethodGet, org + "/dids", 200, "isPrimaryDid"},
		{http.MethodGet, org + "/users", 200, "[ISSUER EMAIL]"},
		{http.MethodPut, org + "/primary-did", 201, "Primary DID"},
		{http.MethodPost, org + "/agents/wallet", 201, "tenantId"},
		{http.MethodDelete, org, 202, "deleted"},
		{http.MethodDelete, org, 404, ""},
		{http.MethodGet, org, 404, ""},
		{http.MethodPatch, org, 404, ""},
	}
	for _, c := range cases {
		code, body := call(t, f, c.method, c.path)
		if code != c.status || !strings.Contains(body, c.want) {
			t.Errorf("%s %s = %d %q, want %d with %q", c.method, c.path, code, body, c.status, c.want)
		}
	}
	f.SetOrgs(fake.NoOrgs)
	if code, _ := call(t, f, http.MethodGet, "/v1/orgs"); code != 404 {
		t.Errorf("an empty platform answered %d", code)
	}
	if calls := f.Calls(); len(calls) != len(cases)+1 || calls[0] != "GET /v1/orgs" {
		t.Errorf("calls = %v", calls)
	}
	missing := fake.New(t.TempDir())
	defer missing.Close()
	if code, _ := call(t, missing, http.MethodPost, "/v1/orgs"); code != 500 {
		t.Errorf("a missing answer gave %d", code)
	}
}

// TestFakeServesTheSchemaCalls covers the answers of P6-C2.
func TestFakeServesTheSchemaCalls(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	for body, want := range map[string]string{
		`{"type":"indy"}`: "/SCHEMA/",
		`{"type":"json","schemaPayload":{"schemaType":"no_ledger"}}`: "schema-file-server",
		`{"type":"json","schemaPayload":{"schemaType":"json"}}`:      "schemaLedgerId",
		`not json`: "schemaLedgerId",
	} {
		if got := post(t, f, "/v1/orgs/org-1/schemas", body); !strings.Contains(got, want) {
			t.Errorf("%s gave %q, want %q", body, got, want)
		}
	}
	if code, body := call(t, f, http.MethodPost, "/v1/orgs/org-1/cred-defs"); code != 201 || !strings.Contains(body, "CLAIM_DEF") {
		t.Errorf("cred-defs = %d %s", code, body)
	}
	if body := get(t, f, "/v1/platform/ledgers"); !strings.Contains(body, "bcovrin:testnet") {
		t.Errorf("ledgers = %s", body)
	}
}

// TestFakeServesTheOfferSessions covers the answers of P6-C5.
func TestFakeServesTheOfferSessions(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	if body := get(t, f, "/v1/orgs/org-1/oid4vc/credential-offer"); !strings.Contains(body, "Completed") {
		t.Errorf("list = %s", body)
	}
	for answer, want := range map[fake.Answer]string{
		fake.OfferPending: "OfferUriRetrieved", fake.OfferCompleted: "Completed", fake.OfferError: "errorMessage",
	} {
		f.SetOfferSession(answer)
		if body := get(t, f, "/v1/orgs/org-1/oid4vc/credential-offer/s-1"); !strings.Contains(body, want) {
			t.Errorf("%s = %s", answer, body)
		}
	}
}

// TestFakeServesTheDidcommCalls covers the DIDComm issuance answers of
// P6-C3 and the switches of the tests.
func TestFakeServesTheDidcommCalls(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	for path, want := range map[string]string{
		"/v1/orgs/org-1/credentials/oob/offer?credentialType=indy": "invitationUrl",
		"/v1/orgs/org-1/credentials/offer?credentialType=indy":     "offer-sent",
		"/v1/orgs/org-1/credentials/oob/email?credentialType=indy": "true",
	} {
		if body := post(t, f, path, "{}"); !strings.Contains(body, want) {
			t.Errorf("%s returned %q", path, body)
		}
	}
	if q := f.Query("/v1/orgs/org-1/credentials/oob/email"); q != "credentialType=indy" {
		t.Errorf("query = %q", q)
	}
	if body := get(t, f, "/v1/orgs/org-1/connections"); !strings.Contains(body, "theirLabel") {
		t.Errorf("connections = %q", body)
	}
	f.SetConnections(fake.NoConnections)
	if body := get(t, f, "/v1/orgs/org-1/connections"); strings.Contains(body, "theirLabel") {
		t.Errorf("no connections = %q", body)
	}
	if body := get(t, f, "/v1/orgs/org-1/credentials/rec-1"); !strings.Contains(body, "offer-sent") {
		t.Errorf("record = %q", body)
	}
	f.SetCredentialRecord(fake.RecordDone)
	if body := get(t, f, "/v1/orgs/org-1/credentials/rec-1"); !strings.Contains(body, `"done"`) {
		t.Errorf("record = %q", body)
	}
	if body := get(t, f, "/v1/orgs/org-1/credentials/rec-1/unknown"); strings.Contains(body, "state") {
		t.Errorf("an unknown path = %q", body)
	}
}

// TestFakeServesTheBulkCalls covers the bulk import answers of P6-C4
// and the upload the tests read back.
func TestFakeServesTheBulkCalls(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, err := w.CreateFormFile("file", "farmers.csv")
	if err != nil {
		t.Fatal(err)
	}
	if _, werr := part.Write([]byte("email_identifier,name\n")); werr != nil {
		t.Fatal(werr)
	}
	if cerr := w.Close(); cerr != nil {
		t.Fatal(cerr)
	}
	resp, err := f.Client().Post(f.URL()+"/v1/orgs/org-1/bulk/upload?schemaType=indy", w.FormDataContentType(), &buf)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(resp.Body)
	if cerr := resp.Body.Close(); cerr != nil || err != nil || resp.StatusCode != http.StatusCreated || !strings.Contains(string(raw), "File imported") {
		t.Errorf("upload = %d %q %v %v", resp.StatusCode, raw, err, cerr)
	}
	name, content, err := f.Upload("/v1/orgs/org-1/bulk/upload")
	if err != nil || name != "farmers.csv" || string(content) != "email_identifier,name\n" {
		t.Errorf("upload read = %q %q %v", name, content, err)
	}
	// A write without a multipart body has no file to read.
	post(t, f, "/v1/orgs/org-1/req-1/bulk", "{}")
	if _, _, err := f.Upload("/v1/orgs/org-1/req-1/bulk"); err == nil {
		t.Error("a JSON write reads as an upload")
	}
	if _, _, err := f.Upload("/v1/orgs/org-1/never"); err == nil {
		t.Error("a path without a call reads as an upload")
	}
	for path, want := range map[string]string{
		"/v1/orgs/org-1/req-1/bulk":        "Process initiated",
		"/v1/orgs/org-1/file-1/retry/bulk": "Process reinitiated",
	} {
		if body := post(t, f, path, "{}"); !strings.Contains(body, want) {
			t.Errorf("%s returned %q", path, body)
		}
	}
	for path, want := range map[string]string{
		"/v1/orgs/org-1/req-1/preview":          "email_identifier",
		"/v1/orgs/org-1/bulk/files":             "PARTIALLY_COMPLETED",
		"/v1/orgs/org-1/file-1/bulk/file-data":  "referenceId",
		"/v1/orgs/org-1/file-1/bulk/file-other": "404 page not found",
	} {
		if body := get(t, f, path); !strings.Contains(body, want) {
			t.Errorf("%s returned %q", path, body)
		}
	}
	f.SetBulkFiles(fake.NoBulkFiles)
	if body := get(t, f, "/v1/orgs/org-1/bulk/files"); strings.Contains(body, "PARTIALLY") {
		t.Errorf("no files = %q", body)
	}
}

// TestFakeServesTheProofCalls: the DIDComm proof calls of P6-C6, the
// answers a test switches between, and the empty lists.
func TestFakeServesTheProofCalls(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	for path, want := range map[string]string{
		"/v1/orgs/org-1/proofs/oob":                      "proofRecordId",
		"/v1/orgs/org-1/proofs":                          "request-sent",
		"/v1/orgs/org-1/proofs/p-1/verify":               "isVerified",
		"/v1/orgs/org-1/proofs/p-1/something-else-to-do": "",
	} {
		if body := post(t, f, path, "{}"); !strings.Contains(body, want) {
			t.Errorf("post %s = %q", path, body)
		}
	}
	for path, want := range map[string]string{
		"/v1/orgs/org-1/proofs":               "presentationId",
		"/v1/orgs/org-1/proofs/p-1":           "request-sent",
		"/v1/orgs/org-1/verified-proofs/p-1":  "credDefId",
		"/v1/platform/schemas":                "schemaLedgerId",
		"/v1/platform/cred-defs":              "credentialDefinitionId",
		"/v1/orgs/org-1/verified-proofs/p-1/": "",
	} {
		if body := get(t, f, path); !strings.Contains(body, want) {
			t.Errorf("get %s = %q", path, body)
		}
	}
	f.SetProof(fake.ProofDone)
	f.SetVerified(fake.VerifiedPE)
	if body := get(t, f, "/v1/orgs/org-1/proofs/p-1"); !strings.Contains(body, `"done"`) {
		t.Errorf("proof = %q", body)
	}
	if body := get(t, f, "/v1/orgs/org-1/verified-proofs/p-1"); strings.Contains(body, "credDefId") {
		t.Errorf("verified = %q", body)
	}
	f.SetProofs(fake.NoProofs)
	f.SetPlatformSchemas(fake.NoPlatformSchemas)
	for _, path := range []string{"/v1/orgs/org-1/proofs", "/v1/platform/schemas"} {
		if code := status(t, f, path); code != http.StatusNotFound {
			t.Errorf("%s = %d", path, code)
		}
	}
}

// statusOf sends one request and returns its status code.
func statusOf(t *testing.T, f *fake.Server, method, path, body string) int {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, f.URL()+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := f.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	if cerr := resp.Body.Close(); cerr != nil {
		t.Errorf("the close failed: %v", cerr)
	}
	return resp.StatusCode
}

// TestFakeKeepsTheNotifySettings is P6-C8: the fake keeps the webhook,
// the notification address and the client credential of each
// organisation, as the platform does.
func TestFakeKeepsTheNotifySettings(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	if body := get(t, f, "/v1/webhooks/orgs/webhookurl?orgId=org-2"); !strings.Contains(body, `"webhookUrl": null`) {
		t.Errorf("no webhook = %s", body)
	}
	post(t, f, "/v1/webhooks/orgs/org-2/register", `{"webhookUrl":"https://hooks.example.org/vca"}`)
	if body := get(t, f, "/v1/webhooks/orgs/webhookurl?orgId=org-2"); !strings.Contains(body, "hooks.example.org") {
		t.Errorf("a webhook = %s", body)
	}
	path := "/v1/notification/register/webhook-endpoint"
	if got := statusOf(t, f, http.MethodPost, path, `{"orgId":"org-2"}`); got != http.StatusCreated {
		t.Errorf("first address = %d", got)
	}
	if got := statusOf(t, f, http.MethodPost, path, `{"orgId":"org-2"}`); got != http.StatusInternalServerError {
		t.Errorf("second address = %d", got)
	}
	if got := statusOf(t, f, http.MethodPost, path, `{`); got != http.StatusInternalServerError {
		t.Errorf("a broken body = %d", got)
	}
	creds := "/v1/orgs/org-2/client_credentials" //nolint:gosec // G101: this is a path, not a credential.
	for _, step := range []struct {
		method string
		want   int
	}{
		{http.MethodGet, http.StatusNotFound}, {http.MethodPost, http.StatusCreated}, {http.MethodGet, http.StatusOK},
		{http.MethodDelete, http.StatusAccepted}, {http.MethodGet, http.StatusNotFound}, {http.MethodPut, http.StatusMethodNotAllowed},
	} {
		if got := statusOf(t, f, step.method, creds, ""); got != step.want {
			t.Errorf("%s %s = %d, want %d", step.method, creds, got, step.want)
		}
	}
}

// TestFakeKeepsTheEcosystems is P6-C9: the fake keeps the ecosystem
// switch, the invitations of the platform admin, and each ecosystem with
// its lead and members, as the platform does.
func TestFakeKeepsTheEcosystems(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	id := fake.EcosystemID
	if body := get(t, f, "/v1/ecosystem/status"); !strings.Contains(body, `"data": false`) {
		t.Errorf("status = %s", body)
	}
	steps := []struct {
		method, path, body string
		want               int
	}{
		{http.MethodGet, "/v1/ecosystem?orgId=org-2", "", http.StatusForbidden},
		{http.MethodPost, "/v1/invitations", `{"email":"admin@example.org"}`, http.StatusForbidden},
		{http.MethodPut, "/v1/config/ecosystem", `{"isEcosystemEnabled":true}`, http.StatusOK},
		{http.MethodPost, "/v1/ecosystem?orgId=org-2", `{"name":"Health","description":"Health agencies"}`, http.StatusForbidden},
		{http.MethodPost, "/v1/invitations", `{"email":"admin@example.org"}`, http.StatusCreated},
		{http.MethodPost, "/v1/ecosystem?orgId=org-2", `{"name":"Health","description":"Health agencies"}`, http.StatusCreated},
		{http.MethodPost, "/v1/invitations", `{"email":"admin@example.org"}`, http.StatusCreated},
		{http.MethodPost, "/v1/ecosystem?orgId=org-2", `{"name":"Health","description":"Again"}`, http.StatusConflict},
		{http.MethodGet, "/v1/ecosystem/members?ecosystemId=" + id, "", http.StatusNotFound},
		{http.MethodPost, "/v1/ecosystem/invitation", `{"ecosystemId":"` + id + `","orgId":"org-2"}`, http.StatusBadRequest},
		{http.MethodPost, "/v1/ecosystem/invitation", `{"ecosystemId":"` + id + `","orgId":"org-3"}`, http.StatusCreated},
		{http.MethodPost, "/v1/ecosystem/invitation", `{`, http.StatusBadRequest},
		{http.MethodPut, "/v1/config/ecosystem", `{`, http.StatusBadRequest},
		{http.MethodPatch, "/v1/ecosystem", "", http.StatusNotFound},
	}
	for _, s := range steps {
		if got := statusOf(t, f, s.method, s.path, s.body); got != s.want {
			t.Errorf("%s %s %s = %d, want %d", s.method, s.path, s.body, got, s.want)
		}
	}
	for org, want := range map[string]string{"org-2": `"memberCount": 1`, "org-3": `"name": "Health"`} {
		body := get(t, f, "/v1/ecosystem?orgId="+org)
		if !strings.Contains(body, want) || !strings.Contains(body, `"id": "org-2"`) || !strings.Contains(body, "Health agencies") {
			t.Errorf("%s lists %s", org, body)
		}
	}
	if body := get(t, f, "/v1/ecosystem?orgId=org-4"); !strings.Contains(body, `"data": []`) {
		t.Errorf("org-4 lists %s", body)
	}
	if body := get(t, f, "/v1/ecosystem/members?ecosystemId="+id); !strings.Contains(body, `"id": "org-3"`) {
		t.Errorf("members = %s", body)
	}
	remove := `{"ecosystemId":"` + id + `","orgIds":["org-3"]}`
	for _, want := range []int{http.StatusCreated, http.StatusBadRequest} {
		if got := statusOf(t, f, http.MethodDelete, "/v1/ecosystem/member", remove); got != want {
			t.Errorf("remove = %d, want %d", got, want)
		}
	}
	if body := get(t, f, "/v1/ecosystem/status"); !strings.Contains(body, `"data": true`) {
		t.Errorf("status = %s", body)
	}
}

// TestFakeKeepsTheCertificates is P6-C9: the fake keeps the status of
// each certificate of the recorded list. It refuses a second active
// certificate of one key type, as the platform does, and filters the
// list by status.
func TestFakeKeepsTheCertificates(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	older, imported := "/v1/x509/org-1/"+fake.OlderCertificateID, "/v1/x509/org-1/"+fake.ImportedCertificateID
	if body := get(t, f, imported); !strings.Contains(body, `"status": "Pending activation"`) {
		t.Errorf("imported = %s", body)
	}
	if body := get(t, f, "/v1/x509/org-1?status=Active&keyType=P-256"); !strings.Contains(body, fake.OlderCertificateID) || strings.Contains(body, fake.ImportedCertificateID) {
		t.Errorf("active list = %s", body)
	}
	steps := []struct {
		method, path string
		want         int
	}{
		{http.MethodPut, "/v1/x509/org-1/activate/" + fake.ImportedCertificateID, http.StatusConflict},
		{http.MethodPut, "/v1/x509/org-1/deactivate/" + fake.OlderCertificateID, http.StatusOK},
		{http.MethodPut, "/v1/x509/org-1/activate/" + fake.ImportedCertificateID, http.StatusOK},
		{http.MethodGet, "/v1/x509/org-1/unknown", http.StatusNotFound},
		{http.MethodPut, "/v1/x509/org-1/activate/unknown", http.StatusNotFound},
		{http.MethodDelete, older, http.StatusNotFound},
	}
	for _, s := range steps {
		if got := statusOf(t, f, s.method, s.path, ""); got != s.want {
			t.Errorf("%s %s = %d, want %d", s.method, s.path, got, s.want)
		}
	}
	if body := get(t, f, "/v1/x509/org-1?status=Active&keyType=P-256"); !strings.Contains(body, fake.ImportedCertificateID) || strings.Contains(body, fake.OlderCertificateID) {
		t.Errorf("active list after the change = %s", body)
	}
	if body := get(t, f, older); !strings.Contains(body, `"status": "In Active"`) {
		t.Errorf("older = %s", body)
	}
}
