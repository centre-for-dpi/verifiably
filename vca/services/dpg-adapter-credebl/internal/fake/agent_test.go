// SPDX-License-Identifier: Apache-2.0

package fake_test

import (
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/fake"
)

// agentCall sends one call to the fake agent with a tenant token and
// returns the status and the body.
func agentCall(t *testing.T, a *fake.Agent, method, path, body, auth string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, a.URL()+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", auth)
	resp, err := a.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(resp.Body)
	if cerr := resp.Body.Close(); err != nil || cerr != nil {
		t.Fatalf("read: %v %v", err, cerr)
	}
	return resp.StatusCode, string(raw)
}

// TestFakeAgentServesTheHolderCalls is P6-C7: the fake agent answers
// each holder call from the agent answers of testdata/doc and keeps the
// state of one offer and one proof request.
func TestFakeAgentServesTheHolderCalls(t *testing.T) {
	a := fake.NewAgent(testdata)
	defer a.Close()
	const bearer = "Bearer [tenant token]" //nolint:gosec // G101: the placeholder token of the recorded answer.
	if code, _ := agentCall(t, a, http.MethodPost, "/agent/token", "", "wrong"); code != http.StatusUnauthorized {
		t.Errorf("a wrong API key: %d", code)
	}
	if code, body := agentCall(t, a, http.MethodPost, "/agent/token", "", fake.AgentAPIKey); code != http.StatusOK || !strings.Contains(body, "token") {
		t.Errorf("token: %d %s", code, body)
	}
	if code, _ := agentCall(t, a, http.MethodGet, "/dids", "", ""); code != http.StatusUnauthorized {
		t.Errorf("no token: %d", code)
	}
	_, first := agentCall(t, a, http.MethodPost, "/multi-tenancy/create-tenant", "{}", bearer)
	_, second := agentCall(t, a, http.MethodPost, "/multi-tenancy/create-tenant", "{}", bearer)
	if !strings.Contains(first, fake.FirstTenant) || !strings.Contains(second, "tenant-2") {
		t.Errorf("tenants %s %s", first, second)
	}
	for path, want := range map[string]string{
		"POST /multi-tenancy/get-token/x": "token", "POST /dids/write": fake.HolderDid, "GET /dids": "did:peer",
		"GET /didcomm/connections": "theirLabel", "GET /didcomm/connections/c": "completed",
		"GET /didcomm/credentials?state=done": "anoncreds", "GET /didcomm/credentials/w3c": "PermanentResidentCard",
		"GET /didcomm/credentials/" + fake.OfferRecord + "/form-data": "offerAttributes",
		"GET /didcomm/credentials/" + fake.OfferRecord:                "offer-received",
		"GET /didcomm/proofs/" + fake.ProofRecord + "/form-data":      "requested_predicates",
		"GET /didcomm/proofs/" + fake.ProofRecord:                     "request-received",
		"DELETE /openid4vc/holder/credential":                         "{}",
		"GET /didcomm/credentials":                                    "[]",
		"GET /didcomm/proofs":                                         "[]",
		"GET /nothing":                                                "404",
		"POST /openid4vc/holder/resolve-credential-offer":             "pre-authorized_code",
		"POST /openid4vc/holder/request-credential":                   "SdJwtVcRecord",
		"GET /openid4vc/holder/sd-jwt-vcs":                            fake.SdJwtRecord,
		"GET /openid4vc/holder/mdoc-vcs":                              fake.MdocRecord,
		"POST /openid4vc/holder/resolve-proof-request":                "dcql_query",
		"POST /openid4vc/holder/accept-proof-request":                 `"status": 200`,
	} {
		method, target, _ := strings.Cut(path, " ")
		if _, body := agentCall(t, a, method, target, "{}", bearer); !strings.Contains(body, want) {
			t.Errorf("%s: %s", path, body)
		}
	}
	// An invitation of each kind, and one the fake cannot read.
	for kind, want := range map[string]string{"offer": "[issuer organisation]", "request": "request-presentation", "connection": "out-of-band"} {
		code, body := agentCall(t, a, http.MethodPost, "/didcomm/oob/receive-invitation-url", `{"invitationUrl":"`+fake.Invitation(testdata, kind)+`"}`, bearer)
		if code != http.StatusOK || !strings.Contains(body, "outOfBandRecord") {
			t.Errorf("%s: %d %s %s", kind, code, body, want)
		}
	}
	for _, bad := range []string{`{`, `{"invitationUrl":"%"}`, `{"invitationUrl":"http://x?oob=%%%"}`, `{"invitationUrl":"http://x?oob=e30"}`} {
		if code, _ := agentCall(t, a, http.MethodPost, "/didcomm/oob/receive-invitation-url", bad, bearer); code != http.StatusBadRequest {
			t.Errorf("%s: %d", bad, code)
		}
	}
	if fake.Invitation(testdata, "none") != "" || fake.Invitation("/nowhere", "offer") != "" {
		t.Error("an unknown invitation")
	}
	// The offer and the request of the invitations wait on their threads
	// until the accept.
	if _, body := agentCall(t, a, http.MethodGet, "/didcomm/credentials?threadId="+fake.OfferThread, "", bearer); !strings.Contains(body, "offer-received") {
		t.Errorf("offer thread: %s", body)
	}
	if _, body := agentCall(t, a, http.MethodGet, "/didcomm/proofs?threadId="+fake.ProofThread, "", bearer); !strings.Contains(body, "request-received") {
		t.Errorf("proof thread: %s", body)
	}
	agentCall(t, a, http.MethodPost, "/didcomm/credentials/accept-offer", "{}", bearer)
	agentCall(t, a, http.MethodPost, "/didcomm/proofs/"+fake.ProofRecord+"/accept-request", "{}", bearer)
	a.SetCredentialEnd(fake.OfferAbandoned)
	a.SetProofEnd(fake.HolderProofAbandoned)
	if _, body := agentCall(t, a, http.MethodGet, "/didcomm/credentials/"+fake.OfferRecord, "", bearer); !strings.Contains(body, "abandoned") {
		t.Errorf("offer end: %s", body)
	}
	if _, body := agentCall(t, a, http.MethodGet, "/didcomm/proofs/"+fake.ProofRecord, "", bearer); !strings.Contains(body, "abandoned") {
		t.Errorf("proof end: %s", body)
	}
	a.SetOid4vc(fake.OfferAuthorizationCode, fake.Oid4vpRefused)
	if _, body := agentCall(t, a, http.MethodPost, "/openid4vc/holder/accept-proof-request", "{}", bearer); !strings.Contains(body, `"status": 400`) {
		t.Errorf("refused answer: %s", body)
	}
	a.SetInbox(true)
	if _, body := agentCall(t, a, http.MethodGet, "/didcomm/credentials?state=offer-received", "", bearer); body != "[]" {
		t.Errorf("an accepted offer stays in the inbox: %s", body)
	}
	a.SetStatus("GET /dids", http.StatusTeapot)
	if code, _ := agentCall(t, a, http.MethodGet, "/dids", "", bearer); code != http.StatusTeapot {
		t.Errorf("forced status: %d", code)
	}
	if len(a.Calls()) == 0 || string(a.Body("POST /didcomm/credentials/accept-offer")) != "{}" {
		t.Error("the fake records no call")
	}
	broken := fake.NewAgent("/nowhere")
	defer broken.Close()
	if code, _ := agentCall(t, broken, http.MethodGet, "/dids", "", bearer); code != http.StatusInternalServerError {
		t.Errorf("a missing answer: %d", code)
	}
	if code, _ := agentCall(t, broken, http.MethodPost, "/multi-tenancy/create-tenant", "", bearer); code != http.StatusInternalServerError {
		t.Errorf("a missing tenant answer: %d", code)
	}
}

// TestFakeAgentReportsWhatItPresented names the claims of an OID4VP
// answer: the output of the claim set or of the claims, and the plain
// claims of the stored SD-JWT.
func TestFakeAgentReportsWhatItPresented(t *testing.T) {
	a := fake.NewAgent("../../testdata")
	defer a.Close()
	const bearer = "Bearer [tenant token]" //nolint:gosec // G101: the placeholder token of the recorded answer.
	if got := a.Presented(); len(got) != 0 {
		t.Fatalf("before an answer: %v", got)
	}
	for resolved, want := range map[fake.Answer]string{
		fake.Oid4vpResolvedPlainClaims: "contactEmail,fullName,residentSince",
		fake.Oid4vpResolved:            "fullName",
		fake.Oid4vpResolvedClaimSets:   "fullName,hectares",
	} {
		a.SetResolved(resolved)
		agentCall(t, a, http.MethodPost, "/openid4vc/holder/accept-proof-request", "{}", bearer)
		got := a.Presented()
		slices.Sort(got)
		if strings.Join(got, ",") != want {
			t.Errorf("%s: presented %v, want %s", resolved, got, want)
		}
		a.Forget()
	}
	a.SetResolved("doc/missing.json")
	agentCall(t, a, http.MethodPost, "/openid4vc/holder/accept-proof-request", "{}", bearer)
	if got := a.Presented(); len(got) != 0 {
		t.Errorf("a missing answer presented %v", got)
	}
}
