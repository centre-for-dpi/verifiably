// SPDX-License-Identifier: Apache-2.0

package credebl

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// P6-C7: the OID4VC holder calls of the shared agent (ADR-062 decision
// 8).

// fixture reads one answer of testdata/doc.
func fixture(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "doc", name)) //nolint:gosec // G304: a fixed fixture name
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// TestAgentClaimsAnOid4vciOffer: the agent resolves the offer, which
// names its grant and whether it needs a transaction code, and then
// claims the configurations of the offer with the code.
func TestAgentClaimsAnOid4vciOffer(t *testing.T) {
	a := newAgentServer(t)
	ctx := context.Background()
	agent := a.agent()
	a.answer("POST /openid4vc/holder/resolve-credential-offer", fixture(t, "agent-oid4vci-offer-resolved.json"))
	a.answer("POST /openid4vc/holder/request-credential", fixture(t, "agent-oid4vci-credential-stored.json"))
	offer, err := agent.ResolveOffer(ctx, testTenant, "openid-credential-offer://?credential_offer_uri=x")
	if err != nil {
		t.Fatal(err)
	}
	if pre, code := offer.PreAuthorized(); !pre || !code || strings.Join(offer.Payload.ConfigurationIDs, ",") != "FarmerCredential-sdjwt" {
		t.Errorf("offer %+v", offer)
	}
	if body, _, _ := a.seen("POST /openid4vc/holder/resolve-credential-offer"); string(body) != `{"credentialOfferUri":"openid-credential-offer://?credential_offer_uri=x"}` {
		t.Errorf("resolve %s", body)
	}
	stored, err := agent.RequestCredential(ctx, testTenant, "openid-credential-offer://?credential_offer_uri=x", offer.Payload.ConfigurationIDs, "1234")
	if err != nil || len(stored) != 1 || stored[0].Type != RecordSdJwt || !strings.HasPrefix(stored[0].Compact(), "ey") || stored[0].Tags["vct"] != "FarmerCredential" {
		t.Fatalf("stored %+v, %v", stored, err)
	}
	if body, _, _ := a.seen("POST /openid4vc/holder/request-credential"); string(body) != `{"credentialOfferUri":"openid-credential-offer://?credential_offer_uri=x","credentialsToRequest":["FarmerCredential-sdjwt"],"txCode":"1234"}` {
		t.Errorf("request %s", body)
	}
	a.answer("POST /openid4vc/holder/resolve-credential-offer", fixture(t, "agent-oid4vci-offer-authorization-code.json"))
	if offer, err = agent.ResolveOffer(ctx, testTenant, "x"); err != nil {
		t.Fatal(err)
	}
	if pre, _ := offer.PreAuthorized(); pre {
		t.Error("an authorization code offer reads as pre-authorized")
	}
}

// TestAgentListsHeldOid4vcCredentials: the agent lists the SD-JWT and
// the mdoc credentials of a tenant, and removes one by its type.
func TestAgentListsHeldOid4vcCredentials(t *testing.T) {
	a := newAgentServer(t)
	ctx := context.Background()
	agent := a.agent()
	a.answer("GET /openid4vc/holder/sd-jwt-vcs", fixture(t, "agent-sd-jwt-vcs.json"))
	a.answer("GET /openid4vc/holder/mdoc-vcs", fixture(t, "agent-mdoc-vcs.json"))
	sd, err := agent.SdJwtCredentials(ctx, testTenant)
	if err != nil || len(sd) != 1 || sd[0].Compact() == "" || sd[0].CreatedAt.IsZero() {
		t.Fatalf("sd-jwt %+v, %v", sd, err)
	}
	mdoc, err := agent.MdocCredentials(ctx, testTenant)
	if err != nil || len(mdoc) != 1 || mdoc[0].Type != RecordMdoc || mdoc[0].Compact() != "[issuer signed]" || mdoc[0].Tags["docType"] != "org.iso.18013.5.1.mDL" {
		t.Fatalf("mdoc %+v, %v", mdoc, err)
	}
	if err = agent.DeleteHeld(ctx, testTenant, HeldSdJwt, "s-1"); err != nil {
		t.Fatal(err)
	}
	if body, _, _ := a.seen("DELETE /openid4vc/holder/credential"); string(body) != `{"credentialId":"s-1","credentialType":"sd-jwt-vc"}` {
		t.Errorf("delete %s", body)
	}
	var none AgentStored
	if none.Compact() != "" {
		t.Error("a record with no instance")
	}
}

// TestAgentAnswersAnOid4vpRequest: the agent resolves the request, which
// names the credential the agent picks for each query, and answers it.
func TestAgentAnswersAnOid4vpRequest(t *testing.T) {
	a := newAgentServer(t)
	ctx := context.Background()
	agent := a.agent()
	a.answer("POST /openid4vc/holder/resolve-proof-request", fixture(t, "agent-oid4vp-request-resolved.json"))
	a.answer("POST /openid4vc/holder/accept-proof-request", fixture(t, "agent-oid4vp-request-accepted.json"))
	req, err := agent.ResolveProofRequest(ctx, testTenant, "openid4vp://?request_uri=x")
	if err != nil {
		t.Fatal(err)
	}
	if picks := req.Picks(); len(picks) != 1 || picks["farmer"] != "e1f2a3b4-c5d6-4e7f-8a9b-0c1d2e3f4a5b" || req.Verifier.ClientID != "x509_san_dns:verifier.example.org" {
		t.Errorf("request %+v", req)
	}
	answer, err := agent.AcceptOid4vpRequest(ctx, testTenant, "openid4vp://?request_uri=x")
	if err != nil || !answer.Accepted() {
		t.Fatalf("answer %+v, %v", answer, err)
	}
	if body, _, _ := a.seen("POST /openid4vc/holder/accept-proof-request"); string(body) != `{"proofRequestUri":"openid4vp://?request_uri=x"}` {
		t.Errorf("accept %s", body)
	}
	a.answer("POST /openid4vc/holder/accept-proof-request", fixture(t, "agent-oid4vp-request-refused.json"))
	if answer, err = agent.AcceptOid4vpRequest(ctx, testTenant, "x"); err != nil || answer.Accepted() {
		t.Errorf("a refused answer %+v, %v", answer, err)
	}
	var pe ResolvedRequest
	if len(pe.Picks()) != 0 {
		t.Error("a request with no DCQL query picks")
	}
	a.fail("POST /openid4vc/holder/resolve-proof-request", http.StatusBadRequest)
	if _, err = agent.ResolveProofRequest(ctx, testTenant, "x"); err == nil {
		t.Error("a refused request")
	}
}

// TestResolvedRequestDisclosures is finding 2.1 of the CREDEBL review:
// the adapter reads what the agent sends for each query. The agent
// discloses the output of the first valid claim set, so a claim that a
// later claim set leaves out still travels.
func TestResolvedRequestDisclosures(t *testing.T) {
	a := newAgentServer(t)
	ctx := context.Background()
	agent := a.agent()
	a.answer("POST /openid4vc/holder/resolve-proof-request", fixture(t, "agent-oid4vp-request-resolved-claim-sets.json"))
	req, err := agent.ResolveProofRequest(ctx, testTenant, "openid4vp://?request_uri=x")
	if err != nil {
		t.Fatal(err)
	}
	got := req.Disclosures()
	if len(got) != 1 || got[0].Query != "farmer" || strings.Join(got[0].Claims, ",") != "fullName,hectares" || got[0].Whole {
		t.Fatalf("claim sets: %+v", got)
	}
	a.answer("POST /openid4vc/holder/resolve-proof-request", fixture(t, "agent-oid4vp-request-resolved.json"))
	if req, err = agent.ResolveProofRequest(ctx, testTenant, "x"); err != nil {
		t.Fatal(err)
	}
	if got = req.Disclosures(); len(got) != 1 || strings.Join(got[0].Claims, ",") != "fullName" {
		t.Fatalf("valid claims only: %+v", got)
	}
	cases := map[string]struct {
		body   string
		claims string
		whole  bool
	}{
		"a query with no claim sends the whole credential": {
			body: `{"authorizationRequestPayload":{"dcql_query":{"credentials":[{"id":"q","format":"dc+sd-jwt"}]}},
"dcql":{"queryResult":{"credential_matches":{"q":{"success":true,"valid_credentials":[{"record":{"id":"r"},
"claims":{"success":true,"valid_claim_sets":[{"success":true,"output":{"b":1,"a":{"c":2}}}]}}]}}}}}`,
			claims: "a,b", whole: true,
		},
		"a claim set index with no claim indexes": {
			body: `{"authorizationRequestPayload":{"dcql_query":{"credentials":[{"id":"q","format":"dc+sd-jwt",
"claims":[{"id":"x","path":["address","street"]},{"id":"y","path":["age"]}],"claim_sets":[["y"],["x","y"]]}]}},
"dcql":{"queryResult":{"credential_matches":{"q":{"success":true,"valid_credentials":[{"record":{"id":"r"},
"claims":{"success":true,"valid_claim_sets":[{"success":true,"claim_set_index":1,"output":{}}]}}]}}}}}`,
			claims: "address.street,age",
		},
		"the query of the result when the payload has none": {
			body: `{"dcql":{"queryResult":{"credentials":[{"id":"q","format":"dc+sd-jwt","claims":[{"path":["age"]}]}],
"credential_matches":{"q":{"success":true,"valid_credentials":[{"record":{"id":"r"}}]}}}}}`,
			claims: "age",
		},
		"claim indexes out of range fall back to the query": {
			body: `{"authorizationRequestPayload":{"dcql_query":{"credentials":[{"id":"q","format":"dc+sd-jwt",
"claims":[{"path":["age"]}]}]}},
"dcql":{"queryResult":{"credential_matches":{"q":{"success":true,"valid_credentials":[{"record":{"id":"r"},
"claims":{"success":true,"valid_claim_sets":[{"success":true,"valid_claim_indexes":[4]}]}}]}}}}}`,
			claims: "age",
		},
	}
	for name, c := range cases {
		a.answer("POST /openid4vc/holder/resolve-proof-request", c.body)
		if req, err = agent.ResolveProofRequest(ctx, testTenant, "x"); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got = req.Disclosures()
		if len(got) != 1 || strings.Join(got[0].Claims, ",") != c.claims || got[0].Whole != c.whole {
			t.Errorf("%s: %+v", name, got)
		}
	}
	a.answer("POST /openid4vc/holder/resolve-proof-request", `{"dcql":{"queryResult":{"credential_matches":{"q":{"success":false}}}}}`)
	if req, err = agent.ResolveProofRequest(ctx, testTenant, "x"); err != nil {
		t.Fatal(err)
	}
	if got = req.Disclosures(); len(got) != 0 {
		t.Errorf("a query the wallet cannot answer: %+v", got)
	}
	var pe ResolvedRequest
	if len(pe.Disclosures()) != 0 {
		t.Error("a request with no DCQL query discloses")
	}
}
