// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"connectrpc.com/connect"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/fake"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/inji"
)

func TestIssueRunsTheWholePreAuthorizedFlow(t *testing.T) {
	svc, f := newService(t, both)
	resp, err := svc.Issue(context.Background(),
		connect.NewRequest(&backendv1.IssueRequest{Spec: farmerSpec()}))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	credential := resp.Msg.GetCredential()
	if credential.GetFormat() != commonv1.Format_FORMAT_LDP_VC {
		t.Fatalf("format = %v", credential.GetFormat())
	}
	var doc map[string]any
	if err := json.Unmarshal(credential.GetPayload(), &doc); err != nil {
		t.Fatalf("the credential is not JSON: %v", err)
	}
	if doc["credentialStatus"] == nil {
		t.Fatal("the credential carries no status entry")
	}
	if resp.Msg.GetCredentialId() != "did:web:inji-certify.example.org#key-0" {
		t.Fatalf("credential id = %q, want the signing key", resp.Msg.GetCredentialId())
	}
	// The token call uses the form grant of OID4VCI.
	token := string(f.Request("/v1/certify/oauth/token"))
	if !strings.Contains(token, "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code") {
		t.Fatalf("token request = %q", token)
	}
	// The credential request repeats the context of the metadata.
	var body inji.CredentialRequest
	if err := f.RequestJSON("/v1/certify/issuance/credential", &body); err != nil {
		t.Fatalf("read the credential request: %v", err)
	}
	if body.Format != "ldp_vc" || body.CredentialDefinition == nil {
		t.Fatalf("request = %+v", body)
	}
	if len(body.CredentialDefinition.Context) != 2 {
		t.Fatalf("context = %v; Inji compares it with the metadata", body.CredentialDefinition.Context)
	}
	// The proof is bound to the issuer of the offer and to the nonce.
	header, claims := readProof(t, body.Proof.JWT)
	if _, ok := header["kid"]; ok {
		t.Fatal("the proof header must not name the key twice")
	}
	if header["typ"] != inji.ProofType {
		t.Fatalf("header = %v", header)
	}
	if claims["aud"] != "https://inji-certify.example.org" {
		t.Fatalf("audience = %v, want the issuer of the offer", claims["aud"])
	}
	if claims["nonce"] != "f2a1d7c4b90e4a1d" {
		t.Fatalf("nonce = %v", claims["nonce"])
	}
}

// readProof reads the header and the claims of a compact proof.
func readProof(t *testing.T, token string) (map[string]any, map[string]any) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("the proof is not a compact token: %q", token)
	}
	return decodePart(t, parts[0]), decodePart(t, parts[1])
}

func decodePart(t *testing.T, part string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("read: %v", err)
	}
	return out
}

func TestIssueReturnsACompactSdJwtUnchanged(t *testing.T) {
	svc, f := newService(t, both)
	f.SetCredential(fake.CredentialSdJwt)
	resp, err := svc.Issue(context.Background(), connect.NewRequest(&backendv1.IssueRequest{
		Spec: &backendv1.IssueSpec{
			ConfigurationId: "IdentityCredential",
			SubjectData:     `{"given_name":"Ada","family_name":"Lovelace","birth_date":"1815-12-10"}`,
		},
	}))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	payload := string(resp.Msg.GetCredential().GetPayload())
	if !strings.Contains(payload, "~") || strings.HasPrefix(payload, `"`) {
		t.Fatalf("payload = %q, a compact token keeps its form", payload)
	}
	if resp.Msg.GetCredential().GetFormat() != commonv1.Format_FORMAT_VC_SD_JWT {
		t.Fatalf("format = %v", resp.Msg.GetCredential().GetFormat())
	}
	var body inji.CredentialRequest
	if err := f.RequestJSON("/v1/certify/issuance/credential", &body); err != nil {
		t.Fatalf("read the credential request: %v", err)
	}
	if body.Vct != "https://inji-certify.example.org/credentials/IdentityCredential" {
		t.Fatalf("vct = %q", body.Vct)
	}
}

func TestIssueChecksItsInput(t *testing.T) {
	svc, _ := newService(t, both)
	_, err := svc.Issue(context.Background(), connect.NewRequest(&backendv1.IssueRequest{}))
	wantCode(t, err, connect.CodeInvalidArgument)
}

func TestIssueReportsAFailureOfEveryStep(t *testing.T) {
	cases := map[string]string{
		"/v1/certify/pre-authorized-data": "stage",
		"/v1/certify/oauth/token":         "redeem",
		"/v1/certify/issuance/credential": "credential",
	}
	for path := range cases {
		svc, f := newService(t, both)
		f.SetStatus(path, http.StatusBadGateway)
		_, err := svc.Issue(context.Background(),
			connect.NewRequest(&backendv1.IssueRequest{Spec: farmerSpec()}))
		wantCode(t, err, connect.CodeUnavailable)
	}
}

func TestIssueReportsABrokenOfferDocument(t *testing.T) {
	svc, f := newService(t, both)
	f.SetStatus("/v1/certify/issuance/credential-offer/0f0b0d26-6a45-4b31-9c17-3a5f7e1c2d84",
		http.StatusNotFound)
	_, err := svc.Issue(context.Background(),
		connect.NewRequest(&backendv1.IssueRequest{Spec: farmerSpec()}))
	wantCode(t, err, connect.CodeNotFound)
}

func TestIssueBatchReturnsOneItemPerSpec(t *testing.T) {
	svc, _ := newService(t, both)
	resp, err := svc.IssueBatch(context.Background(), connect.NewRequest(&backendv1.IssueBatchRequest{
		Specs: []*backendv1.IssueSpec{
			farmerSpec(),
			{ConfigurationId: "Unknown", SubjectData: `{"a":"b"}`},
		},
	}))
	if err != nil {
		t.Fatalf("IssueBatch: %v", err)
	}
	items := resp.Msg.GetItems()
	if len(items) != 2 {
		t.Fatalf("items = %d", len(items))
	}
	if items[0].GetPosition() != 0 || items[0].GetCredential() == nil {
		t.Fatalf("the first item failed: %v", items[0])
	}
	if items[1].GetError() == nil || items[1].GetError().GetCode() == "" {
		t.Fatalf("the second item must carry an error: %v", items[1])
	}
	if items[1].GetError().GetNextStep() == "" {
		t.Fatal("the error must tell the operator what to do")
	}
}

func TestIssueBatchChecksItsInput(t *testing.T) {
	svc, _ := newService(t, both)
	_, err := svc.IssueBatch(context.Background(), connect.NewRequest(&backendv1.IssueBatchRequest{}))
	wantCode(t, err, connect.CodeInvalidArgument)
}
