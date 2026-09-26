// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/authz"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/fake"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/service"
)

// bearer returns an access token that names subject, as the holder
// authorization server mints it. The fake reads sub and checks no
// signature.
func bearer(subject string) string {
	part := func(v map[string]any) string {
		raw, err := json.Marshal(v)
		if err != nil {
			return ""
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	return part(map[string]any{"alg": "RS256"}) + "." + part(map[string]any{"sub": subject, "scope": "vca_credential"}) + ".sig"
}

// askCredential posts one ldp_vc credential request of a type to the
// fake Certify with a token for subject.
func askCredential(t *testing.T, f *fake.Server, subject, typ string) (int, string) {
	t.Helper()
	body := `{"format":"ldp_vc","credential_definition":{"type":["VerifiableCredential","` + typ + `"]}}`
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		f.URL()+"/v1/certify/issuance/credential", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer(subject))
	resp, err := f.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Error(cerr)
		}
	}()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(raw)
}

// registerLdp registers one JSON-LD configuration through the adapter.
func registerLdp(t *testing.T, svc *service.Service, id, typ, schema string) {
	t.Helper()
	if _, err := svc.RegisterCredentialConfiguration(context.Background(), connect.NewRequest(
		&backendv1.RegisterCredentialConfigurationRequest{Configuration: &backendv1.CredentialConfiguration{
			Id: id, Type: typ, Format: commonv1.Format_FORMAT_LDP_VC, JsonSchema: schema,
		}})); err != nil {
		t.Fatalf("register %s: %v", id, err)
	}
}

// TestARowOfOneConfigurationIssuesNoOtherConfiguration is finding 1 of
// the review of the holder authorization server. Every configuration
// has the scope vca_credential, so a token for the row of one
// configuration authorizes a request for any other, and Certify fills
// the template of the requested configuration from that row. The guard
// in every template the adapter registers refuses a row of another
// configuration, for the holder channel and the pre-authorized channel
// (ADR-056 decision 1).
func TestARowOfOneConfigurationIssuesNoOtherConfiguration(t *testing.T) {
	var dir string
	svc, f := newServiceWith(t, both, func(o *serviceOptions) {
		o.AuthzIssuer = authzIssuer + "/"
		o.OfferIssuer = "http://inji-certify-nginx:8091"
		dir = o.Claims.Dir
	})
	f.SetClaimsDir(dir)
	f.SetNow(func() time.Time { return fixedTime })
	ctx := context.Background()
	registerLdp(t, svc, "farmer-registration_ldp_vc", "FarmerRegistration",
		`{"type":"object","properties":{"fullName":{"type":"string"},"email":{"type":"string"},"plotID":{"type":"string"}}}`)
	registerLdp(t, svc, "medical-licence_ldp_vc", "MedicalLicence",
		`{"type":"object","properties":{"holderName":{"type":"string"},"email":{"type":"string"},"licenceNumber":{"type":"string"}}}`)

	// The holder channel: a holder claims a farmer offer, and the
	// authorization server writes the row under the subject of its token.
	spec := &backendv1.IssueSpec{
		ConfigurationId: "farmer-registration_ldp_vc",
		SubjectData:     `{"fullName":"Amina Wanjiru","email":"amina@example.org","plotID":"PLOT-17"}`,
	}
	offer, err := svc.CreateOffer(ctx, connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec: spec, Channel: backendv1.Channel_CHANNEL_OID4VCI_AUTHCODE,
	}))
	if err != nil {
		t.Fatalf("CreateOffer: %v", err)
	}
	if serr := svc.StageOffer(ctx, offer.Msg.GetOfferId(), "holder-row", fixedTime.Add(authz.RowTTL)); serr != nil {
		t.Fatalf("StageOffer: %v", serr)
	}
	if status, body := askCredential(t, f, "holder-row", "MedicalLicence"); status == http.StatusOK ||
		strings.Contains(body, "PLOT-17") || strings.Contains(body, "Amina") {
		t.Errorf("a farmer row gave a medical licence: %d %s", status, body)
	}
	if status, body := askCredential(t, f, "holder-row", "FarmerRegistration"); status != http.StatusOK ||
		!strings.Contains(body, "PLOT-17") {
		t.Errorf("the farmer row gave no farmer credential: %d %s", status, body)
	}

	// The pre-authorized channel: the adapter stages the row, and Certify
	// puts the staged map in the subject of its own token.
	if _, ierr := svc.Issue(ctx, connect.NewRequest(&backendv1.IssueRequest{Spec: spec})); ierr != nil {
		t.Fatalf("Issue: %v", ierr)
	}
	var staged struct {
		Claims map[string]string `json:"claims"`
	}
	if rerr := f.RequestJSON("/v1/certify/pre-authorized-data", &staged); rerr != nil {
		t.Fatal(rerr)
	}
	subject := `{"id":"` + staged.Claims["id"] + `"}`
	if status, body := askCredential(t, f, subject, "MedicalLicence"); status == http.StatusOK || strings.Contains(body, "PLOT-17") {
		t.Errorf("a staged farmer row gave a medical licence: %d %s", status, body)
	}
}
