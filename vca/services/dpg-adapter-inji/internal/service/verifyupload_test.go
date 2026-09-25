// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/fake"
)

// credentialText reads the credential of a recorded answer as the text
// a staff member pastes.
func credentialText(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(testdata + "/" + name) //nolint:gosec // G304: a fixed fixture name
	if err != nil {
		t.Fatal(err)
	}
	var answer struct {
		Credential json.RawMessage `json:"credential"`
	}
	if err := json.Unmarshal(raw, &answer); err != nil {
		t.Fatal(err)
	}
	var compact string
	if json.Unmarshal(answer.Credential, &compact) == nil {
		return compact
	}
	return string(answer.Credential)
}

// verifyText calls VerifyCredential with pasted text.
func verifyText(svc interface {
	VerifyCredential(context.Context, *connect.Request[backendv1.VerifyCredentialRequest]) (
		*connect.Response[backendv1.VerifyCredentialResponse], error)
}, text, mediaType string,
) (*backendv1.VerifyCredentialResponse, error) {
	resp, err := svc.VerifyCredential(context.Background(), connect.NewRequest(&backendv1.VerifyCredentialRequest{
		Payload: []byte(text), MediaType: mediaType,
	}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// checks maps the checks of an answer by name.
func checks(r *backendv1.VerifyCredentialResponse) map[string]*backendv1.GetResultResponse_DpgCheck {
	out := map[string]*backendv1.GetResultResponse_DpgCheck{}
	for _, c := range r.GetDpgChecks() {
		out[c.GetName()] = c
	}
	return out
}

// TestVerifyCredentialMapsChecks sends a pasted credential to the
// credential check of Inji Verify and maps its one status onto the
// checks it covers.
func TestVerifyCredentialMapsChecks(t *testing.T) {
	svc, f := newService(t, both)
	ldp := credentialText(t, "credential-ldp.json")
	got, err := verifyText(svc, ldp, "")
	if err != nil {
		t.Fatal(err)
	}
	c := checks(got)
	if !got.GetVerified() || !c["signature"].GetPassed() || !c["expiry"].GetPassed() || !c["revocation"].GetPassed() ||
		!c["inji-verification-status"].GetPassed() {
		t.Fatalf("success %v", got)
	}
	if !strings.Contains(string(f.Request("/v1/verify/vc-verification")), "FarmerCredential") ||
		f.ContentType("/v1/verify/vc-verification") != "application/json" {
		t.Fatalf("the check took %q", f.ContentType("/v1/verify/vc-verification"))
	}
	cases := []struct {
		answer fake.Answer
		failed string
		absent string
	}{
		{fake.VerificationExpired, "expiry", "revocation"},
		{fake.VerificationRevoked, "revocation", "expiry"},
		{fake.VerificationInvalid, "signature", "expiry"},
	}
	for _, tc := range cases {
		f.SetVerification(tc.answer)
		got, err := verifyText(svc, ldp, "application/ld+json")
		if err != nil {
			t.Fatal(err)
		}
		c := checks(got)
		if got.GetVerified() || c[tc.failed] == nil || c[tc.failed].GetPassed() || c[tc.failed].GetReason() == "" || c[tc.absent] != nil {
			t.Errorf("%s: %v", tc.answer, got)
		}
	}
	f.SetVerification(fake.VerificationSuccess)
	sd := credentialText(t, "credential-sdjwt.json")
	if _, err := verifyText(svc, sd, "text/plain"); err != nil {
		t.Fatal(err)
	}
	if ct := f.ContentType("/v1/verify/vc-verification"); ct != "application/vc+sd-jwt" {
		t.Fatalf("an SD-JWT went as %q", ct)
	}
}

// TestVerifyCredentialRefusesWhatVerifyCannotCheck answers with a reason
// for an input Inji Verify does not check, and maps a failed call.
func TestVerifyCredentialRefusesWhatVerifyCannotCheck(t *testing.T) {
	svc, f := newService(t, both)
	for _, text := range []string{"", "not a credential", "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ4In0.c2ln"} {
		_, err := verifyText(svc, text, "")
		wantCode(t, err, connect.CodeInvalidArgument)
	}
	f.SetStatus("/v1/verify/vc-verification", 503)
	_, err := verifyText(svc, credentialText(t, "credential-ldp.json"), "")
	wantCode(t, err, connect.CodeUnavailable)
	issuer, _ := newService(t, roles{certify: true})
	_, err = verifyText(issuer, credentialText(t, "credential-ldp.json"), "")
	wantCode(t, err, connect.CodeUnimplemented)
}

// TestVerifyUploadListed lists FEATURE_VERIFY_UPLOAD with a Verify URL.
func TestVerifyUploadListed(t *testing.T) {
	for _, c := range []struct {
		r    roles
		want bool
	}{{roles{verify: true}, true}, {roles{certify: true}, false}} {
		svc, _ := newService(t, c.r)
		caps, err := svc.GetCapabilities(context.Background(), connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		if got := slices.Contains(caps.Msg.GetFeatures(), backendv1.Feature_FEATURE_VERIFY_UPLOAD); got != c.want {
			t.Errorf("roles %+v: listed %v", c.r, got)
		}
	}
}
