// SPDX-License-Identifier: Apache-2.0

package fake_test

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/fake"
)

const testdata = "../../testdata"

func TestFakeServesTheRecordedAnswers(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	cases := map[string]string{
		"/v1/certify/issuance/.well-known/openid-credential-issuer": "credential_configurations_supported",
		"/v1/certify/pre-authorized-data":                           "credential_offer_uri",
		"/v1/certify/issuance/credential-offer/1":                   "pre-authorized_code",
		"/v1/certify/oauth/token":                                   "access_token",
		"/v1/certify/issuance/credential":                           "credentialSubject",
		"/v1/verify/vp-request":                                     "requestId",
		"/v1/verify/vp-result/tx":                                   "transactionId",
	}
	for path, want := range cases {
		if body := get(t, f, path); !strings.Contains(body, want) {
			t.Fatalf("%s returned %q, want a body with %q", path, body, want)
		}
	}
}

func TestFakeSwitchesTheAnswers(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	f.SetStaged(fake.StagedOfferError)
	if !strings.Contains(get(t, f, "/v1/certify/pre-authorized-data"), "errorCode") {
		t.Fatal("the error answer is missing")
	}
	f.SetCredential(fake.CredentialSdJwt)
	if !strings.Contains(get(t, f, "/v1/certify/issuance/credential"), "vc+sd-jwt") {
		t.Fatal("the SD-JWT answer is missing")
	}
	for _, answer := range []fake.Answer{
		fake.ResultSuccess, fake.ResultInvalid, fake.ResultWrongCredential, fake.ResultPending,
	} {
		f.SetResult(answer)
		if get(t, f, "/v1/verify/vp-result/tx") == "" {
			t.Fatalf("the answer %s is missing", answer)
		}
	}
}

func TestFakeForcesAStatusAndClearsIt(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	f.SetStatus("/v1/certify/oauth/token", http.StatusTeapot)
	if code := status(t, f, "/v1/certify/oauth/token"); code != http.StatusTeapot {
		t.Fatalf("status = %d", code)
	}
	f.SetStatus("/v1/certify/oauth/token", 0)
	if code := status(t, f, "/v1/certify/oauth/token"); code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
}

func TestFakeReportsAMissingRecording(t *testing.T) {
	f := fake.New("testdata-that-does-not-exist")
	defer f.Close()
	if code := status(t, f, "/v1/certify/oauth/token"); code != http.StatusInternalServerError {
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
	post(t, f, "/v1/certify/pre-authorized-data", `{"credential_configuration_id":"x"}`)
	if string(f.Request("/v1/certify/pre-authorized-data")) == "" {
		t.Fatal("the fake recorded no body")
	}
	var body map[string]any
	if err := f.RequestJSON("/v1/certify/pre-authorized-data", &body); err != nil {
		t.Fatalf("RequestJSON: %v", err)
	}
	if body["credential_configuration_id"] != "x" {
		t.Fatalf("body = %v", body)
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

func post(t *testing.T, f *fake.Server, path, body string) {
	t.Helper()
	resp, err := f.Client().Post(f.URL()+path, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("post %s: %v", path, err)
	}
	if cerr := resp.Body.Close(); cerr != nil {
		t.Errorf("the close failed: %v", cerr)
	}
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
