// SPDX-License-Identifier: Apache-2.0

package scanner_test

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	ingestv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/ingest/v1"
	shared "github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/scanner"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/txn"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// sdjwtSample is an SD-JWT VC with one disclosure.
const sdjwtSample = "eyJhbGciOiJFUzI1NiJ9.eyJ2Y3QiOiJodHRwczovL2V4YW1wbGUudGVzdC9waWQifQ.c2ln~WyJzYWx0IiwiZ2l2ZW5fbmFtZSIsIkFzaGEiXQ~"

// setup wires a server over the camera page.
func setup(t *testing.T) *httptest.Server {
	t.Helper()
	store, err := txn.NewStore(shared.Memory())
	if err != nil {
		t.Fatal(err)
	}
	key, err := jose.GenerateKey(jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := service.New(service.Options{
		Store: store, SigningKey: key, BaseURL: "https://verify.example",
		Now: func() time.Time { return time.Unix(1700000000, 0).UTC() },
	})
	if err != nil {
		t.Fatal(err)
	}
	page, err := scanner.New(scanner.Options{Client: svc})
	if err != nil {
		t.Fatal(err)
	}
	if page.Prefix() != "/scan" {
		t.Fatalf("prefix = %q", page.Prefix())
	}
	mux := http.NewServeMux()
	page.Register(mux)
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

// get performs one GET and returns the status and the body.
func get(t *testing.T, s *httptest.Server, path string) (int, string, http.Header) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, s.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
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
	return resp.StatusCode, string(body), resp.Header
}

// post sends one form and returns the status and the body.
func post(t *testing.T, s *httptest.Server, form url.Values, header http.Header) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, s.URL+"/scan/ingest", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range header {
		req.Header[k] = v
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
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

// upload sends one multipart file and returns the status and the body.
func upload(t *testing.T, s *httptest.Server, field, name string, content []byte) (int, string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, err := w.CreateFormFile(field, name)
	if err != nil {
		t.Fatal(err)
	}
	if _, serr := part.Write(content); serr != nil {
		t.Fatal(serr)
	}
	if serr := w.Close(); serr != nil {
		t.Fatal(serr)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, s.URL+"/scan/ingest", &buf)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
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

func TestNewNeedsClient(t *testing.T) {
	if _, err := scanner.New(scanner.Options{}); err == nil {
		t.Error("the page needs a client")
	}
	page, err := scanner.New(scanner.Options{Client: &service.Service{}, Prefix: "camera/"})
	if err != nil {
		t.Fatal(err)
	}
	if page.Prefix() != "/camera" {
		t.Errorf("prefix = %q", page.Prefix())
	}
}

func TestCameraPage(t *testing.T) {
	s := setup(t)
	status, body, _ := get(t, s, "/scan/")
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	a11ytest.AssertPage(t, body)
	if !strings.Contains(body, "Start camera") || !strings.Contains(body, "scan-video") {
		t.Errorf("the page carries the camera controls, got %s", body)
	}
	if !strings.Contains(body, "/scan/static/scanner.js") || !strings.Contains(body, "/scan/static/jsqr.min.js") {
		t.Error("the page loads the vendored scripts")
	}
	if !strings.Contains(body, "Upload a file") || !strings.Contains(body, "Paste a credential") {
		t.Error("the page carries the fallbacks")
	}
}

func TestStaticAssets(t *testing.T) {
	s := setup(t)
	for _, name := range []string{"scanner.js", "jsqr.min.js"} {
		status, body, header := get(t, s, "/scan/static/"+name)
		if status != http.StatusOK {
			t.Errorf("GET %s answered %d", name, status)
		}
		if len(body) == 0 {
			t.Errorf("%s is empty", name)
		}
		if header.Get("Cache-Control") == "" || header.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s headers = %v", name, header)
		}
	}
	missing, _, _ := get(t, s, "/scan/static/nope.js")
	if missing != http.StatusNotFound {
		t.Errorf("a missing asset answers %d", missing)
	}
}

func TestIngestPaste(t *testing.T) {
	s := setup(t)
	status, body := post(t, s, url.Values{"payload": {sdjwtSample}}, nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	a11ytest.AssertPage(t, body)
	if !strings.Contains(body, "The service read the input") {
		t.Errorf("the page shows the result, got %s", body)
	}
	if !strings.Contains(body, "One credential") {
		t.Error("the page names what the decoders found")
	}
}

func TestIngestFragmentForScript(t *testing.T) {
	s := setup(t)
	status, body := post(t, s, url.Values{"payload": {sdjwtSample}}, http.Header{"Hx-Request": []string{"true"}})
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	if strings.Contains(body, "<html") {
		t.Error("an htmx request gets a fragment, not a page")
	}
	a11ytest.AssertFragment(t, body)
	fetchStatus, fetchBody := post(t, s, url.Values{"payload": {sdjwtSample}},
		http.Header{"Accept": []string{"*/*"}, "Sec-Fetch-Mode": []string{"cors"}})
	if fetchStatus != http.StatusOK || strings.Contains(fetchBody, "<html") {
		t.Error("the browser script gets a fragment too")
	}
}

func TestIngestUpload(t *testing.T) {
	s := setup(t)
	status, body := upload(t, s, "upload", "credential.txt", []byte(sdjwtSample))
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	a11ytest.AssertPage(t, body)
	if !strings.Contains(body, "The service read the input") {
		t.Errorf("the page shows the result, got %s", body)
	}
}

func TestIngestProblems(t *testing.T) {
	s := setup(t)
	empty, body := post(t, s, url.Values{}, nil)
	if empty != http.StatusOK {
		t.Fatalf("status = %d", empty)
	}
	a11ytest.AssertPage(t, body)
	if !strings.Contains(body, "the page received no file and no text") {
		t.Errorf("the page names the problem, got %s", body)
	}
	blankStatus, blank := upload(t, s, "upload", "empty.txt", nil)
	if blankStatus != http.StatusOK || !strings.Contains(blank, "the file is empty") {
		t.Errorf("status = %d, body = %s", blankStatus, blank)
	}
	otherStatus, other := upload(t, s, "other", "x.txt", []byte("hello"))
	if otherStatus != http.StatusOK || !strings.Contains(other, "no file and no text") {
		t.Errorf("a form without the upload field falls back to the text, got %s", other)
	}
}

func TestIngestUnknownBytes(t *testing.T) {
	s := setup(t)
	status, body := post(t, s, url.Values{"payload": {"just some text"}}, nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	if !strings.Contains(body, "Bytes the decoders do not know") {
		t.Errorf("the page names the unknown content, got %s", body)
	}
}

func TestCarrierAndDetectedText(t *testing.T) {
	carriers := map[ingestv1.Carrier]string{
		ingestv1.Carrier_CARRIER_OID4VP:          "OID4VP response", //nolint:staticcheck // the deprecated value stays readable
		ingestv1.Carrier_CARRIER_OID4VP_RESPONSE: "OID4VP response",
		ingestv1.Carrier_CARRIER_OID4VP_REQUEST:  "OID4VP request",
		ingestv1.Carrier_CARRIER_IMAGE:           "Image",
		ingestv1.Carrier_CARRIER_PDF:             "PDF",
		ingestv1.Carrier_CARRIER_XML:             "XML",
		ingestv1.Carrier_CARRIER_JSON:            "JSON",
		ingestv1.Carrier_CARRIER_QR:              "QR code",
		ingestv1.Carrier_CARRIER_QR_CLAIM169:     "Claim 169 QR code",
		ingestv1.Carrier_CARRIER_UNSPECIFIED:     "Unknown",
	}
	for carrier, want := range carriers {
		if got := scanner.CarrierText(carrier); got != want {
			t.Errorf("CarrierText(%v) = %q", carrier, got)
		}
	}
	detected := map[ingestv1.DetectedType]string{
		ingestv1.DetectedType_DETECTED_TYPE_CREDENTIAL:   "One credential",
		ingestv1.DetectedType_DETECTED_TYPE_PRESENTATION: "A presentation",
		ingestv1.DetectedType_DETECTED_TYPE_CWT_CLAIM169: "A CWT with claim 169",
		ingestv1.DetectedType_DETECTED_TYPE_PIXELPASS:    "A legacy PixelPass code",
		ingestv1.DetectedType_DETECTED_TYPE_UNKNOWN:      "Bytes the decoders do not know",
	}
	for value, want := range detected {
		if got := scanner.DetectedText(value); got != want {
			t.Errorf("DetectedText(%v) = %q", value, got)
		}
	}
}

func TestIngestRefusedByTheDecoder(t *testing.T) {
	s := setup(t)
	status, body := post(t, s, url.Values{"payload": {"eyJhbGciOiJFUzI1NiJ9.e30.c2ln~!!~"}}, nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	a11ytest.AssertPage(t, body)
	if !strings.Contains(body, "The service could not read the input") {
		t.Errorf("the page names the problem, got %s", body)
	}
	if !strings.Contains(body, "Not read") {
		t.Error("the page carries the badge of a refused input")
	}
}

func TestIngestJSONPayload(t *testing.T) {
	s := setup(t)
	document := `{"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiableCredential"]}`
	status, body := post(t, s, url.Values{"payload": {document}}, nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	a11ytest.AssertPage(t, body)
	if !strings.Contains(body, "VerifiableCredential") {
		t.Errorf("the page shows the decoded payload, got %s", body)
	}
}
