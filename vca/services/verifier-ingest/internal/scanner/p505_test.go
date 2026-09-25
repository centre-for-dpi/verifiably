// SPDX-License-Identifier: Apache-2.0

package scanner_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	"github.com/centre-for-dpi/vc-adapters/core/fetchguard"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/qrscan"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/scanner"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// TestCameraButtonIsPlain renders the camera start as a plain button
// with the id that the shared scanner script looks for, and without the
// disclosure attributes of the kit, so the kit script does not toggle
// the video against the scanner. Every element id the script reads is
// on the page (P5-05).
func TestCameraButtonIsPlain(t *testing.T) {
	mux := shellMux(t, nil)
	body := staffDo(t, mux, httptest.NewRequest(http.MethodGet, "/scan/", nil)).Body.String()
	a11ytest.AssertPage(t, body)
	button := regexp.MustCompile(`<button[^>]*id="scan-start"[^>]*>`).FindString(body)
	if button == "" {
		t.Fatal("the page has no scan-start button")
	}
	if !strings.Contains(button, `type="button"`) || strings.Contains(button, "aria-controls") || strings.Contains(button, "aria-expanded") {
		t.Errorf("the camera button %s is not a plain button", button)
	}
	script, err := qrscan.Files.ReadFile("static/" + qrscan.Script)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range regexp.MustCompile(`el\('([a-z-]+)'\)`).FindAllStringSubmatch(string(script), -1) {
		if !strings.Contains(body, `id="`+m[1]+`"`) {
			t.Errorf("the script reads #%s, which the page lacks", m[1])
		}
	}
	// The script sends every field of the scan form, so the stack check
	// choice travels with a scanned code.
	if !strings.Contains(string(script), "new FormData(scanForm)") {
		t.Error("the script does not send the fields of the scan form")
	}
}

// credentialServer serves one SD-JWT VC and counts the requests.
func credentialServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/dc+sd-jwt")
		anyval.DiscardWrite(w.Write([]byte(sdjwtSample)))
	}))
	t.Cleanup(s.Close)
	return s, &hits
}

// TestPasteLinkFetchesThroughGuard fetches a pasted link through
// core/fetchguard and decodes the document. The guard refuses a private
// address and a host off the list, and the page says so (P5-05).
func TestPasteLinkFetchesThroughGuard(t *testing.T) {
	server, hits := credentialServer(t)
	link := server.URL + "/credentials/42"

	open := shellMux(t, func(o *scanner.Options) {
		o.Links = fetchguard.New(fetchguard.Options{Guard: fetchguard.Guard{
			AllowPlainHTTP: true, AllowPrivateNetwork: true, AllowedHosts: []string{"127.0.0.1"},
		}})
	})
	page := staffDo(t, open, httptest.NewRequest(http.MethodGet, "/scan/", nil)).Body.String()
	if !strings.Contains(page, `name="link"`) || !strings.Contains(page, "Paste a link") {
		t.Fatal("the page has no link field")
	}
	for _, form := range []url.Values{{"link": {link}}, {"payload": {link}}} {
		rec := staffDo(t, open, formPost("/scan/ingest", form))
		body := rec.Body.String()
		if rec.Code != http.StatusOK || !strings.Contains(body, "The service read the input") {
			t.Fatalf("link %v: status %d body %s", form, rec.Code, body)
		}
		if !strings.Contains(body, "One credential") || !strings.Contains(body, "Fetched from") {
			t.Errorf("link %v: the result lacks the decoded credential or the source", form)
		}
	}
	if hits.Load() != 2 {
		t.Fatalf("want 2 fetches, got %d", hits.Load())
	}

	for name, guard := range map[string]fetchguard.Guard{
		"private":      {AllowPlainHTTP: true},
		"off the list": {AllowPlainHTTP: true, AllowPrivateNetwork: true, AllowedHosts: []string{"credentials.example"}},
		"plain http":   {AllowPrivateNetwork: true},
	} {
		mux := shellMux(t, func(o *scanner.Options) { o.Links = fetchguard.New(fetchguard.Options{Guard: guard}) })
		rec := staffDo(t, mux, formPost("/scan/ingest", url.Values{"link": {link}}))
		if !strings.Contains(rec.Body.String(), "The service did not fetch the link") {
			t.Errorf("%s: want the refusal, got %s", name, rec.Body.String())
		}
	}
	if hits.Load() != 2 {
		t.Fatalf("the guard let a refused link through: %d fetches", hits.Load())
	}
	// A page without a fetcher shows no link field and refuses a link.
	bare := shellMux(t, nil)
	if strings.Contains(staffDo(t, bare, httptest.NewRequest(http.MethodGet, "/scan/", nil)).Body.String(), `name="link"`) {
		t.Error("a page without a fetcher shows the link field")
	}
	if rec := staffDo(t, bare, formPost("/scan/ingest", url.Values{"link": {link}})); !strings.Contains(rec.Body.String(), "The service did not fetch the link") {
		t.Errorf("a page without a fetcher took a link: %s", rec.Body.String())
	}
}

// fakeStack answers VerifyCredential as the verifier of a DPG.
type fakeStack struct {
	got []*backendv1.VerifyCredentialRequest
	url string
	err error
}

func (f *fakeStack) VerifyCredential(_ context.Context, req *connect.Request[backendv1.VerifyCredentialRequest]) (*connect.Response[backendv1.VerifyCredentialResponse], error) {
	f.got = append(f.got, req.Msg)
	if f.err != nil {
		return nil, f.err
	}
	return connect.NewResponse(&backendv1.VerifyCredentialResponse{Verified: false, DpgChecks: []*backendv1.GetResultResponse_DpgCheck{
		{Name: "signature", Passed: true}, {Name: "expiry", Passed: false, Reason: "The credential expired."},
	}}), nil
}

// TestStackCheckOptionOnlyWithFeature offers "Check with the stack" only
// when the live adapter of the own pair lists FEATURE_VERIFY_UPLOAD, and
// shows the checks of the stack beside the decoders (P5-05).
func TestStackCheckOptionOnlyWithFeature(t *testing.T) {
	stack := &fakeStack{}
	withStack := func(o *scanner.Options) {
		o.Stack = func(adapter string) scanner.StackVerifier { stack.url = adapter; return stack }
	}
	without := shellMux(t, withStack)
	if body := staffDo(t, without, httptest.NewRequest(http.MethodGet, "/scan/", nil)).Body.String(); strings.Contains(body, "Check with the stack") {
		t.Fatal("the option shows without the feature")
	}
	if rec := staffDo(t, without, formPost("/scan/ingest", url.Values{"payload": {sdjwtSample}, "stack_check": {"on"}})); strings.Contains(rec.Body.String(), "Stack check") || len(stack.got) != 0 {
		t.Fatal("a posted choice ran the stack check without the feature")
	}

	with := shellMux(t, withStack, backendv1.Feature_FEATURE_VERIFY_UPLOAD)
	body := staffDo(t, with, httptest.NewRequest(http.MethodGet, "/scan/", nil)).Body.String()
	a11ytest.AssertPage(t, body)
	if strings.Count(body, "Check with the stack") < 3 || !strings.Contains(body, "First stack") {
		t.Fatalf("want the option on the camera, upload, and paste forms, naming the stack")
	}
	plain := staffDo(t, with, formPost("/scan/ingest", url.Values{"payload": {sdjwtSample}}))
	if strings.Contains(plain.Body.String(), "Stack check") || len(stack.got) != 0 {
		t.Fatal("the stack check ran without the choice")
	}
	rec := staffDo(t, with, formPost("/scan/ingest", url.Values{"payload": {sdjwtSample}, "stack_check": {"on"}}))
	out := rec.Body.String()
	a11ytest.AssertPage(t, out)
	for _, want := range []string{"Stack check", "First stack", "Not accepted", "signature", "expiry", "The credential expired."} {
		if !strings.Contains(out, want) {
			t.Errorf("the result lacks %q", want)
		}
	}
	if len(stack.got) != 1 || string(stack.got[0].GetPayload()) != sdjwtSample || stack.url != "http://verifier-waltid-adapter:8080" {
		t.Fatalf("the stack got %d calls at %q", len(stack.got), stack.url)
	}
	stack.err = connect.NewError(connect.CodeUnavailable, errors.New("down"))
	failed := staffDo(t, with, formPost("/scan/ingest", url.Values{"payload": {sdjwtSample}, "stack_check": {"on"}}))
	if !strings.Contains(failed.Body.String(), "The stack did not answer") {
		t.Errorf("want the failure sentence, got %s", failed.Body.String())
	}
}
