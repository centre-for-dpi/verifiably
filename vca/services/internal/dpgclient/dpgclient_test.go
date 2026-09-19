// SPDX-License-Identifier: Apache-2.0

package dpgclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/internal/serve/trace"
)

// newTestClient returns a client for the server with no waiting.
func newTestClient(t *testing.T, srv *httptest.Server, opts Options) *Client {
	t.Helper()
	if opts.BaseURL == "" {
		opts.BaseURL = srv.URL
	}
	opts.HTTP = srv.Client()
	opts.Sleep = func(time.Duration) {}
	return New(opts)
}

func TestJSONSendsAndDecodes(t *testing.T) {
	var gotPath, gotAuth, gotAgent, gotType, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.Path, r.Header.Get("Authorization")
		gotAgent, gotType = r.Header.Get("User-Agent"), r.Header.Get("Content-Type")
		buf, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			t.Errorf("read body: %v", readErr)
		}
		gotBody = string(buf)
		w.Header().Set("Content-Type", "application/json")
		_, errAssign2 := w.Write([]byte(`{"id":"abc","count":9007199254740993}`))
		if errAssign2 != nil {
			t.Errorf("w.Write: %v", errAssign2)
		}
	}))
	defer srv.Close()
	c := newTestClient(t, srv, Options{Token: "secret"})
	var out struct {
		ID    string `json:"id"`
		Count any    `json:"count"`
	}
	if err := c.JSON(context.Background(), http.MethodPost, "offers", map[string]string{"a": "b"}, &out); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if gotPath != "/offers" {
		t.Fatalf("path = %q", gotPath)
	}
	if gotAuth != "Bearer secret" {
		t.Fatalf("authorization = %q", gotAuth)
	}
	if gotAgent != UserAgent {
		t.Fatalf("user agent = %q", gotAgent)
	}
	if gotType != "application/json" || gotBody != `{"a":"b"}` {
		t.Fatalf("body %q of type %q", gotBody, gotType)
	}
	if out.ID != "abc" {
		t.Fatalf("id = %q", out.ID)
	}
	if got := out.Count; got == nil || got.(interface{ String() string }).String() != "9007199254740993" {
		t.Fatalf("count = %v, a whole number must stay whole", got)
	}
}

func TestJSONWithoutABodyOrAnOutput(t *testing.T) {
	var gotType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotType = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	c := newTestClient(t, srv, Options{})
	if err := c.JSON(context.Background(), http.MethodDelete, "/offers/1", nil, nil); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if gotType != "" {
		t.Fatalf("content type = %q, want none", gotType)
	}
}

func TestJSONReportsAnUnencodableBody(t *testing.T) {
	c := New(Options{BaseURL: "http://example.test"})
	err := c.JSON(context.Background(), http.MethodPost, "/x", make(chan int), nil)
	if err == nil || !strings.Contains(err.Error(), "encode the request") {
		t.Fatalf("error = %v", err)
	}
}

func TestJSONReportsABrokenResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, errAssign := w.Write([]byte("not json"))
		if errAssign != nil {
			t.Errorf("w.Write: %v", errAssign)
		}
	}))
	defer srv.Close()
	c := newTestClient(t, srv, Options{})
	var out struct{}
	err := c.JSON(context.Background(), http.MethodGet, "/x", nil, &out)
	if err == nil || !strings.Contains(err.Error(), "decode the response") {
		t.Fatalf("error = %v", err)
	}
}

func TestFormSendsTheEncodedValues(t *testing.T) {
	var gotBody, gotType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotType = r.Header.Get("Content-Type")
		buf, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			t.Errorf("read body: %v", readErr)
		}
		gotBody = string(buf)
		_, errAssign2 := w.Write([]byte(`{"access_token":"at"}`))
		if errAssign2 != nil {
			t.Errorf("w.Write: %v", errAssign2)
		}
	}))
	defer srv.Close()
	c := newTestClient(t, srv, Options{})
	var out struct {
		AccessToken string `json:"access_token"`
	}
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:pre-authorized_code"}}
	if err := c.Form(context.Background(), http.MethodPost, "/token", form, &out); err != nil {
		t.Fatalf("Form: %v", err)
	}
	if gotType != "application/x-www-form-urlencoded" {
		t.Fatalf("content type = %q", gotType)
	}
	if !strings.HasPrefix(gotBody, "grant_type=") {
		t.Fatalf("body = %q", gotBody)
	}
	if out.AccessToken != "at" {
		t.Fatalf("token = %q", out.AccessToken)
	}
}

func TestFormReportsAFailedCall(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()
	c := newTestClient(t, srv, Options{})
	if err := c.Form(context.Background(), http.MethodPost, "/token", nil, nil); err == nil {
		t.Fatal("Form returned no error")
	}
}

func TestTextReturnsTheTrimmedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, errAssign := w.Write([]byte("  openid-credential-offer://x  \n"))
		if errAssign != nil {
			t.Errorf("w.Write: %v", errAssign)
		}
	}))
	defer srv.Close()
	c := newTestClient(t, srv, Options{})
	got, err := c.Text(context.Background(), http.MethodPost, "/issue", "application/json", []byte("{}"))
	if err != nil {
		t.Fatalf("Text: %v", err)
	}
	if got != "openid-credential-offer://x" {
		t.Fatalf("body = %q", got)
	}
}

func TestTextReportsAFailedCall(t *testing.T) {
	c := New(Options{})
	if _, err := c.Text(context.Background(), http.MethodGet, "/x", "", nil); !errors.Is(err, ErrNoBaseURL) {
		t.Fatalf("error = %v, want ErrNoBaseURL", err)
	}
}

func TestDoRetriesAServerError(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, errAssign := w.Write([]byte("ok"))
		if errAssign != nil {
			t.Errorf("w.Write: %v", errAssign)
		}
	}))
	defer srv.Close()
	waits := []time.Duration{}
	c := New(Options{BaseURL: srv.URL, HTTP: srv.Client(), Sleep: func(d time.Duration) { waits = append(waits, d) }})
	resp, err := c.Do(context.Background(), Request{Method: http.MethodGet, Path: "/x"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if string(resp.Body) != "ok" || calls != 3 {
		t.Fatalf("body %q after %d calls", resp.Body, calls)
	}
	if len(waits) != 2 || waits[1] != 2*waits[0] {
		t.Fatalf("waits = %v, the wait must grow", waits)
	}
}

func TestDoRetriesTooManyRequests(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	c := newTestClient(t, srv, Options{})
	_, err := c.Do(context.Background(), Request{Method: http.MethodGet, Path: "/x"})
	if !IsStatus(err, http.StatusTooManyRequests) {
		t.Fatalf("error = %v", err)
	}
	if calls != 1+DefaultRetries {
		t.Fatalf("calls = %d, want %d", calls, 1+DefaultRetries)
	}
}

func TestDoDoesNotRetryAClientError(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusNotFound)
		_, errAssign := w.Write([]byte(strings.Repeat("z", 300)))
		if errAssign != nil {
			t.Errorf("w.Write: %v", errAssign)
		}
	}))
	defer srv.Close()
	c := newTestClient(t, srv, Options{})
	_, err := c.Do(context.Background(), Request{Method: http.MethodGet, Path: "/x"})
	if !IsStatus(err, http.StatusNotFound) {
		t.Fatalf("error = %v", err)
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1", calls)
	}
	if !strings.HasSuffix(err.Error(), "...") {
		t.Fatalf("the error %q does not shorten the body", err)
	}
}

func TestDoStopsRetryingWhenTheContextEnds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	c := New(Options{BaseURL: srv.URL, HTTP: srv.Client(), Sleep: func(time.Duration) { cancel() }})
	_, err := c.Do(ctx, Request{Method: http.MethodGet, Path: "/x"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want a cancelled context", err)
	}
}

func TestDoRejectsABodyAboveTheLimit(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		_, errAssign := w.Write([]byte(strings.Repeat("a", 100)))
		if errAssign != nil {
			t.Errorf("w.Write: %v", errAssign)
		}
	}))
	defer srv.Close()
	c := newTestClient(t, srv, Options{MaxBytes: 10})
	_, err := c.Do(context.Background(), Request{Method: http.MethodGet, Path: "/x"})
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("error = %v, want ErrTooLarge", err)
	}
	if calls != 1 {
		t.Fatalf("calls = %d, a body above the limit must not be retried", calls)
	}
}

func TestDoReportsANetworkFailureAfterEveryAttempt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	addr := srv.URL
	srv.Close()
	c := New(Options{BaseURL: addr, Retries: 1, Sleep: func(time.Duration) {}, Timeout: time.Second})
	if _, err := c.Do(context.Background(), Request{Method: http.MethodGet, Path: "/x"}); err == nil {
		t.Fatal("Do returned no error")
	}
}

func TestDoRejectsABadMethod(t *testing.T) {
	c := New(Options{BaseURL: "http://example.test"})
	if _, err := c.Do(context.Background(), Request{Method: "bad method", Path: "/x"}); err == nil {
		t.Fatal("Do accepted a bad method")
	}
}

func TestDoSendsTheTraceparentAndExtraHeaders(t *testing.T) {
	var gotTrace, gotExtra, gotAccept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTrace = r.Header.Get(trace.Header)
		gotExtra = r.Header.Get("X-Correlation-Id")
		gotAccept = r.Header.Get("Accept")
		_, errAssign := w.Write([]byte("{}"))
		if errAssign != nil {
			t.Errorf("w.Write: %v", errAssign)
		}
	}))
	defer srv.Close()
	c := newTestClient(t, srv, Options{})
	tc := trace.New()
	ctx := trace.WithContext(context.Background(), tc)
	_, err := c.Do(ctx, Request{
		Method: http.MethodGet, Path: "/x", Accept: "application/json",
		Header: http.Header{"X-Correlation-Id": {"c-1"}},
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if gotTrace != tc.String() {
		t.Fatalf("traceparent = %q, want %q", gotTrace, tc.String())
	}
	if gotExtra != "c-1" || gotAccept != "application/json" {
		t.Fatalf("headers %q and %q", gotExtra, gotAccept)
	}
}

func TestRequestTokenOverridesTheClientToken(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		_, errAssign := w.Write([]byte("{}"))
		if errAssign != nil {
			t.Errorf("w.Write: %v", errAssign)
		}
	}))
	defer srv.Close()
	c := newTestClient(t, srv, Options{Token: "static"})
	if _, err := c.Do(context.Background(), Request{Method: http.MethodGet, Path: "/x", Token: "per-call"}); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if got != "Bearer per-call" {
		t.Fatalf("authorization = %q", got)
	}
}

func TestWithTokenLeavesTheOriginalClientAlone(t *testing.T) {
	c := New(Options{BaseURL: "http://example.test/", Token: "one"})
	other := c.WithToken("two")
	if c.token != "one" || other.token != "two" {
		t.Fatalf("tokens %q and %q", c.token, other.token)
	}
	if c.BaseURL() != "http://example.test" {
		t.Fatalf("base URL = %q", c.BaseURL())
	}
}

func TestURLKeepsAnAbsolutePath(t *testing.T) {
	c := New(Options{BaseURL: "http://example.test"})
	got, err := c.url("https://other.test/a")
	if err != nil || got != "https://other.test/a" {
		t.Fatalf("url = %q, %v", got, err)
	}
}

func TestNewAppliesTheDefaults(t *testing.T) {
	c := New(Options{BaseURL: "http://example.test"})
	if c.retries != DefaultRetries || c.backoff != DefaultBackoff || c.maxBytes != DefaultMaxBytes {
		t.Fatalf("defaults are wrong: %d %v %d", c.retries, c.backoff, c.maxBytes)
	}
	if c.http.Timeout != DefaultTimeout {
		t.Fatalf("timeout = %v", c.http.Timeout)
	}
	if c.sleep == nil {
		t.Fatal("sleep is nil")
	}
	off := New(Options{BaseURL: "http://example.test", Retries: -1, Timeout: time.Second, MaxBytes: 5, Backoff: time.Second})
	if off.retries != 0 || off.maxBytes != 5 || off.backoff != time.Second || off.http.Timeout != time.Second {
		t.Fatalf("explicit options are wrong: %d %d %v", off.retries, off.maxBytes, off.backoff)
	}
}

func TestIsStatusIgnoresAnotherError(t *testing.T) {
	if IsStatus(errors.New("other"), 404) {
		t.Fatal("IsStatus accepted another error")
	}
}
