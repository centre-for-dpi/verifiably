package httpx

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// srv returns a test server that records the last request it saw and replies
// with the given status and body.
func srv(t *testing.T, status int, body string, seen *http.Request) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if seen != nil {
			*seen = *r.Clone(r.Context())
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(s.Close)
	return s
}

// A nil `out` means the caller doesn't want the body decoded. The client must
// still drain it so the connection can be reused rather than abandoned
// mid-response — that drain is the branch under test here.
func TestDoJSON_NilOutDrainsBody(t *testing.T) {
	s := srv(t, http.StatusOK, `{"ignored":"payload"}`, nil)
	c := New(s.URL)

	if err := c.DoJSON(context.Background(), http.MethodGet, "/thing", nil, nil, nil); err != nil {
		t.Fatalf("DoJSON with nil out: %v", err)
	}
}

func TestDoForm_NilOutDrainsBody(t *testing.T) {
	s := srv(t, http.StatusOK, `{"ignored":"payload"}`, nil)
	c := New(s.URL)

	if err := c.DoForm(context.Background(), http.MethodPost, "/thing",
		url.Values{"a": {"b"}}, nil, nil); err != nil {
		t.Fatalf("DoForm with nil out: %v", err)
	}
}

func TestDoJSON_DecodesIntoOut(t *testing.T) {
	s := srv(t, http.StatusOK, `{"name":"cedula","count":3}`, nil)
	c := New(s.URL)

	var out struct {
		Name  string      `json:"name"`
		Count json.Number `json:"count"`
	}
	if err := c.DoJSON(context.Background(), http.MethodGet, "/thing", nil, &out, nil); err != nil {
		t.Fatalf("DoJSON: %v", err)
	}
	if out.Name != "cedula" {
		t.Errorf("name = %q, want cedula", out.Name)
	}
	// UseNumber is set on the decoder, so integers must not round-trip through
	// float64 — a credential's numeric claims have to survive verbatim.
	if out.Count.String() != "3" {
		t.Errorf("count = %q, want 3", out.Count)
	}
}

func TestDoJSON_StatusErrorCarriesBody(t *testing.T) {
	s := srv(t, http.StatusTeapot, `{"error":"nope"}`, nil)
	c := New(s.URL)

	err := c.DoJSON(context.Background(), http.MethodGet, "/thing", nil, nil, nil)
	if err == nil {
		t.Fatal("expected an error for a 418 response")
	}
	if !IsStatus(err, http.StatusTeapot) {
		t.Errorf("IsStatus(418) = false for %v", err)
	}
	if IsStatus(err, http.StatusNotFound) {
		t.Error("IsStatus must not match a different status")
	}
	var se *StatusError
	if !errors.As(err, &se) {
		t.Fatalf("error is not a *StatusError: %T", err)
	}
	if se.Body == "" || se.Status != http.StatusTeapot {
		t.Errorf("StatusError = %+v, want the 418 body preserved", se)
	}
	if se.Error() == "" {
		t.Error("StatusError.Error() must not be empty")
	}
}

// The token travels in the context rather than the signature so callers deep in
// an adapter don't have to thread it through every helper.
func TestWithToken_SetsAuthorizationHeader(t *testing.T) {
	var seen http.Request
	s := srv(t, http.StatusOK, `{}`, &seen)
	c := New(s.URL)

	ctx := WithToken(context.Background(), "abc123")
	if err := c.DoJSON(ctx, http.MethodGet, "/thing", nil, nil, nil); err != nil {
		t.Fatalf("DoJSON: %v", err)
	}
	if got := seen.Header.Get("Authorization"); got != "Bearer abc123" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer abc123")
	}
}

func TestDoJSON_NoTokenLeavesHeaderUnset(t *testing.T) {
	var seen http.Request
	s := srv(t, http.StatusOK, `{}`, &seen)
	c := New(s.URL)

	if err := c.DoJSON(context.Background(), http.MethodGet, "/thing", nil, nil, nil); err != nil {
		t.Fatalf("DoJSON: %v", err)
	}
	if got := seen.Header.Get("Authorization"); got != "" {
		t.Errorf("Authorization = %q, want unset", got)
	}
}

func TestDoRaw_ReturnsBytes(t *testing.T) {
	s := srv(t, http.StatusOK, `not-json-at-all`, nil)
	c := New(s.URL)

	b, err := c.DoRaw(context.Background(), http.MethodGet, "/thing", nil, "", nil)
	if err != nil {
		t.Fatalf("DoRaw: %v", err)
	}
	if string(b) != "not-json-at-all" {
		t.Errorf("DoRaw = %q", b)
	}
}

func TestIsStatus_NonStatusError(t *testing.T) {
	if IsStatus(nil, 404) {
		t.Error("IsStatus(nil) must be false")
	}
	if IsStatus(context.Canceled, 404) {
		t.Error("IsStatus on a non-StatusError must be false")
	}
}
