// SPDX-License-Identifier: Apache-2.0

package trace

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseAndString(t *testing.T) {
	c, err := Parse("00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01")
	if err != nil {
		t.Fatal(err)
	}
	if c.TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" || c.SpanID != "00f067aa0ba902b7" || !c.Sampled {
		t.Fatalf("%+v", c)
	}
	if c.String() != "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01" {
		t.Fatal(c.String())
	}
	off, err := Parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if off.Sampled || !strings.HasSuffix(off.String(), "-00") {
		t.Fatal("flags")
	}
	for _, bad := range []string{
		"",
		"00-abc",
		"01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		"00-00000000000000000000000000000000-00f067aa0ba902b7-01",
		"00-4bf92f3577b34da6a3ce929d0e0e473-00f067aa0ba902b7-01",
		"00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
		"00-4bf92f3577b34da6a3ce929d0e0e4736-zzf067aa0ba902b7-01",
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-1",
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-zz",
	} {
		if _, err := Parse(bad); err == nil {
			t.Fatalf("%q parsed", bad)
		}
	}
}

func TestNewAndChild(t *testing.T) {
	a := New()
	if _, err := Parse(a.String()); err != nil {
		t.Fatal(err)
	}
	b := a.Child()
	if b.TraceID != a.TraceID || b.SpanID == a.SpanID || b.ParentID != a.SpanID {
		t.Fatalf("%+v %+v", a, b)
	}
	if New().TraceID == a.TraceID {
		t.Fatal("trace ids repeat")
	}
}

func TestContext(t *testing.T) {
	if _, ok := FromContext(context.Background()); ok {
		t.Fatal("empty context")
	}
	c := New()
	got, ok := FromContext(WithContext(context.Background(), c))
	if !ok || got != c {
		t.Fatal("round trip")
	}
	h := http.Header{}
	Inject(context.Background(), h)
	if h.Get(Header) != "" {
		t.Fatal("inject without context")
	}
	Inject(WithContext(context.Background(), c), h)
	if h.Get(Header) != c.String() {
		t.Fatal("inject")
	}
}

func TestMiddleware(t *testing.T) {
	var seen Context
	h := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = FromContext(r.Context())
	}))
	// A valid parent keeps the trace id.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(Header, "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if seen.TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" || seen.ParentID != "00f067aa0ba902b7" || !seen.Sampled {
		t.Fatalf("%+v", seen)
	}
	if rec.Header().Get(Header) != seen.String() {
		t.Fatal("response header")
	}
	// No parent starts a trace.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if seen.ParentID != "" || seen.TraceID == "" || rec.Header().Get(Header) == "" {
		t.Fatalf("%+v", seen)
	}
}
