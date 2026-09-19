// SPDX-License-Identifier: Apache-2.0

package serve

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/internal/serve/trace"
)

func TestPortOf(t *testing.T) {
	for in, want := range map[string]string{":8080": ":8080", "127.0.0.1:9": ":9", "bad": ":8080", "host:": ":8080"} {
		if got := PortOf(in); got != want {
			t.Fatalf("PortOf(%q) = %q", in, got)
		}
	}
}

func TestHandler(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	ready := true
	var seenID string
	h := Handler(Options{
		Log:   log,
		Ready: func() bool { return ready },
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seenID = RequestIDFrom(r.Context())
			if _, ok := trace.FromContext(r.Context()); !ok {
				t.Error("no trace context")
			}
			w.WriteHeader(http.StatusCreated)
			_, errAssign := w.Write([]byte("hello"))
			if errAssign != nil {
				t.Fatalf("w.Write: %v", errAssign)
			}
			flusher, isFlusher := w.(http.Flusher)
			if !isFlusher {
				t.Fatal("the writer is not a flusher")
			}
			flusher.Flush()
		}),
	})
	get := func(path string, hdr map[string]string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	if rec := get("/healthz", nil); rec.Code != 200 || rec.Body.String() != "ok\n" {
		t.Fatalf("healthz: %d %s", rec.Code, rec.Body.String())
	}
	if rec := get("/readyz", nil); rec.Code != 200 {
		t.Fatalf("readyz: %d", rec.Code)
	}
	ready = false
	if rec := get("/readyz", nil); rec.Code != 503 || rec.Body.String() != "not ready\n" {
		t.Fatalf("readyz not ready: %d", rec.Code)
	}
	rec := get("/x", map[string]string{RequestIDHeader: "abc-123", trace.Header: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"})
	if rec.Code != 201 || rec.Header().Get(RequestIDHeader) != "abc-123" || seenID != "abc-123" {
		t.Fatalf("request id: %d %q %q", rec.Code, rec.Header().Get(RequestIDHeader), seenID)
	}
	if !strings.HasPrefix(rec.Header().Get(trace.Header), "00-4bf92f3577b34da6a3ce929d0e0e4736-") {
		t.Fatal("traceparent not propagated")
	}
	var line map[string]any
	last := strings.TrimSpace(buf.String())
	last = last[strings.LastIndex(last, "\n")+1:]
	if err := json.Unmarshal([]byte(last), &line); err != nil {
		t.Fatal(err)
	}
	if line["msg"] != "request" || line["status"] != float64(201) || line["bytes"] != float64(5) || line["request_id"] != "abc-123" || line["trace_id"] != "4bf92f3577b34da6a3ce929d0e0e4736" || line["path"] != "/x" {
		t.Fatalf("log line: %s", last)
	}
	// An unsafe incoming id is replaced.
	rec = get("/x", map[string]string{RequestIDHeader: "bad id\n"})
	if id := rec.Header().Get(RequestIDHeader); id == "bad id\n" || len(id) != 24 {
		t.Fatalf("unsafe id kept: %q", id)
	}
	if safeID(strings.Repeat("a", 129)) || safeID("") || !safeID("ok") {
		t.Fatal("safeID")
	}
	// Defaults: nil handler answers 404.
	rec = httptest.NewRecorder()
	Handler(Options{}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/nope", nil))
	if rec.Code != 404 {
		t.Fatal("default handler")
	}
}

func TestFlushWithoutFlusher(t *testing.T) {
	rec := &statusRecorder{ResponseWriter: plainWriter{}}
	rec.Flush()
}

type plainWriter struct{}

func (plainWriter) Header() http.Header         { return http.Header{} }
func (plainWriter) Write(b []byte) (int, error) { return len(b), nil }
func (plainWriter) WriteHeader(int)             {}

func TestRunAndHealthcheck(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	short, shortCancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer shortCancel()
	if err := Healthcheck(short, addr); err == nil {
		t.Fatal("healthcheck before serve")
	}
	var buf bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{Listener: ln, Log: slog.New(slog.NewJSONHandler(&buf, nil)), Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, errAssign := io.WriteString(w, r.Proto)
			if errAssign != nil {
				t.Errorf("io.WriteString: %v", errAssign)
			}
		})})
	}()
	deadline := time.Now().Add(5 * time.Second)
	for Healthcheck(context.Background(), addr) != nil {
		if time.Now().After(deadline) {
			t.Fatal("server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// h2c: a prior knowledge HTTP/2 client gets HTTP/2.0.
	client := &http.Client{Transport: &http.Transport{Protocols: h2cProtocols()}}
	resp, err := client.Get("http://" + addr + "/proto")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("resp.Body.Close: %v", err)
	}
	if string(body) != "HTTP/2.0" {
		t.Fatalf("proto = %s", body)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "listening") || !strings.Contains(buf.String(), "shutting down") {
		t.Fatal(buf.String())
	}
	if err := Healthcheck(context.Background(), addr); err == nil {
		t.Fatal("healthcheck after stop")
	}
	// A bad listen address fails.
	if err := Run(context.Background(), Options{Listen: "300.0.0.1:x"}); err == nil {
		t.Fatal("bad listen")
	}
	// A closed listener makes Serve fail at once.
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	if err := closed.Close(); err != nil {
		t.Fatalf("closed.Close: %v", err)
	}
	if err := Run(context.Background(), Options{Listener: closed}); err == nil {
		t.Fatal("closed listener")
	}
}

func TestHealthcheckNotReady(t *testing.T) {
	srv := httptest.NewServer(Handler(Options{Ready: func() bool { return false }}))
	defer srv.Close()
	if err := Healthcheck(context.Background(), srv.Listener.Addr().String()); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Healthcheck(ctx, srv.Listener.Addr().String()); err == nil {
		t.Fatal("cancelled context")
	}
}

func h2cProtocols() *http.Protocols {
	var p http.Protocols
	p.SetUnencryptedHTTP2(true)
	return &p
}

func TestReadyMessage(t *testing.T) {
	h := Handler(Options{ReadyMessage: func() string { return "ok providers=2" }})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != 200 || rec.Body.String() != "ok providers=2" {
		t.Fatalf("readyz: %d %q", rec.Code, rec.Body.String())
	}
}
