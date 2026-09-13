// SPDX-License-Identifier: Apache-2.0

package serve

import (
	"context"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func start(t *testing.T, ready func() bool) (string, context.CancelFunc, chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, r.Proto) })
	s := New(ln.Addr().String(), mux, ready)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.serve(ctx, ln) }()
	return "http://" + ln.Addr().String(), cancel, done
}

func TestHealthAndReady(t *testing.T) {
	var ready atomic.Bool
	base, cancel, done := start(t, func() bool { return ready.Load() })
	defer cancel()
	if err := Healthcheck(context.Background(), base+"/healthz"); err != nil {
		t.Fatal(err)
	}
	if err := Healthcheck(context.Background(), base+"/readyz"); err == nil {
		t.Fatal("not ready must fail")
	}
	ready.Store(true)
	if err := Healthcheck(context.Background(), base+"/readyz"); err != nil {
		t.Fatal(err)
	}
	if err := Healthcheck(context.Background(), "http://127.0.0.1:1/x"); err == nil {
		t.Fatal("connection error")
	}
	if err := Healthcheck(context.Background(), "::bad"); err == nil {
		t.Fatal("bad url")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestH2C(t *testing.T) {
	base, cancel, done := start(t, nil)
	defer cancel()
	var protocols http.Protocols
	protocols.SetUnencryptedHTTP2(true)
	client := &http.Client{Transport: &http.Transport{Protocols: &protocols}}
	resp, err := client.Get(base + "/hello")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "HTTP/2.0" {
		t.Fatalf("proto %s", body)
	}
	if err := Healthcheck(context.Background(), base+"/readyz"); err != nil {
		t.Fatal("nil ready means ready")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown timed out")
	}
}

func TestRunListenError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	s := New(ln.Addr().String(), http.NewServeMux(), nil)
	if err := s.Run(context.Background()); err == nil {
		t.Fatal("port in use")
	}
	ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := New(ln.Addr().String(), http.NewServeMux(), nil).Run(ctx); err != nil {
		t.Fatal(err)
	}
}
