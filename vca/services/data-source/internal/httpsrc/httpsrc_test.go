// SPDX-License-Identifier: Apache-2.0

package httpsrc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIsPublic(t *testing.T) {
	deny := []string{"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "0.0.0.0", "100.64.0.1",
		"192.0.0.1", "192.0.2.1", "198.18.0.1", "198.51.100.1", "203.0.113.1", "240.0.0.1", "255.255.255.255",
		"224.0.0.1", "::1", "::", "fe80::1", "fc00::1", "fd12::1", "ff02::1", "64:ff9b::1", "2001:db8::1", "::ffff:10.0.0.1"}
	for _, s := range deny {
		if IsPublic(net.ParseIP(s)) {
			t.Errorf("%s must not be public", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "41.90.1.1", "2001:4860::8888", "::ffff:8.8.8.8"} {
		if !IsPublic(net.ParseIP(s)) {
			t.Errorf("%s must be public", s)
		}
	}
	if IsPublic(nil) {
		t.Fatal("nil")
	}
}

func lookup(m map[string][]string) func(context.Context, string) ([]net.IP, error) {
	return func(_ context.Context, host string) ([]net.IP, error) {
		v, ok := m[host]
		if !ok {
			return nil, errors.New("nxdomain")
		}
		var out []net.IP
		for _, s := range v {
			out = append(out, net.ParseIP(s))
		}
		return out, nil
	}
}

func TestGuardCheck(t *testing.T) {
	g := Guard{
		AllowHosts: []string{"api.gov.example", ".ministry.example", "Alt.Example:8443", ""},
		LookupIP: lookup(map[string][]string{
			"api.gov.example":        {"41.90.1.1"},
			"x.ministry.example":     {"41.90.1.2", "2001:4860::1"},
			"ministry.example":       {"41.90.1.3"},
			"bad.ministry.example":   {"41.90.1.2", "10.0.0.1"},
			"alt.example":            {"41.90.1.4"},
			"empty.ministry.example": {},
		}),
	}
	tests := []struct {
		name string
		url  string
		want error
	}{
		{"ok", "https://api.gov.example/rows", nil},
		{"ok subdomain", "https://x.ministry.example/", nil},
		{"ok apex of wildcard", "https://ministry.example/", nil},
		{"ok host with port", "https://alt.example:8443/", nil},
		{"ok literal ip", "https://41.90.1.1/", ErrHost},
		{"http denied", "http://api.gov.example/", ErrScheme},
		{"ftp", "ftp://api.gov.example/", ErrScheme},
		{"userinfo", "https://u:p@api.gov.example/", ErrUserInfo},
		{"empty host", "https:///path", ErrHost},
		{"not allowlisted", "https://evil.example/", ErrHost},
		{"wrong port", "https://alt.example:9443/", ErrHost},
		{"mixed private", "https://bad.ministry.example/", ErrPrivateIP},
		{"nxdomain", "https://nope.ministry.example/", ErrResolve},
		{"no address", "https://empty.ministry.example/", ErrResolve},
		{"parse", "https://api.gov.example/%zz", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, ips, err := g.Check(context.Background(), tc.url)
			if tc.name == "parse" {
				if err == nil {
					t.Fatal("want parse error")
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("err %v want %v", err, tc.want)
			}
			if err == nil && len(ips) == 0 {
				t.Fatal("no ips")
			}
		})
	}
	if _, _, err := (Guard{}).Check(context.Background(), "https://api.gov.example/"); !errors.Is(err, ErrNoAllowlist) {
		t.Fatalf("empty allowlist %v", err)
	}
	lit := Guard{AllowHosts: []string{"41.90.1.1", "10.0.0.5", "[2001:4860::1]"}}
	if _, _, err := lit.Check(context.Background(), "https://41.90.1.1/"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := lit.Check(context.Background(), "https://[2001:4860::1]/"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := lit.Check(context.Background(), "https://10.0.0.5/"); !errors.Is(err, ErrPrivateIP) {
		t.Fatalf("private literal %v", err)
	}
	lit.AllowPrivate = true
	if _, _, err := lit.Check(context.Background(), "https://10.0.0.5/"); err != nil {
		t.Fatal(err)
	}
	g.LookupIP = nil
	if _, _, err := g.Check(context.Background(), "https://nope.invalid.ministry.example/"); !errors.Is(err, ErrResolve) {
		t.Fatalf("default resolver %v", err)
	}
}

func TestPointerAndRows(t *testing.T) {
	body := []byte(`{"data":{"a/b":[{"id":1,"name":"Grace","ok":true,"n":null,"tags":["x"],"v":1.50}],"arr":[[1]]},"top":[]}`)
	tb, err := Rows(body, "/data/a~1b")
	if err != nil || len(tb.Rows) != 1 || tb.Rows[0]["id"] != "1" || tb.Rows[0]["name"] != "Grace" ||
		tb.Rows[0]["ok"] != "true" || tb.Rows[0]["n"] != "" || tb.Rows[0]["tags"] != `["x"]` || tb.Rows[0]["v"] != "1.50" {
		t.Fatalf("%+v %v", tb, err)
	}
	if strings.Join(tb.Fields, ",") != "id,n,name,ok,tags,v" {
		t.Fatalf("%v", tb.Fields)
	}
	if tb, err := Rows([]byte(`[]`), ""); err != nil || len(tb.Rows) != 0 {
		t.Fatalf("%+v %v", tb, err)
	}
	if tb, err := Rows(body, "/data/arr/0"); err == nil {
		t.Fatalf("array of arrays %+v", tb)
	}
	bad := map[string]string{
		"/data/arr/1": "no index", "/data/arr/x": "no index", "/data/nope": "no member", "/data/a~1b/0/name/x": "not an object",
		"data": "must start with", "/data": "not point at an array",
	}
	for p, want := range bad {
		_, err := Rows(body, p)
		if !errors.Is(err, ErrRowsPath) || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", p, err)
		}
	}
	if _, err := Rows([]byte(`{`), ""); !errors.Is(err, ErrNotJSON) {
		t.Fatalf("not json %v", err)
	}
	if Stringify(map[string]any{"b": 1, "a": "x"}) != `{"a":"x","b":1}` {
		t.Fatal("stringify map")
	}
}

func localGuard() Guard {
	return Guard{AllowHosts: []string{"127.0.0.1"}, AllowHTTP: true, AllowPrivate: true}
}

func TestFetchHTTP(t *testing.T) {
	var seen http.Header
	var seenMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, seenMethod = r.Header.Clone(), r.Method
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "/rows", http.StatusFound)
		case "/big":
			mustWrite(t, w, []byte(`[{"a":"`+strings.Repeat("x", 100)+`"}]`))
		case "/fail":
			w.WriteHeader(http.StatusBadGateway)
		case "/slow":
			time.Sleep(300 * time.Millisecond)
		default:
			mustWrite(t, w, []byte(`{"rows":[{"id":"1"}]}`))
		}
	}))
	defer srv.Close()
	f := Fetcher{Guard: localGuard()}
	tb, err := f.Fetch(context.Background(), Request{
		URL: srv.URL + "/rows", Headers: map[string]string{"X-Trace": "1"}, Auth: Auth{Bearer: "tok"}, RowsPath: "/rows",
	})
	if err != nil || len(tb.Rows) != 1 || tb.Rows[0]["id"] != "1" {
		t.Fatalf("%+v %v", tb, err)
	}
	if seen.Get("Authorization") != "Bearer tok" || seen.Get("X-Trace") != "1" || seen.Get("Accept") != "application/json" || seenMethod != "GET" {
		t.Fatalf("headers %v", seen)
	}
	_, err = f.Fetch(context.Background(), Request{URL: srv.URL + "/rows", Method: "post", Auth: Auth{BasicUser: "u", BasicPassword: "p"}, RowsPath: "/rows"})
	if err != nil || seenMethod != "POST" || !strings.HasPrefix(seen.Get("Authorization"), "Basic ") {
		t.Fatalf("post %v %v", err, seen)
	}
	tests := []struct {
		name string
		req  Request
		f    Fetcher
		want error
	}{
		{"method", Request{URL: srv.URL, Method: "DELETE"}, f, ErrMethod},
		{"guard", Request{URL: "https://evil.example/"}, f, ErrHost},
		{"redirect", Request{URL: srv.URL + "/redirect"}, f, ErrRedirect},
		{"status", Request{URL: srv.URL + "/fail"}, f, ErrStatus},
		{"too large", Request{URL: srv.URL + "/big"}, Fetcher{Guard: localGuard(), MaxBytes: 50}, ErrTooLarge},
		{"bad mtls", Request{URL: srv.URL, Auth: Auth{CertPEM: []byte("x"), KeyPEM: []byte("y")}}, f, ErrBadMTLS},
		{"timeout", Request{URL: srv.URL + "/slow", Timeout: 50 * time.Millisecond}, f, context.DeadlineExceeded},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.f.Fetch(context.Background(), tc.req); !errors.Is(err, tc.want) {
				t.Fatalf("err %v want %v", err, tc.want)
			}
		})
	}
	// A refused connection reports the dial error.
	ln, verr := net.Listen("tcp", "127.0.0.1:0")
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	closed := "http://" + ln.Addr().String()
	if cerr := ln.Close(); cerr != nil {
		t.Errorf("the close failed: %v", cerr)
	}
	if _, err := f.Fetch(context.Background(), Request{URL: closed}); err == nil {
		t.Fatal("closed port")
	}
	if _, err := f.Fetch(context.Background(), Request{URL: "http://127.0.0.1:99999/"}); err == nil {
		t.Fatal("bad port")
	}
}

func selfSigned(t *testing.T) (tls.Certificate, *x509.CertPool, []byte, []byte) {
	t.Helper()
	key, verr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "client"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, verr := x509.MarshalECPrivateKey(key)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, verr := tls.X509KeyPair(certPEM, keyPEM)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	return cert, pool, certPEM, keyPEM
}

func TestFetchTLSAndMTLS(t *testing.T) {
	_, clientPool, certPEM, keyPEM := selfSigned(t)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) == 0 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		mustWrite(t, w, []byte(`[{"ok":"yes"}]`))
	}))
	srv.TLS = &tls.Config{ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: clientPool, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	f := Fetcher{Guard: Guard{AllowHosts: []string{"127.0.0.1"}, AllowPrivate: true}, RootCAs: roots}
	if _, err := f.Fetch(context.Background(), Request{URL: srv.URL}); !errors.Is(err, ErrStatus) {
		t.Fatalf("no client cert %v", err)
	}
	tb, err := f.Fetch(context.Background(), Request{URL: srv.URL, Auth: Auth{CertPEM: certPEM, KeyPEM: keyPEM}})
	if err != nil || tb.Rows[0]["ok"] != "yes" {
		t.Fatalf("%+v %v", tb, err)
	}
	if _, err := (Fetcher{Guard: f.Guard}).Fetch(context.Background(), Request{URL: srv.URL}); err == nil {
		t.Fatal("untrusted root must fail")
	}
}

// TestCheckURLNeedsNoLookup proves the page can check the scheme and the
// allowlist of a new HTTP source without a DNS lookup.
func TestCheckURLNeedsNoLookup(t *testing.T) {
	g := Guard{AllowHosts: []string{".gov.example"}, LookupIP: func(context.Context, string) ([]net.IP, error) {
		t.Fatal("CheckURL must not resolve the host")
		return nil, nil
	}}
	if _, err := g.CheckURL("https://registry.gov.example/farmers"); err != nil {
		t.Fatal(err)
	}
	for raw, want := range map[string]error{
		"http://registry.gov.example/x":    ErrScheme,
		"https://api.other.example/x":      ErrHost,
		"https://u:p@registry.gov.example": ErrUserInfo,
		"https:///x":                       ErrHost,
	} {
		if _, err := g.CheckURL(raw); !errors.Is(err, want) {
			t.Errorf("%s: %v, want %v", raw, err, want)
		}
	}
	if _, err := g.CheckURL("::"); err == nil {
		t.Error("a URL that does not parse must fail")
	}
}
