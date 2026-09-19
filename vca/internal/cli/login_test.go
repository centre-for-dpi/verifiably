// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// idp is a fake OpenID Connect provider.
type idp struct {
	server     *httptest.Server
	code       string
	verifier   string
	deviceCode string
	pending    int
	noDevice   bool
	noAuth     bool
	failToken  bool
}

func newIdp(t *testing.T, state *idp) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	server := httptest.NewUnstartedServer(mux)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		base := "http://" + server.Listener.Addr().String()
		doc := `{"issuer":"` + base + `","token_endpoint":"` + base + `/token"`
		if !state.noAuth {
			doc += `,"authorization_endpoint":"` + base + `/auth"`
		}
		if !state.noDevice {
			doc += `,"device_authorization_endpoint":"` + base + `/device"`
		}
		_, _ = io.WriteString(w, doc+"}")
	})
	mux.HandleFunc("/device", func(w http.ResponseWriter, _ *http.Request) {
		state.deviceCode = "d-code"
		_, _ = io.WriteString(w, `{"device_code":"d-code","user_code":"WXYZ-1234","verification_uri":"http://idp/activate","interval":0}`)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if state.failToken {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":"invalid_grant"}`)
			return
		}
		if r.Form.Get("grant_type") == "urn:ietf:params:oauth:grant-type:device_code" && state.pending > 0 {
			state.pending--
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":"authorization_pending"}`)
			return
		}
		state.verifier = r.Form.Get("code_verifier")
		_, _ = io.WriteString(w, `{"access_token":"an-access-token","token_type":"Bearer","expires_in":300}`)
	})
	server.Start()
	state.server = server
	return server
}

func loginOptions(server *httptest.Server, out io.Writer) LoginOptions {
	return LoginOptions{
		DiscoveryURL: server.URL + "/.well-known/openid-configuration",
		ClientID:     "vca-admin",
		Random:       rand.Reader,
		Out:          out,
		Poll:         time.Millisecond,
		Deadline:     10 * time.Second,
	}
}

func TestNewPkce(t *testing.T) {
	got, err := NewPkce(rand.Reader)
	if err != nil {
		t.Fatalf("NewPkce: %v", err)
	}
	sum := sha256.Sum256([]byte(got.Verifier))
	if got.Challenge != base64.RawURLEncoding.EncodeToString(sum[:]) {
		t.Error("the challenge is not the S256 hash of the verifier")
	}
	if _, err := NewPkce(&shortReader{n: 1}); err == nil {
		t.Fatal("a failing random source passed")
	}
}

func TestFetchDiscovery(t *testing.T) {
	state := &idp{}
	server := newIdp(t, state)
	defer server.Close()
	got, err := FetchDiscovery(context.Background(), nil, server.URL+"/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("FetchDiscovery: %v", err)
	}
	if got.TokenEndpoint == "" || got.AuthorizationEndpoint == "" {
		t.Errorf("discovery = %+v", got)
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{}`)
	}))
	defer bad.Close()
	if _, err := FetchDiscovery(context.Background(), nil, bad.URL); err == nil {
		t.Error("a document with no token endpoint passed")
	}
	notJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `nope`)
	}))
	defer notJSON.Close()
	if _, err := FetchDiscovery(context.Background(), nil, notJSON.URL); err == nil {
		t.Error("a document that is not JSON passed")
	}
	if _, err := FetchDiscovery(context.Background(), nil, "://"); err == nil {
		t.Error("a bad URL passed")
	}
}

// visit reads the printed authorization URL and calls the redirect URI.
func visit(t *testing.T, printed string, values url.Values) {
	t.Helper()
	line := ""
	for _, l := range strings.Split(printed, "\n") {
		if strings.Contains(l, "response_type=code") {
			line = l
		}
	}
	if line == "" {
		t.Fatalf("no authorization URL was printed:\n%s", printed)
	}
	u, err := url.Parse(line)
	if err != nil {
		t.Fatalf("parse the printed URL: %v", err)
	}
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" {
		t.Errorf("the challenge method = %q", q.Get("code_challenge_method"))
	}
	if q.Get("response_type") != "code" {
		t.Errorf("the response type = %q", q.Get("response_type"))
	}
	redirect, err := url.Parse(q.Get("redirect_uri"))
	if err != nil {
		t.Fatalf("parse the redirect URI: %v", err)
	}
	if redirect.Hostname() != "127.0.0.1" {
		t.Errorf("the redirect host = %q", redirect.Hostname())
	}
	if values.Get("state") == "keep" {
		values.Set("state", q.Get("state"))
	}
	redirect.RawQuery = values.Encode()
	resp, err := http.Get(redirect.String()) // #nosec G107 -- a loopback address in a test
	if err != nil {
		t.Fatalf("call the redirect URI: %v", err)
	}
	_ = resp.Body.Close()
}

func TestLoopbackLogin(t *testing.T) {
	state := &idp{}
	server := newIdp(t, state)
	defer server.Close()
	var out lockedBuffer
	opts := loginOptions(server, &out)
	done := make(chan struct{})
	var token string
	var err error
	go func() {
		token, err = LoopbackLogin(context.Background(), opts)
		close(done)
	}()
	waitForPrint(t, &out)
	visit(t, out.String(), url.Values{"code": {"an-auth-code"}, "state": {"keep"}})
	<-done
	if err != nil {
		t.Fatalf("LoopbackLogin: %v\n%s", err, out.String())
	}
	if token != "an-access-token" {
		t.Errorf("token = %q", token)
	}
	if state.verifier == "" {
		t.Error("the token call carried no PKCE verifier")
	}
}

func TestLoopbackLoginRejectsABadState(t *testing.T) {
	state := &idp{}
	server := newIdp(t, state)
	defer server.Close()
	var out lockedBuffer
	done := make(chan struct{})
	var err error
	go func() {
		_, err = LoopbackLogin(context.Background(), loginOptions(server, &out))
		close(done)
	}()
	waitForPrint(t, &out)
	visit(t, out.String(), url.Values{"code": {"c"}, "state": {"wrong"}})
	<-done
	if err == nil || !strings.Contains(err.Error(), "state") {
		t.Fatalf("got %v", err)
	}
}

func TestLoopbackLoginReportsAProviderError(t *testing.T) {
	state := &idp{}
	server := newIdp(t, state)
	defer server.Close()
	var out lockedBuffer
	done := make(chan struct{})
	var err error
	go func() {
		_, err = LoopbackLogin(context.Background(), loginOptions(server, &out))
		close(done)
	}()
	waitForPrint(t, &out)
	visit(t, out.String(), url.Values{"error": {"access_denied"}, "state": {"keep"}})
	<-done
	if err == nil || !strings.Contains(err.Error(), "access_denied") {
		t.Fatalf("got %v", err)
	}
}

func TestLoopbackLoginNeedsACode(t *testing.T) {
	state := &idp{}
	server := newIdp(t, state)
	defer server.Close()
	var out lockedBuffer
	done := make(chan struct{})
	var err error
	go func() {
		_, err = LoopbackLogin(context.Background(), loginOptions(server, &out))
		close(done)
	}()
	waitForPrint(t, &out)
	visit(t, out.String(), url.Values{"state": {"keep"}})
	<-done
	if err == nil || !strings.Contains(err.Error(), "no code") {
		t.Fatalf("got %v", err)
	}
}

func TestLoopbackLoginTimesOut(t *testing.T) {
	state := &idp{}
	server := newIdp(t, state)
	defer server.Close()
	var out bytes.Buffer
	opts := loginOptions(server, &out)
	opts.Deadline = 10 * time.Millisecond
	if _, err := LoopbackLogin(context.Background(), opts); err == nil {
		t.Fatal("a login with no answer passed")
	}
}

func TestLoopbackLoginNeedsAnAuthorizationEndpoint(t *testing.T) {
	state := &idp{noAuth: true}
	server := newIdp(t, state)
	defer server.Close()
	var out bytes.Buffer
	if _, err := LoopbackLogin(context.Background(), loginOptions(server, &out)); err == nil {
		t.Fatal("a provider with no authorization endpoint passed")
	}
}

func TestLoopbackLoginReportsABadDiscoveryURL(t *testing.T) {
	var out bytes.Buffer
	opts := loginOptions(httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})), &out)
	opts.DiscoveryURL = "://"
	if _, err := LoopbackLogin(context.Background(), opts); err == nil {
		t.Fatal("a bad discovery URL passed")
	}
}

func TestLoopbackLoginReportsAFailedListener(t *testing.T) {
	state := &idp{}
	server := newIdp(t, state)
	defer server.Close()
	var out bytes.Buffer
	opts := loginOptions(server, &out)
	opts.Listen = func() (net.Listener, error) { return nil, io.ErrUnexpectedEOF }
	if _, err := LoopbackLogin(context.Background(), opts); err == nil {
		t.Fatal("a failed listener passed")
	}
}

func TestLoopbackLoginReportsAFailingRandomSource(t *testing.T) {
	state := &idp{}
	server := newIdp(t, state)
	defer server.Close()
	var out bytes.Buffer
	for _, n := range []int{1, 40} {
		opts := loginOptions(server, &out)
		opts.Random = &shortReader{n: n}
		if _, err := LoopbackLogin(context.Background(), opts); err == nil {
			t.Errorf("a random source of %d bytes passed", n)
		}
	}
}

func TestDeviceLogin(t *testing.T) {
	state := &idp{pending: 2}
	server := newIdp(t, state)
	defer server.Close()
	var out bytes.Buffer
	token, err := DeviceLogin(context.Background(), loginOptions(server, &out))
	if err != nil {
		t.Fatalf("DeviceLogin: %v", err)
	}
	if token != "an-access-token" {
		t.Errorf("token = %q", token)
	}
	if !strings.Contains(out.String(), "WXYZ-1234") {
		t.Errorf("the user code is missing:\n%s", out.String())
	}
	if state.pending != 0 {
		t.Errorf("the CLI stopped polling with %d answers left", state.pending)
	}
}

func TestDeviceLoginNeedsTheEndpoint(t *testing.T) {
	state := &idp{noDevice: true}
	server := newIdp(t, state)
	defer server.Close()
	var out bytes.Buffer
	if _, err := DeviceLogin(context.Background(), loginOptions(server, &out)); err == nil {
		t.Fatal("a provider with no device endpoint passed")
	}
}

func TestDeviceLoginReportsAProviderError(t *testing.T) {
	state := &idp{failToken: true}
	server := newIdp(t, state)
	defer server.Close()
	var out bytes.Buffer
	_, err := DeviceLogin(context.Background(), loginOptions(server, &out))
	if err == nil || !strings.Contains(err.Error(), "invalid_grant") {
		t.Fatalf("got %v", err)
	}
}

func TestDeviceLoginGivesUp(t *testing.T) {
	state := &idp{pending: 1000}
	server := newIdp(t, state)
	defer server.Close()
	var out bytes.Buffer
	opts := loginOptions(server, &out)
	opts.Deadline = 20 * time.Millisecond
	if _, err := DeviceLogin(context.Background(), opts); err == nil {
		t.Fatal("a login that never finished passed")
	}
}

func TestDeviceLoginReportsABadStart(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "openid-configuration") {
			base := "http://" + r.Host
			_, _ = io.WriteString(w, `{"token_endpoint":"`+base+`/token","device_authorization_endpoint":"`+base+`/device"}`)
			return
		}
		_, _ = io.WriteString(w, `{}`)
	}))
	defer bad.Close()
	var out bytes.Buffer
	opts := LoginOptions{
		DiscoveryURL: bad.URL + "/.well-known/openid-configuration",
		ClientID:     "vca-admin", Random: rand.Reader, Out: &out,
		Poll: time.Millisecond, Deadline: time.Second,
	}
	if _, err := DeviceLogin(context.Background(), opts); err == nil {
		t.Fatal("an answer with no device code passed")
	}
}

func TestDeviceLoginReportsABadDiscoveryURL(t *testing.T) {
	var out bytes.Buffer
	if _, err := DeviceLogin(context.Background(), LoginOptions{DiscoveryURL: "://", Out: &out}); err == nil {
		t.Fatal("a bad discovery URL passed")
	}
}

func TestSaveAndLoadToken(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	got, err := LoadToken(dir)
	if err != nil || got != "" {
		t.Fatalf("got %q, %v, want an empty token", got, err)
	}
	path, err := SaveToken(dir, "a-token")
	if err != nil {
		t.Fatalf("SaveToken: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("the token file has mode %04o", info.Mode().Perm())
	}
	got, err = LoadToken(dir)
	if err != nil || got != "a-token" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestSaveTokenReportsABadDirectory(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := SaveToken(file, "t"); err == nil {
		t.Fatal("a file in place of a directory passed")
	}
}

func TestLoadTokenReportsAnUnreadableFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, TokenFileName), 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadToken(dir); err == nil {
		t.Fatal("a directory in place of the token file passed")
	}
}

func TestLoginOptionDefaults(t *testing.T) {
	var opts LoginOptions
	if len(opts.scopes()) == 0 || opts.poll() == 0 || opts.deadline() == 0 {
		t.Error("a zero LoginOptions has no defaults")
	}
	set := LoginOptions{Scopes: []string{"openid"}, Poll: time.Second, Deadline: time.Minute}
	if len(set.scopes()) != 1 || set.poll() != time.Second || set.deadline() != time.Minute {
		t.Error("the set values were ignored")
	}
	listener, err := opts.listen()
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_ = listener.Close()
}

func TestPendingError(t *testing.T) {
	e := &pendingError{code: "slow_down"}
	if !strings.Contains(e.Error(), "slow_down") {
		t.Errorf("got %q", e.Error())
	}
	s := &statusError{status: 400}
	if !strings.Contains(s.Error(), "400") {
		t.Errorf("got %q", s.Error())
	}
}

func TestPostFormReportsABadEndpoint(t *testing.T) {
	if _, err := postForm(context.Background(), LoginOptions{}, "://", nil); err == nil {
		t.Fatal("a bad endpoint passed")
	}
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := server.URL
	server.Close()
	if _, err := postForm(context.Background(), LoginOptions{}, url, nil); err == nil {
		t.Fatal("a closed server passed")
	}
}

// lockedBuffer is a buffer two goroutines can use.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// waitForPrint waits until the login prints the authorization URL.
func waitForPrint(t *testing.T, b *lockedBuffer) {
	t.Helper()
	for i := 0; i < 500; i++ {
		if strings.Contains(b.String(), "response_type=code") {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("the login printed no authorization URL")
}
