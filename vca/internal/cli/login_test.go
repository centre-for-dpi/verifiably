// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
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

// fakeAdmin is a stand in for the admin service login endpoints.
type fakeAdmin struct {
	server *httptest.Server
	// port is the loopback port the CLI asked for.
	port string
	// provider and bootstrap record the form fields the CLI sent.
	provider  string
	bootstrap string
	// pending is the number of authorization_pending answers to send.
	pending int
	// noURL drops the authorization URL from the start answer.
	noURL bool
	// noDeviceCode drops the device code from the start answer.
	noDeviceCode bool
	// failStart makes the start endpoint answer an OAuth error.
	failStart bool
	// failToken makes the token endpoints answer an OAuth error.
	failToken bool
	// noToken drops the access token from the token answer.
	noToken bool
}

func newFakeAdmin(t *testing.T, state *fakeAdmin) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	server := httptest.NewUnstartedServer(mux)
	// record keeps the last value the CLI sent for each field. The
	// second call of a flow carries the code only, so an empty field
	// leaves the record alone.
	record := func(r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("r.ParseForm: %v", err)
		}
		if v := r.PostFormValue("provider"); v != "" {
			state.provider = v
		}
		if v := r.PostFormValue(BootstrapField); v != "" {
			state.bootstrap = v
		}
	}
	mux.HandleFunc(LoopbackStartPath, func(w http.ResponseWriter, r *http.Request) {
		record(r)
		state.port = r.PostFormValue("port")
		if state.failStart {
			w.WriteHeader(http.StatusBadRequest)
			_, errAssign := io.WriteString(w, `{"error":"invalid_request","error_description":"port must be a number from 1024 to 65535"}`)
			if errAssign != nil {
				t.Fatalf("io.WriteString: %v", errAssign)
			}
			return
		}
		if state.noURL {
			_, errAssign2 := io.WriteString(w, `{}`)
			if errAssign2 != nil {
				t.Fatalf("io.WriteString: %v", errAssign2)
			}
			return
		}
		_, errAssign3 := io.WriteString(w, `{"authorization_url":"https://idp.example/auth?state=abc",`+
			`"redirect_uri":"http://127.0.0.1:`+state.port+`/callback"}`)
		if errAssign3 != nil {
			t.Fatalf("io.WriteString: %v", errAssign3)
		}
	})
	mux.HandleFunc(LoopbackTokenPath, func(w http.ResponseWriter, r *http.Request) {
		record(r)
		if r.PostFormValue("code") == "" || state.failToken {
			w.WriteHeader(http.StatusBadRequest)
			_, errAssign4 := io.WriteString(w, `{"error":"invalid_grant","error_description":"the code is not valid or it expired"}`)
			if errAssign4 != nil {
				t.Fatalf("io.WriteString: %v", errAssign4)
			}
			return
		}
		writeSession(w, state)
	})
	mux.HandleFunc(DeviceStartPath, func(w http.ResponseWriter, r *http.Request) {
		record(r)
		if state.failStart {
			w.WriteHeader(http.StatusBadRequest)
			_, errAssign5 := io.WriteString(w, `{"error":"unsupported_grant_type","error_description":"the provider supports no device grant, use the loopback helper at /cli/login"}`)
			if errAssign5 != nil {
				t.Fatalf("io.WriteString: %v", errAssign5)
			}
			return
		}
		if state.noDeviceCode {
			_, errAssign6 := io.WriteString(w, `{}`)
			if errAssign6 != nil {
				t.Fatalf("io.WriteString: %v", errAssign6)
			}
			return
		}
		_, errAssign7 := io.WriteString(w,
			`{"device_code":"d-code","user_code":"WXYZ-1234","verification_uri":"https://idp.example/activate","interval":0,"provider":"p-1"}`)
		if errAssign7 != nil {
			t.Fatalf("io.WriteString: %v", errAssign7)
		}
	})
	mux.HandleFunc(DeviceTokenPath, func(w http.ResponseWriter, r *http.Request) {
		record(r)
		if r.PostFormValue("grant_type") != DeviceGrant || r.PostFormValue("device_code") == "" {
			w.WriteHeader(http.StatusBadRequest)
			_, errAssign8 := io.WriteString(w, `{"error":"invalid_request"}`)
			if errAssign8 != nil {
				t.Fatalf("io.WriteString: %v", errAssign8)
			}
			return
		}
		if state.failToken {
			w.WriteHeader(http.StatusBadRequest)
			_, errAssign9 := io.WriteString(w, `{"error":"access_denied","error_description":"the admin refused the login"}`)
			if errAssign9 != nil {
				t.Fatalf("io.WriteString: %v", errAssign9)
			}
			return
		}
		if state.pending > 0 {
			state.pending--
			w.WriteHeader(http.StatusBadRequest)
			_, errAssign10 := io.WriteString(w, `{"error":"authorization_pending"}`)
			if errAssign10 != nil {
				t.Fatalf("io.WriteString: %v", errAssign10)
			}
			return
		}
		writeSession(w, state)
	})
	server.Start()
	state.server = server
	return server
}

func writeSession(w http.ResponseWriter, state *fakeAdmin) {
	if state.noToken {
		_, _ = io.WriteString(w, `{"token_type":"Bearer"}`)
		return
	}
	_, _ = io.WriteString(w, `{"access_token":"an-admin-session","token_type":"Bearer","expires_in":900,"csrf_token":"c"}`)
}

func adminLoginOptions(server *httptest.Server, out io.Writer) LoginOptions {
	return LoginOptions{
		AdminURL: server.URL,
		Out:      out,
		Poll:     time.Millisecond,
		Deadline: 10 * time.Second,
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

// waitForPort waits until the fake admin service knows the loopback port.
func waitForPort(t *testing.T, state *fakeAdmin, out *lockedBuffer) string {
	t.Helper()
	for i := 0; i < 500; i++ {
		if strings.Contains(out.String(), "https://idp.example/auth") {
			return state.port
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("the login printed no authorization URL:\n%s", out.String())
	return ""
}

// callback calls the loopback address the way the admin service does.
func callback(t *testing.T, port string, values url.Values) {
	t.Helper()
	target := "http://127.0.0.1:" + port + LoopbackCallbackPath + "?" + values.Encode()
	resp, err := http.Get(target) // #nosec G107 -- a loopback address in a test
	if err != nil {
		t.Fatalf("call the loopback address: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("resp.Body.Close: %v", err)
	}
}

func TestLoopbackLogin(t *testing.T) {
	state := &fakeAdmin{}
	server := newFakeAdmin(t, state)
	defer server.Close()
	var out lockedBuffer
	opts := adminLoginOptions(server, &out)
	opts.Provider = "p-1"
	opts.BootstrapToken = "boot"
	done := make(chan struct{})
	var token string
	var err error
	go func() {
		token, err = LoopbackLogin(context.Background(), opts)
		close(done)
	}()
	port := waitForPort(t, state, &out)
	callback(t, port, url.Values{"code": {"one-time-code"}})
	<-done
	if err != nil {
		t.Fatalf("LoopbackLogin: %v\n%s", err, out.String())
	}
	if token != "an-admin-session" {
		t.Errorf("token = %q", token)
	}
	if state.provider != "p-1" || state.bootstrap != "boot" {
		t.Errorf("provider = %q, bootstrap = %q", state.provider, state.bootstrap)
	}
	if port == "" || port == "0" {
		t.Errorf("the CLI asked for port %q", port)
	}
}

func TestLoopbackLoginReportsAnAdminError(t *testing.T) {
	state := &fakeAdmin{}
	server := newFakeAdmin(t, state)
	defer server.Close()
	var out lockedBuffer
	done := make(chan struct{})
	var err error
	go func() {
		_, err = LoopbackLogin(context.Background(), adminLoginOptions(server, &out))
		close(done)
	}()
	port := waitForPort(t, state, &out)
	callback(t, port, url.Values{"error": {"access_denied"}})
	<-done
	if err == nil || !strings.Contains(err.Error(), "access_denied") {
		t.Fatalf("got %v", err)
	}
}

func TestLoopbackLoginNeedsACode(t *testing.T) {
	state := &fakeAdmin{}
	server := newFakeAdmin(t, state)
	defer server.Close()
	var out lockedBuffer
	done := make(chan struct{})
	var err error
	go func() {
		_, err = LoopbackLogin(context.Background(), adminLoginOptions(server, &out))
		close(done)
	}()
	port := waitForPort(t, state, &out)
	callback(t, port, url.Values{})
	<-done
	if err == nil || !strings.Contains(err.Error(), "no code") {
		t.Fatalf("got %v", err)
	}
}

func TestLoopbackLoginIgnoresAnotherPath(t *testing.T) {
	state := &fakeAdmin{}
	server := newFakeAdmin(t, state)
	defer server.Close()
	var out lockedBuffer
	opts := adminLoginOptions(server, &out)
	opts.Deadline = 300 * time.Millisecond
	done := make(chan struct{})
	var err error
	go func() {
		_, err = LoopbackLogin(context.Background(), opts)
		close(done)
	}()
	port := waitForPort(t, state, &out)
	resp, getErr := http.Get("http://127.0.0.1:" + port + "/other") // #nosec G107 -- a loopback address
	if getErr != nil {
		t.Fatalf("call the loopback address: %v", getErr)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("another path answered %d", resp.StatusCode)
	}
	if gotErr := resp.Body.Close(); gotErr != nil {
		t.Fatalf("resp.Body.Close: %v", gotErr)
	}
	<-done
	if err == nil {
		t.Fatal("a login with no callback passed")
	}
}

func TestLoopbackLoginReportsAFailedExchange(t *testing.T) {
	state := &fakeAdmin{failToken: true}
	server := newFakeAdmin(t, state)
	defer server.Close()
	var out lockedBuffer
	done := make(chan struct{})
	var err error
	go func() {
		_, err = LoopbackLogin(context.Background(), adminLoginOptions(server, &out))
		close(done)
	}()
	port := waitForPort(t, state, &out)
	callback(t, port, url.Values{"code": {"c"}})
	<-done
	if err == nil || !strings.Contains(err.Error(), "invalid_grant") {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("the description is missing: %v", err)
	}
}

func TestLoopbackLoginReportsAFailedStart(t *testing.T) {
	state := &fakeAdmin{failStart: true}
	server := newFakeAdmin(t, state)
	defer server.Close()
	var out bytes.Buffer
	_, err := LoopbackLogin(context.Background(), adminLoginOptions(server, &out))
	if err == nil || !strings.Contains(err.Error(), "invalid_request") {
		t.Fatalf("got %v", err)
	}
}

func TestLoopbackLoginNeedsAnAuthorizationURL(t *testing.T) {
	state := &fakeAdmin{noURL: true}
	server := newFakeAdmin(t, state)
	defer server.Close()
	var out bytes.Buffer
	_, err := LoopbackLogin(context.Background(), adminLoginOptions(server, &out))
	if err == nil || !strings.Contains(err.Error(), "authorization_url") {
		t.Fatalf("got %v", err)
	}
}

func TestLoopbackLoginTimesOut(t *testing.T) {
	state := &fakeAdmin{}
	server := newFakeAdmin(t, state)
	defer server.Close()
	var out bytes.Buffer
	opts := adminLoginOptions(server, &out)
	opts.Deadline = 10 * time.Millisecond
	if _, err := LoopbackLogin(context.Background(), opts); err == nil {
		t.Fatal("a login with no answer passed")
	}
}

func TestLoopbackLoginReportsAFailedListener(t *testing.T) {
	state := &fakeAdmin{}
	server := newFakeAdmin(t, state)
	defer server.Close()
	var out bytes.Buffer
	opts := adminLoginOptions(server, &out)
	opts.Listen = func() (net.Listener, error) { return nil, io.ErrUnexpectedEOF }
	if _, err := LoopbackLogin(context.Background(), opts); err == nil {
		t.Fatal("a failed listener passed")
	}
}

func TestLoginNeedsTheAdminURL(t *testing.T) {
	var out bytes.Buffer
	for _, bad := range []string{"", "  ", "://", "ftp://admin.example", "admin.example"} {
		opts := LoginOptions{AdminURL: bad, Out: &out}
		if _, err := LoopbackLogin(context.Background(), opts); err == nil {
			t.Errorf("loopback accepted %q", bad)
		}
		if _, err := DeviceLogin(context.Background(), opts); err == nil {
			t.Errorf("device accepted %q", bad)
		}
	}
}

func TestDeviceLogin(t *testing.T) {
	state := &fakeAdmin{pending: 2}
	server := newFakeAdmin(t, state)
	defer server.Close()
	var out bytes.Buffer
	token, err := DeviceLogin(context.Background(), adminLoginOptions(server, &out))
	if err != nil {
		t.Fatalf("DeviceLogin: %v", err)
	}
	if token != "an-admin-session" {
		t.Errorf("token = %q", token)
	}
	if !strings.Contains(out.String(), "WXYZ-1234") {
		t.Errorf("the user code is missing:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "https://idp.example/activate") {
		t.Errorf("the verification URI is missing:\n%s", out.String())
	}
	if state.pending != 0 {
		t.Errorf("the CLI stopped polling with %d answers left", state.pending)
	}
	// The CLI sends back the provider the start answer named.
	if state.provider != "p-1" {
		t.Errorf("provider = %q", state.provider)
	}
}

func TestDeviceLoginReportsAFailedStart(t *testing.T) {
	state := &fakeAdmin{failStart: true}
	server := newFakeAdmin(t, state)
	defer server.Close()
	var out bytes.Buffer
	_, err := DeviceLogin(context.Background(), adminLoginOptions(server, &out))
	if err == nil || !strings.Contains(err.Error(), "unsupported_grant_type") {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(err.Error(), "/cli/login") {
		t.Errorf("the advice is missing: %v", err)
	}
}

func TestDeviceLoginNeedsADeviceCode(t *testing.T) {
	state := &fakeAdmin{noDeviceCode: true}
	server := newFakeAdmin(t, state)
	defer server.Close()
	var out bytes.Buffer
	_, err := DeviceLogin(context.Background(), adminLoginOptions(server, &out))
	if err == nil || !strings.Contains(err.Error(), "device_code") {
		t.Fatalf("got %v", err)
	}
}

func TestDeviceLoginReportsARefusedLogin(t *testing.T) {
	state := &fakeAdmin{failToken: true}
	server := newFakeAdmin(t, state)
	defer server.Close()
	var out bytes.Buffer
	_, err := DeviceLogin(context.Background(), adminLoginOptions(server, &out))
	if err == nil || !strings.Contains(err.Error(), "access_denied") {
		t.Fatalf("got %v", err)
	}
}

func TestDeviceLoginNeedsAnAccessToken(t *testing.T) {
	state := &fakeAdmin{noToken: true}
	server := newFakeAdmin(t, state)
	defer server.Close()
	var out bytes.Buffer
	_, err := DeviceLogin(context.Background(), adminLoginOptions(server, &out))
	if err == nil || !strings.Contains(err.Error(), "access_token") {
		t.Fatalf("got %v", err)
	}
}

func TestDeviceLoginGivesUp(t *testing.T) {
	state := &fakeAdmin{pending: 1000}
	server := newFakeAdmin(t, state)
	defer server.Close()
	var out bytes.Buffer
	opts := adminLoginOptions(server, &out)
	opts.Deadline = 20 * time.Millisecond
	if _, err := DeviceLogin(context.Background(), opts); err == nil {
		t.Fatal("a login that never finished passed")
	}
}

func TestDeviceLoginReportsAClosedService(t *testing.T) {
	state := &fakeAdmin{}
	server := newFakeAdmin(t, state)
	base := server.URL
	server.Close()
	var out bytes.Buffer
	opts := LoginOptions{AdminURL: base, Out: &out, Poll: time.Millisecond, Deadline: time.Second}
	if _, err := DeviceLogin(context.Background(), opts); err == nil {
		t.Fatal("a closed service passed")
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
	if opts.poll() == 0 || opts.deadline() == 0 {
		t.Error("a zero LoginOptions has no defaults")
	}
	set := LoginOptions{Poll: time.Second, Deadline: time.Minute}
	if set.poll() != time.Second || set.deadline() != time.Minute {
		t.Error("the set values were ignored")
	}
	listener, err := opts.listen()
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	if _, err := listenPort(listener); err != nil {
		t.Errorf("listenPort: %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("listener.Close: %v", err)
	}
}

func TestFormCarriesOnlyWhatIsSet(t *testing.T) {
	empty := LoginOptions{}.form()
	if len(empty) != 0 {
		t.Errorf("an empty login sent %v", empty)
	}
	full := LoginOptions{Provider: "p", BootstrapToken: "b"}.form()
	if full.Get("provider") != "p" || full.Get(BootstrapField) != "b" {
		t.Errorf("form = %v", full)
	}
}

func TestPendingAndStatusErrors(t *testing.T) {
	e := &pendingError{code: "slow_down"}
	if !strings.Contains(e.Error(), "slow_down") {
		t.Errorf("got %q", e.Error())
	}
	s := &statusError{status: 400}
	if !strings.Contains(s.Error(), "400") {
		t.Errorf("got %q", s.Error())
	}
	// describe keeps an error it cannot read.
	if got := describe(io.ErrUnexpectedEOF); !errors.Is(got, io.ErrUnexpectedEOF) {
		t.Errorf("describe changed a plain error: %v", got)
	}
	if got := describe(&statusError{status: 500, body: []byte("boom")}); !strings.Contains(got.Error(), "500") {
		t.Errorf("describe lost the status: %v", got)
	}
	plain := describe(&statusError{status: 400, body: []byte(`{"error":"invalid_request"}`)})
	if plain.Error() != "invalid_request" {
		t.Errorf("describe = %q", plain.Error())
	}
	withMessage := describe(&statusError{status: 400, body: []byte(`{"error":"x","message":"why"}`)})
	if withMessage.Error() != "x: why" {
		t.Errorf("describe = %q", withMessage.Error())
	}
}

func TestPostFormReportsABadEndpoint(t *testing.T) {
	if _, err := postForm(context.Background(), LoginOptions{}, "://", nil); err == nil {
		t.Fatal("a bad endpoint passed")
	}
}
