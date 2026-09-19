// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
)

// TokenFileName is the file that holds the admin session token.
const TokenFileName = "admin-token"

// The admin service holds the OpenID Connect client, so the CLI needs no
// client id, no client secret, and no provider discovery. These are the
// four endpoints it calls (services/admin/README.md, ADR-010 decision 6).
const (
	// LoopbackStartPath starts a loopback login.
	LoopbackStartPath = "/cli/login"
	// LoopbackTokenPath exchanges the one time loopback code.
	LoopbackTokenPath = "/cli/token"
	// DeviceStartPath starts the device authorization grant.
	DeviceStartPath = "/device_authorization"
	// DeviceTokenPath exchanges a device code for a session token.
	DeviceTokenPath = "/token"
)

// LoopbackCallbackPath is the path the admin service redirects to on the
// loopback address. The admin service builds the same URL, so the two
// must match.
const LoopbackCallbackPath = "/callback"

// DeviceGrant is the grant type of the device authorization grant
// ([RFC 8628] section 3.4).
const DeviceGrant = "urn:ietf:params:oauth:grant-type:device_code"

// BootstrapField is the form field that carries the one time bootstrap
// token of the first super admin (ADR-010 decision 4).
const BootstrapField = "bootstrap_token"

// LoginOptions holds one admin login.
type LoginOptions struct {
	// AdminURL is the base URL of the admin service.
	AdminURL string
	// Provider is the provider id to log in with. Empty takes the only
	// enabled provider.
	Provider string
	// BootstrapToken binds the first super admin. It is empty after that.
	BootstrapToken string
	// HTTP makes the calls.
	HTTP *http.Client
	// Out receives the instructions for the operator.
	Out io.Writer
	// Listen builds the loopback listener. A nil value listens on
	// 127.0.0.1 with a port the system picks.
	Listen func() (net.Listener, error)
	// Poll is the wait between two device token calls.
	Poll time.Duration
	// Deadline limits the whole login.
	Deadline time.Duration
}

// endpoint returns one admin endpoint URL.
func (o LoginOptions) endpoint(path string) (string, error) {
	base := strings.TrimRight(strings.TrimSpace(o.AdminURL), "/")
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", errors.New("login: set the admin service URL with --url or VCA_ADMIN_URL")
	}
	return base + path, nil
}

// form builds the shared fields of a login request.
func (o LoginOptions) form() url.Values {
	values := url.Values{}
	if o.Provider != "" {
		values.Set("provider", o.Provider)
	}
	if o.BootstrapToken != "" {
		values.Set(BootstrapField, o.BootstrapToken)
	}
	return values
}

// sessionAnswer is the answer of /cli/token and /token.
type sessionAnswer struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	CsrfToken   string `json:"csrf_token"`
	Error       string `json:"error"`
}

// LoopbackLogin logs a super admin in through the browser.
// The CLI opens a loopback port, asks the admin service for the
// authorization URL, and waits for the one time code ([RFC 8252]
// section 7.3). No token travels in a URL ([RFC 9700] section 4.3.2).
func LoopbackLogin(ctx context.Context, opts LoginOptions) (string, error) {
	start, startErr := opts.endpoint(LoopbackStartPath)
	if startErr != nil {
		return "", startErr
	}
	exchange, exchangeErr := opts.endpoint(LoopbackTokenPath)
	if exchangeErr != nil {
		return "", exchangeErr
	}
	listener, err := opts.listen()
	if err != nil {
		return "", fmt.Errorf("listen on the loopback address: %w", err)
	}
	defer func() { anyval.Discard(listener.Close()) }()
	port, err := listenPort(listener)
	if err != nil {
		return "", err
	}
	begin := opts.form()
	begin.Set("port", port)
	body, err := postForm(ctx, opts, start, begin)
	if err != nil {
		return "", fmt.Errorf("start the login: %w", describe(err))
	}
	var answer struct {
		AuthorizationURL string `json:"authorization_url"`
		RedirectURI      string `json:"redirect_uri"`
	}
	if gotErr := json.Unmarshal(body, &answer); gotErr != nil || answer.AuthorizationURL == "" {
		return "", errors.New("start the login: the answer holds no authorization_url")
	}
	anyval.DiscardWrite(fmt.Fprintf(opts.Out, "Open this address in a browser and log in:\n%s\n", answer.AuthorizationURL))

	code, err := waitForCode(ctx, listener, opts.deadline())
	if err != nil {
		return "", err
	}
	return postSession(ctx, opts, exchange, url.Values{"code": {code}})
}

// listenPort returns the port of a loopback listener as text.
func listenPort(listener net.Listener) (string, error) {
	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return "", errors.New("login: the loopback listener has no TCP address")
	}
	return strconv.Itoa(addr.Port), nil
}

// codeResult is the answer of the loopback callback.
type codeResult struct {
	code string
	err  error
}

// waitForCode serves one request on the loopback listener and returns
// the one time code that the admin service sent.
func waitForCode(ctx context.Context, listener net.Listener, deadline time.Duration) (string, error) {
	results := make(chan codeResult, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != LoopbackCallbackPath {
			http.NotFound(w, r)
			return
		}
		q := r.URL.Query()
		if fault := q.Get("error"); fault != "" {
			http.Error(w, "the login failed", http.StatusBadRequest)
			results <- codeResult{err: fmt.Errorf("login: the admin service reported %s", fault)}
			return
		}
		code := q.Get("code")
		if code == "" {
			http.Error(w, "the answer holds no code", http.StatusBadRequest)
			results <- codeResult{err: errors.New("login: the answer holds no code")}
			return
		}
		anyval.DiscardWrite(io.WriteString(w, "Login done. Close this page and go back to the terminal.\n"))
		results <- codeResult{code: code}
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go func() { anyval.Discard(server.Serve(listener)) }()
	// Shutdown waits for the browser to receive the answer page. Close
	// would cut the connection before the answer leaves.
	defer func() {
		stop, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		anyval.Discard(server.Shutdown(stop))
	}()
	timer := time.NewTimer(deadline)
	defer timer.Stop()
	select {
	case got := <-results:
		return got.code, got.err
	case <-timer.C:
		return "", errors.New("login: no answer came back in time")
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// DeviceLogin logs a super admin in on a host with no browser.
// The admin service proxies the device authorization grant ([RFC 8628]),
// so the CLI holds no client secret.
func DeviceLogin(ctx context.Context, opts LoginOptions) (string, error) {
	start, err := opts.endpoint(DeviceStartPath)
	if err != nil {
		return "", err
	}
	exchange, err := opts.endpoint(DeviceTokenPath)
	if err != nil {
		return "", err
	}
	body, err := postForm(ctx, opts, start, opts.form())
	if err != nil {
		return "", fmt.Errorf("start the device login: %w", describe(err))
	}
	var device struct {
		DeviceCode      string `json:"device_code"`
		UserCode        string `json:"user_code"`
		VerificationURI string `json:"verification_uri"`
		Interval        int    `json:"interval"`
		Provider        string `json:"provider"`
	}
	if err := json.Unmarshal(body, &device); err != nil || device.DeviceCode == "" {
		return "", errors.New("start the device login: the answer holds no device_code")
	}
	anyval.DiscardWrite(fmt.Fprintf(opts.Out, "Open %s and type the code %s\n", device.VerificationURI, device.UserCode))
	wait := opts.poll()
	if device.Interval > 0 {
		wait = time.Duration(device.Interval) * time.Second
	}
	form := opts.form()
	form.Set("grant_type", DeviceGrant)
	form.Set("device_code", device.DeviceCode)
	if device.Provider != "" {
		form.Set("provider", device.Provider)
	}
	end := time.Now().Add(opts.deadline())
	for time.Now().Before(end) {
		token, err := postSession(ctx, opts, exchange, form)
		if err == nil {
			return token, nil
		}
		var pending *pendingError
		if !errors.As(err, &pending) {
			return "", err
		}
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	return "", errors.New("login: the operator did not finish the device login in time")
}

// pendingError reports that the operator has not finished yet.
type pendingError struct{ code string }

func (e *pendingError) Error() string { return "login: the admin service reports " + e.code }

// postSession calls one token endpoint and returns the session token.
func postSession(ctx context.Context, opts LoginOptions, endpoint string, form url.Values) (string, error) {
	body, err := postForm(ctx, opts, endpoint, form)
	if err != nil {
		var fault *statusError
		if errors.As(err, &fault) {
			var parsed sessionAnswer
			anyval.Discard(json.Unmarshal(fault.body, &parsed))
			if parsed.Error == "authorization_pending" || parsed.Error == "slow_down" {
				return "", &pendingError{code: parsed.Error}
			}
		}
		return "", fmt.Errorf("get a session token: %w", describe(err))
	}
	var parsed sessionAnswer
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("get a session token: %w", err)
	}
	if parsed.AccessToken == "" {
		return "", errors.New("get a session token: the answer holds no access_token")
	}
	return parsed.AccessToken, nil
}

// describe turns a status error into the message the admin service sent.
func describe(err error) error {
	var fault *statusError
	if !errors.As(err, &fault) {
		return err
	}
	var body struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
		Message     string `json:"message"`
	}
	anyval.Discard(json.Unmarshal(fault.body, &body))
	text := body.Description
	if text == "" {
		text = body.Message
	}
	switch {
	case body.Error != "" && text != "":
		return fmt.Errorf("%s: %s", body.Error, text)
	case body.Error != "":
		return errors.New(body.Error)
	default:
		return fault
	}
}

// statusError carries the body of an answer outside the 2xx range.
type statusError struct {
	status int
	body   []byte
}

func (e *statusError) Error() string {
	return fmt.Sprintf("the admin service answered %d", e.status)
}

// postForm sends one form encoded request.
func postForm(ctx context.Context, opts LoginOptions, endpoint string, form url.Values) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build the request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	client := opts.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { anyval.Discard(resp.Body.Close()) }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read the answer: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, &statusError{status: resp.StatusCode, body: body}
	}
	return body, nil
}

func (o LoginOptions) poll() time.Duration {
	if o.Poll > 0 {
		return o.Poll
	}
	return 5 * time.Second
}

func (o LoginOptions) deadline() time.Duration {
	if o.Deadline > 0 {
		return o.Deadline
	}
	return 5 * time.Minute
}

func (o LoginOptions) listen() (net.Listener, error) {
	if o.Listen != nil {
		return o.Listen()
	}
	return net.Listen("tcp", "127.0.0.1:0")
}

// SaveToken writes the session token with mode 0600.
func SaveToken(dir, token string) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("make %s: %w", dir, err)
	}
	path := filepath.Join(dir, TokenFileName)
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("write %s: %w", path, err)
	}
	return path, nil
}

// LoadToken reads the saved session token. A missing file gives an empty
// token and no error, so a command can fall back to a flag.
func LoadToken(dir string) (string, error) {
	path := filepath.Join(dir, TokenFileName)
	data, err := os.ReadFile(path) // #nosec G304 -- the path comes from the CLI
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	return strings.TrimSpace(string(data)), nil
}
