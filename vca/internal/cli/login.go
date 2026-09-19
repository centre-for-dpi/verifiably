// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// TokenFileName is the file that holds the admin access token.
const TokenFileName = "admin-token"

// Discovery holds the endpoints the CLI needs from an OpenID Connect
// discovery document ([OIDC Discovery 1.0]).
type Discovery struct {
	// Issuer is the issuer identifier.
	Issuer string `json:"issuer"`
	// AuthorizationEndpoint starts the loopback login.
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	// TokenEndpoint exchanges the code for a token.
	TokenEndpoint string `json:"token_endpoint"`
	// DeviceAuthorizationEndpoint starts the device login ([RFC 8628]).
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
}

// FetchDiscovery reads the discovery document of a provider.
func FetchDiscovery(ctx context.Context, client *http.Client, discoveryURL string) (Discovery, error) {
	var out Discovery
	body, err := doJSON(ctx, orDefault(client), http.MethodGet, discoveryURL, "", nil)
	if err != nil {
		return out, fmt.Errorf("read the discovery document: %w", err)
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return out, fmt.Errorf("read the discovery document: %w", err)
	}
	if out.TokenEndpoint == "" {
		return out, errors.New("read the discovery document: it holds no token_endpoint")
	}
	return out, nil
}

func orDefault(c *http.Client) *http.Client {
	if c == nil {
		return http.DefaultClient
	}
	return c
}

// Pkce holds one proof key for code exchange ([RFC 7636]).
type Pkce struct {
	// Verifier is the random secret.
	Verifier string
	// Challenge is the S256 hash of the verifier.
	Challenge string
}

// NewPkce builds a verifier and its S256 challenge.
func NewPkce(random io.Reader) (Pkce, error) {
	verifier, err := RandomSecret(random)
	if err != nil {
		return Pkce{}, err
	}
	sum := sha256.Sum256([]byte(verifier))
	return Pkce{Verifier: verifier, Challenge: base64.RawURLEncoding.EncodeToString(sum[:])}, nil
}

// LoginOptions holds one admin login.
type LoginOptions struct {
	// DiscoveryURL is the OIDC discovery URL of the provider.
	DiscoveryURL string
	// ClientID is the OAuth 2.0 client id of the CLI.
	ClientID string
	// Scopes are the scopes to ask for.
	Scopes []string
	// HTTP makes the calls.
	HTTP *http.Client
	// Random is the source of the PKCE verifier and the state.
	Random io.Reader
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

// tokenAnswer is the answer of a token endpoint.
type tokenAnswer struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Error       string `json:"error"`
}

// LoopbackLogin runs the authorization code flow with PKCE against a
// loopback redirect URI. The flow has no client secret and no implicit
// grant (ADR-010 decision 2).
func LoopbackLogin(ctx context.Context, opts LoginOptions) (string, error) {
	found, err := FetchDiscovery(ctx, opts.HTTP, opts.DiscoveryURL)
	if err != nil {
		return "", err
	}
	if found.AuthorizationEndpoint == "" {
		return "", errors.New("login: the provider has no authorization_endpoint")
	}
	pkce, err := NewPkce(opts.Random)
	if err != nil {
		return "", err
	}
	state, err := RandomSecret(opts.Random)
	if err != nil {
		return "", err
	}
	listener, err := opts.listen()
	if err != nil {
		return "", fmt.Errorf("listen on the loopback address: %w", err)
	}
	defer func() { _ = listener.Close() }()
	redirect := "http://" + listener.Addr().String() + "/callback"
	query := url.Values{
		"response_type":         {"code"},
		"client_id":             {opts.ClientID},
		"redirect_uri":          {redirect},
		"state":                 {state},
		"code_challenge":        {pkce.Challenge},
		"code_challenge_method": {"S256"},
		"scope":                 {strings.Join(opts.scopes(), " ")},
	}
	fmt.Fprintf(opts.Out, "Open this address in a browser and log in:\n%s?%s\n",
		found.AuthorizationEndpoint, query.Encode())

	code, err := waitForCode(ctx, listener, state, opts.deadline())
	if err != nil {
		return "", err
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirect},
		"client_id":     {opts.ClientID},
		"code_verifier": {pkce.Verifier},
	}
	return postToken(ctx, opts, found.TokenEndpoint, form)
}

// codeResult is the answer of the loopback callback.
type codeResult struct {
	code string
	err  error
}

// waitForCode serves one request on the loopback listener and returns the
// authorization code. It checks the state value ([RFC 9700]).
func waitForCode(ctx context.Context, listener net.Listener, state string, deadline time.Duration) (string, error) {
	results := make(chan codeResult, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if got := q.Get("state"); got != state {
			http.Error(w, "the state value does not match", http.StatusBadRequest)
			results <- codeResult{err: errors.New("login: the state value does not match")}
			return
		}
		if fault := q.Get("error"); fault != "" {
			http.Error(w, "the provider reported an error", http.StatusBadRequest)
			results <- codeResult{err: fmt.Errorf("login: the provider reported %s", fault)}
			return
		}
		code := q.Get("code")
		if code == "" {
			http.Error(w, "the answer holds no code", http.StatusBadRequest)
			results <- codeResult{err: errors.New("login: the answer holds no code")}
			return
		}
		_, _ = io.WriteString(w, "Login done. Close this page and go back to the terminal.\n")
		results <- codeResult{code: code}
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = server.Serve(listener) }()
	// Shutdown waits for the browser to receive the answer page. Close
	// would cut the connection before the answer leaves.
	defer func() {
		stop, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(stop)
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

// DeviceLogin runs the device authorization grant ([RFC 8628]).
// An operator uses it on a host with no browser.
func DeviceLogin(ctx context.Context, opts LoginOptions) (string, error) {
	found, err := FetchDiscovery(ctx, opts.HTTP, opts.DiscoveryURL)
	if err != nil {
		return "", err
	}
	if found.DeviceAuthorizationEndpoint == "" {
		return "", errors.New("login: the provider has no device_authorization_endpoint")
	}
	start := url.Values{
		"client_id": {opts.ClientID},
		"scope":     {strings.Join(opts.scopes(), " ")},
	}
	body, err := postForm(ctx, opts, found.DeviceAuthorizationEndpoint, start)
	if err != nil {
		return "", fmt.Errorf("start the device login: %w", err)
	}
	var device struct {
		DeviceCode      string `json:"device_code"`
		UserCode        string `json:"user_code"`
		VerificationURI string `json:"verification_uri"`
		Interval        int    `json:"interval"`
	}
	if err := json.Unmarshal(body, &device); err != nil || device.DeviceCode == "" {
		return "", errors.New("start the device login: the answer holds no device_code")
	}
	fmt.Fprintf(opts.Out, "Open %s and type the code %s\n", device.VerificationURI, device.UserCode)
	wait := opts.poll()
	if device.Interval > 0 {
		wait = time.Duration(device.Interval) * time.Second
	}
	form := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {device.DeviceCode},
		"client_id":   {opts.ClientID},
	}
	end := time.Now().Add(opts.deadline())
	for time.Now().Before(end) {
		token, err := postToken(ctx, opts, found.TokenEndpoint, form)
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

func (e *pendingError) Error() string { return "login: the provider reports " + e.code }

// postToken calls the token endpoint and returns the access token.
func postToken(ctx context.Context, opts LoginOptions, endpoint string, form url.Values) (string, error) {
	body, err := postForm(ctx, opts, endpoint, form)
	if err != nil {
		var fault *statusError
		if errors.As(err, &fault) {
			var parsed tokenAnswer
			_ = json.Unmarshal(fault.body, &parsed)
			if parsed.Error == "authorization_pending" || parsed.Error == "slow_down" {
				return "", &pendingError{code: parsed.Error}
			}
			if parsed.Error != "" {
				return "", fmt.Errorf("login: the provider reported %s", parsed.Error)
			}
		}
		return "", fmt.Errorf("get a token: %w", err)
	}
	var parsed tokenAnswer
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("get a token: %w", err)
	}
	if parsed.AccessToken == "" {
		return "", errors.New("get a token: the answer holds no access_token")
	}
	return parsed.AccessToken, nil
}

// statusError carries the body of a non 2xx answer.
type statusError struct {
	status int
	body   []byte
}

func (e *statusError) Error() string {
	return fmt.Sprintf("the provider answered %d", e.status)
}

// postForm sends one form encoded request.
func postForm(ctx context.Context, opts LoginOptions, endpoint string, form url.Values) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build the request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := orDefault(opts.HTTP).Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read the answer: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, &statusError{status: resp.StatusCode, body: body}
	}
	return body, nil
}

func (o LoginOptions) scopes() []string {
	if len(o.Scopes) > 0 {
		return o.Scopes
	}
	return []string{"openid", "profile", "email"}
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

// SaveToken writes the access token with mode 0600.
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

// LoadToken reads the saved access token. A missing file gives an empty
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
