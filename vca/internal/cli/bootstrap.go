// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// Bootstrap variables that no service reads, so they are not in the
// Config message. They name the DPG administrator that the one time
// bootstrap run uses (ADR-008 decision 4).
const (
	// EnvBootstrapURL overrides the DPG URL for the bootstrap run.
	EnvBootstrapURL = "VCA_BOOTSTRAP_URL"
	// EnvBootstrapUser is the DPG administrator name.
	EnvBootstrapUser = "VCA_BOOTSTRAP_ADMIN_USER"
	// EnvBootstrapSecret names the DPG administrator password variable.
	EnvBootstrapSecret = "VCA_BOOTSTRAP_ADMIN_PASSWORD" //nolint:gosec // G101: this is a variable name, not a credential.
	// EnvBootstrapOrg is the CREDEBL organisation name.
	EnvBootstrapOrg = "VCA_BOOTSTRAP_ORG"
)

// IssuerFile holds the walt.id onboarding answer, with the DID and the
// issuer key. The adapter service reads it.
const IssuerFile = "waltid-issuer.json"

// BootstrapOptions holds one DPG bootstrap run.
type BootstrapOptions struct {
	// Pair is the role and DPG the run configures.
	Pair Pair
	// Dir is the output directory of the pair, for example
	// deploy/issuer-waltid.
	Dir string
	// Values holds the .env values of the pair.
	Values map[string]string
	// Client makes the HTTP calls. A test passes a client that points
	// at an httptest server.
	Client *http.Client
	// Out receives one line per step.
	Out io.Writer
}

// BootstrapResult lists what the run did. A step that found the object
// already present reports "present", not "created", so a second run
// changes nothing (ADR-008 decision 4).
type BootstrapResult struct {
	// Steps lists one line per step, in order.
	Steps []string
}

// step records one step and prints it.
func (r *BootstrapResult) step(out io.Writer, format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	r.Steps = append(r.Steps, line)
	if out != nil {
		fmt.Fprintln(out, line)
	}
}

// client returns the HTTP client of the run.
func (o BootstrapOptions) client() *http.Client {
	if o.Client != nil {
		return o.Client
	}
	return http.DefaultClient
}

// baseURL returns the DPG base URL of the run, without a trailing slash.
func (o BootstrapOptions) baseURL() (string, error) {
	raw := o.Values[EnvBootstrapURL]
	if raw == "" {
		raw = o.Values["VCA_DPG_URL"]
	}
	raw = strings.TrimRight(raw, "/")
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", fmt.Errorf("bootstrap: set %s or VCA_DPG_URL to an absolute http or https URL", EnvBootstrapURL)
	}
	return raw, nil
}

// value returns one value with a fallback.
func (o BootstrapOptions) value(key, fallback string) string {
	if v := strings.TrimSpace(o.Values[key]); v != "" {
		return v
	}
	return fallback
}

// Bootstrap runs the post boot configuration of the DPG of the pair.
func Bootstrap(ctx context.Context, opts BootstrapOptions) (BootstrapResult, error) {
	switch opts.Pair.Dpg {
	case configv1.Dpg_DPG_WALTID:
		return BootstrapWaltid(ctx, opts)
	case configv1.Dpg_DPG_INJI:
		return BootstrapInji(ctx, opts)
	case configv1.Dpg_DPG_CREDEBL:
		return BootstrapCredebl(ctx, opts)
	default:
		return BootstrapResult{}, fmt.Errorf("bootstrap: no DPG named %s", ShortName(opts.Pair.Dpg.String()))
	}
}

// BootstrapWaltid provisions a did:web issuer and its key on the walt.id
// issuer API. The run writes the answer to waltid-issuer.json. A second
// run finds that file and does nothing (ADR-008 decision 4).
func BootstrapWaltid(ctx context.Context, opts BootstrapOptions) (BootstrapResult, error) {
	var result BootstrapResult
	base, err := opts.baseURL()
	if err != nil {
		return result, err
	}
	path := filepath.Join(opts.Dir, IssuerFile)
	if did, ok := readIssuerDid(path); ok {
		result.step(opts.Out, "walt.id issuer present: %s", did)
		return result, nil
	}
	body, err := WaltidOnboard(opts.Values)
	if err != nil {
		return result, err
	}
	answer, err := doJSON(ctx, opts.client(), http.MethodPost, base+"/onboard/issuer", "", body)
	if err != nil {
		return result, fmt.Errorf("walt.id onboard: %w", err)
	}
	var parsed struct {
		IssuerDid string `json:"issuerDid"`
	}
	if err := json.Unmarshal(answer, &parsed); err != nil || parsed.IssuerDid == "" {
		return result, errors.New("walt.id onboard: the answer holds no issuerDid")
	}
	if err := os.WriteFile(path, answer, 0o600); err != nil {
		return result, fmt.Errorf("write %s: %w", path, err)
	}
	result.step(opts.Out, "walt.id issuer created: %s", parsed.IssuerDid)
	return result, nil
}

// readIssuerDid reads the DID out of an earlier onboarding answer.
func readIssuerDid(path string) (string, bool) {
	data, err := os.ReadFile(path) // #nosec G304 -- the path comes from the pair
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return "", false
		}
		return "", false
	}
	var parsed struct {
		IssuerDid string `json:"issuerDid"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil || parsed.IssuerDid == "" {
		return "", false
	}
	return parsed.IssuerDid, true
}

// BootstrapInji imports the generated Keycloak realm that Inji and
// eSignet log in against. Keycloak imports a realm from its data
// directory only when the realm is absent, so the CLI uses the admin API
// instead (ADR-008 decision 4).
func BootstrapInji(ctx context.Context, opts BootstrapOptions) (BootstrapResult, error) {
	return bootstrapRealm(ctx, opts, "Inji")
}

// bootstrapRealm creates or updates the realm of a Keycloak based stack.
func bootstrapRealm(ctx context.Context, opts BootstrapOptions, stack string) (BootstrapResult, error) {
	var result BootstrapResult
	base, err := opts.baseURL()
	if err != nil {
		return result, err
	}
	realmBody, err := os.ReadFile(filepath.Join(opts.Dir, RealmFile)) // #nosec G304 -- the path comes from the pair
	if err != nil {
		return result, fmt.Errorf("read the generated realm: %w", err)
	}
	token, err := keycloakToken(ctx, opts, base)
	if err != nil {
		return result, err
	}
	result.step(opts.Out, "%s Keycloak token received", stack)
	status, _, err := doStatus(ctx, opts.client(), http.MethodGet, base+"/admin/realms/"+DefaultRealm, token, nil)
	if err != nil {
		return result, fmt.Errorf("read the realm: %w", err)
	}
	if status == http.StatusOK {
		if _, err := doJSON(ctx, opts.client(), http.MethodPut,
			base+"/admin/realms/"+DefaultRealm, token, realmBody); err != nil {
			return result, fmt.Errorf("update the realm: %w", err)
		}
		result.step(opts.Out, "%s realm %s present and updated", stack, DefaultRealm)
		return result, nil
	}
	if status != http.StatusNotFound {
		return result, fmt.Errorf("read the realm: the server answered %d", status)
	}
	if _, err := doJSON(ctx, opts.client(), http.MethodPost, base+"/admin/realms", token, realmBody); err != nil {
		return result, fmt.Errorf("create the realm: %w", err)
	}
	result.step(opts.Out, "%s realm %s created", stack, DefaultRealm)
	return result, nil
}

// keycloakToken gets an administrator token from the master realm.
func keycloakToken(ctx context.Context, opts BootstrapOptions, base string) (string, error) {
	form := url.Values{
		"grant_type": {"password"},
		"client_id":  {"admin-cli"},
		"username":   {opts.value(EnvBootstrapUser, "admin")},
		"password":   {opts.value(EnvBootstrapSecret, "admin")},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		base+"/realms/master/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("build the token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	body, err := send(opts.client(), req)
	if err != nil {
		return "", fmt.Errorf("get an administrator token: %w", err)
	}
	var parsed struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil || parsed.AccessToken == "" {
		return "", errors.New("get an administrator token: the answer holds no access_token")
	}
	return parsed.AccessToken, nil
}

// credeblOrg is one organisation of the CREDEBL API.
type credeblOrg struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// BootstrapCredebl signs in to the CREDEBL API and creates the
// organisation of the deployment. A second run finds the organisation
// and does nothing (ADR-008 decision 4).
func BootstrapCredebl(ctx context.Context, opts BootstrapOptions) (BootstrapResult, error) {
	var result BootstrapResult
	base, baseErr := opts.baseURL()
	if baseErr != nil {
		return result, baseErr
	}
	name := opts.value(EnvBootstrapOrg, "vca-"+ShortName(opts.Pair.Role.String()))
	signin, err := json.Marshal(map[string]string{
		"email":    opts.value(EnvBootstrapUser, "admin@example.com"),
		"password": opts.value(EnvBootstrapSecret, ""),
	})
	if err != nil {
		return result, fmt.Errorf("build the sign in request: %w", err)
	}
	answer, err := doJSON(ctx, opts.client(), http.MethodPost, base+"/v1/auth/signin", "", signin)
	if err != nil {
		return result, fmt.Errorf("CREDEBL sign in: %w", err)
	}
	var session struct {
		Data struct {
			AccessToken string `json:"access_token"`
		} `json:"data"`
	}
	if gotErr := json.Unmarshal(answer, &session); gotErr != nil || session.Data.AccessToken == "" {
		return result, errors.New("CREDEBL sign in: the answer holds no access_token")
	}
	result.step(opts.Out, "CREDEBL sign in done")
	listed, err := doJSON(ctx, opts.client(), http.MethodGet,
		base+"/v1/orgs?search="+url.QueryEscape(name), session.Data.AccessToken, nil)
	if err != nil {
		return result, fmt.Errorf("list the organisations: %w", err)
	}
	var orgs struct {
		Data struct {
			Organizations []credeblOrg `json:"organizations"`
		} `json:"data"`
	}
	if gotErr := json.Unmarshal(listed, &orgs); gotErr != nil {
		return result, fmt.Errorf("list the organisations: %w", gotErr)
	}
	for _, org := range orgs.Data.Organizations {
		if org.Name == name {
			result.step(opts.Out, "CREDEBL organisation present: %s", name)
			return result, nil
		}
	}
	body, err := json.Marshal(map[string]string{
		"name":        name,
		"description": "Verifiable Credentials Adapters " + ShortName(opts.Pair.Role.String()),
		"website":     opts.Values["VCA_PUBLIC_URL"],
	})
	if err != nil {
		return result, fmt.Errorf("build the organisation request: %w", err)
	}
	if _, err := doJSON(ctx, opts.client(), http.MethodPost, base+"/v1/orgs", session.Data.AccessToken, body); err != nil {
		return result, fmt.Errorf("create the organisation: %w", err)
	}
	result.step(opts.Out, "CREDEBL organisation created: %s", name)
	return result, nil
}

// doJSON sends one JSON request and returns the answer body.
// It reports an error for any status outside the 2xx range.
func doJSON(ctx context.Context, c *http.Client, method, target, token string, body []byte) ([]byte, error) {
	status, answer, err := doStatus(ctx, c, method, target, token, body)
	if err != nil {
		return nil, err
	}
	if status < 200 || status > 299 {
		return nil, fmt.Errorf("%s %s: the server answered %d", method, target, status)
	}
	return answer, nil
}

// doStatus sends one JSON request and returns the status and the body.
func doStatus(ctx context.Context, c *http.Client, method, target, token string, body []byte) (int, []byte, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return 0, nil, fmt.Errorf("build the request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("%s %s: %w", method, target, err)
	}
	defer func() { _ = resp.Body.Close() }()
	answer, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return 0, nil, fmt.Errorf("read the answer: %w", err)
	}
	return resp.StatusCode, answer, nil
}

// send makes one request and returns the body of a 2xx answer.
func send(c *http.Client, req *http.Request) ([]byte, error) {
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("read the answer: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("the server answered %d", resp.StatusCode)
	}
	return body, nil
}
