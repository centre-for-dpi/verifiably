// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
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
	// EnvBootstrapAdapterURL overrides the address of the walt.id adapter
	// for the bootstrap run. Empty means 127.0.0.1 and the host port of
	// the adapter of the pair.
	EnvBootstrapAdapterURL = "VCA_BOOTSTRAP_ADAPTER_URL"
)

// IssuerFile is the walt.id onboarding answer that an older bootstrap
// run wrote beside the .env file of the pair. It holds the issuer key.
// A run that finds it imports it into the adapter and says the file can
// go, because the adapter keeps the key now (ADR-046 decision 4).
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
		anyval.DiscardWrite(fmt.Fprintln(out, line))
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

// adapterURL returns the address of the walt.id adapter: the override,
// else 127.0.0.1 and the host port of the adapter of the pair. The
// reverse proxy publishes no adapter service, so the CLI reaches the
// adapter where compose publishes its port on VCA_BIND, as the
// Caddyfile does (ADR-047 decision 3). The port comes from the port
// plan and the VCA_HOST_PORT_* overrides of the .env file.
func (o BootstrapOptions) adapterURL() (string, error) {
	raw := strings.TrimRight(o.value(EnvBootstrapAdapterURL, localAdapterURL(o.Pair, o.Values)), "/")
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", fmt.Errorf("bootstrap: set %s to an absolute http or https URL", EnvBootstrapAdapterURL)
	}
	return raw, nil
}

// localAdapterURL returns http://127.0.0.1 and the host port of the DPG
// adapter of a pair, or "" when the pair runs no adapter.
func localAdapterURL(p Pair, values map[string]string) string {
	for _, a := range HostPorts(p, values) {
		if a.Service.Dpg != configv1.Dpg_DPG_UNSPECIFIED {
			return fmt.Sprintf("http://%s:%d", LoopbackAddress, a.Host)
		}
	}
	return ""
}

// BootstrapWaltid gives the issuer of the pair its identity through the
// walt.id adapter (ADR-046). The adapter makes a did:web of the host of
// the pair and a secp256r1 key through the walt.id onboarding endpoint,
// and keeps the key in its data volume. The CLI never holds the key
// (ADR-001 decision 3). A file of an older run moves into the adapter by
// import. A second run finds the identity and does nothing (ADR-008
// decision 4).
func BootstrapWaltid(ctx context.Context, opts BootstrapOptions) (BootstrapResult, error) {
	var result BootstrapResult
	if opts.Pair.Role != commonv1.Role_ROLE_ISSUER {
		result.step(opts.Out, "bootstrap: the %s pair needs no issuer identity", ShortName(opts.Pair.Role.String()))
		return result, nil
	}
	base, err := opts.adapterURL()
	if err != nil {
		return result, err
	}
	domain := hostOf(opts.Values["VCA_PUBLIC_URL"])
	if domain == "" {
		return result, errors.New("bootstrap: VCA_PUBLIC_URL is not an absolute URL, so the did:web has no host")
	}
	adapter := backendv1connect.NewIssuerBackendServiceClient(opts.client(), base)
	current, err := adapter.GetIssuerIdentity(ctx, connect.NewRequest(&backendv1.GetIssuerIdentityRequest{}))
	if err != nil {
		return result, fmt.Errorf("the issuer adapter at %s: %w", base, err)
	}
	if ids := current.Msg.GetIdentity().GetIdentifiers(); len(ids) > 0 {
		result.step(opts.Out, "walt.id issuer present: %s", ids[0])
		return result, nil
	}
	path := filepath.Join(opts.Dir, IssuerFile)
	if did, key, ok := readIssuerFile(path); ok {
		if _, ierr := adapter.ImportIssuerIdentity(ctx, connect.NewRequest(&backendv1.ImportIssuerIdentityRequest{
			Subject: &backendv1.ImportIssuerIdentityRequest_Did{Did: did}, KeyReference: key,
		})); ierr != nil {
			return result, fmt.Errorf("the issuer adapter import: %w", ierr)
		}
		result.step(opts.Out, "walt.id issuer imported: %s. The adapter keeps the key now, so delete %s", did, path)
		return result, nil
	}
	made, err := adapter.ProvisionIssuerIdentity(ctx, connect.NewRequest(&backendv1.ProvisionIssuerIdentityRequest{
		Method: "did:web", KeyType: "secp256r1", Domain: domain,
	}))
	if err != nil {
		return result, fmt.Errorf("the issuer adapter provision: %w", err)
	}
	result.step(opts.Out, "walt.id issuer created: %s", strings.Join(made.Msg.GetIdentity().GetIdentifiers(), ", "))
	return result, nil
}

// readIssuerFile reads the DID and the key object out of the answer an
// older run wrote. A missing file, or one with no DID or no key, gives
// nothing.
func readIssuerFile(path string) (string, string, bool) {
	data, err := os.ReadFile(path) // #nosec G304 -- the path comes from the pair
	if err != nil {
		return "", "", false
	}
	var parsed struct {
		IssuerDid string          `json:"issuerDid"`
		IssuerKey json.RawMessage `json:"issuerKey"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil || parsed.IssuerDid == "" || len(parsed.IssuerKey) == 0 || string(parsed.IssuerKey) == "{}" {
		return "", "", false
	}
	return parsed.IssuerDid, string(parsed.IssuerKey), true
}

// BootstrapInji imports the generated Keycloak realm that Inji and
// eSignet log in against. Keycloak imports a realm from its data
// directory only when the realm is absent, so the CLI uses the admin API
// instead (ADR-008 decision 4).
//
// An issuer or a holder pair then registers the VCA client in the
// eSignet of the stack (registerEsignetClient).
func BootstrapInji(ctx context.Context, opts BootstrapOptions) (BootstrapResult, error) {
	result, err := bootstrapRealm(ctx, opts, "Inji")
	if err != nil || !usesEsignet(opts.Pair) {
		return result, err
	}
	return result, registerEsignetClient(ctx, opts, &result)
}

// realmPath returns the path of the realm of the pair role. The realm
// lives in the directory of the Keycloak of the stack, beside the pair
// directory (ADR-035 decision 1).
func (o BootstrapOptions) realmPath() string {
	return filepath.Join(filepath.Dir(o.Dir), filepath.FromSlash(RealmFileOf(o.Pair)))
}

// bootstrapRealm creates or updates the realm of the pair role at the
// Keycloak of a stack.
func bootstrapRealm(ctx context.Context, opts BootstrapOptions, stack string) (BootstrapResult, error) {
	var result BootstrapResult
	base, err := opts.baseURL()
	if err != nil {
		return result, err
	}
	realm := RealmName(opts.Pair.Role)
	realmBody, err := os.ReadFile(opts.realmPath()) // #nosec G304 -- the path comes from the pair
	if err != nil {
		return result, fmt.Errorf("read the generated realm: %w", err)
	}
	token, err := keycloakToken(ctx, opts, base)
	if err != nil {
		return result, err
	}
	result.step(opts.Out, "%s Keycloak token received", stack)
	status, _, err := doStatus(ctx, opts.client(), http.MethodGet, base+"/admin/realms/"+realm, token, nil)
	if err != nil {
		return result, fmt.Errorf("read the realm: %w", err)
	}
	if status == http.StatusOK {
		if _, err := doJSON(ctx, opts.client(), http.MethodPut,
			base+"/admin/realms/"+realm, token, realmBody); err != nil {
			return result, fmt.Errorf("update the realm: %w", err)
		}
		result.step(opts.Out, "%s realm %s present and updated", stack, realm)
		return result, nil
	}
	if status != http.StatusNotFound {
		return result, fmt.Errorf("read the realm: the server answered %d", status)
	}
	if _, err := doJSON(ctx, opts.client(), http.MethodPost, base+"/admin/realms", token, realmBody); err != nil {
		return result, fmt.Errorf("create the realm: %w", err)
	}
	result.step(opts.Out, "%s realm %s created", stack, realm)
	return result, nil
}

// keycloakToken gets an administrator token from the master realm. The
// password comes from the .env of the Keycloak of the stack or from the
// environment; no default exists (ADR-035 consequence 3).
func keycloakToken(ctx context.Context, opts BootstrapOptions, base string) (string, error) {
	password := opts.value(EnvBootstrapSecret, "")
	if password == "" {
		return "", fmt.Errorf("get an administrator token: set %s, or run vca setup so %s holds %s",
			EnvBootstrapSecret, KeycloakEnvFile(opts.Pair.Dpg), KeycloakAdminPasswordEnv)
	}
	form := url.Values{
		"grant_type": {"password"},
		"client_id":  {"admin-cli"},
		"username":   {opts.value(EnvBootstrapUser, keycloakAdminUser)},
		"password":   {password},
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
	defer func() { anyval.Discard(resp.Body.Close()) }()
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
	defer func() { anyval.Discard(resp.Body.Close()) }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("read the answer: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("the server answered %d", resp.StatusCode)
	}
	return body, nil
}
