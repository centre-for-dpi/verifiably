// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/rand"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// injiPair returns the Inji pair of a role.
func injiPair(role commonv1.Role) Pair { return Pair{Role: role, Dpg: configv1.Dpg_DPG_INJI} }

// planEnv runs a setup plan and returns the values of its .env file.
func planEnv(t *testing.T, req SetupRequest) map[string]string {
	t.Helper()
	if req.Flags == nil {
		req.Flags = baseFlags()
	}
	req.Random = rand.Reader
	plan, err := BuildPlan(req)
	if err != nil {
		t.Fatalf("%s: BuildPlan: %v", req.Pair.Name(), err)
	}
	values, err := ParseDotenv(strings.NewReader(string(plan.Files[0].Data)))
	if err != nil {
		t.Fatal(err)
	}
	return values
}

// TestInjiEsignetAddressFollowsTheDeployment is P6-I7f. The browser
// opens the eSignet login page at the address its tokens carry. A local
// deployment reaches the page on its host port. A base domain puts it on
// the host of the Inji issuer pair, which publishes it, and every Inji
// pair that runs eSignet names that one address, so each deploy starts
// eSignet the same way. No pair names eSignet as the authorization
// server of an offer any more: the holder authorization server of the
// adapter is (ADR-052).
func TestInjiEsignetAddressFollowsTheDeployment(t *testing.T) {
	issuer, holder := injiPair(commonv1.Role_ROLE_ISSUER), injiPair(commonv1.Role_ROLE_HOLDER)
	for _, tc := range []struct {
		name string
		req  SetupRequest
		want string
	}{
		{name: "local issuer", req: SetupRequest{Pair: issuer}, want: "http://localhost:17089"},
		{name: "local holder", req: SetupRequest{Pair: holder}, want: "http://localhost:17089"},
		{name: "domain issuer", req: SetupRequest{Pair: issuer, Domain: "labs.example"}, want: "https://issuer-inji.labs.example"},
		{name: "domain holder", req: SetupRequest{Pair: holder, Domain: "labs.example"}, want: "https://issuer-inji.labs.example"},
		{name: "holder beside an issuer of its own name", req: SetupRequest{Pair: holder, Domain: "labs.example",
			Peers: PeerOverrides{issuer.Name(): {"VCA_PUBLIC_URL": "https://issue.gov.example"}}}, want: "https://issue.gov.example"},
		{name: "issuer on a host of its own", req: SetupRequest{Pair: issuer,
			Flags: withFlag(baseFlags(), "VCA_PUBLIC_URL", "https://issue.gov.example")}, want: "https://issue.gov.example"},
		// A holder alone has no issuer host to lean on, so the browser
		// opens the host port of the page.
		{name: "holder alone on a public host", req: SetupRequest{Pair: holder,
			Flags: withFlag(baseFlags(), "VCA_PUBLIC_URL", "https://wallet.gov.example")}, want: "http://wallet.gov.example:17089"},
	} {
		env := planEnv(t, tc.req)
		if env["INJI_ESIGNET_PUBLIC_URL"] != tc.want {
			t.Errorf("%s: INJI_ESIGNET_PUBLIC_URL = %q, want %q", tc.name, env["INJI_ESIGNET_PUBLIC_URL"], tc.want)
		}
		if server, ok := env["VCA_INJI_AUTHORIZATION_SERVER"]; ok {
			t.Errorf("%s: the pair names the authorization server %q", tc.name, server)
		}
	}
	// An operator value still reaches the adapter.
	flags := withFlag(baseFlags(), "VCA_INJI_AUTHORIZATION_SERVER", "https://idp.gov.example")
	if env := planEnv(t, SetupRequest{Pair: issuer, Flags: flags}); env["VCA_INJI_AUTHORIZATION_SERVER"] != "https://idp.gov.example" {
		t.Errorf("the operator value was lost: %q", env["VCA_INJI_AUTHORIZATION_SERVER"])
	}
	for _, p := range AllPairs() {
		if p == issuer || p == holder {
			continue
		}
		if _, ok := planEnv(t, SetupRequest{Pair: p})["INJI_ESIGNET_PUBLIC_URL"]; ok {
			t.Errorf("%s runs no eSignet but names its address", p.Name())
		}
	}
}

// TestSetupWritesTheAuthzIssuer: the issuer pair runs the holder
// authorization server of the adapter (ADR-052). Setup names its issuer
// under the public URL of the pair, seals its token key with the pair
// session key, points it at the holder realm of the stack Keycloak, and
// at the data source service of the pair. The wallet client of Inji Web
// joins once the holder bootstrap wrote the public key of Mimoto.
func TestSetupWritesTheAuthzIssuer(t *testing.T) {
	issuer := injiPair(commonv1.Role_ROLE_ISSUER)
	flags := withFlag(baseFlags(), "VCA_PUBLIC_URL", "https://issue.gov.example")
	jwk := `{"kty":"RSA","n":"xyz","e":"AQAB"}`
	env := planEnv(t, SetupRequest{Pair: issuer, Flags: flags, WalletJWK: jwk,
		Peers: PeerOverrides{injiPair(commonv1.Role_ROLE_HOLDER).Name(): {InjiWebPublicURLEnv: "https://web.gov.example"}}})
	for key, want := range map[string]string{
		InjiAuthzIssuerEnv:                   "https://issue.gov.example/authz",
		"VCA_INJI_HOLDER_OIDC_DISCOVERY_URL": "http://inji-keycloak:8080/realms/vca-holder-realm/.well-known/openid-configuration",
		"VCA_INJI_HOLDER_OIDC_CLIENT_ID":     InjiAuthzClientID,
		"VCA_INJI_HOLDER_OIDC_PUBLIC_URL":    env0(t, issuer, flags)["VCA_OIDC_PUBLIC_URL"],
		"VCA_INJI_DATA_SOURCE_URL":           "http://issuer-inji-data-source:" + env0(t, issuer, flags)["VCA_PORTS_DATA_SOURCE"],
	} {
		if env[key] != want || want == "" {
			t.Errorf("%s = %q, want %q", key, env[key], want)
		}
	}
	if env["VCA_INJI_AUTHZ_KEY_SECRET"] == "" || env["VCA_INJI_AUTHZ_KEY_SECRET"] != env["VCA_SECRETS_SESSION_KEY"] {
		t.Errorf("the key secret is not the pair session key")
	}
	var clients []struct {
		ID        string          `json:"client_id"`
		Redirects []string        `json:"redirect_uris"`
		JWK       json.RawMessage `json:"jwk"`
	}
	if err := json.Unmarshal([]byte(env["VCA_INJI_WALLET_CLIENTS"]), &clients); err != nil || len(clients) != 1 {
		t.Fatalf("wallet clients = %q, %v", env["VCA_INJI_WALLET_CLIENTS"], err)
	}
	if clients[0].ID != EsignetClientID || strings.Join(clients[0].Redirects, " ") != "https://web.gov.example/redirect" ||
		string(clients[0].JWK) != jwk {
		t.Errorf("wallet client = %+v", clients[0])
	}
	// Without the key of Mimoto, Inji Web has no client yet.
	if v := planEnv(t, SetupRequest{Pair: issuer})["VCA_INJI_WALLET_CLIENTS"]; v != "" {
		t.Errorf("wallet clients without a key = %q", v)
	}
	for _, role := range []commonv1.Role{commonv1.Role_ROLE_HOLDER, commonv1.Role_ROLE_VERIFIER} {
		v := planEnv(t, SetupRequest{Pair: injiPair(role), WalletJWK: jwk})
		for _, key := range []string{InjiAuthzIssuerEnv, "VCA_INJI_AUTHZ_KEY_SECRET", "VCA_INJI_WALLET_CLIENTS", "VCA_INJI_HOLDER_OIDC_DISCOVERY_URL"} {
			if v[key] != "" {
				t.Errorf("%s writes %s", role, key)
			}
		}
	}
}

// env0 is the .env of a plan with the flags and nothing else.
func env0(t *testing.T, p Pair, flags map[string]string) map[string]string {
	t.Helper()
	copied := map[string]string{}
	for k, v := range flags {
		copied[k] = v
	}
	return planEnv(t, SetupRequest{Pair: p, Flags: copied})
}

// TestInjiHolderRealmHasTheAuthzClient: the holder realm of the stack
// Keycloak holds the public client of the holder authorization server,
// with PKCE S256 and the one callback of the issuer pair (ADR-052
// decision 2). The issuer realm does not.
func TestInjiHolderRealmHasTheAuthzClient(t *testing.T) {
	holder, issuer := injiPair(commonv1.Role_ROLE_HOLDER), injiPair(commonv1.Role_ROLE_ISSUER)
	for _, tc := range []struct {
		name string
		req  SetupRequest
		want string
	}{
		{name: "domain", req: SetupRequest{Pair: holder, Domain: "labs.example"}, want: "https://issuer-inji.labs.example/authz/callback"},
		{name: "peer", req: SetupRequest{Pair: holder, Peers: PeerOverrides{issuer.Name(): {InjiAuthzIssuerEnv: "https://issue.gov.example/authz"}}},
			want: "https://issue.gov.example/authz/callback"},
		{name: "local", req: SetupRequest{Pair: holder}, want: LocalPublicURL(issuer) + "/authz/callback"},
	} {
		var r realm
		if err := json.Unmarshal(sharedFile(t, planOf(t, tc.req), RealmFileOf(holder)).Data, &r); err != nil {
			t.Fatal(err)
		}
		var found *realmClient
		for i := range r.Clients {
			if r.Clients[i].ClientID == InjiAuthzClientID {
				found = &r.Clients[i]
			}
		}
		if found == nil {
			t.Fatalf("%s: the holder realm has no %s", tc.name, InjiAuthzClientID)
		}
		if !found.PublicClient || found.Secret != "" || !found.StandardFlowEnabled || found.ImplicitFlowEnabled ||
			found.DirectAccessGrantsEnabled || found.Attributes.PkceCodeChallengeMethod != "S256" ||
			strings.Join(found.RedirectUris, " ") != tc.want {
			t.Errorf("%s: client = %+v", tc.name, *found)
		}
	}
	body := string(sharedFile(t, planOf(t, SetupRequest{Pair: issuer}), RealmFileOf(issuer)).Data)
	if strings.Contains(body, InjiAuthzClientID) {
		t.Error("the issuer realm holds the client of the holder authorization server")
	}
}

// withFlag returns the flags with one more value.
func withFlag(flags map[string]string, key, value string) map[string]string {
	flags[key] = value
	return flags
}

// planOf runs a setup plan.
func planOf(t *testing.T, req SetupRequest) Plan {
	t.Helper()
	if req.Flags == nil {
		req.Flags = baseFlags()
	}
	req.Random = rand.Reader
	plan, err := BuildPlan(req)
	if err != nil {
		t.Fatalf("%s: BuildPlan: %v", req.Pair.Name(), err)
	}
	return plan
}

// planFile returns one file of the pair directory by name.
func planFile(t *testing.T, plan Plan, name string) string {
	t.Helper()
	for _, f := range plan.Files {
		if f.Name == name {
			return string(f.Data)
		}
	}
	t.Fatalf("%s: the plan writes no %s", plan.Pair.Name(), name)
	return ""
}

// TestSetupWritesTheMimotoFilesFromTheDeployment is P6-I7h. The issuer
// list and the trusted verifiers of Mimoto name addresses that a browser
// or a wallet opens: the redirect page and the token proxy of Inji Web,
// the token endpoint of the holder authorization server of the issuer
// pair (ADR-052), and the addresses of Inji Verify. vca setup writes both files into deploy/mimoto-inji from
// the addresses of the deployment: the host ports on a laptop, and one
// host per container under a base domain, which the Caddyfile of the
// pair that runs it publishes. The addresses inside the compose network
// stay as they are.
func TestSetupWritesTheMimotoFilesFromTheDeployment(t *testing.T) {
	holder := injiPair(commonv1.Role_ROLE_HOLDER)
	for _, tc := range []struct {
		name, domain                                  string
		web, authz, verifyService, verifyUI, loginURL string
	}{
		{name: "local", web: "http://localhost:17085", authz: LocalPublicURL(injiPair(commonv1.Role_ROLE_ISSUER)) + "/authz",
			verifyService: "http://localhost:17086", verifyUI: "http://localhost:17087", loginURL: "http://localhost:17080"},
		{name: "domain", domain: "labs.example", web: "https://inji-web.labs.example", authz: "https://issuer-inji.labs.example/authz",
			verifyService: "https://inji-verify-service.labs.example", verifyUI: "https://inji-verify-ui.labs.example",
			loginURL: "https://inji-keycloak.labs.example"},
	} {
		adapter, _ := serviceURL(injiPair(commonv1.Role_ROLE_ISSUER), "dpg-adapter-inji")
		plan := planOf(t, SetupRequest{Pair: holder, Domain: tc.domain})
		var issuers struct {
			Issuers []map[string]any `json:"issuers"`
		}
		if err := json.Unmarshal(sharedFile(t, plan, filepath.Join(MimotoDir, MimotoIssuersFile)).Data, &issuers); err != nil || len(issuers.Issuers) != 1 {
			t.Fatalf("%s: issuers = %v %v", tc.name, issuers, err)
		}
		issuer := issuers.Issuers[0]
		for key, want := range map[string]string{
			"redirect_uri":           tc.web + "/redirect",
			"token_endpoint":         tc.web + "/v1/mimoto/get-token/InjiCertify",
			"authorization_audience": tc.authz + "/token",
			// Mimoto calls these inside the compose network.
			"proxy_token_endpoint":   adapter + "/authz/token",
			"credential_issuer_host": "http://inji-certify-nginx:8091",
			"wellknown_endpoint":     "http://inji-certify-nginx:8091/.well-known/openid-credential-issuer",
			"client_id":              EsignetClientID, "client_alias": EsignetClientID,
			"issuer_id": "InjiCertify", "protocol": "OpenId4VCI", "qr_code_type": "EmbeddedVC", "enabled": "true",
		} {
			if issuer[key] != want {
				t.Errorf("%s: issuer %s = %v, want %s", tc.name, key, issuer[key], want)
			}
		}
		var verifiers struct {
			Verifiers []struct {
				ClientID      string   `json:"client_id"`
				RedirectURIs  []string `json:"redirect_uris"`
				ResponseURIs  []string `json:"response_uris"`
				JwksURI       string   `json:"jwks_uri"`
				AllowUnsigned bool     `json:"allow_unsigned_request"`
			} `json:"verifiers"`
		}
		if err := json.Unmarshal(sharedFile(t, plan, filepath.Join(MimotoDir, MimotoVerifiersFile)).Data, &verifiers); err != nil || len(verifiers.Verifiers) != 1 {
			t.Fatalf("%s: verifiers = %v %v", tc.name, verifiers, err)
		}
		v := verifiers.Verifiers[0]
		if v.ClientID != tc.verifyUI || strings.Join(v.RedirectURIs, " ") != tc.verifyUI+"/" ||
			strings.Join(v.ResponseURIs, " ") != tc.verifyService+"/v1/verify/vp-submission/vp-direct-post" ||
			v.JwksURI != tc.verifyService+"/.well-known/jwks.json" || !v.AllowUnsigned {
			t.Errorf("%s: verifier = %+v", tc.name, v)
		}
		env, err := ParseDotenv(strings.NewReader(planFile(t, plan, EnvFileName)))
		if err != nil {
			t.Fatal(err)
		}
		for key, want := range map[string]string{
			"INJI_WEB_PUBLIC_URL": tc.web, "VCA_INJI_WEB_URL": tc.web, "INJI_MIMOTO_HOLDER_LOGIN_URL": tc.loginURL,
		} {
			if env[key] != want {
				t.Errorf("%s: %s = %q, want %q", tc.name, key, env[key], want)
			}
		}
		realmBody := string(sharedFile(t, plan, RealmFileOf(holder)).Data)
		if !strings.Contains(realmBody, tc.web+"/v1/mimoto/oauth2/callback/google") {
			t.Errorf("%s: the holder realm does not allow the Mimoto callback of %s", tc.name, tc.web)
		}
		caddy := planFile(t, plan, CaddyFile)
		if site := hostOf(tc.web) + " {\n\treverse_proxy 127.0.0.1:17085\n}\n"; (tc.domain != "") != strings.Contains(caddy, site) {
			t.Errorf("%s: the holder Caddyfile and the site of Inji Web:\n%s", tc.name, caddy)
		}
	}
	for _, p := range AllPairs() {
		if p == holder {
			continue
		}
		for _, f := range planOf(t, SetupRequest{Pair: p}).Shared {
			if strings.HasPrefix(f.Name, MimotoDir) {
				t.Errorf("%s writes %s", p.Name(), f.Name)
			}
		}
	}
}

// TestSetupWritesTheInjiVerifyAddress: Inji Verify tells a wallet where
// to post a presentation, and its did:web names its host. The issuer
// and the verifier profiles both run it, so both pairs write the same
// address. The verifier pair publishes the service and its page under
// a base domain.
func TestSetupWritesTheInjiVerifyAddress(t *testing.T) {
	for _, role := range []commonv1.Role{commonv1.Role_ROLE_ISSUER, commonv1.Role_ROLE_VERIFIER} {
		p := injiPair(role)
		local := planEnv(t, SetupRequest{Pair: p})
		if local["INJI_VERIFY_PUBLIC_URL"] != "http://localhost:17086" || local["INJI_VERIFY_DID_HOST"] != "localhost%3A17086" {
			t.Errorf("%s local: %q %q", p.Name(), local["INJI_VERIFY_PUBLIC_URL"], local["INJI_VERIFY_DID_HOST"])
		}
		plan := planOf(t, SetupRequest{Pair: p, Domain: "labs.example"})
		env, err := ParseDotenv(strings.NewReader(planFile(t, plan, EnvFileName)))
		if err != nil {
			t.Fatal(err)
		}
		if env["INJI_VERIFY_PUBLIC_URL"] != "https://inji-verify-service.labs.example" || env["INJI_VERIFY_DID_HOST"] != "inji-verify-service.labs.example" {
			t.Errorf("%s domain: %q %q", p.Name(), env["INJI_VERIFY_PUBLIC_URL"], env["INJI_VERIFY_DID_HOST"])
		}
		caddy := planFile(t, plan, CaddyFile)
		for _, site := range []string{
			"inji-verify-service.labs.example {\n\treverse_proxy 127.0.0.1:17086\n}\n",
			"inji-verify-ui.labs.example {\n\treverse_proxy 127.0.0.1:17087\n}\n",
		} {
			if (role == commonv1.Role_ROLE_VERIFIER) != strings.Contains(caddy, site) {
				t.Errorf("%s: the Caddyfile and the site %q:\n%s", p.Name(), site, caddy)
			}
		}
	}
	if _, ok := planEnv(t, SetupRequest{Pair: injiPair(commonv1.Role_ROLE_HOLDER)})["INJI_VERIFY_PUBLIC_URL"]; ok {
		t.Error("the holder profile runs no Inji Verify")
	}
}

// TestSetupWritesTheCertifyDIDAndTheAdapter: the issuer pair gets
// did:web of its public host as the issuer DID of both Certify
// containers, and the address of its adapter on the compose network,
// where Certify reads the presentation definition (ADR-051). Another
// pair runs no Certify and gets neither.
func TestSetupWritesTheCertifyDIDAndTheAdapter(t *testing.T) {
	flags := withFlag(baseFlags(), "VCA_PUBLIC_URL", "https://issue.gov.example")
	values := planEnv(t, SetupRequest{Pair: injiPair(commonv1.Role_ROLE_ISSUER), Flags: flags})
	if values[InjiCertifyDIDEnv] != "did:web:issue.gov.example" {
		t.Errorf("DID = %q", values[InjiCertifyDIDEnv])
	}
	if values[InjiAdapterURLEnv] != "http://issuer-inji-dpg-adapter-inji:"+values["VCA_PORTS_ADAPTER"] || values["VCA_PORTS_ADAPTER"] == "" {
		t.Errorf("adapter = %q (port %q)", values[InjiAdapterURLEnv], values["VCA_PORTS_ADAPTER"])
	}
	if values["VCA_INJI_IAR_IDENTITY_CLAIMS"] != "vcaSubject" || values["VCA_INJI_CLAIMS_DIR"] != InjiClaimsPath {
		t.Errorf("identity claims %q, claims dir %q", values["VCA_INJI_IAR_IDENTITY_CLAIMS"], values["VCA_INJI_CLAIMS_DIR"])
	}
	local := planEnv(t, SetupRequest{Pair: injiPair(commonv1.Role_ROLE_ISSUER)})
	if local[InjiCertifyDIDEnv] != "did:web:localhost%3A"+strings.TrimPrefix(hostPortOf(local["VCA_PUBLIC_URL"]), ":") {
		t.Errorf("local DID = %q for %s", local[InjiCertifyDIDEnv], local["VCA_PUBLIC_URL"])
	}
	for _, role := range []commonv1.Role{commonv1.Role_ROLE_HOLDER, commonv1.Role_ROLE_VERIFIER} {
		v := planEnv(t, SetupRequest{Pair: injiPair(role)})
		if v[InjiCertifyDIDEnv] != "" || v[InjiAdapterURLEnv] != "" || v["VCA_INJI_CLAIMS_DIR"] != "" {
			t.Errorf("%s writes %q %q %q", role, v[InjiCertifyDIDEnv], v[InjiAdapterURLEnv], v["VCA_INJI_CLAIMS_DIR"])
		}
	}
}

// hostPortOf returns the :port of an address, or "".
func hostPortOf(raw string) string {
	if i := strings.LastIndex(raw, ":"); i > len("https:") {
		return raw[i:]
	}
	return ""
}
