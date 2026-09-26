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
// eSignet the same way. The issuer pair names it as the authorization
// server of an authorization code offer.
func TestInjiEsignetAddressFollowsTheDeployment(t *testing.T) {
	issuer, holder := injiPair(commonv1.Role_ROLE_ISSUER), injiPair(commonv1.Role_ROLE_HOLDER)
	for _, tc := range []struct {
		name   string
		req    SetupRequest
		want   string
		server bool
	}{
		{name: "local issuer", req: SetupRequest{Pair: issuer}, want: "http://localhost:17089", server: true},
		{name: "local holder", req: SetupRequest{Pair: holder}, want: "http://localhost:17089"},
		{name: "domain issuer", req: SetupRequest{Pair: issuer, Domain: "labs.example"}, want: "https://issuer-inji.labs.example", server: true},
		{name: "domain holder", req: SetupRequest{Pair: holder, Domain: "labs.example"}, want: "https://issuer-inji.labs.example"},
		{name: "holder beside an issuer of its own name", req: SetupRequest{Pair: holder, Domain: "labs.example",
			Peers: PeerOverrides{issuer.Name(): {"VCA_PUBLIC_URL": "https://issue.gov.example"}}}, want: "https://issue.gov.example"},
		{name: "issuer on a host of its own", req: SetupRequest{Pair: issuer,
			Flags: withFlag(baseFlags(), "VCA_PUBLIC_URL", "https://issue.gov.example")}, want: "https://issue.gov.example", server: true},
		// A holder alone has no issuer host to lean on, so the browser
		// opens the host port of the page.
		{name: "holder alone on a public host", req: SetupRequest{Pair: holder,
			Flags: withFlag(baseFlags(), "VCA_PUBLIC_URL", "https://wallet.gov.example")}, want: "http://wallet.gov.example:17089"},
	} {
		env := planEnv(t, tc.req)
		if env["INJI_ESIGNET_PUBLIC_URL"] != tc.want {
			t.Errorf("%s: INJI_ESIGNET_PUBLIC_URL = %q, want %q", tc.name, env["INJI_ESIGNET_PUBLIC_URL"], tc.want)
		}
		server, ok := env["VCA_INJI_AUTHORIZATION_SERVER"]
		if tc.server && server != tc.want {
			t.Errorf("%s: VCA_INJI_AUTHORIZATION_SERVER = %q, want %q", tc.name, server, tc.want)
		}
		if !tc.server && ok {
			t.Errorf("%s: the pair names an authorization server", tc.name)
		}
	}
	// An operator value wins.
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
// the token endpoint of the eSignet login page, and the addresses of
// Inji Verify. vca setup writes both files into deploy/mimoto-inji from
// the addresses of the deployment: the host ports on a laptop, and one
// host per container under a base domain, which the Caddyfile of the
// pair that runs it publishes. The addresses inside the compose network
// stay as they are.
func TestSetupWritesTheMimotoFilesFromTheDeployment(t *testing.T) {
	holder := injiPair(commonv1.Role_ROLE_HOLDER)
	for _, tc := range []struct {
		name, domain                                    string
		web, esignet, verifyService, verifyUI, loginURL string
	}{
		{name: "local", web: "http://localhost:17085", esignet: "http://localhost:17089",
			verifyService: "http://localhost:17086", verifyUI: "http://localhost:17087", loginURL: "http://localhost:17080"},
		{name: "domain", domain: "labs.example", web: "https://inji-web.labs.example", esignet: "https://issuer-inji.labs.example",
			verifyService: "https://inji-verify-service.labs.example", verifyUI: "https://inji-verify-ui.labs.example",
			loginURL: "https://inji-keycloak.labs.example"},
	} {
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
			"authorization_audience": tc.esignet + "/v1/esignet/oauth/v2/token",
			// Mimoto calls these inside the compose network.
			"proxy_token_endpoint":   "http://inji-esignet:8088/v1/esignet/oauth/v2/token",
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
