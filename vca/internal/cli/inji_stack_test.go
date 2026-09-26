// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// injiService is the part of one service of the Inji stack file that
// the holder tests read.
type injiService struct {
	Image       string            `yaml:"image"`
	Profiles    []string          `yaml:"profiles"`
	Ports       []string          `yaml:"ports"`
	Volumes     []string          `yaml:"volumes"`
	Environment map[string]string `yaml:"environment"`
	DependsOn   map[string]struct {
		Condition string `yaml:"condition"`
	} `yaml:"depends_on"`
	// Networks is a list or a map of network settings.
	Networks any `yaml:"networks"`
	EnvFile  []struct {
		Path     string `yaml:"path"`
		Required bool   `yaml:"required"`
	} `yaml:"env_file"`
}

// readInjiStack reads deploy/vca/dpg/inji.yaml.
func readInjiStack(t *testing.T) map[string]injiService {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot(), "deploy", "vca", "dpg", "inji.yaml")) // #nosec G304 -- a fixed test path
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Services map[string]injiService `yaml:"services"`
		Volumes  map[string]any         `yaml:"volumes"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	for name := range doc.Volumes {
		doc.Services["volume:"+name] = injiService{}
	}
	return doc.Services
}

// readProperties reads a Java properties file with continuation lines.
func readProperties(t *testing.T, path string) map[string]string {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- a fixed test path
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	var pending string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if pending == "" && (line == "" || strings.HasPrefix(line, "#")) {
			continue
		}
		if strings.HasSuffix(line, `\`) {
			pending += strings.TrimSuffix(line, `\`)
			continue
		}
		line = pending + line
		pending = ""
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("%s: the line %q holds no =", path, line)
		}
		out[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return out
}

// mountSource returns the host side of the volume line that mounts the
// container path, or empty.
func mountSource(volumes []string, target string) string {
	for _, v := range volumes {
		parts := strings.Split(v, ":")
		if len(parts) >= 2 && parts[1] == target {
			return parts[0]
		}
	}
	return ""
}

// TestInjiStackRunsMimotoWithWhatItNeeds is the holder part of the
// Inji stack file (P6-I7d). Mimoto 0.21.0 runs with a Postgres of its
// own that the init script of the release prepares, a Redis for its
// sessions, and a properties file that points the token login provider
// "google" at the holder realm of the stack Keycloak and the eSignet
// host at the eSignet of the stack. Inji Web 0.16.0 listens on 3004,
// reaches Mimoto under the name its nginx file names, and serves the
// issuer list that Mimoto reads.
func TestInjiStackRunsMimotoWithWhatItNeeds(t *testing.T) {
	stack := readInjiStack(t)
	holderOnly := func(name string) injiService {
		t.Helper()
		svc, ok := stack[name]
		if !ok {
			t.Fatalf("the Inji stack has no %s service", name)
		}
		if strings.Join(svc.Profiles, ",") != "holder-inji" {
			t.Errorf("%s profiles = %v, want holder-inji", name, svc.Profiles)
		}
		return svc
	}
	db := holderOnly("inji-mimoto-postgres")
	redis := holderOnly("inji-mimoto-redis")
	mimoto := holderOnly("inji-mimoto")
	web := holderOnly("inji-web")

	if db.Image != "postgres:15.8" {
		t.Errorf("the Mimoto database image = %q", db.Image)
	}
	initSQL := mountSource(db.Volumes, "/docker-entrypoint-initdb.d/mimoto_init.sql")
	if initSQL == "" {
		t.Fatalf("the Mimoto database runs no init script: %v", db.Volumes)
	}
	sql, err := os.ReadFile(filepath.Join(repoRoot(), "deploy", "vca", filepath.FromSlash(initSQL))) // #nosec G304 -- a path of the stack file
	if err != nil || !strings.Contains(string(sql), "CREATE DATABASE inji_mimoto") || !strings.Contains(string(sql), "CREATE TABLE IF NOT EXISTS wallet") {
		t.Fatalf("the init script %s is not the one of Mimoto 0.21.0: %v", initSQL, err)
	}
	if !strings.HasPrefix(redis.Image, "redis:7.4.1-alpine") {
		t.Errorf("the Redis image = %q", redis.Image)
	}
	for _, dep := range []string{"inji-mimoto-postgres", "inji-mimoto-redis", "inji-web"} {
		if _, ok := mimoto.DependsOn[dep]; !ok {
			t.Errorf("inji-mimoto does not wait for %s: %v", dep, mimoto.DependsOn)
		}
	}
	if mimoto.DependsOn["inji-mimoto-postgres"].Condition != "service_healthy" {
		t.Error("inji-mimoto starts before its database is healthy")
	}
	for key, want := range map[string]string{
		"SPRING_CONFIG_LOCATION":          "/home/mosip/",
		"SPRING_CONFIG_NAME":              "mimoto",
		"active_profile_env":              "default",
		"SPRING_DATASOURCE_URL":           "jdbc:postgresql://inji-mimoto-postgres:5432/inji_mimoto",
		"SPRING_CLOUD_BOOTSTRAP_LOCATION": "/home/mosip/mimoto-bootstrap.properties",
	} {
		if mimoto.Environment[key] != want {
			t.Errorf("inji-mimoto %s = %q, want %q", key, mimoto.Environment[key], want)
		}
	}
	if !slices.Contains(networkAliases(mimoto.Networks, "vca"), "mimoto-service") {
		t.Errorf("inji-mimoto has no alias mimoto-service, which the nginx file of Inji Web names: %v", mimoto.Networks)
	}
	if mountSource(mimoto.Volumes, "/home/mosip/certs") != "../mimoto-inji" {
		t.Errorf("inji-mimoto does not read the client key store of vca dpg bootstrap: %v", mimoto.Volumes)
	}
	if len(mimoto.EnvFile) != 1 || mimoto.EnvFile[0].Path != "../mimoto-inji/.env" || mimoto.EnvFile[0].Required {
		t.Errorf("inji-mimoto env_file = %+v", mimoto.EnvFile)
	}
	if mountSource(mimoto.Volumes, "/home/mosip/keymanager") != "inji-mimoto-keys" {
		t.Errorf("the key manager of Mimoto keeps no volume: %v", mimoto.Volumes)
	}
	if _, ok := stack["volume:inji-mimoto-keys"]; !ok {
		t.Error("the stack file declares no volume inji-mimoto-keys")
	}

	propsPath := mountSource(mimoto.Volumes, "/home/mosip/mimoto-default.properties")
	if propsPath == "" {
		t.Fatalf("inji-mimoto mounts no mimoto-default.properties: %v", mimoto.Volumes)
	}
	props := readProperties(t, filepath.Join(repoRoot(), "deploy", "vca", filepath.FromSlash(propsPath)))
	for key, want := range map[string]string{
		"spring.session.store-type": "redis",
		"spring.data.redis.host":    "inji-mimoto-redis",
		"spring.data.redis.port":    "6379",
		// The token login provider bean is "google" in Mimoto 0.21.0.
		// It trusts the holder realm of the stack Keycloak.
		"spring.security.oauth2.client.registration.google.client-id": "${MIMOTO_TOKEN_LOGIN_CLIENT_ID:vca-holder}",
		"google.issuer": "${MIMOTO_TOKEN_LOGIN_ISSUER:http://inji-keycloak:8080/realms/vca-holder-realm}",
		"spring.security.oauth2.client.provider.google.jwk-set-uri":                      "http://inji-keycloak:8080/realms/vca-holder-realm/protocol/openid-connect/certs",
		"spring.security.oauth2.client.provider.google.token-uri":                        "http://inji-keycloak:8080/realms/vca-holder-realm/protocol/openid-connect/token",
		"spring.security.oauth2.client.provider.google.user-info-uri":                    "http://inji-keycloak:8080/realms/vca-holder-realm/protocol/openid-connect/userinfo",
		"spring.security.oauth2.client.provider.google.authorization-uri":                "${MIMOTO_HOLDER_LOGIN_URL:http://localhost:17080}/realms/vca-holder-realm/protocol/openid-connect/auth",
		"spring.security.oauth2.client.registration.google.client-authentication-method": "none",
		"spring.security.oauth2.client.registration.google.redirect-uri":                 "${mosip.inji.web.url}/v1/mimoto/oauth2/callback/{registrationId}",
		"mosip.esignet.host":                      "http://inji-esignet:8088",
		"mosip.inji.web.url":                      "${INJI_WEB_PUBLIC_URL:http://localhost:17085}",
		"mosip.kernel.keymanager.hsm.config-path": "/home/mosip/keymanager/keymanager.p12",
		"mosip.oidc.p12.path":                     "certs/",
		"mosip.oidc.p12.filename":                 "oidckeystore.p12",
		"mosip.oidc.p12.password":                 "${oidc_p12_password:}",
		"mosip.openid.issuers":                    "mimoto-issuers-config.json",
		"mosip.security.origins":                  "${mosip.inji.web.url}",
	} {
		if props[key] != want {
			t.Errorf("%s = %q, want %q", key, props[key], want)
		}
	}
	if !strings.Contains(props["mosip.security.ignore-auth-urls"], "/auth/*/token-login") {
		t.Error("the token login needs no session, and the properties lost that rule")
	}

	if len(web.Ports) != 1 || !strings.HasSuffix(web.Ports[0], ":3004") || !strings.Contains(web.Ports[0], "INJI_WEB_HOST_PORT:-17085") {
		t.Errorf("inji-web ports = %v; Inji Web 0.16.0 listens on 3004", web.Ports)
	}
	if web.Environment["MIMOTO_URL"] != "${INJI_WEB_PUBLIC_URL:-http://localhost:17085}/v1/mimoto" {
		t.Errorf("inji-web MIMOTO_URL = %q", web.Environment["MIMOTO_URL"])
	}
	boot := readProperties(t, filepath.Join(repoRoot(), "deploy", "vca",
		filepath.FromSlash(mountSource(mimoto.Volumes, "/home/mosip/mimoto-bootstrap.properties"))))
	if boot["config.server.file.storage.uri"] != "http://inji-web:3004/" || boot["server.servlet.context-path"] != "/v1/mimoto" {
		t.Errorf("the bootstrap properties = %v", boot)
	}
	issuersPath := mountSource(web.Volumes, "/home/mosip/mimoto-issuers-config.json")
	raw, err := os.ReadFile(filepath.Join(repoRoot(), "deploy", "vca", filepath.FromSlash(issuersPath))) // #nosec G304 -- a path of the stack file
	if err != nil {
		t.Fatalf("Inji Web serves no issuer list: %v", err)
	}
	var issuers struct {
		Issuers []map[string]any `json:"issuers"`
	}
	if err := json.Unmarshal(raw, &issuers); err != nil || len(issuers.Issuers) != 1 {
		t.Fatalf("issuers = %s, %v", raw, err)
	}
	issuer := issuers.Issuers[0]
	for key, want := range map[string]string{
		// Mimoto reads <credential_issuer_host>/.well-known/openid-credential-issuer,
		// so the host is the nginx server of the Certify that takes
		// eSignet tokens (P6-I0).
		"wellknown_endpoint":     "http://inji-certify-nginx:8091/.well-known/openid-credential-issuer",
		"credential_issuer_host": "http://inji-certify-nginx:8091",
		"client_id":              EsignetClientID,
		"client_alias":           EsignetClientID,
		"proxy_token_endpoint":   "http://inji-esignet:8088/v1/esignet/oauth/v2/token",
		"authorization_audience": "http://inji-esignet:8088/v1/esignet/oauth/v2/token",
		"redirect_uri":           DefaultInjiWebURL + "/redirect",
		"protocol":               "OpenId4VCI",
		"enabled":                "true",
	} {
		if issuer[key] != want {
			t.Errorf("issuer %s = %v, want %s", key, issuer[key], want)
		}
	}
	for _, target := range []string{"/home/mosip/mimoto-trusted-verifiers.json", "/home/mosip/credential-template.html"} {
		if mountSource(web.Volumes, target) == "" {
			t.Errorf("Inji Web does not serve %s to Mimoto: %v", target, web.Volumes)
		}
	}
}

// networkAliases returns the aliases of one network of a service whose
// networks are a map.
func networkAliases(networks any, name string) []string {
	byName, ok := networks.(map[string]any)
	if !ok {
		return nil
	}
	settings, ok := byName[name].(map[string]any)
	if !ok {
		return nil
	}
	list, ok := settings["aliases"].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, v := range list {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// TestInjiStackPointsCertifyAtInjiVerify is P6-I4b: Certify 0.14.0 asks
// Inji Verify for the presentation it wants before it issues, so the
// issuer profile runs Inji Verify 0.16.0 too, on its real port 8080
// with its database. Certify reads the definition over HTTP from a
// small nginx, as the injistack compose file does. The Inji issuer pair
// then turns the feature on.
func TestInjiStackPointsCertifyAtInjiVerify(t *testing.T) {
	stack := readInjiStack(t)
	certify := stack["inji-certify"]
	for key, want := range map[string]string{
		"MOSIP_CERTIFY_VERIFY_SERVICE_BASE_URL":            "http://inji-verify-service:8080",
		"MOSIP_CERTIFY_VERIFY_SERVICE_VP_REQUEST_ENDPOINT": "http://inji-verify-service:8080/v1/verify/vp-request",
		"MOSIP_CERTIFY_VERIFY_SERVICE_VP_RESULT_ENDPOINT":  "http://inji-verify-service:8080/v1/verify/vp-result",
		"MOSIP_CERTIFY_VERIFY_SERVICE_VERIFIER_CLIENT_ID":  "certify-verifier-client",
		"MOSIP_CERTIFY_VP_REQUEST_CONFIG_FILE_URL":         "http://inji-certify-nginx/vp_request_config.json",
	} {
		if certify.Environment[key] != want {
			t.Errorf("inji-certify %s = %q, want %q", key, certify.Environment[key], want)
		}
	}
	if _, ok := certify.DependsOn["inji-verify-service"]; !ok {
		t.Error("inji-certify does not wait for Inji Verify")
	}
	nginx := stack["inji-certify-nginx"]
	if strings.Join(nginx.Profiles, ",") != "issuer-inji" || nginx.Image != "nginx:1.27.2-alpine" {
		t.Errorf("inji-certify-nginx = %+v", nginx)
	}
	config := mountSource(nginx.Volumes, "/usr/share/nginx/html/vp_request_config.json")
	raw, err := os.ReadFile(filepath.Join(repoRoot(), "deploy", "vca", filepath.FromSlash(config))) // #nosec G304 -- a path of the stack file
	if err != nil {
		t.Fatalf("the nginx serves no vp_request_config.json: %v", err)
	}
	var vp struct {
		Definition struct {
			ID     string            `json:"id"`
			Inputs []json.RawMessage `json:"input_descriptors"`
		} `json:"presentation_definition"`
	}
	if err := json.Unmarshal(raw, &vp); err != nil || vp.Definition.ID == "" || len(vp.Definition.Inputs) == 0 {
		t.Fatalf("vp_request_config.json = %s %v", raw, err)
	}
	for _, name := range []string{"inji-verify-service", "inji-verify-postgres"} {
		if got := strings.Join(stack[name].Profiles, ","); got != "issuer-inji,verifier-inji" {
			t.Errorf("%s profiles = %s", name, got)
		}
	}
	verify := stack["inji-verify-service"]
	if len(verify.Ports) != 1 || !strings.HasSuffix(verify.Ports[0], ":8080") {
		t.Errorf("inji-verify-service ports = %v; the service listens on 8080", verify.Ports)
	}
	for key, want := range map[string]string{
		"DATABASE_HOST": "inji-verify-postgres", "DATABASE_PORT": "5432", "DATABASE_NAME": "injiverify",
		"DATABASE_SCHEMA": "verify", "DATABASE_USERNAME": "injiverify",
	} {
		if verify.Environment[key] != want {
			t.Errorf("inji-verify-service %s = %q, want %q", key, verify.Environment[key], want)
		}
	}
	initSQL := mountSource(stack["inji-verify-postgres"].Volumes, "/docker-entrypoint-initdb.d/init.sql")
	if sql, err := os.ReadFile(filepath.Join(repoRoot(), "deploy", "vca", filepath.FromSlash(initSQL))); err != nil || // #nosec G304 -- a path of the stack file
		!strings.Contains(string(sql), "CREATE TABLE IF NOT EXISTS verify.vp_submission") {
		t.Fatalf("the Inji Verify database runs no init script of the release: %v", err)
	}
	ui := stack["inji-verify-ui"]
	if len(ui.Ports) != 1 || !strings.HasSuffix(ui.Ports[0], ":8000") {
		t.Errorf("inji-verify-ui ports = %v; its nginx listens on 8000", ui.Ports)
	}
	if got := DefaultDpgURL(Pair{Role: commonv1.Role_ROLE_VERIFIER, Dpg: configv1.Dpg_DPG_INJI}); got != "http://inji-verify-service:8080" {
		t.Errorf("the verifier DPG URL = %s", got)
	}
}

// certifyService reads one Certify service of the stack file with its
// health check.
type certifyService struct {
	injiService `yaml:",inline"`
	User        string `yaml:"user"`
	Healthcheck struct {
		Test []string `yaml:"test"`
	} `yaml:"healthcheck"`
}

// readCertifyServices reads the services of the stack file with the
// fields the Certify test needs.
func readCertifyServices(t *testing.T) map[string]certifyService {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot(), "deploy", "vca", "dpg", "inji.yaml")) // #nosec G304 -- a fixed test path
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Services map[string]certifyService `yaml:"services"`
		Volumes  map[string]any            `yaml:"volumes"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	for name := range doc.Volumes {
		doc.Services["volume:"+name] = certifyService{}
	}
	return doc.Services
}

// mountedFile reads a file that the stack file mounts, by its host path.
func mountedFile(t *testing.T, source string) string {
	t.Helper()
	if source == "" {
		t.Fatal("the stack file mounts no such file")
	}
	data, err := os.ReadFile(filepath.Join(repoRoot(), "deploy", "vca", filepath.FromSlash(source))) // #nosec G304 -- a path of the stack file
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// TestInjiStackRunsCertifyAsTheReleaseDoes is P6-I0. Certify 0.14.0
// reads its properties from /home/mosip/config/, as the injistack
// compose file of the release mounts them, and its database comes from
// certify_init.sql of the release. Certify checks every access token
// against one issuer and one key set, so the stack runs it twice on one
// database and one key store: inji-certify is its own authorization
// server for the pre-authorized code and the presentation during
// issuance, with the pre-authorized data provider; inji-certify-esignet
// takes the eSignet tokens of Inji Web and of the authorization code
// offer, with the CSV data provider and the farmer data of the release.
func TestInjiStackRunsCertifyAsTheReleaseDoes(t *testing.T) {
	stack := readCertifyServices(t)
	db := stack["inji-certify-postgres"]
	if db.Image != "postgres:15.8" {
		t.Errorf("the Certify database image = %q; certify_init.sql names the locale en_US.UTF-8", db.Image)
	}
	sql := mountedFile(t, mountSource(db.Volumes, "/docker-entrypoint-initdb.d/certify_init.sql"))
	for _, want := range []string{"CREATE DATABASE inji_certify", "CREATE TABLE IF NOT EXISTS certify.iar_session", "'FarmerCredential'"} {
		if !strings.Contains(sql, want) {
			t.Errorf("certify_init.sql is not the one of Certify 0.14.0: it lacks %q", want)
		}
	}
	did := mountedFile(t, mountSource(db.Volumes, "/docker-entrypoint-initdb.d/vca_certify_did.sql"))
	if !strings.Contains(did, `\getenv`) || !strings.Contains(did, "INJI_CERTIFY_DID") {
		t.Errorf("the sample configuration keeps the DID of the release sample:\n%s", did)
	}
	if db.Environment["INJI_CERTIFY_DID"] == "" {
		t.Error("the Certify database does not read the DID of the stack")
	}

	type want struct {
		profile, profileFile, plugin, issuerURI, jwks string
		audiences                                     []string
	}
	wants := map[string]want{
		"inji-certify": {
			profile: "default,preauth", profileFile: "certify-preauth.properties",
			plugin:    "PreAuthDataProviderPlugin",
			issuerURI: "${mosip.certify.oauth.issuer}",
			jwks:      "http://inji-certify:8090/v1/certify/.well-known/jwks.json",
			audiences: []string{"${mosip.certify.oauth.access-token.audience}"},
		},
		"inji-certify-esignet": {
			profile: "default,csvdp-farmer", profileFile: "certify-csvdp-farmer.properties",
			plugin:    "MockCSVDataProviderPlugin",
			issuerURI: "${INJI_ESIGNET_PUBLIC_URL:http://localhost:17082}/v1/esignet",
			jwks:      "http://inji-esignet:8088/v1/esignet/oauth/.well-known/jwks.json",
			audiences: []string{EsignetClientID, "${mosip.certify.domain.url}${server.servlet.path}/issuance/credential"},
		},
	}
	defaults := ""
	for name, w := range wants {
		svc, ok := stack[name]
		if !ok {
			t.Fatalf("the Inji stack has no %s service", name)
		}
		if svc.Image != "injistack/inji-certify-with-plugins:0.14.0" || strings.Join(svc.Profiles, ",") != "issuer-inji" {
			t.Errorf("%s = %s %v", name, svc.Image, svc.Profiles)
		}
		for key, value := range map[string]string{
			"active_profile_env": w.profile, "SPRING_CONFIG_NAME": "certify", "SPRING_CONFIG_LOCATION": "/home/mosip/config/",
			"container_user": "mosip", "enable_certify_artifactory": "false", "download_hsm_client": "false",
			"SPRING_DATASOURCE_URL": "jdbc:postgresql://inji-certify-postgres:5432/inji_certify?currentSchema=certify",
		} {
			if svc.Environment[key] != value {
				t.Errorf("%s %s = %q, want %q", name, key, svc.Environment[key], value)
			}
		}
		if svc.User != "root" {
			t.Errorf("%s runs as %q; the release runs Certify as root and drops to container_user", name, svc.User)
		}
		if mountSource(svc.Volumes, "/home/mosip/CERTIFY_PKCS12") != "inji-certify-keys" {
			t.Errorf("%s does not keep the key store on the shared volume: %v", name, svc.Volumes)
		}
		defaults = mountedFile(t, mountSource(svc.Volumes, "/home/mosip/config/certify-default.properties"))
		props := readProperties(t, filepath.Join(repoRoot(), "deploy", "vca",
			filepath.FromSlash(mountSource(svc.Volumes, "/home/mosip/config/"+w.profileFile))))
		for key, value := range map[string]string{
			"mosip.certify.integration.data-provider-plugin": w.plugin,
			"mosip.certify.integration.scan-base-package":    "io.mosip.certify.mock.integration",
			"mosip.certify.authn.issuer-uri":                 w.issuerURI,
			"mosip.certify.authn.jwk-set-uri":                w.jwks,
			"mosip.certify.plugin-mode":                      "DataProvider",
		} {
			if props[key] != value {
				t.Errorf("%s %s = %q, want %q", name, key, props[key], value)
			}
		}
		for _, aud := range w.audiences {
			if !strings.Contains(props["mosip.certify.authn.allowed-audiences"], "'"+aud+"'") {
				t.Errorf("%s does not take tokens for %s: %s", name, aud, props["mosip.certify.authn.allowed-audiences"])
			}
		}
	}
	if !strings.Contains(defaults, "mosip.kernel.keymanager.hsm.config-path=CERTIFY_PKCS12/local.p12") ||
		!strings.Contains(defaults, "mosip.certify.database.hostname=inji-certify-postgres") ||
		!strings.Contains(defaults, "management.endpoint.health.probes.enabled=true") {
		t.Error("certify-default.properties does not point Certify at the stack")
	}
	preauth := stack["inji-certify"]
	if len(preauth.Healthcheck.Test) == 0 || !strings.Contains(strings.Join(preauth.Healthcheck.Test, " "), "/v1/certify/actuator/health/readiness") {
		t.Errorf("inji-certify has no readiness check: %v", preauth.Healthcheck.Test)
	}
	esignet := stack["inji-certify-esignet"]
	if esignet.DependsOn["inji-certify"].Condition != "service_healthy" {
		t.Error("inji-certify-esignet starts before inji-certify made the keys of the shared key store")
	}
	csv := mountSource(esignet.Volumes, "/home/mosip/config/farmer_identity_data.csv")
	if !strings.HasPrefix(mountedFile(t, csv), "id,fullName,mobileNumber,dateOfBirth") {
		t.Errorf("inji-certify-esignet mounts no farmer data of the release: %s", csv)
	}
	if _, ok := stack["volume:inji-certify-keys"]; !ok {
		t.Error("the stack file declares no volume inji-certify-keys")
	}

	// The nginx serves the presentation definition and fronts each
	// Certify at the root, as certify-nginx of the release does:
	// OID4VCI puts the metadata under the credential issuer.
	nginx := stack["inji-certify-nginx"]
	conf := mountedFile(t, mountSource(nginx.Volumes, "/etc/nginx/conf.d/default.conf"))
	for _, want := range []string{
		"listen 80;", "set $certify http://inji-certify:8090;",
		"listen 8091;", "set $certify http://inji-certify-esignet:8090;",
		"proxy_pass $certify/v1/certify/.well-known/openid-credential-issuer;",
		"location = /.well-known/openid-credential-issuer", "location = /.well-known/did.json",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("the nginx file lacks %q", want)
		}
	}
	for name, domain := range map[string]string{
		"certify-preauth.properties": "http://inji-certify-nginx", "certify-csvdp-farmer.properties": "http://inji-certify-nginx:8091",
	} {
		source := mountSource(stack["inji-certify"].Volumes, "/home/mosip/config/"+name)
		if source == "" {
			source = mountSource(esignet.Volumes, "/home/mosip/config/"+name)
		}
		props := readProperties(t, filepath.Join(repoRoot(), "deploy", "vca", filepath.FromSlash(source)))
		if props["mosip.certify.domain.url"] != domain {
			t.Errorf("%s domain = %q, want %q", name, props["mosip.certify.domain.url"], domain)
		}
	}
}
