// SPDX-License-Identifier: Apache-2.0

package cli

import (
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
	// vca setup writes the issuer list and the trusted verifiers from the
	// addresses of the deployment (P6-I7h). Mimoto and Inji Web read the
	// same files.
	for _, svc := range []injiService{web, mimoto} {
		for _, name := range []string{MimotoIssuersFile, MimotoVerifiersFile} {
			if got := mountSource(svc.Volumes, "/home/mosip/"+name); got != "../"+MimotoDir+"/"+name {
				t.Errorf("%s is mounted from %q, not from the file of vca setup", name, got)
			}
		}
	}
	for _, name := range []string{MimotoIssuersFile, MimotoVerifiersFile} {
		if _, err := os.Stat(filepath.Join(repoRoot(), "deploy", "vca", "dpg", "inji", "mimoto", name)); err == nil {
			t.Errorf("the tree still tracks a static %s", name)
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
// with its database. Certify reads the definition over HTTP from the
// adapter (TestCertifyPropertiesNameThePostgresProvider). The Inji
// issuer pair then turns the feature on.
func TestInjiStackPointsCertifyAtInjiVerify(t *testing.T) {
	stack := readInjiStack(t)
	certify := stack["inji-certify"]
	for key, want := range map[string]string{
		"MOSIP_CERTIFY_VERIFY_SERVICE_BASE_URL":            "http://inji-verify-service:8080",
		"MOSIP_CERTIFY_VERIFY_SERVICE_VP_REQUEST_ENDPOINT": "http://inji-verify-service:8080/v1/verify/vp-request",
		"MOSIP_CERTIFY_VERIFY_SERVICE_VP_RESULT_ENDPOINT":  "http://inji-verify-service:8080/v1/verify/vp-result",
		"MOSIP_CERTIFY_VERIFY_SERVICE_VERIFIER_CLIENT_ID":  "certify-verifier-client",
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

// TestInjiStackRunsCertifyOnTheVcaStore is P6-I0 with ADR-051. Certify
// 0.14.0 reads its properties from /home/mosip/config/, as the injistack
// compose file of the release mounts them, and its database comes from
// certify_init.sql of the release without its sample configuration.
// Certify checks every access token against one issuer and one key set,
// so the stack runs it twice on one database and one key store:
// inji-certify is its own authorization server for the pre-authorized
// code and the presentation during issuance; inji-certify-authcode takes
// the tokens of the holder authorization server of the adapter. Both
// issue from the VCA claims store, which the Postgres reads from the
// volume that the adapter writes.
func TestInjiStackRunsCertifyOnTheVcaStore(t *testing.T) {
	stack := readCertifyServices(t)
	db := stack["inji-certify-postgres"]
	if db.Image != "postgres:15.8" {
		t.Errorf("the Certify database image = %q; certify_init.sql names the locale en_US.UTF-8 and file_fdw ships with it", db.Image)
	}
	sql := mountedFile(t, mountSource(db.Volumes, "/docker-entrypoint-initdb.d/certify_init.sql"))
	for _, want := range []string{"CREATE DATABASE inji_certify", "CREATE TABLE IF NOT EXISTS certify.iar_session", "INSERT INTO certify.key_policy_def"} {
		if !strings.Contains(sql, want) {
			t.Errorf("certify_init.sql is not the one of Certify 0.14.0: it lacks %q", want)
		}
	}
	if strings.Contains(sql, "INSERT INTO certify.credential_config") {
		t.Error("certify_init.sql still inserts a credential configuration (ADR-050)")
	}
	store := mountedFile(t, mountSource(db.Volumes, "/docker-entrypoint-initdb.d/vca_claims.sql"))
	for _, want := range []string{"CREATE EXTENSION IF NOT EXISTS file_fdw", "CREATE FOREIGN TABLE IF NOT EXISTS certify.vca_claims",
		"subject text", "v_status_index text", "c1 text", "c64 text", "program 'cat /vca/claims/*.csv 2>/dev/null; exit 0'", "format 'csv'"} {
		if !strings.Contains(store, want) {
			t.Errorf("vca_claims.sql lacks %q", want)
		}
	}
	if strings.Contains(store, "c65 text") {
		t.Error("vca_claims.sql has more than 64 claim columns")
	}
	if got := volumeMount(db.Volumes, "/vca/claims"); got != "inji-claims:/vca/claims:ro" {
		t.Errorf("the Certify database mounts the claims store as %q, want it read only", got)
	}
	if _, ok := stack["volume:inji-claims"]; !ok {
		t.Error("the stack file declares no volume inji-claims")
	}
	if _, ok := db.Environment["INJI_CERTIFY_DID"]; ok {
		t.Error("the Certify database still reads a DID")
	}

	wants := map[string]struct{ profile, domain string }{
		"inji-certify":          {"default,vca-store", "http://inji-certify-nginx"},
		"inji-certify-authcode": {"default,vca-store,authcode", "http://inji-certify-nginx:8091"},
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
			"INJI_CERTIFY_DID":      "${INJI_CERTIFY_DID:-}",
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
		for _, v := range svc.Volumes {
			if strings.Contains(v, "farmer") || strings.Contains(v, "vp_request_config") || strings.Contains(v, ".csv") {
				t.Errorf("%s mounts %s", name, v)
			}
		}
		defaults = mountedFile(t, mountSource(svc.Volumes, "/home/mosip/config/certify-default.properties"))
		props := map[string]string{}
		for _, profile := range strings.Split(w.profile, ",")[1:] {
			source := mountSource(svc.Volumes, "/home/mosip/config/certify-"+profile+".properties")
			if source == "" {
				t.Fatalf("%s mounts no file of the profile %s", name, profile)
			}
			// A later profile beats an earlier one, as Spring reads them.
			for k, v := range readProperties(t, filepath.Join(repoRoot(), "deploy", "vca", filepath.FromSlash(source))) {
				props[k] = v
			}
		}
		if props["mosip.certify.domain.url"] != w.domain {
			t.Errorf("%s domain = %q, want %q", name, props["mosip.certify.domain.url"], w.domain)
		}
		if props["mosip.certify.integration.data-provider-plugin"] != "PostgresDataProviderPlugin" {
			t.Errorf("%s data provider = %q", name, props["mosip.certify.integration.data-provider-plugin"])
		}
	}
	if !strings.Contains(defaults, "mosip.kernel.keymanager.hsm.config-path=CERTIFY_PKCS12/local.p12") ||
		!strings.Contains(defaults, "mosip.certify.database.hostname=inji-certify-postgres") ||
		!strings.Contains(defaults, "management.endpoint.health.probes.enabled=true") {
		t.Error("certify-default.properties does not point Certify at the stack")
	}
	certify := stack["inji-certify"]
	if len(certify.Healthcheck.Test) == 0 || !strings.Contains(strings.Join(certify.Healthcheck.Test, " "), "/v1/certify/actuator/health/readiness") {
		t.Errorf("inji-certify has no readiness check: %v", certify.Healthcheck.Test)
	}
	authcode := stack["inji-certify-authcode"]
	if authcode.DependsOn["inji-certify"].Condition != "service_healthy" {
		t.Error("inji-certify-authcode starts before inji-certify made the keys of the shared key store")
	}
	if _, ok := authcode.DependsOn["inji-esignet"]; ok {
		t.Error("inji-certify-authcode still waits for eSignet")
	}
	if _, ok := stack["inji-certify-esignet"]; ok {
		t.Error("the stack still runs inji-certify-esignet")
	}
	if _, ok := stack["volume:inji-certify-keys"]; !ok {
		t.Error("the stack file declares no volume inji-certify-keys")
	}

	// The nginx fronts each Certify at the root, as certify-nginx of the
	// release does: OID4VCI puts the metadata under the credential issuer.
	nginx := stack["inji-certify-nginx"]
	if len(nginx.Volumes) != 1 {
		t.Errorf("the nginx mounts more than its configuration: %v", nginx.Volumes)
	}
	conf := mountedFile(t, mountSource(nginx.Volumes, "/etc/nginx/conf.d/default.conf"))
	for _, want := range []string{
		"listen 80;", "set $certify http://inji-certify:8090;",
		"listen 8091;", "set $certify http://inji-certify-authcode:8090;",
		"proxy_pass $certify/v1/certify/.well-known/openid-credential-issuer;",
		"location = /.well-known/openid-credential-issuer", "location = /.well-known/did.json",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("the nginx file lacks %q", want)
		}
	}
	if strings.Contains(conf, "vp_request_config") {
		t.Error("the nginx still serves a fixed presentation definition")
	}

	// No file of the Certify folder names the removed sample.
	entries, err := os.ReadDir(filepath.Join(repoRoot(), "deploy", "vca", "dpg", "inji", "certify"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(repoRoot(), "deploy", "vca", "dpg", "inji", "certify", e.Name())) // #nosec G304 -- a file of the folder
		if err != nil {
			t.Fatal(err)
		}
		if lower := strings.ToLower(string(data)); strings.Contains(lower, "farmer") || strings.Contains(e.Name(), ".csv") {
			t.Errorf("%s names the removed sample", e.Name())
		}
	}
}

// TestCertifyPropertiesNameThePostgresProvider: both Certify containers
// run the Postgres data provider of the digital credential plugins 0.6.0
// with one query on the claims store for the shared scope, and take the
// identity claims of a presentation during issuance from setup
// (ADR-051 decisions 1, 3, and 5). inji-certify-authcode trusts the
// holder authorization server of the adapter (ADR-052 decision 4).
func TestCertifyPropertiesNameThePostgresProvider(t *testing.T) {
	dir := filepath.Join(repoRoot(), "deploy", "vca", "dpg", "inji", "certify")
	store := readProperties(t, filepath.Join(dir, "certify-vca-store.properties"))
	for key, want := range map[string]string{
		"mosip.certify.integration.scan-base-package":                     "io.mosip.certify.postgresdataprovider.integration",
		"mosip.certify.integration.data-provider-plugin":                  "PostgresDataProviderPlugin",
		"mosip.certify.integration.audit-plugin":                          "LoggerAuditService",
		"mosip.certify.plugin-mode":                                       "DataProvider",
		"mosip.certify.data-provider-plugin.postgres.scope-query-mapping": "{'vca_credential': 'select * from certify.vca_claims where subject = :id and cast(expires_at as timestamptz) > now()'}",
		"mosip.certify.iar.identity-data":                                 "${INJI_IAR_IDENTITY_CLAIMS}",
		"mosip.certify.data-provider-plugin.did-url":                      "${INJI_CERTIFY_DID}",
		"mosip.certify.authn.issuer-uri":                                  "${mosip.certify.oauth.issuer}",
		"mosip.certify.authn.jwk-set-uri":                                 "http://inji-certify:8090/v1/certify/.well-known/jwks.json",
	} {
		if got := store[key]; got != want {
			t.Errorf("certify-vca-store.properties %s = %q, want %q", key, got, want)
		}
	}
	authcode := readProperties(t, filepath.Join(dir, "certify-authcode.properties"))
	for key, want := range map[string]string{
		"mosip.certify.domain.url":              "http://inji-certify-nginx:8091",
		"mosip.certify.authorization.url":       "${VCA_INJI_AUTHZ_ISSUER}",
		"mosip.certify.authn.issuer-uri":        "${VCA_INJI_AUTHZ_ISSUER}",
		"mosip.certify.authn.jwk-set-uri":       "${INJI_ADAPTER_URL}/authz/.well-known/jwks.json",
		"mosip.certify.authn.allowed-audiences": "{ '${mosip.certify.domain.url}${server.servlet.path}/issuance/credential' }",
	} {
		if got := authcode[key]; got != want {
			t.Errorf("certify-authcode.properties %s = %q, want %q", key, got, want)
		}
	}
	if _, ok := authcode["mosip.certify.integration.data-provider-plugin"]; ok {
		t.Error("certify-authcode.properties names a data provider; the store profile names it for both")
	}
	defaults := readProperties(t, filepath.Join(dir, "certify-default.properties"))
	if got := defaults["mosip.certify.vp-request.config-file-url"]; got != "${INJI_ADAPTER_URL}/iar/presentation-definition.json" {
		t.Errorf("the definition URL = %q", got)
	}
	stack := readInjiStack(t)
	env := stack["inji-certify"].Environment
	for key, want := range map[string]string{
		"INJI_IAR_IDENTITY_CLAIMS":                 "${VCA_INJI_IAR_IDENTITY_CLAIMS:-vcaSubject}",
		"INJI_ADAPTER_URL":                         "${" + InjiAdapterURLEnv + ":-}",
		"VCA_INJI_AUTHZ_ISSUER":                    "${VCA_INJI_AUTHZ_ISSUER:-}",
		"MOSIP_CERTIFY_VP_REQUEST_CONFIG_FILE_URL": "${INJI_ADAPTER_URL:-}/iar/presentation-definition.json",
	} {
		if env[key] != want {
			t.Errorf("inji-certify %s = %q, want %q", key, env[key], want)
		}
	}
}

// volumeMount returns the volume entry that mounts the target path.
func volumeMount(volumes []string, target string) string {
	for _, v := range volumes {
		parts := strings.Split(v, ":")
		if len(parts) >= 2 && parts[1] == target {
			return v
		}
	}
	return ""
}

// TestInjiStackRunsEsignetWithItsLoginPage is P6-I7f. eSignet 1.5.1 runs
// as the compose file of its release runs it: a Postgres that the init
// script of the release prepares for eSignet and for the mock identity
// system, a Redis, the mock plugin, and the local profile. Its login
// page, oidc-ui 1.5.1, serves the authorize page of a browser and sends
// /v1/esignet to eSignet. The mock identity names the identity by its
// individual id. A credential scope maps onto the credential endpoint
// of inji-certify-authcode.
func TestInjiStackRunsEsignetWithItsLoginPage(t *testing.T) {
	stack := readCertifyServices(t)
	both := func(name string) certifyService {
		t.Helper()
		svc, ok := stack[name]
		if !ok {
			t.Fatalf("the Inji stack has no %s service", name)
		}
		if strings.Join(svc.Profiles, ",") != "issuer-inji,holder-inji" {
			t.Errorf("%s profiles = %v, want issuer-inji,holder-inji", name, svc.Profiles)
		}
		return svc
	}
	db := both("inji-esignet-postgres")
	if db.Image != "postgres:15.8" {
		t.Errorf("the eSignet database image = %q; its init script names the locale en_US.UTF-8", db.Image)
	}
	sql := mountedFile(t, mountSource(db.Volumes, "/docker-entrypoint-initdb.d/init.sql"))
	for _, want := range []string{"CREATE DATABASE mosip_esignet", "CREATE DATABASE mosip_mockidentitysystem", "CREATE TABLE mockidentitysystem.mock_identity("} {
		if !strings.Contains(sql, want) {
			t.Errorf("the eSignet init script lacks %q", want)
		}
	}
	if redis := both("inji-esignet-redis"); redis.Image != "redis:7.4.1-alpine" {
		t.Errorf("the eSignet Redis image = %q", redis.Image)
	}

	certify := readProperties(t, filepath.Join(repoRoot(), "deploy", "vca", "dpg", "inji", "certify", "certify-authcode.properties"))
	credentialEndpoint := strings.NewReplacer("${mosip.certify.domain.url}", certify["mosip.certify.domain.url"],
		"${server.servlet.path}", "/v1/certify").Replace("${mosip.certify.domain.url}${server.servlet.path}/issuance/credential")
	esignet := both("inji-esignet")
	for key, want := range map[string]string{
		"active_profile_env":            "default,local",
		"plugin_name_env":               "esignet-mock-plugin.jar",
		"SPRING_DATASOURCE_URL":         "jdbc:postgresql://inji-esignet-postgres:5432/mosip_esignet?currentSchema=esignet",
		"MOSIP_ESIGNET_MOCK_DOMAIN_URL": "http://inji-mock-identity:8082",
		"SPRING_REDIS_HOST":             "inji-esignet-redis",
		"MOSIP_ESIGNET_DOMAIN_URL":      "${INJI_ESIGNET_PUBLIC_URL:-http://localhost:17089}",
		// The key set of the pair host belongs to its auth service, so
		// eSignet names the path of its own service.
		"MOSIP_ESIGNET_JWKS_URI":                          "${INJI_ESIGNET_PUBLIC_URL:-http://localhost:17089}/v1/esignet/oauth/.well-known/jwks.json",
		"MOSIP_ESIGNET_SUPPORTED_CREDENTIAL_SCOPES":       "{'mock_identity_vc_ldp'}",
		"MOSIP_ESIGNET_CREDENTIAL_SCOPE_RESOURCE_MAPPING": "{'mock_identity_vc_ldp': '" + credentialEndpoint + "'}",
	} {
		if esignet.Environment[key] != want {
			t.Errorf("inji-esignet %s = %q, want %q", key, esignet.Environment[key], want)
		}
	}
	for _, dep := range []string{"inji-esignet-postgres", "inji-esignet-redis", "inji-mock-identity"} {
		if _, ok := esignet.DependsOn[dep]; !ok {
			t.Errorf("inji-esignet does not wait for %s", dep)
		}
	}
	mock := both("inji-mock-identity")
	for key, want := range map[string]string{
		"active_profile_env":            "default,local",
		"SPRING_DATASOURCE_URL":         "jdbc:postgresql://inji-esignet-postgres:5432/mosip_mockidentitysystem?currentSchema=mockidentitysystem",
		"MOSIP_MOCK_IDA_KYC_PSUT_FIELD": "individualId",
	} {
		if mock.Environment[key] != want {
			t.Errorf("inji-mock-identity %s = %q, want %q", key, mock.Environment[key], want)
		}
	}

	ui := both("inji-esignet-ui")
	if ui.Image != "mosipid/oidc-ui:1.5.1" {
		t.Errorf("the login page image = %q", ui.Image)
	}
	if len(ui.Ports) != 1 || !strings.HasSuffix(ui.Ports[0], ":3000") || !strings.Contains(ui.Ports[0], "INJI_ESIGNET_UI_HOST_PORT:-17089") {
		t.Errorf("inji-esignet-ui ports = %v; oidc-ui listens on 3000", ui.Ports)
	}
	if ui.Environment["OIDC_UI_PUBLIC_URL"] != "esignet-ui" {
		t.Errorf("the assets of the login page share /static with VCA: OIDC_UI_PUBLIC_URL = %q", ui.Environment["OIDC_UI_PUBLIC_URL"])
	}
	conf := mountedFile(t, mountSource(ui.Volumes, "/etc/nginx/nginx.conf"))
	for _, want := range []string{
		"listen 3000;", "set $esignet http://inji-esignet:8088;", "location /v1/esignet {",
		"location /esignet-ui/ {", "alias /usr/share/nginx/esignet-ui/theme/;", "alias /usr/share/nginx/esignet-ui/locales/;",
		"try_files $uri /esignet-ui/index.html;",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("the nginx file of the login page lacks %q", want)
		}
	}
}

// TestStackFilesHaveNoSecretDefault: no stack file gives a password, a
// secret or a key a default. vca setup generates every stack secret
// into the .env of the stack directory, and compose fails with the name
// of the variable when the file is absent (ADR-055 decision 1).
func TestStackFilesHaveNoSecretDefault(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(repoRoot(), "deploy", "vca", "dpg", "*.yaml"))
	if err != nil || len(files) != 3 {
		t.Fatalf("stack files = %v, %v", files, err)
	}
	for _, path := range files {
		data, err := os.ReadFile(path) // #nosec G304 -- a fixed test path
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			if secretDefaultRe.MatchString(line) {
				t.Errorf("%s:%d gives a secret a default: %s", filepath.Base(path), i+1, strings.TrimSpace(line))
			}
		}
		for _, name := range stackSecretNames(dpgOfStackFile(path)) {
			if !strings.Contains(string(data), "${"+name+":?") {
				t.Errorf("%s does not require %s with ${%s:?...}", filepath.Base(path), name, name)
			}
		}
	}
}

// dpgOfStackFile maps deploy/vca/dpg/<dpg>.yaml onto its DPG.
func dpgOfStackFile(path string) configv1.Dpg {
	name := strings.TrimSuffix(filepath.Base(path), ".yaml")
	for _, d := range []configv1.Dpg{configv1.Dpg_DPG_WALTID, configv1.Dpg_DPG_INJI, configv1.Dpg_DPG_CREDEBL} {
		if ShortName(d.String()) == name {
			return d
		}
	}
	return configv1.Dpg_DPG_UNSPECIFIED
}

// TestKeyCertificateSubjectComesFromSetup: the key manager of both
// Certify containers and of Mimoto names the organisation that setup
// collected, not an upstream example (ADR-055 decision 3). The stack
// file passes the subject from the .env of the pair. A part of the
// subject that setup does not collect stays empty, and the key manager
// leaves an empty part out of the certificate (CertificateUtility of
// mosip/keymanager release-1.3.x, lines 214 to 231).
func TestKeyCertificateSubjectComesFromSetup(t *testing.T) {
	want := map[string]string{
		"common-name":         "${" + KeyCertCNEnv + "}",
		"organizational-unit": "${" + KeyCertOUEnv + "}",
		"organization":        "${" + KeyCertOEnv + "}",
		"location":            "",
		"state":               "",
		"country":             "",
	}
	dir := filepath.Join(repoRoot(), "deploy", "vca", "dpg", "inji")
	files := map[string][]string{
		filepath.Join(dir, "certify", "certify-default.properties"): {"mosip.kernel.keymanager.certificate.default.", "mosip.kernel.keymanager.softhsm.certificate."},
		filepath.Join(dir, "mimoto", "mimoto-default.properties"):   {"mosip.kernel.keymanager.certificate.default."},
	}
	for path, prefixes := range files {
		props := readProperties(t, path)
		for _, prefix := range prefixes {
			for part, value := range want {
				key := prefix + part
				if prefix == "mosip.kernel.keymanager.softhsm.certificate." && (part == "location" || part == "state") {
					continue
				}
				got, ok := props[key]
				if !ok || got != value {
					t.Errorf("%s: %s = %q (set %v), want %q", filepath.Base(path), key, got, ok, value)
				}
			}
		}
	}
	stack := readInjiStack(t)
	for _, name := range []string{"inji-certify", "inji-certify-authcode", "inji-mimoto"} {
		env := stack[name].Environment
		for _, v := range []string{KeyCertCNEnv, KeyCertOUEnv, KeyCertOEnv} {
			if got := env[v]; got != "${"+v+":-}" {
				t.Errorf("%s: %s = %q, want the value of the pair .env", name, v, got)
			}
		}
	}
}

// TestMimotoRunsNoPlatformSecret: the Mimoto profile names MOSIP
// platform services that the stack does not run. Their secrets and
// addresses are empty, so no upstream literal ships (ADR-055 decision
// 2). Mimoto still finds every key it reads at start.
func TestMimotoRunsNoPlatformSecret(t *testing.T) {
	props := readProperties(t, filepath.Join(repoRoot(), "deploy", "vca", "dpg", "inji", "mimoto", "mimoto-default.properties"))
	for _, key := range []string{
		"mosip.event.secret", "mosip.partner.crypto.p12.password", "mosip.partner.encryption.key",
		"token.request.password", "token.request.secretKey", "mosip.iam.adapter.clientsecret",
		"mosip.idp.partner.encryption.key", "wallet.binding.partner.api.key",
		"mosip.inji.allowedAuthType", "mosip.inji.allowedEkycAuthType", "mosip.inji.faceSdkModelUrl",
		"keycloak.external.url", "mosip.resident.base.url",
	} {
		got, ok := props[key]
		if !ok {
			t.Errorf("%s is gone; Mimoto reads it at start", key)
		} else if got != "" {
			t.Errorf("%s = %q, want empty", key, got)
		}
	}
	certify := readProperties(t, filepath.Join(repoRoot(), "deploy", "vca", "dpg", "inji", "certify", "certify-default.properties"))
	for key, want := range map[string]string{
		"mosip.certify.authorization.url": "",
		"mosip.certify.authn.jwk-set-uri": "",
		"spring.data.redis.password":      "",
		"spring.datasource.password":      "${INJI_DB_PASSWORD}",
		// The key store password has no fallback in the file either.
		"mosip.kernel.keymanager.hsm.keystore-pass": "${INJI_CERTIFY_KEYSTORE_PASSWORD}",
	} {
		if got, ok := certify[key]; !ok || got != want {
			t.Errorf("certify-default.properties: %s = %q (set %v), want %q", key, got, ok, want)
		}
	}
}
