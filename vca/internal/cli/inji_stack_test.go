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
		"wellknown_endpoint":     "http://inji-certify:8090/v1/certify/issuance/.well-known/openid-credential-issuer",
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
