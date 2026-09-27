// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// P6-C5b: the CREDEBL stack runs the status list host that the platform
// names as STATUS_LIST_HOST and the agent as STATUS_LIST_SERVER_URL, so
// an OID4VC offer is revocable.

// statusListStack is the part of the stack file the status list tests
// read.
type statusListStack struct {
	XPlatform struct {
		Environment map[string]string `yaml:"environment"`
	} `yaml:"x-credebl-platform"`
	Services map[string]struct {
		Image    string   `yaml:"image"`
		Profiles []string `yaml:"profiles"`
		Build    struct {
			Context          string `yaml:"context"`
			DockerfileInline string `yaml:"dockerfile_inline"`
		} `yaml:"build"`
		Ports       []string          `yaml:"ports"`
		Volumes     []string          `yaml:"volumes"`
		Environment map[string]string `yaml:"environment"`
	} `yaml:"services"`
}

// TestCredeblStackRunsTheStatusListHost: the stack builds the status
// list server of the platform from its repository at one commit, on a
// base image pinned by digest. The platform and the agent reach it on
// the same address, and it takes the generated API key of the stack.
func TestCredeblStackRunsTheStatusListHost(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRoot(), "deploy", "vca", "dpg", "credebl.yaml")) // #nosec G304 -- a fixed test path
	if err != nil {
		t.Fatal(err)
	}
	var doc statusListStack
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	svc, ok := doc.Services[CredeblStatusListService]
	if !ok {
		t.Fatalf("the stack file runs no %s", CredeblStatusListService)
	}
	if !regexp.MustCompile(`^https://github\.com/sovio-id/status-list-server\.git#[0-9a-f]{40}$`).MatchString(svc.Build.Context) {
		t.Errorf("build context %q is not the repository at one commit", svc.Build.Context)
	}
	from := regexp.MustCompile(`(?m)^FROM (\S+)`).FindAllStringSubmatch(svc.Build.DockerfileInline, -1)
	if len(from) == 0 {
		t.Errorf("the build names no base image:\n%s", svc.Build.DockerfileInline)
	}
	for _, m := range from {
		if !regexp.MustCompile(`^[a-z0-9./-]+:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}$`).MatchString(m[1]) {
			t.Errorf("the base image %s is not pinned by digest", m[1])
		}
	}
	if !strings.Contains(svc.Image, ":") || strings.HasSuffix(svc.Image, ":latest") {
		t.Errorf("image %q carries no pinned tag", svc.Image)
	}
	for _, profile := range []string{"issuer-credebl", "holder-credebl", "verifier-credebl"} {
		if !slices.Contains(svc.Profiles, profile) {
			t.Errorf("profiles %v lack %s", svc.Profiles, profile)
		}
	}
	key := "${" + CredeblStatusListKeyEnv + ":?set by vca setup}"
	if svc.Environment["API_KEY"] != key || svc.Environment["PORT"] != "3000" ||
		!strings.HasPrefix(svc.Environment["DATABASE_URL"], "file:/app/data/") {
		t.Errorf("status list environment = %v", svc.Environment)
	}
	if len(svc.Volumes) != 1 || !strings.HasSuffix(svc.Volumes[0], ":/app/data") {
		t.Errorf("status list volumes = %v, want one volume on /app/data", svc.Volumes)
	}
	if len(svc.Ports) != 1 || !strings.Contains(svc.Ports[0], "${CREDEBL_STATUS_LIST_HOST_PORT:-17183}:3000") {
		t.Errorf("status list ports = %v", svc.Ports)
	}
	url := "${CREDEBL_STATUS_LIST_URL:-http://" + CredeblStatusListService + ":3000}"
	if got := doc.XPlatform.Environment["STATUS_LIST_HOST"]; got != url {
		t.Errorf("platform STATUS_LIST_HOST = %q, want %q", got, url)
	}
	agent := doc.Services["credebl-agent"].Environment
	if agent["STATUS_LIST_SERVER_URL"] != url || agent["STATUS_LIST_API_KEY"] != key || agent["STATUS_LIST_DEFAULT_SIZE"] != "131072" {
		t.Errorf("agent status list environment = %v", agent)
	}
}

// TestCredeblStackEnvHoldsTheStatusListKey: setup generates the API key
// that guards the writes of the status list server.
func TestCredeblStackEnvHoldsTheStatusListKey(t *testing.T) {
	values := writeStackEnvAt(t, t.TempDir(), configv1.Dpg_DPG_CREDEBL, secretsTime, nil)
	if len(values[CredeblStatusListKeyEnv]) != stackSecretLength {
		t.Errorf("%s = %q, want %d characters", CredeblStatusListKeyEnv, values[CredeblStatusListKeyEnv], stackSecretLength)
	}
}

// TestCredeblIssuerPairNamesTheStatusList: the adapter of an issuer pair
// knows that the stack runs the status list host, so its offers are
// revocable. The other roles issue nothing.
func TestCredeblIssuerPairNamesTheStatusList(t *testing.T) {
	for role, want := range map[commonv1.Role]string{
		commonv1.Role_ROLE_ISSUER: "true", commonv1.Role_ROLE_HOLDER: "", commonv1.Role_ROLE_VERIFIER: "",
	} {
		plan, err := BuildPlan(SetupRequest{Pair: credeblPair(role), Flags: credeblFlags(), Random: rand.Reader})
		if err != nil {
			t.Fatal(err)
		}
		env, err := ParseDotenv(strings.NewReader(planFile(t, plan, EnvFileName)))
		if err != nil {
			t.Fatal(err)
		}
		if got := env[CredeblAdapterStatusListEnv]; got != want {
			t.Errorf("%v: %s = %q, want %q", role, CredeblAdapterStatusListEnv, got, want)
		}
	}
}

// TestDoctorChecksTheStatusListPort: a verifier outside the host
// fetches the status lists, so the port of the host is one the doctor
// checks for every CREDEBL pair that runs the platform.
func TestDoctorChecksTheStatusListPort(t *testing.T) {
	for _, role := range []commonv1.Role{commonv1.Role_ROLE_ISSUER, commonv1.Role_ROLE_HOLDER, commonv1.Role_ROLE_VERIFIER} {
		found := false
		for _, d := range DpgHostPorts(credeblPair(role)) {
			found = found || (d.Container == CredeblStatusListService && d.Host == 17183 && d.Env == "CREDEBL_STATUS_LIST_HOST_PORT" && d.Port == 3000)
		}
		if !found {
			t.Errorf("%v: the doctor does not check the status list port: %v", role, DpgHostPorts(credeblPair(role)))
		}
	}
	for _, d := range DpgHostPorts(credeblPair(commonv1.Role_ROLE_ADMIN)) {
		if d.Container == CredeblStatusListService {
			t.Error("the admin pair runs no status list host")
		}
	}
	checks := portChecks(DoctorOptions{Probe: &fakeProbe{}, Pairs: []Pair{credeblPair(commonv1.Role_ROLE_ISSUER)}})
	names := make([]string, 0, len(checks))
	for _, c := range checks {
		names = append(names, c.Name)
	}
	if !slices.Contains(names, "port 17183") {
		t.Errorf("checks = %v", names)
	}
}
