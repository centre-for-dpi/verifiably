// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// portRx reads the two default port numbers out of one port line.
var portRx = regexp.MustCompile(`:-(\d+)\}:\$\{[A-Z_]+:-(\d+)\}`)

// repoRoot is the repository root, two directories above this package.
func repoRoot() string { return filepath.Join("..", "..", "..") }

// composeDoc is the part of a compose file the tests read.
type composeDoc struct {
	Name     string                    `yaml:"name"`
	Include  []map[string]string       `yaml:"include"`
	Services map[string]composeService `yaml:"services"`
	Networks map[string]any            `yaml:"networks"`
	Volumes  map[string]any            `yaml:"volumes"`
}

type composeService struct {
	Image       string            `yaml:"image"`
	Profiles    []string          `yaml:"profiles"`
	Ports       []string          `yaml:"ports"`
	ReadOnly    bool              `yaml:"read_only"`
	User        string            `yaml:"user"`
	CapDrop     []string          `yaml:"cap_drop"`
	SecurityOpt []string          `yaml:"security_opt"`
	Volumes     []string          `yaml:"volumes"`
	Environment map[string]string `yaml:"environment"`
}

// TestComposeFileIsCurrent keeps the committed compose file equal to the
// renderer. Set VCA_WRITE_COMPOSE=1 to write the file again.
func TestComposeFileIsCurrent(t *testing.T) {
	path := filepath.Join(repoRoot(), ComposeFile)
	want := RenderCompose()
	if os.Getenv("VCA_WRITE_COMPOSE") != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(want), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(path) // #nosec G304 -- a fixed test path
	if err != nil {
		t.Fatalf("read %s: %v", ComposeFile, err)
	}
	if string(got) != want {
		t.Errorf("%s is not current; run VCA_WRITE_COMPOSE=1 go test ./internal/cli/", ComposeFile)
	}
}

func TestRenderComposeIsValidYaml(t *testing.T) {
	var doc composeDoc
	if err := yaml.Unmarshal([]byte(RenderCompose()), &doc); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if doc.Name != ComposeProject {
		t.Errorf("project name = %q", doc.Name)
	}
	if len(doc.Include) != len(DpgStackFiles()) {
		t.Errorf("got %d includes, want %d", len(doc.Include), len(DpgStackFiles()))
	}
	for i, want := range DpgStackFiles() {
		if doc.Include[i]["path"] != want {
			t.Errorf("include %d = %v, want %s", i, doc.Include[i], want)
		}
	}
	if _, ok := doc.Networks["vca"]; !ok {
		t.Error("the vca network is missing")
	}
}

func TestRenderComposeIsDeterministic(t *testing.T) {
	first, second := RenderCompose(), RenderCompose()
	if first != second {
		t.Error("two renders differ")
	}
}

func TestComposeHasOneServicePerPairAndService(t *testing.T) {
	var doc composeDoc
	if err := yaml.Unmarshal([]byte(RenderCompose()), &doc); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	want := 0
	for _, p := range AllPairs() {
		want += len(ServicesFor(p))
	}
	if len(doc.Services) != want {
		t.Errorf("got %d services, want %d", len(doc.Services), want)
	}
	for _, p := range AllPairs() {
		for _, s := range ServicesFor(p) {
			name := composeServiceName(p, s)
			svc, ok := doc.Services[name]
			if !ok {
				t.Fatalf("service %s is missing", name)
			}
			if len(svc.Profiles) != 1 || svc.Profiles[0] != p.Name() {
				t.Errorf("%s profiles = %v", name, svc.Profiles)
			}
			if !strings.HasPrefix(svc.Image, s.Image()+":") {
				t.Errorf("%s image = %q", name, svc.Image)
			}
			if s.Stateful && !hasVolume(svc.Volumes, "/data") {
				t.Errorf("%s is stateful but has no data volume: %v", name, svc.Volumes)
			}
		}
	}
}

func TestComposeServicesAreHardened(t *testing.T) {
	var doc composeDoc
	if err := yaml.Unmarshal([]byte(RenderCompose()), &doc); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	for name, svc := range doc.Services {
		if !svc.ReadOnly {
			t.Errorf("%s does not run read only", name)
		}
		if svc.User == "" || svc.User == "0:0" || svc.User == "root" {
			t.Errorf("%s runs as %q", name, svc.User)
		}
		if len(svc.CapDrop) != 1 || svc.CapDrop[0] != "ALL" {
			t.Errorf("%s cap_drop = %v", name, svc.CapDrop)
		}
		if len(svc.SecurityOpt) != 1 || svc.SecurityOpt[0] != "no-new-privileges:true" {
			t.Errorf("%s security_opt = %v", name, svc.SecurityOpt)
		}
	}
	if strings.Contains(RenderCompose(), "docker.sock") {
		t.Error("the compose file mounts the Docker socket")
	}
	if strings.Contains(RenderCompose(), "privileged") {
		t.Error("the compose file runs a privileged container")
	}
}

func TestComposeHostPortsAreUnique(t *testing.T) {
	var doc composeDoc
	if err := yaml.Unmarshal([]byte(RenderCompose()), &doc); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	seen := map[string]string{}
	for name, svc := range doc.Services {
		if len(svc.Ports) != 1 {
			t.Fatalf("%s has %d port lines", name, len(svc.Ports))
		}
		m := portRx.FindStringSubmatch(svc.Ports[0])
		if m == nil {
			t.Fatalf("%s port line %q does not parse", name, svc.Ports[0])
		}
		host := m[1]
		if other, ok := seen[host]; ok {
			t.Errorf("host port %s is used by %s and %s", host, other, name)
		}
		seen[host] = name
	}
}

func TestProfilesAndPairsForDpg(t *testing.T) {
	pairs := PairsForDpg(configv1.Dpg_DPG_INJI)
	if len(pairs) != len(Roles()) {
		t.Fatalf("got %d pairs, want %d", len(pairs), len(Roles()))
	}
	got := strings.Join(Profiles(pairs), ",")
	want := "issuer-inji,holder-inji,verifier-inji,admin-inji"
	if got != want {
		t.Errorf("profiles = %q, want %q", got, want)
	}
	if len(Profiles(nil)) != 0 {
		t.Error("no pairs gave a profile")
	}
}

func TestDpgStackFilesExistAndArePinned(t *testing.T) {
	// The versions come from verifiably-go/docs/dpg-matrix.md
	// (ADR-008 decision 3).
	wantImages := map[string][]string{
		"dpg/waltid.yaml": {
			"waltid/issuer-api:0.18.2", "waltid/verifier-api:0.18.2", "waltid/wallet-api:0.18.2",
		},
		"dpg/inji.yaml": {
			"injistack/inji-certify-with-plugins:0.14.0",
			"mosipid/esignet-with-plugins:1.5.1",
			"quay.io/keycloak/keycloak:25.0",
		},
		"dpg/credebl.yaml": {"quay.io/keycloak/keycloak:25.0"},
	}
	for name, images := range wantImages {
		path := filepath.Join(repoRoot(), "deploy", "vca", name)
		data, err := os.ReadFile(path) // #nosec G304 -- a fixed test path
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		var doc composeDoc
		if err := yaml.Unmarshal(data, &doc); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(doc.Services) == 0 {
			t.Errorf("%s has no services", name)
		}
		for _, image := range images {
			if !strings.Contains(string(data), image) {
				t.Errorf("%s does not pin %s", name, image)
			}
		}
		for svcName, svc := range doc.Services {
			// Every image carries a tag. A bare :latest is not allowed.
			// CREDEBL publishes no version tag, so its tag is a variable
			// the operator pins.
			if !strings.Contains(svc.Image, ":") {
				t.Errorf("%s: %s image %q has no tag", name, svcName, svc.Image)
			}
			if strings.HasSuffix(svc.Image, ":latest") && !strings.Contains(svc.Image, "${") {
				t.Errorf("%s: %s image %q is not pinned", name, svcName, svc.Image)
			}
			if len(svc.Profiles) == 0 {
				t.Errorf("%s: %s has no profile", name, svcName)
			}
			for _, profile := range svc.Profiles {
				if !knownProfile(profile) {
					t.Errorf("%s: %s names the unknown profile %q", name, svcName, profile)
				}
			}
		}
	}
}

func knownProfile(name string) bool {
	for _, p := range AllPairs() {
		if p.Name() == name {
			return true
		}
	}
	return false
}

// hasVolume reports whether one volume line mounts the target path.
func hasVolume(volumes []string, target string) bool {
	for _, v := range volumes {
		if strings.Contains(v, ":"+target+":") || strings.HasSuffix(v, ":"+target) {
			return true
		}
	}
	return false
}

// TestUIServicesMountTheThemeFile is the delivery of the theme file
// (ADR-032 decision 1): every service that draws pages reads
// VCA_THEME_FILE and mounts the file read only; no other service does.
func TestUIServicesMountTheThemeFile(t *testing.T) {
	var doc composeDoc
	if err := yaml.Unmarshal([]byte(RenderCompose()), &doc); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	ui := 0
	for _, p := range AllPairs() {
		for _, s := range ServicesFor(p) {
			name := composeServiceName(p, s)
			svc := doc.Services[name]
			mounted := hasVolume(svc.Volumes, ThemeMountPath)
			value, hasVar := svc.Environment[ThemeFileEnv]
			if s.UI {
				ui++
				if !mounted {
					t.Errorf("%s draws pages but does not mount the theme file: %v", name, svc.Volumes)
				}
				if value != ThemeMountPath {
					t.Errorf("%s %s = %q, want %q", name, ThemeFileEnv, value, ThemeMountPath)
				}
				continue
			}
			if mounted || hasVar {
				t.Errorf("%s draws no page but has the theme file", name)
			}
		}
	}
	if ui == 0 {
		t.Fatal("no service draws pages")
	}
	want := "${" + ThemeHostFileEnv + ":-./theme.yaml}:" + ThemeMountPath + ":ro"
	if !strings.Contains(RenderCompose(), want) {
		t.Errorf("the compose file has no %q mount", want)
	}
}
