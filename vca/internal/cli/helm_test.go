// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/themefile"
)

// chartMeta is the part of a Chart.yaml the tests read.
type chartMeta struct {
	APIVersion   string         `yaml:"apiVersion"`
	Name         string         `yaml:"name"`
	Description  string         `yaml:"description"`
	Version      string         `yaml:"version"`
	AppVersion   string         `yaml:"appVersion"`
	Dependencies []chartDepMeta `yaml:"dependencies"`
}

type chartDepMeta struct {
	Name       string `yaml:"name"`
	Version    string `yaml:"version"`
	Repository string `yaml:"repository"`
	Condition  string `yaml:"condition"`
}

// chartValues is the part of a values.yaml the tests read.
type chartValues struct {
	ReplicaCount int `yaml:"replicaCount"`
	Image        struct {
		Repository string `yaml:"repository"`
		Tag        string `yaml:"tag"`
		PullPolicy string `yaml:"pullPolicy"`
	} `yaml:"image"`
	ContainerPort  int    `yaml:"containerPort"`
	ListenVariable string `yaml:"listenVariable"`
	Service        struct {
		Type string `yaml:"type"`
		Port int    `yaml:"port"`
	} `yaml:"service"`
	RunAsUser      int    `yaml:"runAsUser"`
	ExistingSecret string `yaml:"existingSecret"`
	Persistence    struct {
		Enabled   bool   `yaml:"enabled"`
		MountPath string `yaml:"mountPath"`
	} `yaml:"persistence"`
	Resources map[string]any `yaml:"resources"`
}

func readYaml[T any](t *testing.T, path string, out *T) {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- a fixed test path
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := yaml.Unmarshal(data, out); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
}

func TestEveryServiceHasAChart(t *testing.T) {
	root := repoRoot()
	entries, err := os.ReadDir(filepath.Join(root, HelmRoot))
	if err != nil {
		t.Fatalf("read the chart root: %v", err)
	}
	onDisk := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() {
			onDisk[e.Name()] = true
		}
	}
	for _, name := range HelmChartNames() {
		if !onDisk[name] {
			t.Errorf("chart %s is missing", name)
		}
		delete(onDisk, name)
	}
	for name := range onDisk {
		t.Errorf("chart %s has no service", name)
	}
}

func TestServiceChartsMatchTheCatalog(t *testing.T) {
	root := repoRoot()
	for _, s := range Catalog() {
		dir := HelmChartDir(root, s.Name)
		var meta chartMeta
		readYaml(t, filepath.Join(dir, "Chart.yaml"), &meta)
		if meta.APIVersion != "v2" {
			t.Errorf("%s apiVersion = %q", s.Name, meta.APIVersion)
		}
		if meta.Name != s.Name {
			t.Errorf("%s chart name = %q", s.Name, meta.Name)
		}
		if meta.Version != ChartVersion || meta.Description == "" {
			t.Errorf("%s meta = %+v", s.Name, meta)
		}
		var values chartValues
		readYaml(t, filepath.Join(dir, "values.yaml"), &values)
		if values.Image.Repository != s.Image() {
			t.Errorf("%s image = %q, want %q", s.Name, values.Image.Repository, s.Image())
		}
		if values.ContainerPort != s.ExposedPort || values.Service.Port != s.ExposedPort {
			t.Errorf("%s port = %d and %d, want %d", s.Name, values.ContainerPort, values.Service.Port, s.ExposedPort)
		}
		if values.ListenVariable != s.ListenEnv {
			t.Errorf("%s listen variable = %q, want %q", s.Name, values.ListenVariable, s.ListenEnv)
		}
		if values.Persistence.Enabled != s.Stateful {
			t.Errorf("%s persistence = %v, want %v", s.Name, values.Persistence.Enabled, s.Stateful)
		}
		if values.RunAsUser == 0 {
			t.Errorf("%s runs as root", s.Name)
		}
		if values.ExistingSecret == "" {
			t.Errorf("%s names no Secret", s.Name)
		}
		if values.ReplicaCount < 1 || values.Resources == nil {
			t.Errorf("%s values = %+v", s.Name, values)
		}
	}
}

func TestServiceChartTemplatesAreHardened(t *testing.T) {
	root := repoRoot()
	want := []string{
		"readOnlyRootFilesystem: true",
		"runAsNonRoot: true",
		"allowPrivilegeEscalation: false",
		"drop:",
		"- ALL",
		"path: /healthz",
		"path: /readyz",
		"livenessProbe:",
		"readinessProbe:",
		"automountServiceAccountToken: false",
	}
	for _, s := range Catalog() {
		path := filepath.Join(HelmChartDir(root, s.Name), "templates", "deployment.yaml")
		data, err := os.ReadFile(path) // #nosec G304 -- a fixed test path
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		text := string(data)
		for _, line := range want {
			if !strings.Contains(text, line) {
				t.Errorf("%s deployment has no %q", s.Name, line)
			}
		}
		if strings.Contains(text, "privileged: true") || strings.Contains(text, "hostNetwork") {
			t.Errorf("%s deployment asks for host access", s.Name)
		}
		if strings.Contains(text, "docker.sock") {
			t.Errorf("%s deployment mounts the Docker socket", s.Name)
		}
		for _, name := range []string{"service.yaml", "configmap.yaml", "_helpers.tpl"} {
			if _, err := os.Stat(filepath.Join(HelmChartDir(root, s.Name), "templates", name)); err != nil {
				t.Errorf("%s has no %s", s.Name, name)
			}
		}
	}
}

func TestUmbrellaChartTurnsRolesOn(t *testing.T) {
	root := repoRoot()
	dir := HelmChartDir(root, UmbrellaChart)
	var meta chartMeta
	readYaml(t, filepath.Join(dir, "Chart.yaml"), &meta)
	if len(meta.Dependencies) != len(Catalog()) {
		t.Fatalf("got %d dependencies, want %d", len(meta.Dependencies), len(Catalog()))
	}
	byName := map[string]chartDepMeta{}
	for _, d := range meta.Dependencies {
		byName[d.Name] = d
	}
	for _, s := range Catalog() {
		dep, ok := byName[s.Name]
		if !ok {
			t.Errorf("the umbrella chart does not depend on %s", s.Name)
			continue
		}
		if dep.Condition != ChartCondition(s) {
			t.Errorf("%s condition = %q, want %q", s.Name, dep.Condition, ChartCondition(s))
		}
		if dep.Repository != "file://../"+s.Name {
			t.Errorf("%s repository = %q", s.Name, dep.Repository)
		}
		// The packaged dependency is committed, so helm lint, helm
		// template, and helm package work with no network.
		tgz := filepath.Join(dir, "charts", s.Name+"-"+dep.Version+".tgz")
		if _, err := os.Stat(tgz); err != nil {
			t.Errorf("%s has no packaged dependency at charts/: %v", s.Name, err)
		}
	}
	var values map[string]map[string]map[string]any
	readYaml(t, filepath.Join(dir, "values.yaml"), &values)
	for _, r := range Roles() {
		name := ShortName(r.String())
		if _, ok := values["roles"][name]; !ok {
			t.Errorf("the umbrella values have no roles.%s", name)
		}
		if values["roles"][name]["enabled"] == true {
			t.Errorf("roles.%s.enabled is on by default", name)
		}
	}
	for _, d := range Dpgs() {
		name := ShortName(d.String())
		if _, ok := values["dpg"][name]; !ok {
			t.Errorf("the umbrella values have no dpg.%s", name)
		}
	}
}

func TestChartCondition(t *testing.T) {
	adapter := Service{Name: "dpg-adapter-inji", Dpg: configv1.Dpg_DPG_INJI,
		Roles: []commonv1.Role{commonv1.Role_ROLE_ISSUER}}
	if got := ChartCondition(adapter); got != "dpg.inji.enabled" {
		t.Errorf("got %q", got)
	}
	plain := Service{Name: "issuance", Roles: []commonv1.Role{commonv1.Role_ROLE_ISSUER}}
	if got := ChartCondition(plain); got != "roles.issuer.enabled" {
		t.Errorf("got %q", got)
	}
}

// TestHelmLintAndTemplate runs the real helm binary when it is installed.
// The Go checks above cover the same ground when it is not.
func TestHelmLintAndTemplate(t *testing.T) {
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm is not installed; the Go chart checks cover the charts")
	}
	root := repoRoot()
	for _, name := range HelmChartNames() {
		dir := HelmChartDir(root, name)
		for _, args := range [][]string{{"lint", dir}, {"template", "test", dir}} {
			var out bytes.Buffer
			cmd := exec.CommandContext(context.Background(), helm, args...) // #nosec G204 -- fixed arguments
			cmd.Stdout = &out
			cmd.Stderr = &out
			if err := cmd.Run(); err != nil {
				t.Errorf("helm %s %s: %v\n%s", args[0], name, err, out.String())
			}
		}
	}
	// One role on renders three objects per service of the role.
	var out bytes.Buffer
	cmd := exec.CommandContext(context.Background(), helm, "template", "test",
		HelmChartDir(root, UmbrellaChart), "--set", "roles.admin.enabled=true") // #nosec G204 -- fixed arguments
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("helm template the umbrella chart: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "trust-registry") {
		t.Error("the admin role rendered no trust registry")
	}
	if strings.Contains(out.String(), "name: test-issuance") {
		t.Error("the admin role rendered an issuer service")
	}
}

// themeValues is the theme part of a UI chart's values.yaml.
type themeValues struct {
	Theme struct {
		Enabled   bool   `yaml:"enabled"`
		ConfigMap string `yaml:"configMap"`
		MountPath string `yaml:"mountPath"`
	} `yaml:"theme"`
	Global struct {
		Theme struct {
			File string `yaml:"file"`
		} `yaml:"theme"`
	} `yaml:"global"`
}

// TestUIChartsMountTheThemeConfigMap checks the Kubernetes delivery of
// the theme file (ADR-032 decision 1): every UI chart mounts the theme
// ConfigMap read only, sets VCA_THEME_FILE, and rolls its pods through a
// checksum of the file. No other chart touches it.
func TestUIChartsMountTheThemeConfigMap(t *testing.T) {
	root := repoRoot()
	for _, s := range Catalog() {
		dir := HelmChartDir(root, s.Name)
		data, err := os.ReadFile(filepath.Join(dir, "templates", "deployment.yaml")) // #nosec G304 -- a fixed test path
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		mentions := strings.Contains(text, ThemeFileEnv) || strings.Contains(text, "checksum/theme") || strings.Contains(text, "name: theme")
		if !s.UI {
			if mentions {
				t.Errorf("%s draws no page but its deployment names the theme", s.Name)
			}
			continue
		}
		for _, want := range []string{
			"checksum/theme: {{ .Values.global.theme.file | sha256sum }}",
			"- name: " + ThemeFileEnv,
			"value: {{ .Values.theme.mountPath }}/theme.yaml",
			"mountPath: {{ .Values.theme.mountPath }}",
			"readOnly: true",
			`{{ .Values.theme.configMap | default (printf "%s-theme" .Release.Name) }}`,
		} {
			if !strings.Contains(text, want) {
				t.Errorf("%s deployment lacks %q", s.Name, want)
			}
		}
		var values themeValues
		readYaml(t, filepath.Join(dir, "values.yaml"), &values)
		if !values.Theme.Enabled || values.Theme.MountPath != filepath.Dir(ThemeMountPath) || values.Theme.ConfigMap != "" {
			t.Errorf("%s theme values = %+v", s.Name, values.Theme)
		}
		if values.Global.Theme.File != "" {
			t.Errorf("%s ships a theme file in its values", s.Name)
		}
	}
	umbrella := HelmChartDir(root, UmbrellaChart)
	data, err := os.ReadFile(filepath.Join(umbrella, "templates", "theme-configmap.yaml")) // #nosec G304 -- a fixed test path
	if err != nil {
		t.Fatalf("the umbrella chart has no theme ConfigMap: %v", err)
	}
	for _, want := range []string{"kind: ConfigMap", "name: {{ .Release.Name }}-theme", "theme.yaml:", `.Files.Get "files/theme.yaml"`, ".Values.global.theme.file"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("the theme ConfigMap lacks %q", want)
		}
	}
	var values themeValues
	readYaml(t, filepath.Join(umbrella, "values.yaml"), &values)
	if values.Global.Theme.File != "" {
		t.Error("the umbrella values carry a theme file; the default comes from files/theme.yaml")
	}
}

// TestUmbrellaThemeFileEqualsShippedTheme keeps the default the chart
// ships equal to the tracked theme file.
func TestUmbrellaThemeFileEqualsShippedTheme(t *testing.T) {
	root := repoRoot()
	chart, err := os.ReadFile(filepath.Join(HelmChartDir(root, UmbrellaChart), "files", "theme.yaml")) // #nosec G304 -- a fixed test path
	if err != nil {
		t.Fatal(err)
	}
	shipped, err := os.ReadFile(filepath.Join(root, themefile.ShippedPath)) // #nosec G304 -- a fixed test path
	if err != nil {
		t.Fatal(err)
	}
	if string(chart) != string(shipped) {
		t.Errorf("deploy/vca/helm/vca/files/theme.yaml differs from %s; copy the tracked file over it", themefile.ShippedPath)
	}
	if string(chart) != string(themefile.Default()) {
		t.Error("the chart theme file differs from the embedded default")
	}
}

// TestPackagedChartsMatchTheSource keeps the packaged dependencies of the
// umbrella chart equal to the chart directories, so helm renders the
// templates the tree holds. Set VCA_WRITE_HELM=1 to package them again.
func TestPackagedChartsMatchTheSource(t *testing.T) {
	root := repoRoot()
	for _, s := range Catalog() {
		want, err := PackageChart(HelmChartDir(root, s.Name), s.Name)
		if err != nil {
			t.Fatalf("package %s: %v", s.Name, err)
		}
		wantFiles, err := ChartFiles(want)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(HelmChartDir(root, UmbrellaChart), "charts", s.Name+"-"+ChartVersion+".tgz")
		got, err := os.ReadFile(path) // #nosec G304 -- a fixed test path
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		gotFiles, err := ChartFiles(got)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if reflect.DeepEqual(gotFiles, wantFiles) {
			continue
		}
		// A package that already holds the source stays as helm wrote it.
		if os.Getenv("VCA_WRITE_HELM") != "" {
			if err := os.WriteFile(path, want, 0o600); err != nil {
				t.Fatal(err)
			}
			continue
		}
		t.Errorf("%s differs from the chart directory; run VCA_WRITE_HELM=1 go test ./internal/cli/ -run TestPackagedCharts", path)
	}
}

func TestPackageChartIsDeterministicAndNamed(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "templates"), 0o750); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"Chart.yaml": "name: x\n", "templates/a.yaml": "a: 1\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	first, err := PackageChart(dir, "x")
	if err != nil {
		t.Fatal(err)
	}
	second, err := PackageChart(dir, "x")
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Error("two packages of one chart differ")
	}
	files, err := ChartFiles(first)
	if err != nil {
		t.Fatal(err)
	}
	if files["x/Chart.yaml"] != "name: x\n" || files["x/templates/a.yaml"] != "a: 1\n" || len(files) != 2 {
		t.Errorf("files = %v", files)
	}
	if _, err := PackageChart(filepath.Join(dir, "missing"), "x"); err == nil {
		t.Error("a missing chart packaged")
	}
	if _, err := ChartFiles([]byte("not a tgz")); err == nil {
		t.Error("garbage read as a chart")
	}
}
