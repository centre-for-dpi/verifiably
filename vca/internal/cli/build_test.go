// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// buildDoc is the part of the build override file the tests read.
type buildDoc struct {
	Name     string                         `yaml:"name"`
	Services map[string]buildComposeService `yaml:"services"`
}

type buildComposeService struct {
	Build struct {
		Context    string `yaml:"context"`
		Dockerfile string `yaml:"dockerfile"`
	} `yaml:"build"`
}

// TestComposeBuildFileIsCurrent keeps the committed override file equal
// to the renderer. Set VCA_WRITE_COMPOSE=1 to write the file again.
func TestComposeBuildFileIsCurrent(t *testing.T) {
	path := filepath.Join(repoRoot(), ComposeBuildFile)
	want := RenderComposeBuild()
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
		t.Fatalf("read %s: %v", ComposeBuildFile, err)
	}
	if string(got) != want {
		t.Errorf("%s is not current; run VCA_WRITE_COMPOSE=1 go test ./internal/cli/", ComposeBuildFile)
	}
}

func TestRenderComposeBuildHasEveryService(t *testing.T) {
	var doc buildDoc
	if err := yaml.Unmarshal([]byte(RenderComposeBuild()), &doc); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if doc.Name != ComposeProject {
		t.Errorf("project name = %q", doc.Name)
	}
	var main composeDoc
	if err := yaml.Unmarshal([]byte(RenderCompose()), &main); err != nil {
		t.Fatalf("Unmarshal the compose file: %v", err)
	}
	if len(doc.Services) != len(main.Services) {
		t.Fatalf("got %d services, want %d", len(doc.Services), len(main.Services))
	}
	for name := range main.Services {
		got, ok := doc.Services[name]
		if !ok {
			t.Fatalf("the override file has no service %s", name)
		}
		if got.Build.Context != BuildContext {
			t.Errorf("%s context = %q", name, got.Build.Context)
		}
		if !strings.HasPrefix(got.Build.Dockerfile, "services/") ||
			!strings.HasSuffix(got.Build.Dockerfile, "/Dockerfile") {
			t.Errorf("%s dockerfile = %q", name, got.Build.Dockerfile)
		}
	}
}

func TestEveryBuildDockerfileExists(t *testing.T) {
	for _, s := range Catalog() {
		path := filepath.Join(repoRoot(), "vca", DockerfilePath(s))
		if _, err := os.Stat(path); err != nil {
			t.Errorf("%s: %v", s.Name, err)
		}
	}
}

func TestBuildServicesAreUnique(t *testing.T) {
	pairs := PairsForDpg(configv1.Dpg_DPG_WALTID)
	list := BuildServices(pairs)
	seen := map[string]bool{}
	for _, s := range list {
		if seen[s.Name] {
			t.Errorf("service %s is in the list twice", s.Name)
		}
		seen[s.Name] = true
	}
	if len(list) == 0 {
		t.Fatal("no service to build")
	}
	for _, s := range list {
		if s.Dpg != 0 && s.Name != "dpg-adapter-waltid" {
			t.Errorf("the list holds the adapter of another DPG: %s", s.Name)
		}
	}
}

func TestBuildArgsNameTheDockerfileAndTheTag(t *testing.T) {
	s := Catalog()[0]
	args := BuildArgs("/repo", s)
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, filepath.Join("/repo", "vca", DockerfilePath(s))) {
		t.Errorf("args = %v", args)
	}
	if !strings.Contains(joined, LocalImage(s)) {
		t.Errorf("args = %v", args)
	}
	if !strings.HasSuffix(joined, filepath.Join("/repo", "vca")) {
		t.Errorf("the context is not last: %v", args)
	}
}

func TestBuildImagesBuildsAndSetsTheVersion(t *testing.T) {
	root := t.TempDir()
	pair := Pair{Role: commonv1.Role_ROLE_ISSUER, Dpg: configv1.Dpg_DPG_WALTID}
	dir := filepath.Join(root, "deploy", pair.Name())
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, EnvFileName), []byte("VCA_ROLE=issuer\n"))
	rec := &recorder{}
	var out strings.Builder
	err := BuildImages(context.Background(), ImageOptions{
		Root: root, Pairs: []Pair{pair}, Out: &out, Run: rec.run,
	})
	if err != nil {
		t.Fatalf("BuildImages: %v", err)
	}
	want := len(ServicesFor(pair)) + len(DeploymentServices())
	if len(rec.calls) != want {
		t.Errorf("got %d builds, want %d", len(rec.calls), want)
	}
	data, err := os.ReadFile(filepath.Clean(filepath.Join(dir, EnvFileName)))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), VersionEnv+"="+LocalTag) {
		t.Errorf(".env = %q", data)
	}
	// The landing .env, when present, gets the version too; a missing
	// one is not an error.
	if strings.Contains(out.String(), "in "+LandingEnvPath(root)) {
		t.Errorf("a missing landing file was named:\n%s", out.String())
	}
	landing := LandingEnvPath(root)
	if mkErr := os.MkdirAll(filepath.Dir(landing), 0o750); mkErr != nil {
		t.Fatal(mkErr)
	}
	writeFile(t, landing, []byte("VCA_LANDING_LISTEN=:8080\n"))
	out.Reset()
	if buildErr := BuildImages(context.Background(), ImageOptions{Root: root, Pairs: []Pair{pair}, Out: &out, Run: rec.run}); buildErr != nil {
		t.Fatalf("BuildImages: %v", buildErr)
	}
	data, err = os.ReadFile(filepath.Clean(landing))
	if err != nil || !strings.Contains(string(data), VersionEnv+"="+LocalTag) {
		t.Errorf("landing .env = %q, %v", data, err)
	}
	out.Reset()
	if err := BuildImages(context.Background(), ImageOptions{Root: root, Pairs: []Pair{pair}, Out: &out, DryRun: true}); err != nil {
		t.Fatalf("BuildImages dry run: %v", err)
	}
	if !strings.Contains(out.String(), "# set "+VersionEnv+"="+LocalTag+" in "+landing) {
		t.Errorf("dry run output:\n%s", out.String())
	}
	// A directory in place of the file is an error.
	if err := os.Remove(landing); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(landing, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := BuildImages(context.Background(), ImageOptions{Root: root, Pairs: []Pair{pair}, Out: &out, Run: rec.run}); err == nil {
		t.Error("an unreadable landing file passed")
	}
}

func TestBuildImagesDryRunStartsNothing(t *testing.T) {
	var out strings.Builder
	pair := Pair{Role: commonv1.Role_ROLE_ADMIN, Dpg: configv1.Dpg_DPG_WALTID}
	err := BuildImages(context.Background(), ImageOptions{
		Root: "/repo", Pairs: []Pair{pair}, DryRun: true, Out: &out,
	})
	if err != nil {
		t.Fatalf("BuildImages: %v", err)
	}
	if !strings.Contains(out.String(), "docker build") {
		t.Errorf("out = %q", out.String())
	}
	if !strings.Contains(out.String(), "set "+VersionEnv) {
		t.Errorf("out = %q", out.String())
	}
}

func TestBuildImagesFailures(t *testing.T) {
	if err := BuildImages(context.Background(), ImageOptions{Out: &strings.Builder{}}); !errors.Is(err, ErrNoPairs) {
		t.Errorf("err = %v", err)
	}
	pair := Pair{Role: commonv1.Role_ROLE_ADMIN, Dpg: configv1.Dpg_DPG_WALTID}
	var out strings.Builder
	err := BuildImages(context.Background(), ImageOptions{
		Root: "/repo", Pairs: []Pair{pair}, Out: &out,
	})
	if err == nil {
		t.Error("a run with no runner must fail")
	}
	boom := errors.New("boom")
	rec := &recorder{fail: boom}
	err = BuildImages(context.Background(), ImageOptions{
		Root: "/repo", Pairs: []Pair{pair}, Out: &out, Run: rec.run,
	})
	if !errors.Is(err, boom) {
		t.Errorf("err = %v", err)
	}
	// The .env file of the pair is missing, so the version write fails.
	rec = &recorder{}
	err = BuildImages(context.Background(), ImageOptions{
		Root: t.TempDir(), Pairs: []Pair{pair}, Out: &out, Run: rec.run,
	})
	if err == nil {
		t.Error("a missing .env file must fail")
	}
}

func TestApplyEnvLineReplacesAndAdds(t *testing.T) {
	got := ApplyEnvLine("A=1\nVCA_VERSION=latest\nB=2\n", "VCA_VERSION", "local")
	if !strings.Contains(got, "VCA_VERSION=local") || strings.Contains(got, "latest") {
		t.Errorf("got %q", got)
	}
	got = ApplyEnvLine("A=1", "VCA_VERSION", "local")
	if !strings.HasSuffix(got, "VCA_VERSION=local\n") {
		t.Errorf("got %q", got)
	}
	got = ApplyEnvLine("export VCA_VERSION=x\n", "VCA_VERSION", "local")
	if !strings.Contains(got, "VCA_VERSION=local") {
		t.Errorf("got %q", got)
	}
}

func TestSetEnvValueFails(t *testing.T) {
	if err := SetEnvValue(filepath.Join(t.TempDir(), "none"), "A", "b"); err == nil {
		t.Error("a missing file must fail")
	}
}

func TestDeployBuildUsesBothFiles(t *testing.T) {
	root := deployRoot(t, issuerPair())
	rec := &recorder{}
	status, out, errOut := run(t, Environment{Root: root, Run: rec.run},
		"deploy", "--role", "issuer", "--dpg", "waltid", "--build")
	if status != 0 {
		t.Fatalf("status = %d, err = %s", status, errOut)
	}
	joined := strings.Join(rec.calls[0], " ")
	for _, want := range []string{ComposePath(root), ComposeBuildPath(root), "--build"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the command has no %q: %s", want, joined)
		}
	}
	if !strings.Contains(out, ComposeBuildPath(root)) {
		t.Errorf("out = %s", out)
	}
}

func TestDeployBuildDryRunPrintsTheOverrideFile(t *testing.T) {
	root := deployRoot(t, issuerPair())
	status, out, errOut := run(t, Environment{Root: root},
		"deploy", "--role", "issuer", "--dpg", "waltid", "--build", "--dry-run")
	if status != 0 {
		t.Fatalf("status = %d, err = %s", status, errOut)
	}
	if !strings.Contains(out, "dockerfile: services/issuance/Dockerfile") {
		t.Errorf("out = %s", out)
	}
	if !strings.Contains(out, "--build") {
		t.Errorf("out = %s", out)
	}
}

func TestImagesBuildCommand(t *testing.T) {
	root := deployRoot(t, issuerPair())
	rec := &recorder{}
	status, out, errOut := run(t, Environment{Root: root, Run: rec.run},
		"images", "build", "--role", "issuer", "--dpg", "waltid")
	if status != 0 {
		t.Fatalf("status = %d, err = %s", status, errOut)
	}
	// The landing runs in every profile, so it is built too.
	if len(rec.calls) != len(ServicesFor(issuerPair()))+len(DeploymentServices()) {
		t.Errorf("calls = %v", rec.calls)
	}
	if !strings.Contains(out, LocalTag) {
		t.Errorf("out = %s", out)
	}
}

func TestImagesBuildCommandNeedsAPair(t *testing.T) {
	status, _, errOut := run(t, Environment{Root: t.TempDir()}, "images", "build")
	if status == 0 || !strings.Contains(errOut, "--role") {
		t.Errorf("status = %d, err = %s", status, errOut)
	}
}
