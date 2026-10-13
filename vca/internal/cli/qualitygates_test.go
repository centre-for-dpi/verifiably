// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// ciWorkflow is the part of a GitHub workflow file that the quality
// gate tests read.
type ciWorkflow struct {
	On          map[string]*ciTrigger `yaml:"on"`
	Env         map[string]string     `yaml:"env"`
	Concurrency struct {
		Group            string `yaml:"group"`
		CancelInProgress bool   `yaml:"cancel-in-progress"`
	} `yaml:"concurrency"`
	Jobs map[string]ciJob `yaml:"jobs"`
}

type ciTrigger struct {
	Branches    []string `yaml:"branches"`
	Paths       []string `yaml:"paths"`
	PathsIgnore []string `yaml:"paths-ignore"`
}

type ciJob struct {
	Needs       []string          `yaml:"needs"`
	If          string            `yaml:"if"`
	Permissions map[string]string `yaml:"permissions"`
	Steps       []ciStep          `yaml:"steps"`
}

type ciStep struct {
	Name  string            `yaml:"name"`
	Uses  string            `yaml:"uses"`
	Run   string            `yaml:"run"`
	Shell string            `yaml:"shell"`
	If    string            `yaml:"if"`
	With  map[string]string `yaml:"with"`
	Env   map[string]string `yaml:"env"`
}

// forkGuard is the condition of quality.yml that skips a job on a pull
// request from a fork, which gets no repository secret.
const forkGuard = "github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository"

func readVCACI(t *testing.T) ciWorkflow {
	t.Helper()
	var w ciWorkflow
	text := readText(t, filepath.Join(repoRoot(), ".github", "workflows", "vca-ci.yml"))
	if err := yaml.Unmarshal([]byte(text), &w); err != nil {
		t.Fatalf("parse vca-ci.yml: %v", err)
	}
	return w
}

func ciJobNamed(t *testing.T, w ciWorkflow, name string) ciJob {
	t.Helper()
	job, ok := w.Jobs[name]
	if !ok {
		t.Fatalf("vca-ci has no %s job", name)
	}
	return job
}

// stepThatRuns returns the first step whose script holds every part.
func stepThatRuns(job ciJob, parts ...string) (ciStep, bool) {
	for _, s := range job.Steps {
		all := s.Run != ""
		for _, p := range parts {
			all = all && strings.Contains(s.Run, p)
		}
		if all {
			return s, true
		}
	}
	return ciStep{}, false
}

// stepThatUses returns the first step that runs the action.
func stepThatUses(job ciJob, action string) (ciStep, bool) {
	for _, s := range job.Steps {
		if strings.HasPrefix(s.Uses, action+"@") {
			return s, true
		}
	}
	return ciStep{}, false
}

// stepsThatUse returns every step that runs the action.
func stepsThatUse(job ciJob, action string) []ciStep {
	var out []ciStep
	for _, s := range job.Steps {
		if strings.HasPrefix(s.Uses, action+"@") {
			out = append(out, s)
		}
	}
	return out
}

// TestVCACIIsSafeAsARequiredCheck keeps the rule of quality.yml: a
// required check that filters itself out by path leaves a pull request
// waiting for a status that never comes.
func TestVCACIIsSafeAsARequiredCheck(t *testing.T) {
	w := readVCACI(t)
	for _, event := range []string{"push", "pull_request"} {
		trigger, ok := w.On[event]
		if !ok {
			t.Errorf("vca-ci does not run on %s", event)
			continue
		}
		if trigger != nil && (len(trigger.Paths) > 0 || len(trigger.PathsIgnore) > 0) {
			t.Errorf("vca-ci filters %s by path; a required check must always run", event)
		}
	}
	if _, ok := w.On["workflow_dispatch"]; !ok {
		t.Error("vca-ci has no workflow_dispatch trigger")
	}
	if w.Concurrency.Group != "vca-ci-${{ github.ref }}" || !w.Concurrency.CancelInProgress {
		t.Errorf("concurrency = %+v, want group vca-ci-${{ github.ref }} with cancel-in-progress", w.Concurrency)
	}
}

// TestVCACITestJobRatchetsTheTotalCoverage checks the test job: the
// test step fails on a failing test, the per package gate stays, and a
// total floor only moves up.
func TestVCACITestJobRatchetsTheTotalCoverage(t *testing.T) {
	job := ciJobNamed(t, readVCACI(t), "test")
	run, ok := stepThatRuns(job, "go test", "-coverprofile=coverage.out")
	if !ok {
		t.Fatal("the test job has no go test step that writes coverage.out")
	}
	if run.Shell != "bash" {
		t.Errorf("the go test step has shell %q, want bash so that pipefail applies", run.Shell)
	}
	for _, want := range []string{"-race", "-covermode=atomic", "-coverpkg=./...", "tee test-output.txt"} {
		if !strings.Contains(run.Run, want) {
			t.Errorf("the go test step does not hold %q", want)
		}
	}
	if _, found := stepThatRuns(job, "./hack/coverage.sh 90"); !found {
		t.Error("the test job no longer runs the per package gate ./hack/coverage.sh 90")
	}
	if _, found := stepThatRuns(job, "GITHUB_STEP_SUMMARY", "go tool cover -func"); !found {
		t.Error("the test job writes no coverage summary to GITHUB_STEP_SUMMARY")
	}
	floor := ""
	for _, s := range job.Steps {
		if v, set := s.Env["COVERAGE_FLOOR"]; set {
			floor = v
			if !strings.Contains(s.Run, "COVERAGE_FLOOR") {
				t.Errorf("the step %q sets COVERAGE_FLOOR but does not read it", s.Name)
			}
		}
	}
	if !regexp.MustCompile(`^\d{1,3}\.\d$`).MatchString(floor) {
		t.Errorf("COVERAGE_FLOOR = %q, want a percent with one decimal", floor)
	}
	upload, ok := stepThatUses(job, "actions/upload-artifact")
	if !ok {
		t.Fatal("the test job uploads no artifact")
	}
	if upload.With["name"] != "vca-coverage" {
		t.Errorf("the coverage artifact is %q, want vca-coverage", upload.With["name"])
	}
	for _, want := range []string{"vca/coverage.out", "vca/test-output.txt"} {
		if !strings.Contains(upload.With["path"], want) {
			t.Errorf("the vca-coverage artifact does not hold %s", want)
		}
	}
}

// TestVCACILintJobWritesACheckstyleReport checks the report that Sonar
// reads: the same golangci-lint as the blocking step, and a report step
// that never fails the job a second time.
func TestVCACILintJobWritesACheckstyleReport(t *testing.T) {
	w := readVCACI(t)
	job := ciJobNamed(t, w, "lint")
	version := w.Env["GOLANGCI_LINT_VERSION"]
	if !regexp.MustCompile(`^v2\.\d+\.\d+$`).MatchString(version) {
		t.Fatalf("GOLANGCI_LINT_VERSION = %q, want an exact v2 release", version)
	}
	lint, ok := stepThatUses(job, "golangci/golangci-lint-action")
	if !ok {
		t.Fatal("the lint job does not run golangci-lint-action")
	}
	if lint.With["version"] != "${{ env.GOLANGCI_LINT_VERSION }}" {
		t.Errorf("the blocking golangci-lint runs %q, want ${{ env.GOLANGCI_LINT_VERSION }}", lint.With["version"])
	}
	report, ok := stepThatRuns(job, "--output.checkstyle.path=golangci-lint-report.xml")
	if !ok {
		t.Fatal("the lint job writes no checkstyle report")
	}
	for _, want := range []string{"--issues-exit-code=0", "GOLANGCI_LINT_VERSION"} {
		if !strings.Contains(report.Run, want) {
			t.Errorf("the report step does not hold %q", want)
		}
	}
	if !strings.Contains(report.If, "!cancelled()") {
		t.Errorf("the report step runs if %q, want it to run after a failed lint too", report.If)
	}
	upload, ok := stepThatUses(job, "actions/upload-artifact")
	if !ok || upload.With["name"] != "golangci-lint-report" || upload.With["path"] != "vca/golangci-lint-report.xml" {
		t.Errorf("the lint job does not upload vca/golangci-lint-report.xml as golangci-lint-report: %+v", upload)
	}
}

// TestVCACIRunsSonarCloud checks the SonarCloud job against quality.yml.
func TestVCACIRunsSonarCloud(t *testing.T) {
	job := ciJobNamed(t, readVCACI(t), "sonarcloud")
	if strings.Join(job.Needs, ",") != "lint,test" {
		t.Errorf("sonarcloud needs %v, want [lint test]", job.Needs)
	}
	if job.If != forkGuard {
		t.Errorf("sonarcloud runs if %q, want the fork guard of quality.yml", job.If)
	}
	checkout, ok := stepThatUses(job, "actions/checkout")
	if !ok || checkout.With["fetch-depth"] != "0" {
		t.Errorf("sonarcloud does not check out the full history: %+v", checkout)
	}
	got := map[string]string{}
	for _, s := range stepsThatUse(job, "actions/download-artifact") {
		got[s.With["name"]] = s.With["path"]
	}
	for _, name := range []string{"vca-coverage", "golangci-lint-report"} {
		if got[name] != "vca" {
			t.Errorf("sonarcloud does not download %s into vca: %v", name, got)
		}
	}
	scan, ok := stepThatUses(job, "SonarSource/sonarqube-scan-action")
	if !ok {
		t.Fatal("sonarcloud does not run sonarqube-scan-action")
	}
	if scan.With["projectBaseDir"] != "vca" || scan.Env["SONAR_TOKEN"] != "${{ secrets.SONAR_TOKEN }}" {
		t.Errorf("the scan step = %+v, want projectBaseDir vca and the SONAR_TOKEN secret", scan)
	}
	gate, ok := stepThatUses(job, "SonarSource/sonarqube-quality-gate-action")
	if !ok {
		t.Fatal("sonarcloud does not wait for the quality gate")
	}
	if gate.With["scanMetadataReportFile"] != "vca/.scannerwork/report-task.txt" || gate.Env["SONAR_TOKEN"] != "${{ secrets.SONAR_TOKEN }}" {
		t.Errorf("the quality gate step = %+v", gate)
	}
}

// TestVCACIRunsGosecToTheSecurityTab checks the SARIF report of gosec.
func TestVCACIRunsGosecToTheSecurityTab(t *testing.T) {
	job := ciJobNamed(t, readVCACI(t), "gosec")
	if job.Permissions["security-events"] != "write" {
		t.Errorf("gosec permissions = %v, want security-events: write", job.Permissions)
	}
	run, ok := stepThatRuns(job, "github.com/securego/gosec/v2/cmd/gosec@")
	if !ok {
		t.Fatal("the gosec job does not run gosec")
	}
	if !regexp.MustCompile(`gosec@v\d+\.\d+\.\d+\s`).MatchString(run.Run) {
		t.Errorf("gosec is not pinned to an exact release: %q", run.Run)
	}
	for _, want := range []string{"-no-fail", "-fmt=sarif", "-out=gosec.sarif", "-exclude=G104", "./..."} {
		if !strings.Contains(run.Run, want) {
			t.Errorf("the gosec step does not hold %q", want)
		}
	}
	upload, ok := stepThatUses(job, "github/codeql-action/upload-sarif")
	if !ok {
		t.Fatal("the gosec job does not upload its SARIF file")
	}
	if upload.With["sarif_file"] != "vca/gosec.sarif" || upload.With["category"] != "gosec-vca" {
		t.Errorf("the SARIF upload = %+v, want vca/gosec.sarif in category gosec-vca", upload.With)
	}
}

// TestVCACIShellchecksEveryScript checks that the blocking shellcheck
// job reads every script under vca/ and deploy/vca/.
func TestVCACIShellchecksEveryScript(t *testing.T) {
	job := ciJobNamed(t, readVCACI(t), "shellcheck")
	run, ok := stepThatRuns(job, "shellcheck -S style")
	if !ok {
		t.Fatal("the shellcheck job does not check at the style level")
	}
	for _, want := range []string{"find . ../deploy/vca", "-name '*.sh'"} {
		if !strings.Contains(run.Run, want) {
			t.Errorf("the shellcheck step does not hold %q", want)
		}
	}
	if strings.Contains(run.Run, "|| true") {
		t.Error("the shellcheck step hides its exit status")
	}
}

// parseProperties reads a Java properties file: key=value lines, a
// backslash at the end of a line continues the value, # and ! start a
// comment.
func parseProperties(t *testing.T, text string) map[string]string {
	t.Helper()
	out := map[string]string{}
	var logical strings.Builder
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if logical.Len() == 0 && (line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!")) {
			continue
		}
		if cont, ok := strings.CutSuffix(line, `\`); ok {
			logical.WriteString(cont)
			continue
		}
		logical.WriteString(line)
		key, value, found := strings.Cut(logical.String(), "=")
		logical.Reset()
		if !found {
			t.Errorf("sonar-project.properties: %q is not key=value", line)
			continue
		}
		out[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	if logical.Len() != 0 {
		t.Error("sonar-project.properties ends inside a continued line")
	}
	return out
}

// TestSonarProjectPropertiesOfVCA checks the SonarCloud project of vca.
func TestSonarProjectPropertiesOfVCA(t *testing.T) {
	props := parseProperties(t, readText(t, filepath.Join("..", "..", "sonar-project.properties")))
	for key, want := range map[string]string{
		"sonar.projectKey":                   "centre-for-dpi_verifiably_vca",
		"sonar.organization":                 "centre-for-dpi",
		"sonar.sources":                      ".",
		"sonar.tests":                        ".",
		"sonar.test.inclusions":              "**/*_test.go",
		"sonar.sourceEncoding":               "UTF-8",
		"sonar.go.coverage.reportPaths":      "coverage.out",
		"sonar.go.tests.reportPaths":         "test-output.txt",
		"sonar.go.golangci-lint.reportPaths": "golangci-lint-report.xml",
	} {
		if props[key] != want {
			t.Errorf("%s = %q, want %q", key, props[key], want)
		}
	}
	for _, key := range []string{"sonar.login", "sonar.token", "sonar.host.url"} {
		if _, ok := props[key]; ok {
			t.Errorf("%s belongs in the workflow, not in the file", key)
		}
	}
	excluded := strings.Split(props["sonar.exclusions"], ",")
	for _, want := range []string{"gen/**", "**/*_test.go", "**/testdata/**", "**/*.min.js", "deploy/**", "dist/**"} {
		if !containsString(excluded, want) {
			t.Errorf("sonar.exclusions %v does not hold %s", excluded, want)
		}
	}
	for _, want := range []string{"gen/**", "**/cmd/**", "ui/example/**"} {
		if !containsString(strings.Split(props["sonar.coverage.exclusions"], ","), want) {
			t.Errorf("sonar.coverage.exclusions does not hold %s, which the coverage floor leaves out", want)
		}
	}
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if strings.TrimSpace(s) == want {
			return true
		}
	}
	return false
}
