// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// recorder records the commands a lifecycle run makes.
type recorder struct {
	calls [][]string
	fail  error
}

func (r *recorder) run(_ context.Context, name string, args []string) error {
	r.calls = append(r.calls, append([]string{name}, args...))
	return r.fail
}

// deployRoot builds a root with a .env file for every named pair.
func deployRoot(t *testing.T, pairs ...Pair) string {
	t.Helper()
	root := t.TempDir()
	for _, p := range pairs {
		dir := filepath.Join(root, "deploy", p.Name())
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, EnvFileName), []byte("VCA_ROLE=x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestComposeArgs(t *testing.T) {
	got := ComposeArgs("/repo", issuerPair(), []string{"up", "-d"})
	want := strings.Join([]string{
		"compose", "--project-name", "vca",
		"--file", filepath.Join("/repo", "deploy", "vca", "compose.yaml"),
		"--env-file", filepath.Join("/repo", "deploy", "issuer-waltid", ".env"),
		"--profile", "issuer-waltid", "up", "-d",
	}, " ")
	if strings.Join(got, " ") != want {
		t.Errorf("got %q\nwant %q", strings.Join(got, " "), want)
	}
}

func TestDeployRunsComposeUp(t *testing.T) {
	root := deployRoot(t, issuerPair())
	rec := &recorder{}
	var out bytes.Buffer
	err := Deploy(context.Background(), DeployOptions{
		Root: root, Pairs: []Pair{issuerPair()}, Out: &out, Run: rec.run,
	})
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if len(rec.calls) != 1 {
		t.Fatalf("got %d commands", len(rec.calls))
	}
	line := strings.Join(rec.calls[0], " ")
	for _, want := range []string{"docker compose", "--profile issuer-waltid", "up -d"} {
		if !strings.Contains(line, want) {
			t.Errorf("the command has no %q: %s", want, line)
		}
	}
	if !strings.Contains(out.String(), "docker compose") {
		t.Error("the run printed no command")
	}
}

func TestDeployAllRunsEveryPairOfTheDpg(t *testing.T) {
	pairs := PairsForDpg(dpgWaltid(t))
	root := deployRoot(t, pairs...)
	rec := &recorder{}
	err := Deploy(context.Background(), DeployOptions{
		Root: root, Pairs: pairs, Out: &bytes.Buffer{}, Run: rec.run,
	})
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if len(rec.calls) != len(pairs) {
		t.Fatalf("got %d commands, want %d", len(rec.calls), len(pairs))
	}
	for i, p := range pairs {
		if !strings.Contains(strings.Join(rec.calls[i], " "), "--profile "+p.Name()) {
			t.Errorf("command %d does not name %s", i, p.Name())
		}
	}
}

func TestStatusAndDown(t *testing.T) {
	root := deployRoot(t, issuerPair())
	opts := func(rec *recorder) DeployOptions {
		return DeployOptions{Root: root, Pairs: []Pair{issuerPair()}, Out: &bytes.Buffer{}, Run: rec.run}
	}
	rec := &recorder{}
	if err := Status(context.Background(), opts(rec)); err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !strings.HasSuffix(strings.Join(rec.calls[0], " "), "ps") {
		t.Errorf("status ran %v", rec.calls[0])
	}
	rec = &recorder{}
	if err := Down(context.Background(), opts(rec)); err != nil {
		t.Fatalf("Down: %v", err)
	}
	line := strings.Join(rec.calls[0], " ")
	if !strings.Contains(line, "down --remove-orphans") {
		t.Errorf("down ran %v", rec.calls[0])
	}
	if strings.Contains(line, "--volumes") {
		t.Error("down removed the volumes")
	}
}

func TestDryRunPrintsTheRenderedCompose(t *testing.T) {
	var out bytes.Buffer
	err := Deploy(context.Background(), DeployOptions{
		Root: "/repo", Pairs: []Pair{issuerPair()}, DryRun: true, Out: &out,
	})
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	text := out.String()
	if !strings.Contains(text, "name: vca") || !strings.Contains(text, "issuer-waltid-issuance:") {
		t.Errorf("the rendered compose file is missing:\n%s", text[:200])
	}
	if !strings.Contains(text, "docker compose --project-name vca") {
		t.Error("the command line is missing")
	}
	// A dry run touches no file and needs no .env file.
	if strings.Contains(text, "is missing; run vca setup") {
		t.Error("a dry run checked for the env file")
	}
}

func TestDryRunReportsAWriteFailure(t *testing.T) {
	err := Deploy(context.Background(), DeployOptions{
		Root: "/repo", Pairs: []Pair{issuerPair()}, DryRun: true, Out: failWriter{},
	})
	if err == nil {
		t.Fatal("a failing writer passed")
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("no room") }

func TestLifecycleNeedsAPair(t *testing.T) {
	if err := Deploy(context.Background(), DeployOptions{Out: &bytes.Buffer{}}); !errors.Is(err, ErrNoPairs) {
		t.Fatalf("got %v, want ErrNoPairs", err)
	}
}

func TestLifecycleNeedsARunner(t *testing.T) {
	root := deployRoot(t, issuerPair())
	err := Deploy(context.Background(), DeployOptions{
		Root: root, Pairs: []Pair{issuerPair()}, Out: &bytes.Buffer{},
	})
	if err == nil {
		t.Fatal("a run with no runner passed")
	}
}

func TestDeployNeedsTheEnvFile(t *testing.T) {
	rec := &recorder{}
	err := Deploy(context.Background(), DeployOptions{
		Root: t.TempDir(), Pairs: []Pair{issuerPair()}, Out: &bytes.Buffer{}, Run: rec.run,
	})
	if err == nil {
		t.Fatal("a missing .env file passed")
	}
	if !strings.Contains(err.Error(), "vca setup --role issuer --dpg waltid") {
		t.Errorf("the error does not say what to do: %v", err)
	}
	if len(rec.calls) != 0 {
		t.Error("the run started a container anyway")
	}
}

func TestDeployReportsACommandFailure(t *testing.T) {
	root := deployRoot(t, issuerPair())
	rec := &recorder{fail: errors.New("exit status 1")}
	err := Deploy(context.Background(), DeployOptions{
		Root: root, Pairs: []Pair{issuerPair()}, Out: &bytes.Buffer{}, Run: rec.run,
	})
	if err == nil || !strings.Contains(err.Error(), "issuer-waltid") {
		t.Fatalf("got %v", err)
	}
}

func TestExecRunner(t *testing.T) {
	var out, errOut bytes.Buffer
	run := ExecRunner(&out, &errOut)
	if err := run(context.Background(), "true", nil); err != nil {
		t.Fatalf("run true: %v", err)
	}
	if err := run(context.Background(), "false", nil); err == nil {
		t.Fatal("run false passed")
	}
}

func TestEnvPathAndComposePath(t *testing.T) {
	if ComposePath("/r") != filepath.Join("/r", "deploy", "vca", "compose.yaml") {
		t.Errorf("ComposePath = %q", ComposePath("/r"))
	}
	if EnvPath("/r", issuerPair()) != filepath.Join("/r", "deploy", "issuer-waltid", ".env") {
		t.Errorf("EnvPath = %q", EnvPath("/r", issuerPair()))
	}
}

func TestCheckEnvFileReportsAnUnreadablePath(t *testing.T) {
	root := t.TempDir()
	// A file where a directory must be makes Stat fail with a non
	// "not exist" error.
	if err := os.MkdirAll(filepath.Join(root, "deploy"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "deploy", "issuer-waltid"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkEnvFile(root, issuerPair()); err == nil {
		t.Fatal("a file in place of the directory passed")
	}
}
