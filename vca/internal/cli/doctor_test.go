// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeProbe answers the doctor checks from fields, so a test needs no
// Docker and no network.
type fakeProbe struct {
	goVersion   string
	goErr       error
	docker      string
	dockerErr   error
	compose     string
	composeErr  error
	memory      int
	memoryErr   error
	busyPorts   map[int]bool
	portErr     error
	lookupErr   error
	lookedUp    []string
	testedPorts []int
}

func (p *fakeProbe) GoVersion() (string, error)      { return p.goVersion, p.goErr }
func (p *fakeProbe) DockerVersion() (string, error)  { return p.docker, p.dockerErr }
func (p *fakeProbe) ComposeVersion() (string, error) { return p.compose, p.composeErr }
func (p *fakeProbe) FreeMemoryMiB() (int, error)     { return p.memory, p.memoryErr }

func (p *fakeProbe) PortFree(port int) (bool, error) {
	p.testedPorts = append(p.testedPorts, port)
	if p.portErr != nil {
		return false, p.portErr
	}
	return !p.busyPorts[port], nil
}

func (p *fakeProbe) LookupHost(host string) error {
	p.lookedUp = append(p.lookedUp, host)
	return p.lookupErr
}

// healthyProbe answers every check with a pass.
func healthyProbe() *fakeProbe {
	return &fakeProbe{
		goVersion: "go1.25.1", docker: "27.1.1", compose: "v2.29.0", memory: 16000,
	}
}

// failed returns the checks that did not pass.
func failed(checks []Check) []Check {
	var out []Check
	for _, c := range checks {
		if !c.OK {
			out = append(out, c)
		}
	}
	return out
}

func TestDoctorPassesOnAHealthyHost(t *testing.T) {
	probe := healthyProbe()
	var out strings.Builder
	err := Doctor(DoctorOptions{
		Pairs: []Pair{issuerPair()}, FromSource: true, Probe: probe, Out: &out,
	})
	if err != nil {
		t.Fatalf("Doctor: %v", err)
	}
	if strings.Contains(out.String(), "FAIL") {
		t.Errorf("out = %s", out.String())
	}
	if !strings.Contains(out.String(), "The host is ready") {
		t.Errorf("out = %s", out.String())
	}
	want := len(ServicesFor(issuerPair())) + len(DpgHostPorts(issuerPair()))
	if len(probe.testedPorts) != want {
		t.Errorf("tested %v, want %d ports", probe.testedPorts, want)
	}
}

func TestDoctorSkipsGoWhenTheOperatorInstallsABinary(t *testing.T) {
	probe := healthyProbe()
	probe.goErr = errors.New("no go")
	checks := RunChecks(DoctorOptions{Pairs: []Pair{issuerPair()}, Probe: probe})
	for _, c := range checks {
		if c.Name == "go" {
			t.Error("the run checks Go without --from-source")
		}
	}
}

func TestDoctorReportsTheGoVersion(t *testing.T) {
	cases := []struct {
		name    string
		version string
		err     error
		ok      bool
	}{
		{name: "new", version: "go1.25.1", ok: true},
		{name: "newer", version: "go1.26.0", ok: true},
		{name: "old", version: "go1.24.5"},
		{name: "older major", version: "go0.9"},
		{name: "not a version", version: "tip"},
		{name: "missing", err: errors.New("no go")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := goCheck(&fakeProbe{goVersion: c.version, goErr: c.err})
			if got.OK != c.ok {
				t.Errorf("OK = %v, detail %q", got.OK, got.Detail)
			}
			if !got.OK && !strings.Contains(got.Fix, "go.dev") {
				t.Errorf("fix = %q", got.Fix)
			}
		})
	}
}

func TestDoctorReportsDockerAndCompose(t *testing.T) {
	probe := healthyProbe()
	probe.dockerErr = errors.New("daemon")
	probe.composeErr = errors.New("plugin")
	checks := RunChecks(DoctorOptions{Pairs: []Pair{issuerPair()}, Probe: probe})
	names := map[string]Check{}
	for _, c := range checks {
		names[c.Name] = c
	}
	if names["docker"].OK || !strings.Contains(names["docker"].Fix, "daemon") {
		t.Errorf("docker = %+v", names["docker"])
	}
	if names["docker compose"].OK || !strings.Contains(names["docker compose"].Fix, "Compose v2") {
		t.Errorf("compose = %+v", names["docker compose"])
	}
	if got := dockerCheck(&fakeProbe{docker: "20.10.1"}); got.OK {
		t.Error("Docker 20 is too old")
	}
	if got := dockerCheck(&fakeProbe{docker: "none"}); got.OK {
		t.Error("a version with no number must fail")
	}
	if got := composeCheck(&fakeProbe{compose: "1.29.2"}); got.OK {
		t.Error("compose v1 must fail")
	}
	if got := composeCheck(&fakeProbe{compose: "none"}); got.OK {
		t.Error("a version with no number must fail")
	}
}

func TestDoctorComparesTheMemoryFloor(t *testing.T) {
	pair := issuerPair()
	want := MemoryFloorMiB(pair)
	if want != 2912 {
		t.Errorf("the floor of issuer-waltid = %d MiB, want 2912", want)
	}
	probe := healthyProbe()
	probe.memory = want - 1
	got := memoryCheck(DoctorOptions{Pairs: []Pair{pair}, Probe: probe})
	if got.OK || !strings.Contains(got.Fix, "free memory") {
		t.Errorf("check = %+v", got)
	}
	probe.memoryErr = errors.New("no meminfo")
	got = memoryCheck(DoctorOptions{Pairs: []Pair{pair}, Probe: probe})
	if got.OK || !strings.Contains(got.Detail, "cannot read") {
		t.Errorf("check = %+v", got)
	}
}

func TestMemoryFloorOfEveryPairMatchesTheDocument(t *testing.T) {
	want := map[string]int{
		"issuer-waltid": 2912, "issuer-inji": 3424, "holder-waltid": 2336,
		"verifier-waltid": 2624, "admin-waltid": 704, "admin-inji": 704,
	}
	for _, p := range AllPairs() {
		if got, ok := want[p.Name()]; ok && MemoryFloorMiB(p) != got {
			t.Errorf("%s = %d MiB, want %d", p.Name(), MemoryFloorMiB(p), got)
		}
	}
}

func TestDoctorReportsABusyHostPort(t *testing.T) {
	pair := issuerPair()
	busy := HostPorts(pair, nil)[0]
	probe := healthyProbe()
	probe.busyPorts = map[int]bool{busy.Host: true}
	var out strings.Builder
	err := Doctor(DoctorOptions{Pairs: []Pair{pair}, Probe: probe, Out: &out})
	if !errors.Is(err, ErrDoctorFailed) {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(out.String(), "VCA_HOST_PORT_") {
		t.Errorf("out = %s", out.String())
	}
	if !strings.Contains(out.String(), "1 of") {
		t.Errorf("out = %s", out.String())
	}
}

func TestDoctorReportsAPortItCannotTest(t *testing.T) {
	probe := healthyProbe()
	probe.portErr = errors.New("no socket")
	checks := portChecks(DoctorOptions{Pairs: []Pair{issuerPair()}, Probe: probe})
	if len(failed(checks)) != len(checks) {
		t.Errorf("checks = %+v", checks)
	}
}

func TestDoctorUsesThePortOfTheEnvFile(t *testing.T) {
	pair := issuerPair()
	name := "VCA_HOST_PORT_" + envName(ServicesFor(pair)[0].Name)
	values := map[string]string{name: "19999"}
	probe := healthyProbe()
	checks := portChecks(DoctorOptions{
		Pairs: []Pair{pair}, Probe: probe,
		Values: func(Pair) map[string]string { return values },
	})
	found := false
	for _, c := range checks {
		if strings.Contains(c.Name, "19999") {
			found = true
		}
	}
	if !found {
		t.Errorf("checks = %+v", checks)
	}
}

func TestDoctorChecksThePublicURL(t *testing.T) {
	probe := healthyProbe()
	checks := publicURLChecks(DoctorOptions{PublicURL: "https://issuer.example", Probe: probe})
	if len(failed(checks)) != 0 {
		t.Errorf("checks = %+v", checks)
	}
	if len(probe.lookedUp) != 1 || probe.lookedUp[0] != "issuer.example" {
		t.Errorf("looked up %v", probe.lookedUp)
	}
	if len(probe.testedPorts) != 2 {
		t.Errorf("tested %v", probe.testedPorts)
	}
}

func TestDoctorReportsAPublicURLThatDoesNotResolve(t *testing.T) {
	probe := healthyProbe()
	probe.lookupErr = errors.New("no such host")
	checks := publicURLChecks(DoctorOptions{PublicURL: "https://issuer.example", Probe: probe})
	if !strings.Contains(checks[0].Fix, "DNS") {
		t.Errorf("check = %+v", checks[0])
	}
}

func TestDoctorReportsBusyTLSPorts(t *testing.T) {
	probe := healthyProbe()
	probe.busyPorts = map[int]bool{80: true, 443: true}
	checks := publicURLChecks(DoctorOptions{PublicURL: "https://issuer.example", Probe: probe})
	if len(failed(checks)) != 2 {
		t.Errorf("checks = %+v", checks)
	}
	probe = healthyProbe()
	probe.portErr = errors.New("no socket")
	checks = publicURLChecks(DoctorOptions{PublicURL: "https://issuer.example", Probe: probe})
	if len(failed(checks)) != 2 {
		t.Errorf("checks = %+v", checks)
	}
}

func TestDoctorSkipsTLSForALocalURL(t *testing.T) {
	probe := healthyProbe()
	checks := publicURLChecks(DoctorOptions{PublicURL: "http://localhost:18000", Probe: probe})
	if len(checks) != 1 || !checks[0].OK {
		t.Errorf("checks = %+v", checks)
	}
	if len(probe.testedPorts) != 0 {
		t.Errorf("tested %v", probe.testedPorts)
	}
	checks = publicURLChecks(DoctorOptions{Probe: probe})
	if len(checks) != 1 || !checks[0].OK {
		t.Errorf("checks = %+v", checks)
	}
	checks = publicURLChecks(DoctorOptions{PublicURL: "issuer.example", Probe: probe})
	if checks[0].OK {
		t.Errorf("a value that is not a URL must fail: %+v", checks[0])
	}
}

func TestCheckLine(t *testing.T) {
	pass := Check{Name: "docker", OK: true, Detail: "27.1.1"}
	if !strings.HasPrefix(pass.Line(), "pass") {
		t.Errorf("line = %q", pass.Line())
	}
	fail := Check{Name: "docker", Detail: "none", Fix: "install it"}
	if !strings.HasPrefix(fail.Line(), "FAIL") || !strings.Contains(fail.Line(), "install it") {
		t.Errorf("line = %q", fail.Line())
	}
}

func TestParseMemAvailable(t *testing.T) {
	got, err := parseMemAvailable("MemTotal:  16000 kB\nMemAvailable:  2048000 kB\n")
	if err != nil || got != 2000 {
		t.Errorf("got %d, %v", got, err)
	}
	for _, text := range []string{"MemTotal: 1 kB\n", "MemAvailable:\n", "MemAvailable: many kB\n"} {
		if _, err := parseMemAvailable(text); err == nil {
			t.Errorf("%q must fail", text)
		}
	}
}

func TestSystemProbeReadsTheHost(t *testing.T) {
	probe := &SystemProbe{
		Ctx: context.Background(),
		Output: func(_ context.Context, name string, args []string) (string, error) {
			if name != "docker" {
				return "", errors.New("wrong command")
			}
			if args[0] == "version" {
				return "27.1.1\n", nil
			}
			return "v2.29.0\n", nil
		},
		Listen:          net.Listen,
		Lookup:          net.LookupHost,
		ReadFile:        func(string) ([]byte, error) { return []byte("MemAvailable: 1024 kB\n"), nil },
		GoVersionString: "go1.25.1",
	}
	if got, err := probe.GoVersion(); err != nil || got != "go1.25.1" {
		t.Errorf("GoVersion = %q, %v", got, err)
	}
	if got, err := probe.DockerVersion(); err != nil || got != "27.1.1" {
		t.Errorf("DockerVersion = %q, %v", got, err)
	}
	if got, err := probe.ComposeVersion(); err != nil || got != "v2.29.0" {
		t.Errorf("ComposeVersion = %q, %v", got, err)
	}
	if got, err := probe.FreeMemoryMiB(); err != nil || got != 1 {
		t.Errorf("FreeMemoryMiB = %d, %v", got, err)
	}
	if err := probe.LookupHost("localhost"); err != nil {
		t.Errorf("LookupHost: %v", err)
	}
	free, err := probe.PortFree(0)
	if err != nil || !free {
		t.Errorf("PortFree = %v, %v", free, err)
	}
}

func TestSystemProbeFailures(t *testing.T) {
	boom := errors.New("boom")
	probe := &SystemProbe{
		Ctx:      context.Background(),
		Output:   func(context.Context, string, []string) (string, error) { return "", boom },
		ReadFile: func(string) ([]byte, error) { return nil, boom },
		Listen:   func(string, string) (net.Listener, error) { return nil, boom },
		Lookup:   func(string) ([]string, error) { return nil, boom },
	}
	if _, err := probe.GoVersion(); err == nil {
		t.Error("an empty Go version must fail")
	}
	if _, err := probe.DockerVersion(); !errors.Is(err, boom) {
		t.Errorf("err = %v", err)
	}
	if _, err := probe.ComposeVersion(); !errors.Is(err, boom) {
		t.Errorf("err = %v", err)
	}
	if _, err := probe.FreeMemoryMiB(); !errors.Is(err, boom) {
		t.Errorf("err = %v", err)
	}
	if err := probe.LookupHost("nowhere.invalid"); !errors.Is(err, boom) {
		t.Errorf("err = %v", err)
	}
	free, err := probe.PortFree(80)
	if err != nil || free {
		t.Errorf("PortFree = %v, %v", free, err)
	}
	empty := &SystemProbe{
		Ctx:    context.Background(),
		Output: func(context.Context, string, []string) (string, error) { return " \n", nil },
	}
	if _, err := empty.DockerVersion(); err == nil {
		t.Error("an empty answer must fail")
	}
	if _, err := empty.ComposeVersion(); err == nil {
		t.Error("an empty answer must fail")
	}
}

func TestNewSystemProbeFillsEveryField(t *testing.T) {
	probe := NewSystemProbe(context.Background())
	if probe.Output == nil || probe.Listen == nil || probe.Lookup == nil ||
		probe.ReadFile == nil || probe.GoVersionString == "" {
		t.Errorf("probe = %+v", probe)
	}
	if _, err := commandOutput(context.Background(), "true", nil); err != nil {
		t.Errorf("commandOutput: %v", err)
	}
}

func TestPublicURLOfReadsTheEnvironmentThenTheFile(t *testing.T) {
	root := t.TempDir()
	pair := issuerPair()
	dir := filepath.Join(root, "deploy", pair.Name())
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, EnvFileName), []byte("VCA_PUBLIC_URL=https://file.example\n"))
	got, err := PublicURLOf(root, []Pair{pair}, func(string) string { return "https://env.example" })
	if err != nil || got != "https://env.example" {
		t.Errorf("got %q, %v", got, err)
	}
	got, err = PublicURLOf(root, []Pair{pair}, nil)
	if err != nil || got != "https://file.example" {
		t.Errorf("got %q, %v", got, err)
	}
	got, err = PublicURLOf(t.TempDir(), []Pair{pair}, func(string) string { return "" })
	if err != nil || got != "" {
		t.Errorf("got %q, %v", got, err)
	}
	writeFile(t, filepath.Join(dir, EnvFileName), []byte("not a dotenv line\n"))
	if _, err := PublicURLOf(root, []Pair{pair}, nil); err == nil {
		t.Error("a broken .env file must fail")
	}
}

func TestDoctorCommandReadsTheRealHost(t *testing.T) {
	root := markedRoot(t)
	status, out, _ := run(t, Environment{
		Root:   root,
		Getenv: func(string) string { return "" },
	}, "doctor", "--role", "issuer", "--dpg", "waltid")
	// The host may or may not run Docker, so the test checks the rule:
	// a failed check gives status 1 and a FAIL line.
	if (status == 1) != strings.Contains(out, "FAIL") {
		t.Errorf("status = %d, out = %s", status, out)
	}
	for _, want := range []string{"docker", "docker compose", "memory", "public url"} {
		if !strings.Contains(out, want) {
			t.Errorf("out has no %q: %s", want, out)
		}
	}
}

func TestDoctorCommandNeedsAPair(t *testing.T) {
	status, _, errOut := run(t, Environment{Root: t.TempDir()}, "doctor")
	if status == 0 || !strings.Contains(errOut, "--role") {
		t.Errorf("status = %d, err = %s", status, errOut)
	}
}

func TestPortsCommandPrintsThePlan(t *testing.T) {
	root := t.TempDir()
	status, out, errOut := run(t, Environment{Root: root}, "ports", "--role", "issuer", "--dpg", "waltid")
	if status != 0 {
		t.Fatalf("status = %d, err = %s", status, errOut)
	}
	if !strings.Contains(out, "issuer-waltid") {
		t.Errorf("out = %s", out)
	}
	for _, s := range ServicesFor(issuerPair()) {
		if !strings.Contains(out, s.Name) {
			t.Errorf("out has no %s", s.Name)
		}
	}
}

func TestPortsCommandFailsOnABrokenEnvFile(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "deploy", issuerPair().Name())
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, EnvFileName), []byte("not a dotenv line\n"))
	status, _, errOut := run(t, Environment{Root: root}, "ports", "--role", "issuer", "--dpg", "waltid")
	if status == 0 || errOut == "" {
		t.Errorf("status = %d, err = %s", status, errOut)
	}
}
