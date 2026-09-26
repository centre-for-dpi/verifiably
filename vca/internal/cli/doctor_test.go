// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
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
	// One port per service of the pair, the DPG stack ports, and the
	// landing once.
	want := len(ServicesFor(issuerPair())) + len(DpgHostPorts(issuerPair())) + 1
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
		// Inji Verify, its database, and the nginx of the presentation
		// definition add 672 MiB to the Inji issuer (P6-I4b).
		"issuer-waltid": 2912, "issuer-inji": 4096, "holder-waltid": 2336,
		"verifier-waltid": 2720, "admin-waltid": 704, "admin-inji": 704,
		// Mimoto, its database and Redis, and Inji Web add 1024 MiB (P6-I7d).
		"holder-inji": 3872,
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

// TestDoctorAcceptsAHeldTLSPort is the shared host case: a reverse
// proxy of another project holds 80 and 443 and imports the Caddyfile.
func TestDoctorAcceptsAHeldTLSPort(t *testing.T) {
	probe := healthyProbe()
	probe.busyPorts = map[int]bool{80: true, 443: true}
	checks := publicURLChecks(DoctorOptions{PublicURL: "https://issuer.example", Probe: probe})
	if len(failed(checks)) != 0 {
		t.Errorf("checks = %+v", checks)
	}
	held := 0
	for _, c := range checks {
		if strings.Contains(c.Detail, "import deploy/*/Caddyfile") {
			held++
		}
	}
	if held != 2 {
		t.Errorf("checks = %+v", checks)
	}
	probe = healthyProbe()
	probe.portErr = errors.New("no socket")
	checks = publicURLChecks(DoctorOptions{PublicURL: "https://issuer.example", Probe: probe})
	if len(failed(checks)) != 2 {
		t.Errorf("checks = %+v", checks)
	}
}

// TestDoctorResolvesEveryPairHost reads the host of every pair and of
// the Keycloak out of the .env values, once each.
func TestDoctorResolvesEveryPairHost(t *testing.T) {
	probe := healthyProbe()
	pairs := PairsForDpg(dpgWaltid(t))
	values := func(p Pair) map[string]string {
		return map[string]string{
			"VCA_PUBLIC_URL":      "https://" + p.Name() + ".labs.example",
			"VCA_OIDC_PUBLIC_URL": "https://waltid-keycloak.labs.example",
		}
	}
	checks := publicURLChecks(DoctorOptions{Pairs: pairs, Values: values, Probe: probe})
	if len(failed(checks)) != 0 {
		t.Errorf("checks = %+v", checks)
	}
	want := []string{
		"admin-waltid.labs.example", "holder-waltid.labs.example", "issuer-waltid.labs.example",
		"verifier-waltid.labs.example", "waltid-keycloak.labs.example",
	}
	if strings.Join(probe.lookedUp, " ") != strings.Join(want, " ") {
		t.Errorf("looked up %v, want %v", probe.lookedUp, want)
	}
	local := func(Pair) map[string]string {
		return map[string]string{"VCA_PUBLIC_URL": "http://localhost:18002", "VCA_OIDC_PUBLIC_URL": "http://localhost:17010"}
	}
	checks = publicURLChecks(DoctorOptions{Pairs: pairs, Values: local, Probe: healthyProbe()})
	if len(checks) != 1 || !checks[0].OK {
		t.Errorf("local values must give one passing check: %+v", checks)
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

func TestSelectionFloorAddsOnlyTheSelectedPairs(t *testing.T) {
	one := SelectionFloorMiB([]Pair{issuerPair()})
	if one != MemoryFloorMiB(issuerPair()) {
		t.Errorf("one pair = %d MiB", one)
	}
	stack := SelectionFloorMiB(PairsForDpg(dpgWaltid(t)))
	if stack <= one {
		t.Errorf("one stack = %d MiB, one pair = %d MiB", stack, one)
	}
	if all := SelectionFloorMiB(AllPairs()); all <= stack {
		t.Errorf("every pair = %d MiB, one stack = %d MiB", all, stack)
	}
}

func TestSelectionsGrowInOrder(t *testing.T) {
	list := Selections()
	if len(list) != len(AllPairs())+len(Dpgs())+1 {
		t.Fatalf("got %d selections", len(list))
	}
	for i := 1; i < len(list); i++ {
		if list[i].MemoryMiB < list[i-1].MemoryMiB {
			t.Errorf("selection %d is smaller than %d", i, i-1)
		}
	}
	if list[len(list)-1].Flags != "--all" {
		t.Errorf("the largest selection = %q", list[len(list)-1].Flags)
	}
}

func TestLargestFit(t *testing.T) {
	all := SelectionFloorMiB(AllPairs())
	got, ok := LargestFit(all)
	if !ok || got.Flags != "--all" {
		t.Errorf("got %+v, ok %v", got, ok)
	}
	smallest := Selections()[0]
	if _, fit := LargestFit(smallest.MemoryMiB - 1); fit {
		t.Error("a host with no memory got a selection")
	}
	got, ok = LargestFit(smallest.MemoryMiB)
	if !ok || got.MemoryMiB != smallest.MemoryMiB {
		t.Errorf("got %+v", got)
	}
}

// TestMemoryHintNamesASmallerSelection is the laptop of ADR-008
// decision 7. Six GB is under the floor of every pair together.
func TestMemoryHintNamesASmallerSelection(t *testing.T) {
	hint := MemoryHint(6 * 1024)
	for _, want := range []string{"--all --dpg ", "for one stack (", "--role ", "for one pair ("} {
		if !strings.Contains(hint, want) {
			t.Errorf("the hint has no %q:\n%s", want, hint)
		}
	}
	tiny := MemoryHint(0)
	if !strings.Contains(tiny, "--all --dpg ") {
		t.Errorf("hint = %s", tiny)
	}
}

func TestDoctorPrintsTheFloorOfEverySelectedPair(t *testing.T) {
	pairs := PairsForDpg(dpgWaltid(t))
	var out strings.Builder
	probe := healthyProbe()
	probe.memory = 64000
	if err := Doctor(DoctorOptions{Pairs: pairs, Probe: probe, Out: &out}); err != nil {
		t.Fatalf("Doctor: %v", err)
	}
	text := out.String()
	for _, p := range pairs {
		if !strings.Contains(text, p.Name()) {
			t.Errorf("the report misses %s:\n%s", p.Name(), text)
		}
	}
	if !strings.Contains(text, "Memory floor of this selection") {
		t.Errorf("the report has no floor table:\n%s", text)
	}
	if strings.Contains(text, "for one stack (") {
		t.Errorf("a host with free memory got the hint:\n%s", text)
	}
}

func TestDoctorPrintsTheHintOnASmallHost(t *testing.T) {
	var out strings.Builder
	probe := healthyProbe()
	probe.memory = 6 * 1024
	err := Doctor(DoctorOptions{Pairs: AllPairs(), Probe: probe, Out: &out})
	if !errors.Is(err, ErrDoctorFailed) {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(out.String(), MemoryHint(6*1024)) {
		t.Errorf("the report has no hint:\n%s", out.String())
	}
}

func TestSuggestPrintsTheLargestSelectionThatFits(t *testing.T) {
	var out strings.Builder
	probe := healthyProbe()
	probe.memory = 6 * 1024
	if err := Suggest(DoctorOptions{Probe: probe, Out: &out}); err != nil {
		t.Fatalf("Suggest: %v", err)
	}
	best, ok := LargestFit(6 * 1024)
	if !ok {
		t.Fatal("no selection fits 6 GB")
	}
	for _, want := range []string{best.Flags, "6144 MiB free", "Memory floor of this selection"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the output has no %q:\n%s", want, out.String())
		}
	}
}

func TestSuggestReportsAHostWithNoRoom(t *testing.T) {
	var out strings.Builder
	probe := healthyProbe()
	probe.memory = 1
	if err := Suggest(DoctorOptions{Probe: probe, Out: &out}); !errors.Is(err, ErrDoctorFailed) {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(out.String(), "No selection fits") {
		t.Errorf("out = %s", out.String())
	}
	probe.memoryErr = errors.New("no meminfo")
	if err := Suggest(DoctorOptions{Probe: probe, Out: &out}); err == nil {
		t.Fatal("a failed probe passed")
	}
}

func TestMemoryHintOfIsSilentWithoutPairsOrMemory(t *testing.T) {
	probe := healthyProbe()
	if got := memoryHintOf(probe, nil); got != "" {
		t.Errorf("got %q", got)
	}
	probe.memoryErr = errors.New("no meminfo")
	if got := memoryHintOf(probe, AllPairs()); got != "" {
		t.Errorf("got %q", got)
	}
}

// TestMemoryCheckCountsAStackOnce keeps the check line and the floor
// table of the same report in step.
func TestMemoryCheckCountsAStackOnce(t *testing.T) {
	pairs := PairsForDpg(dpgWaltid(t))
	probe := healthyProbe()
	probe.memory = SelectionFloorMiB(pairs)
	got := memoryCheck(DoctorOptions{Pairs: pairs, Probe: probe})
	if !got.OK || !strings.Contains(got.Detail, fmt.Sprintf("%d MiB needed", SelectionFloorMiB(pairs))) {
		t.Errorf("check = %+v", got)
	}
}

// TestDoctorChecksTheLandingPort adds the one host port of the landing to
// the port checks, once, whatever the selection (ADR-033 decision 2).
func TestDoctorChecksTheLandingPort(t *testing.T) {
	probe := healthyProbe()
	probe.busyPorts = map[int]bool{LandingHostPort: true}
	pairs := PairsForDpg(dpgWaltid(t))
	checks := portChecks(DoctorOptions{Pairs: pairs, Probe: probe})
	count := 0
	for _, c := range checks {
		if c.Name != fmt.Sprintf("port %d", LandingHostPort) {
			continue
		}
		count++
		if c.OK || !strings.Contains(c.Detail, "vca-landing") || !strings.Contains(c.Fix, "VCA_HOST_PORT_LANDING") || !strings.Contains(c.Fix, "deploy/landing/.env") {
			t.Errorf("landing check = %+v", c)
		}
	}
	if count != 1 {
		t.Errorf("the landing port appears %d times, want once", count)
	}
	// An override of the landing file moves the check.
	checks = portChecks(DoctorOptions{Pairs: pairs, Probe: probe, Landing: map[string]string{"VCA_HOST_PORT_LANDING": "17999"}})
	found := false
	for _, c := range checks {
		if c.Name == "port 17999" && c.OK && strings.Contains(c.Detail, "vca-landing") {
			found = true
		}
		if c.Name == fmt.Sprintf("port %d", LandingHostPort) {
			t.Error("the default landing port is still checked")
		}
	}
	if !found {
		t.Errorf("no check of the overridden landing port: %+v", checks)
	}
	// A probe error is reported, not hidden.
	probe.portErr = errors.New("no permission")
	for _, c := range portChecks(DoctorOptions{Pairs: pairs[:1], Probe: probe}) {
		if strings.Contains(c.Detail, "vca-landing") && (c.OK || !strings.Contains(c.Detail, "cannot test")) {
			t.Errorf("landing check with a probe error = %+v", c)
		}
	}
}

// TestFloorTableNamesTheLanding keeps the deploy document honest: the
// landing adds one service to a deployment, once, whatever the pairs.
func TestFloorTableNamesTheLanding(t *testing.T) {
	if LandingMemoryMiB != perServiceMemoryMiB {
		t.Errorf("landing floor = %d MiB, want %d", LandingMemoryMiB, perServiceMemoryMiB)
	}
	note := FloorNote()
	if !strings.Contains(note, "landing") || !strings.Contains(note, "96 MiB") || !strings.Contains(note, "once") {
		t.Errorf("floor note:\n%s", note)
	}
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "deploy.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(doc), note) {
		t.Errorf("docs/deploy.md does not hold the floor note:\n%s", note)
	}
}

// TestDoctorChecksTheInjiWebPort: the Inji holder pair runs Inji Web on
// host port 17085, where the browser of the holder claims (P6-I7d).
// vca doctor reports a held port with the variable that moves it, and
// counts the memory of Mimoto and Inji Web in the floor.
func TestDoctorChecksTheInjiWebPort(t *testing.T) {
	holder := Pair{Role: commonv1.Role_ROLE_HOLDER, Dpg: configv1.Dpg_DPG_INJI}
	probe := healthyProbe()
	probe.busyPorts = map[int]bool{17085: true}
	var out strings.Builder
	err := Doctor(DoctorOptions{Pairs: []Pair{holder}, Probe: probe, Out: &out})
	if !errors.Is(err, ErrDoctorFailed) {
		t.Fatalf("err = %v", err)
	}
	for _, want := range []string{"port 17085", "inji-web: another program holds it", "INJI_WEB_HOST_PORT", "holder-inji", "3872 MiB"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the report lacks %q:\n%s", want, out.String())
		}
	}
}
