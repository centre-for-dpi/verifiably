// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// MinGoMajor and MinGoMinor are the oldest Go version that builds the
// tool from source.
const (
	MinGoMajor = 1
	MinGoMinor = 25
)

// MinDockerMajor is the oldest Docker version the deployment needs.
const MinDockerMajor = 24

// MinComposeMajor is the oldest Docker Compose version. Compose v2 is a
// plugin of the docker command (ADR-008 decision 1).
const MinComposeMajor = 2

// Probe reports the facts of the host. The doctor command takes a Probe,
// so a test checks every rule with no Docker and no network (ADR-004).
type Probe interface {
	// GoVersion returns the Go version, for example go1.25.1.
	GoVersion() (string, error)
	// DockerVersion returns the version of the reachable Docker daemon.
	DockerVersion() (string, error)
	// ComposeVersion returns the version of the compose plugin.
	ComposeVersion() (string, error)
	// FreeMemoryMiB returns the memory the host can still give.
	FreeMemoryMiB() (int, error)
	// PortFree reports whether a host port is free.
	PortFree(port int) (bool, error)
	// LookupHost resolves a host name.
	LookupHost(host string) error
}

// Check is the result of one prerequisite. The doctor command prints one
// line per check.
type Check struct {
	// Name is the prerequisite, for example "docker".
	Name string
	// OK reports whether the host meets it.
	OK bool
	// Detail is what the probe found.
	Detail string
	// Fix tells the operator what to do. It is empty when OK is true.
	Fix string
}

// Line renders one check as one line of output.
func (c Check) Line() string {
	if c.OK {
		return fmt.Sprintf("pass  %-28s %s", c.Name, c.Detail)
	}
	return fmt.Sprintf("FAIL  %-28s %s; fix: %s", c.Name, c.Detail, c.Fix)
}

// DoctorOptions holds everything one doctor run needs.
type DoctorOptions struct {
	// Pairs lists the role and DPG pairs the operator wants to run.
	Pairs []Pair
	// FromSource turns the Go version check on. Only a source build
	// needs Go.
	FromSource bool
	// PublicURL is the value of VCA_PUBLIC_URL. An empty value means a
	// local deployment with no TLS.
	PublicURL string
	// Values returns the .env values of one pair. A nil function uses
	// the port plan defaults.
	Values func(Pair) map[string]string
	// Probe reads the host.
	Probe Probe
	// Out receives the report.
	Out io.Writer
}

// ErrDoctorFailed reports at least one failed check. The command exits
// with status 1 (ADR-008 decision 6).
var ErrDoctorFailed = errors.New("doctor: the host does not meet every prerequisite")

// MemoryFloorMiB returns the memory floor of one pair, in MiB. The
// figure is the table of docs/deploy.md (ADR-008 decision 7).
func MemoryFloorMiB(p Pair) int { return Floor(p).TotalMemoryMiB() }

// SelectionFloorMiB returns the memory floor of a list of pairs. The
// doctor command adds only the pairs the operator selected. The roles
// of one DPG share one DPG stack and one Keycloak, so the DPG figure of
// a stack counts once, at the largest figure of the selected roles.
func SelectionFloorMiB(pairs []Pair) int {
	total := 0
	stacks := map[configv1.Dpg]int{}
	for _, p := range pairs {
		f := Floor(p)
		total += f.VcaMemoryMiB
		if f.DpgMemoryMiB > stacks[p.Dpg] {
			stacks[p.Dpg] = f.DpgMemoryMiB
		}
	}
	for _, m := range stacks {
		total += m
	}
	return total
}

// Selection is one choice of pairs with the flags that name it and its
// memory floor.
type Selection struct {
	// Flags is the command line that selects the pairs.
	Flags string
	// Pairs are the role and DPG pairs of the selection.
	Pairs []Pair
	// MemoryMiB is the memory floor of the selection.
	MemoryMiB int
}

// newSelection builds one selection from its flags and its pairs.
func newSelection(flags string, pairs []Pair) Selection {
	return Selection{Flags: flags, Pairs: pairs, MemoryMiB: SelectionFloorMiB(pairs)}
}

// StackSelections lists one selection per DPG stack, smallest first.
func StackSelections() []Selection {
	var out []Selection
	for _, d := range Dpgs() {
		name := ShortName(d.String())
		out = append(out, newSelection("--all --dpg "+name, PairsForDpg(d)))
	}
	sortSelections(out)
	return out
}

// PairSelections lists one selection per role and DPG pair, smallest
// first.
func PairSelections() []Selection {
	var out []Selection
	for _, p := range AllPairs() {
		flags := fmt.Sprintf("--role %s --dpg %s", ShortName(p.Role.String()), ShortName(p.Dpg.String()))
		out = append(out, newSelection(flags, []Pair{p}))
	}
	sortSelections(out)
	return out
}

// Selections lists every selection the CLI offers, smallest first.
func Selections() []Selection {
	out := append(PairSelections(), StackSelections()...)
	out = append(out, newSelection("--all", AllPairs()))
	sortSelections(out)
	return out
}

// sortSelections orders selections by memory, then by flags, so the
// output never changes between runs.
func sortSelections(list []Selection) {
	sort.Slice(list, func(i, j int) bool {
		if list[i].MemoryMiB != list[j].MemoryMiB {
			return list[i].MemoryMiB < list[j].MemoryMiB
		}
		return list[i].Flags < list[j].Flags
	})
}

// LargestFit returns the largest selection that fits the free memory.
// It reports false when even the smallest one does not fit.
func LargestFit(freeMiB int) (Selection, bool) {
	list := Selections()
	for i := len(list) - 1; i >= 0; i-- {
		if list[i].MemoryMiB <= freeMiB {
			return list[i], true
		}
	}
	return list[0], false
}

// fits returns the largest selection of the list that fits the free
// memory. It falls back to the smallest one.
func fits(list []Selection, freeMiB int) Selection {
	out := list[0]
	for _, s := range list {
		if s.MemoryMiB <= freeMiB {
			out = s
		}
	}
	return out
}

// MemoryHint returns the one line hint that names a smaller selection.
// The doctor command and the setup command print it when the free
// memory is under the floor of the selection (ADR-008 decision 7).
func MemoryHint(freeMiB int) string {
	stack := fits(StackSelections(), freeMiB)
	pair := fits(PairSelections(), freeMiB)
	return fmt.Sprintf("Use %s for one stack (%d MiB) or %s for one pair (%d MiB)",
		stack.Flags, stack.MemoryMiB, pair.Flags, pair.MemoryMiB)
}

// FloorReport renders the memory floor of every selected pair as a
// plain text table with a total.
func FloorReport(pairs []Pair) string {
	var b strings.Builder
	b.WriteString("\nMemory floor of this selection\n")
	for _, p := range pairs {
		fmt.Fprintf(&b, "  %-18s %5d MiB\n", p.Name(), MemoryFloorMiB(p))
	}
	fmt.Fprintf(&b, "  %-18s %5d MiB\n", "total", SelectionFloorMiB(pairs))
	return b.String()
}

// HostPorts returns every host port of one pair, in service name order.
// The .env file of the pair can override a port, so the values map wins.
func HostPorts(p Pair, values map[string]string) []PortAssignment {
	plan := AssignPorts(p, values)
	out := make([]PortAssignment, len(plan))
	copy(out, plan)
	for i, a := range out {
		name := "VCA_HOST_PORT_" + envName(a.Service.Name)
		out[i].Host = portFrom(values, name, a.Host)
	}
	return out
}

// RunChecks reads the host and returns one check per prerequisite. The
// function is pure: every fact comes from the Probe.
func RunChecks(opts DoctorOptions) []Check {
	var out []Check
	if opts.FromSource {
		out = append(out, goCheck(opts.Probe))
	}
	out = append(out, dockerCheck(opts.Probe), composeCheck(opts.Probe), memoryCheck(opts))
	out = append(out, portChecks(opts)...)
	out = append(out, publicURLChecks(opts)...)
	return out
}

// Doctor prints one line per check and reports a failed run. It also
// prints the memory floor of every selected pair.
func Doctor(opts DoctorOptions) error {
	checks := RunChecks(opts)
	failed := 0
	for _, c := range checks {
		anyval.DiscardWrite(fmt.Fprintln(opts.Out, c.Line()))
		if !c.OK {
			failed++
		}
	}
	anyval.DiscardWrite(fmt.Fprint(opts.Out, FloorReport(opts.Pairs)))
	if hint := memoryHintOf(opts.Probe, opts.Pairs); hint != "" {
		anyval.DiscardWrite(fmt.Fprintf(opts.Out, "\n%s\n", hint))
	}
	if failed == 0 {
		anyval.DiscardWrite(fmt.Fprintf(opts.Out, "\n%d checks passed. The host is ready.\n", len(checks)))
		return nil
	}
	anyval.DiscardWrite(fmt.Fprintf(opts.Out, "\n%d of %d checks failed.\n", failed, len(checks)))
	return ErrDoctorFailed
}

// memoryHintOf returns the hint when the free memory is under the floor
// of the selection. It returns an empty string when the selection fits
// or when the probe cannot read the memory.
func memoryHintOf(probe Probe, pairs []Pair) string {
	if len(pairs) == 0 {
		return ""
	}
	free, err := probe.FreeMemoryMiB()
	if err != nil || free >= SelectionFloorMiB(pairs) {
		return ""
	}
	return MemoryHint(free)
}

// Suggest prints the largest selection that fits the free memory of the
// host (ADR-008 decision 7).
func Suggest(opts DoctorOptions) error {
	free, err := opts.Probe.FreeMemoryMiB()
	if err != nil {
		return fmt.Errorf("read the free memory: %w", err)
	}
	anyval.DiscardWrite(fmt.Fprintf(opts.Out, "%d MiB free\n", free))
	best, ok := LargestFit(free)
	if !ok {
		anyval.DiscardWrite(fmt.Fprintf(opts.Out,
			"No selection fits. The smallest is %s, which needs %d MiB.\n", best.Flags, best.MemoryMiB))
		return ErrDoctorFailed
	}
	anyval.DiscardWrite(fmt.Fprintf(opts.Out,
		"The largest selection that fits is %s, which needs %d MiB.\n", best.Flags, best.MemoryMiB))
	anyval.DiscardWrite(fmt.Fprintf(opts.Out, "  vca setup %s\n  vca deploy %s --build\n", best.Flags, best.Flags))
	anyval.DiscardWrite(fmt.Fprint(opts.Out, FloorReport(best.Pairs)))
	return nil
}

// goCheck reports the Go version of a source build.
func goCheck(p Probe) Check {
	fix := fmt.Sprintf("install Go %d.%d or newer from https://go.dev/dl/", MinGoMajor, MinGoMinor)
	got, err := p.GoVersion()
	if err != nil {
		return Check{Name: "go", Detail: "go is not on the path", Fix: fix}
	}
	major, minor, ok := parseGoVersion(got)
	if !ok {
		return Check{Name: "go", Detail: "cannot read the version " + got, Fix: fix}
	}
	if major < MinGoMajor || (major == MinGoMajor && minor < MinGoMinor) {
		return Check{Name: "go", Detail: got + " is too old", Fix: fix}
	}
	return Check{Name: "go", OK: true, Detail: got}
}

// dockerCheck reports a Docker daemon the CLI can reach.
func dockerCheck(p Probe) Check {
	fix := fmt.Sprintf("install Docker %d or newer and start the daemon; see https://docs.docker.com/engine/install/",
		MinDockerMajor)
	got, err := p.DockerVersion()
	if err != nil {
		return Check{Name: "docker", Detail: "no Docker daemon answers", Fix: fix}
	}
	major, ok := parseMajor(got)
	if !ok {
		return Check{Name: "docker", Detail: "cannot read the version " + got, Fix: fix}
	}
	if major < MinDockerMajor {
		return Check{Name: "docker", Detail: got + " is too old", Fix: fix}
	}
	return Check{Name: "docker", OK: true, Detail: got}
}

// composeCheck reports the Docker Compose plugin.
func composeCheck(p Probe) Check {
	fix := "install the Docker Compose v2 plugin; see https://docs.docker.com/compose/install/"
	got, err := p.ComposeVersion()
	if err != nil {
		return Check{Name: "docker compose", Detail: "docker compose version failed", Fix: fix}
	}
	major, ok := parseMajor(got)
	if !ok {
		return Check{Name: "docker compose", Detail: "cannot read the version " + got, Fix: fix}
	}
	if major < MinComposeMajor {
		return Check{Name: "docker compose", Detail: got + " is version 1", Fix: fix}
	}
	return Check{Name: "docker compose", OK: true, Detail: got}
}

// memoryCheck compares the free memory with the floor of the pairs.
func memoryCheck(opts DoctorOptions) Check {
	want := SelectionFloorMiB(opts.Pairs)
	name := "memory"
	fix := fmt.Sprintf("free memory, or use a host with %d MiB for this selection", want)
	got, err := opts.Probe.FreeMemoryMiB()
	if err != nil {
		return Check{Name: name, Detail: "cannot read the free memory", Fix: "check the free memory by hand; " + fix}
	}
	detail := fmt.Sprintf("%d MiB free, %d MiB needed", got, want)
	if got < want {
		return Check{Name: name, Detail: detail, Fix: fix}
	}
	return Check{Name: name, OK: true, Detail: detail}
}

// portChecks reports one check per host port of every pair. The
// Keycloak of a DPG stack is shared by the roles of that stack, so its
// port appears once.
func portChecks(opts DoctorOptions) []Check {
	var out []Check
	seen := map[int]bool{}
	for _, p := range opts.Pairs {
		var values map[string]string
		if opts.Values != nil {
			values = opts.Values(p)
		}
		for _, d := range DpgHostPorts(p) {
			if seen[d.Host] {
				continue
			}
			seen[d.Host] = true
			out = append(out, dpgPortCheck(opts.Probe, d))
		}
		for _, a := range HostPorts(p, values) {
			name := fmt.Sprintf("port %d", a.Host)
			detail := p.Name() + " " + a.Service.Name
			free, err := opts.Probe.PortFree(a.Host)
			switch {
			case err != nil:
				out = append(out, Check{Name: name, Detail: detail + ": cannot test the port",
					Fix: "check the port by hand with: ss -ltnp"})
			case !free:
				out = append(out, Check{Name: name, Detail: detail + ": another program holds it",
					Fix: fmt.Sprintf("stop that program, or set VCA_HOST_PORT_%s in deploy/%s/.env",
						envName(a.Service.Name), p.Name())})
			default:
				out = append(out, Check{Name: name, OK: true, Detail: detail})
			}
		}
	}
	return out
}

// dpgPortCheck reports one host port of a DPG stack container.
func dpgPortCheck(probe Probe, d DpgPort) Check {
	name := fmt.Sprintf("port %d", d.Host)
	free, err := probe.PortFree(d.Host)
	switch {
	case err != nil:
		return Check{Name: name, Detail: d.Container + ": cannot test the port",
			Fix: "check the port by hand with: ss -ltnp"}
	case !free:
		return Check{Name: name, Detail: d.Container + ": another program holds it",
			Fix: "stop that program, or set " + d.Env + " in the environment of docker compose"}
	default:
		return Check{Name: name, OK: true, Detail: d.Container}
	}
}

// publicURLChecks report the name resolution of every public host name
// of the selection and the state of the TLS ports. A local deployment
// needs neither. The hosts come from the .env file of every pair, so a
// base domain gives one check per pair host and one per Keycloak host.
// VCA_PUBLIC_URL in the environment or in the options adds one more.
func publicURLChecks(opts DoctorOptions) []Check {
	raw := strings.TrimSpace(opts.PublicURL)
	hosts, bad := publicHosts(opts)
	if bad != "" {
		return []Check{{Name: "public url", Detail: bad + " is not a URL",
			Fix: "set VCA_PUBLIC_URL to a URL, for example https://issuer.example"}}
	}
	if len(hosts) == 0 {
		if raw == "" {
			return []Check{{Name: "public url", OK: true,
				Detail: "VCA_PUBLIC_URL is not set; the deployment stays local"}}
		}
		return []Check{{Name: "public url", OK: true, Detail: raw + " is local; no TLS is needed"}}
	}
	var out []Check
	for _, host := range hosts {
		out = append(out, resolveCheck(opts.Probe, host))
	}
	for _, port := range []int{80, 443} {
		out = append(out, publicPortCheck(opts.Probe, port))
	}
	return out
}

// publicHosts collects the public host names of the selection, sorted
// and without repeats. Local names are left out. The second value is
// a public URL that does not parse.
func publicHosts(opts DoctorOptions) ([]string, string) {
	seen := map[string]bool{}
	add := func(raw string) string {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return ""
		}
		host := hostOf(raw)
		if host == "" {
			return raw
		}
		if !isLocalHost(host) {
			seen[host] = true
		}
		return ""
	}
	if bad := add(opts.PublicURL); bad != "" {
		return nil, bad
	}
	if opts.Values != nil {
		for _, p := range opts.Pairs {
			values := opts.Values(p)
			add(values["VCA_PUBLIC_URL"])
			add(values["VCA_OIDC_PUBLIC_URL"])
		}
	}
	hosts := make([]string, 0, len(seen))
	for host := range seen {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	return hosts, ""
}

// resolveCheck reports a public host name that does not resolve.
func resolveCheck(p Probe, host string) Check {
	if err := p.LookupHost(host); err != nil {
		return Check{Name: "public url", Detail: host + " does not resolve",
			Fix: "add a DNS A record or AAAA record for " + host + " that points at this host, " +
				"or one wildcard record for the base domain"}
	}
	return Check{Name: "public url", OK: true, Detail: host + " resolves"}
}

// publicPortCheck reports port 80 or port 443 of a public deployment.
// A held port is not a failure: a reverse proxy that other projects
// share holds them on a shared host, and it imports the generated
// Caddyfile. A free port means the operator starts Caddy with the
// generated file. Caddy needs both ports for a Let's Encrypt
// certificate.
func publicPortCheck(p Probe, port int) Check {
	name := fmt.Sprintf("port %d", port)
	free, err := p.PortFree(port)
	switch {
	case err != nil:
		return Check{Name: name, Detail: "cannot test the port", Fix: "check the port by hand with: ss -ltnp"}
	case !free:
		return Check{Name: name, OK: true,
			Detail: "a web server holds it; import deploy/*/Caddyfile into that server"}
	default:
		return Check{Name: name, OK: true, Detail: "free; start Caddy with deploy/<pair>/Caddyfile"}
	}
}

// isLocalHost reports a host name that stays on the machine.
func isLocalHost(host string) bool {
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "::1", "0.0.0.0":
		return true
	default:
		return false
	}
}

// parseGoVersion reads the major and the minor number of go1.25.1.
func parseGoVersion(raw string) (int, int, bool) {
	text := strings.TrimPrefix(strings.TrimSpace(raw), "go")
	parts := strings.Split(text, ".")
	if len(parts) < 2 {
		return 0, 0, false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, false
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, false
	}
	return major, minor, true
}

// parseMajor reads the first number of a version string such as
// "Docker Compose version v2.29.0" or "27.1.1".
func parseMajor(raw string) (int, bool) {
	digits := ""
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c >= '0' && c <= '9' {
			digits += string(c)
			continue
		}
		if digits != "" {
			break
		}
	}
	if digits == "" {
		return 0, false
	}
	n, err := strconv.Atoi(digits)
	if err != nil {
		return 0, false
	}
	return n, true
}

// parseMemAvailable reads MemAvailable out of the text of /proc/meminfo
// and returns it in MiB.
func parseMemAvailable(text string) (int, error) {
	for _, line := range strings.Split(text, "\n") {
		if !strings.HasPrefix(line, "MemAvailable:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			break
		}
		kb, err := strconv.Atoi(fields[1])
		if err != nil {
			break
		}
		return kb / 1024, nil
	}
	return 0, errors.New("meminfo: no MemAvailable line")
}

// SystemProbe reads the real host. Every side effect is one field, so a
// test replaces it (ADR-004).
type SystemProbe struct {
	// Ctx bounds the docker calls.
	Ctx context.Context
	// Output runs one command and returns its output.
	Output func(ctx context.Context, name string, args []string) (string, error)
	// Listen opens a TCP port to test that it is free.
	Listen func(network, address string) (net.Listener, error)
	// Lookup resolves a host name.
	Lookup func(host string) ([]string, error)
	// ReadFile reads /proc/meminfo.
	ReadFile func(name string) ([]byte, error)
	// GoVersionString is the Go version of this binary.
	GoVersionString string
}

// NewSystemProbe returns a Probe that reads the real host.
func NewSystemProbe(ctx context.Context) *SystemProbe {
	return &SystemProbe{
		Ctx:             ctx,
		Output:          commandOutput,
		Listen:          net.Listen,
		Lookup:          net.LookupHost,
		ReadFile:        os.ReadFile,
		GoVersionString: runtime.Version(),
	}
}

// commandOutput runs one command and returns its standard output.
func commandOutput(ctx context.Context, name string, args []string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).Output() // #nosec G204 -- the CLI builds the arguments
	return string(out), err
}

// GoVersion returns the Go version of this binary.
func (p *SystemProbe) GoVersion() (string, error) {
	if p.GoVersionString == "" {
		return "", errors.New("no Go version")
	}
	return p.GoVersionString, nil
}

// DockerVersion asks the Docker daemon for its version. The call fails
// when no daemon answers.
func (p *SystemProbe) DockerVersion() (string, error) {
	out, err := p.Output(p.Ctx, "docker", []string{"version", "--format", "{{.Server.Version}}"})
	if err != nil {
		return "", err
	}
	text := strings.TrimSpace(out)
	if text == "" {
		return "", errors.New("docker version: no answer")
	}
	return text, nil
}

// ComposeVersion asks the compose plugin for its version.
func (p *SystemProbe) ComposeVersion() (string, error) {
	out, err := p.Output(p.Ctx, "docker", []string{"compose", "version", "--short"})
	if err != nil {
		return "", err
	}
	text := strings.TrimSpace(out)
	if text == "" {
		return "", errors.New("docker compose version: no answer")
	}
	return text, nil
}

// FreeMemoryMiB reads the memory the host can still give.
func (p *SystemProbe) FreeMemoryMiB() (int, error) {
	data, err := p.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	return parseMemAvailable(string(data))
}

// PortFree reports whether the CLI can listen on a host port. A listen
// error means another program holds the port, which is an answer and not
// a failure of the check.
func (p *SystemProbe) PortFree(port int) (bool, error) {
	listener, listenErr := p.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	free := listenErr == nil
	if !free {
		return false, nil
	}
	return true, listener.Close()
}

// LookupHost resolves a host name.
func (p *SystemProbe) LookupHost(host string) error {
	_, err := p.Lookup(host)
	return err
}

// PublicURLOf returns the public URL of a run. The process environment
// wins, then the .env file of the first pair that holds a value.
func PublicURLOf(root string, pairs []Pair, getenv func(string) string) (string, error) {
	if getenv != nil {
		if v := strings.TrimSpace(getenv("VCA_PUBLIC_URL")); v != "" {
			return v, nil
		}
	}
	for _, p := range pairs {
		values, err := ReadExisting(filepath.Join(root, "deploy"), p)
		if err != nil {
			return "", err
		}
		if v := strings.TrimSpace(values["VCA_PUBLIC_URL"]); v != "" {
			return v, nil
		}
	}
	return "", nil
}
