// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

// Package walkthrough_test runs the services of a deployment as
// processes and walks a person through them (P7-05). The CLI writes
// the settings of each pair, as vca setup does. The test then points
// the addresses of the compose network at the loopback address, puts a
// proxy that follows the Caddyfile routes in front of each pair, and
// replaces the DPG and the identity provider with test doubles.
package walkthrough_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/cli"
	"github.com/centre-for-dpi/vc-adapters/internal/peerauth"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow/oidctest"
)

// moduleRoot is the directory of go.mod, seen from this package.
const moduleRoot = "../.."

// publicURLEnv names the public address of a pair in its .env.
const publicURLEnv = "VCA_PUBLIC_URL"

// binaries builds the commands of the services once per machine. The
// directory sits in the user cache, so a later run relinks nothing
// that did not change. A file lock keeps two test processes from
// writing it at once.
func binaries(t *testing.T, names []string) string {
	t.Helper()
	cache, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(cache, "vca", "walkthrough-bin")
	if merr := os.MkdirAll(dir, 0o750); merr != nil {
		t.Fatal(merr)
	}
	lock, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_CREATE|os.O_RDWR, 0o600) // #nosec G304 -- a path under the user cache
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cerr := lock.Close(); cerr != nil {
			t.Error(cerr)
		}
	}()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil { // #nosec G115 -- a file descriptor fits an int
		t.Fatal(err)
	}
	args := []string{"build", "-ldflags=-s -w", "-o", dir + string(os.PathSeparator)}
	for _, n := range names {
		args = append(args, "./services/"+n)
	}
	cmd := exec.Command("go", args...) // #nosec G204 -- the arguments are service names of the catalogue
	cmd.Dir = moduleRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return dir
}

// freePort returns a free TCP port of the loopback address. It picks
// below the ephemeral range of Linux and macOS, so an outgoing
// connection of another process cannot take the port before the
// service binds it.
func freePort(t *testing.T) int {
	t.Helper()
	portsMu.Lock()
	defer portsMu.Unlock()
	for range 1000 {
		n, err := rand.Int(rand.Reader, big.NewInt(portSpan))
		if err != nil {
			t.Fatal(err)
		}
		port := portBase + int(n.Int64())
		if portsTaken[port] {
			continue
		}
		l, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
		if err != nil {
			continue
		}
		if err := l.Close(); err != nil {
			t.Fatal(err)
		}
		portsTaken[port] = true
		return port
	}
	t.Fatal("no free port")
	return 0
}

// The ports the test hands out.
const (
	portBase = 20000
	portSpan = 12000
)

var (
	portsMu    sync.Mutex
	portsTaken = map[int]bool{}
)

// logBuffer keeps the output of one process for the failure report.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// deployment is one running deployment: the pairs, the landing, the
// identity providers, and the DPG doubles.
type deployment struct {
	t   *testing.T
	bin string
	// pairs holds the running pairs by name.
	pairs map[string]*runningPair
	// landing is the public URL of the landing.
	landing string
	// dpgURLs maps a DPG address of the stack file onto its double.
	dpgURLs map[string]string
	// providers holds the identity provider of each role.
	providers map[commonv1.Role]*oidctest.Provider
	// logs holds the output of each process by name.
	logs map[string]*logBuffer
	// extra holds settings per pair that the test adds.
	extra map[string]map[string]string
	// exited closes when the process behind a ready address ends.
	exited map[string]chan struct{}
	// answers holds the answers of the operator to the questions of
	// vca setup.
	answers map[string]string
	// authority is the peer authority of the deployment, as vca setup
	// keeps it in deploy/peer (ADR-075).
	authority []byte
}

// runningPair is one pair of the deployment.
type runningPair struct {
	pair cli.Pair
	// public is the address a browser opens.
	public string
	// proxy is the port of the proxy of the pair.
	proxy int
	// ports maps each service onto its loopback port.
	ports map[string]int
	// env is the settings of the pair after the rewrite.
	env map[string]string
	// identities holds the identity file of each service by service
	// name (ADR-075).
	identities map[string]map[string]string
}

// newDeployment prepares a deployment of the pairs. dpgURLs maps each
// DPG address of the stack file onto its double.
func newDeployment(t *testing.T, pairs []cli.Pair, dpgURLs map[string]string) *deployment {
	t.Helper()
	authority, err := peerauth.NewAuthority(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authorityPEM, err := authority.PEM()
	if err != nil {
		t.Fatal(err)
	}
	d := &deployment{
		t: t, pairs: map[string]*runningPair{}, dpgURLs: dpgURLs,
		providers: map[commonv1.Role]*oidctest.Provider{}, logs: map[string]*logBuffer{},
		extra: map[string]map[string]string{}, exited: map[string]chan struct{}{}, answers: map[string]string{},
		authority: authorityPEM,
	}
	names := []string{cli.LandingService}
	for _, p := range pairs {
		rp := &runningPair{pair: p, proxy: freePort(t), ports: map[string]int{}}
		rp.public = "http://localhost:" + strconv.Itoa(rp.proxy)
		for _, a := range cli.HostPorts(p, nil) {
			rp.ports[a.Service.Name] = freePort(t)
			if !slices.Contains(names, a.Service.Name) {
				names = append(names, a.Service.Name)
			}
		}
		d.pairs[p.Name()] = rp
		if _, ok := d.providers[p.Role]; !ok {
			op := oidctest.New()
			t.Cleanup(op.Close)
			d.providers[p.Role] = op
		}
	}
	sort.Strings(names)
	d.bin = binaries(t, names)
	d.landing = "http://localhost:" + strconv.Itoa(freePort(t))
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		keys := make([]string, 0, len(d.logs))
		for k := range d.logs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			t.Logf("---- %s\n%s", k, tail(d.logs[k].String(), 40))
		}
	})
	return d
}

// tail returns the last n lines of s.
func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// set adds a setting to the .env of a pair, as an operator edits it.
func (d *deployment) set(pair, key, value string) {
	if d.extra[pair] == nil {
		d.extra[pair] = map[string]string{}
	}
	d.extra[pair][key] = value
}

// replacer rewrites the compose addresses of the running pairs, the
// default public addresses, the landing, and the DPG addresses.
func (d *deployment) replacer(t *testing.T) *strings.Replacer {
	t.Helper()
	var pairs []string
	for name, rp := range d.pairs {
		for _, a := range cli.HostPorts(rp.pair, nil) {
			pairs = append(pairs,
				"http://"+name+"-"+a.Service.Name+":"+strconv.Itoa(a.Listen), "http://127.0.0.1:"+strconv.Itoa(rp.ports[a.Service.Name]))
		}
		plan := d.plan(t, rp.pair)
		pairs = append(pairs, plan[publicURLEnv], rp.public)
	}
	pairs = append(pairs, cli.LandingPublicURL(""), d.landing)
	for from, to := range d.dpgURLs {
		pairs = append(pairs, from, to)
	}
	return strings.NewReplacer(pairs...)
}

// plan returns the .env of a pair as vca setup writes it.
func (d *deployment) plan(t *testing.T, p cli.Pair) map[string]string {
	t.Helper()
	values, _ := d.planWithPeers(t, p)
	return values
}

// planWithPeers returns the .env of a pair and the identity file of each
// service, keyed by the path vca setup writes it to (ADR-075). The
// landing file sits under its directory, beside the pair files.
func (d *deployment) planWithPeers(t *testing.T, p cli.Pair) (map[string]string, map[string]map[string]string) {
	t.Helper()
	flags := map[string]string{
		"VCA_OIDC_DISCOVERY_URL": d.providers[p.Role].DiscoveryURL(),
	}
	for k, v := range d.answers {
		flags[k] = v
	}
	plan, err := cli.BuildPlan(cli.SetupRequest{Pair: p, Flags: flags, Random: rand.Reader, PeerAuthority: d.authority})
	if err != nil {
		t.Fatal(err)
	}
	parse := func(data []byte) map[string]string {
		values, err := cli.ParseDotenv(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		return values
	}
	var env map[string]string
	peers := map[string]map[string]string{}
	for _, f := range plan.Files {
		switch {
		case f.Name == cli.EnvFileName:
			env = parse(f.Data)
		case strings.HasPrefix(f.Name, cli.PeerDir+string(filepath.Separator)) && strings.HasSuffix(f.Name, cli.EnvFileName):
			peers[f.Name] = parse(f.Data)
		}
	}
	for _, f := range plan.Shared {
		if f.Name == filepath.Join(cli.LandingDir, cli.PeerFile(cli.LandingService)) {
			peers[f.Name] = parse(f.Data)
		}
	}
	if env == nil {
		t.Fatalf("the plan of %s writes no %s", p.Name(), cli.EnvFileName)
	}
	return env, peers
}

// peers keeps the running pairs of a peer list.
func (d *deployment) peers(t *testing.T, value string) string {
	t.Helper()
	list, err := topology.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	var out []topology.Peer
	for _, p := range list {
		if _, ok := d.pairs[p.Pair]; ok {
			out = append(out, p)
		}
	}
	return topology.Format(out)
}

// start writes the settings of every pair and of the landing, starts
// every process, and waits until each one is ready.
func (d *deployment) start(ctx context.Context) {
	t := d.t
	t.Helper()
	rewrite := d.replacer(t)
	names := make([]string, 0, len(d.pairs))
	for name := range d.pairs {
		names = append(names, name)
	}
	sort.Strings(names)
	var ready []string
	var landingPeer map[string]string
	for _, name := range names {
		rp := d.pairs[name]
		env := map[string]string{}
		values, identities := d.planWithPeers(t, rp.pair)
		for k, v := range values {
			env[k] = rewrite.Replace(v)
		}
		landingPeer = identities[filepath.Join(cli.LandingDir, cli.PeerFile(cli.LandingService))]
		env[topology.Env] = d.peers(t, env[topology.Env])
		for k, v := range d.extra[name] {
			env[k] = v
		}
		rp.env = env
		rp.identities = map[string]map[string]string{}
		op := d.providers[rp.pair.Role]
		op.ClientID, op.ClientSecret = env["VCA_OIDC_CLIENT_ID"], env["VCA_OIDC_CLIENT_SECRET"]
		for _, a := range cli.HostPorts(rp.pair, nil) {
			addr := "127.0.0.1:" + strconv.Itoa(rp.ports[a.Service.Name])
			// Each process reads its own identity file too, as compose
			// gives each container its own (ADR-075).
			identity := identities[cli.PeerFile(a.Service.Name)]
			if identity == nil {
				t.Fatalf("setup wrote no identity for %s/%s", name, a.Service.Name)
			}
			rp.identities[a.Service.Name] = identity
			d.run(ctx, name+"/"+a.Service.Name, a.Service.Name, a.Service.ListenEnv, addr, merged(env, identity))
			ready = append(ready, "http://"+addr+"/readyz")
		}
		d.proxy(rp)
	}
	landing := cli.LandingValues("", nil, "")
	env := map[string]string{}
	for k, v := range landing {
		env[k] = rewrite.Replace(v)
	}
	env[topology.Env] = d.peers(t, env[topology.Env])
	u, err := url.Parse(d.landing)
	if err != nil {
		t.Fatal(err)
	}
	addr := "127.0.0.1:" + u.Port()
	listenEnv := ""
	for _, s := range cli.DeploymentServices() {
		if s.Name == cli.LandingService {
			listenEnv = s.ListenEnv
		}
	}
	if landingPeer == nil {
		t.Fatal("setup wrote no identity for the landing")
	}
	d.run(ctx, cli.LandingService, cli.LandingService, listenEnv, addr, merged(env, landingPeer))
	ready = append(ready, "http://"+addr+"/readyz")
	d.waitReady(ctx, ready)
}

// merged returns the values of a and b in one map. b wins.
func merged(a, b map[string]string) map[string]string {
	out := make(map[string]string, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

// run starts one service process with its own data directory.
func (d *deployment) run(ctx context.Context, name, service, listenEnv, addr string, pairEnv map[string]string) {
	t := d.t
	data := t.TempDir()
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + data, "TMPDIR=" + data}
	for k, v := range pairEnv {
		if v == "/data" || strings.HasPrefix(v, "/data/") {
			v = data + strings.TrimPrefix(v, "/data")
		}
		env = append(env, k+"="+v)
	}
	theme, err := filepath.Abs(filepath.Join(moduleRoot, "..", "deploy", "vca", "theme.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	env = append(env, listenEnv+"="+addr, "VCA_THEME_FILE="+theme)
	cmd := exec.CommandContext(ctx, filepath.Join(d.bin, service)) // #nosec G204 -- a service of the catalogue
	cmd.Env = env
	cmd.Dir = data
	logs := &logBuffer{}
	d.logs[name] = logs
	cmd.Stdout, cmd.Stderr = logs, logs
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 3 * time.Second
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", name, err)
	}
	done := make(chan struct{})
	d.exited["http://"+addr+"/readyz"] = done
	go func() {
		defer close(done)
		if err := cmd.Wait(); err != nil && ctx.Err() == nil {
			anyval.DiscardWrite(fmt.Fprintf(logs, "exit: %v\n", err))
		}
	}()
	t.Cleanup(func() {
		if err := cmd.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
			t.Log(err)
		}
		<-done
	})
}

// waitReady waits until every address answers 200.
func (d *deployment) waitReady(ctx context.Context, urls []string) {
	t := d.t
	deadline := time.Now().Add(20 * time.Second)
	for _, u := range urls {
		for {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
			if err != nil {
				t.Fatal(err)
			}
			res, err := http.DefaultClient.Do(req)
			if err == nil {
				ok := res.StatusCode == http.StatusOK
				if _, cerr := io.Copy(io.Discard, res.Body); cerr != nil {
					t.Log(cerr)
				}
				if cerr := res.Body.Close(); cerr != nil {
					t.Log(cerr)
				}
				if ok {
					break
				}
			}
			select {
			case <-d.exited[u]:
				t.Fatalf("the process behind %s ended", u)
			default:
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s is not ready: %v", u, err)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
}

// proxy serves the public address of a pair as its Caddyfile does: the
// routes of the catalogue, a 404 for the refused paths, the redirect of
// the root to the home page, and the home service for the rest.
func (d *deployment) proxy(rp *runningPair) {
	t := d.t
	routes := cli.PairRoutes(rp.pair, nil)
	refused := cli.RefusedRoutes(rp.pair)
	home := cli.HomeOf(rp.pair.Role)
	target := func(service string) *url.URL {
		return &url.URL{Scheme: "http", Host: "127.0.0.1:" + strconv.Itoa(rp.ports[service])}
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		for _, m := range refused {
			if strings.HasPrefix(path, strings.TrimSuffix(m, "*")) {
				http.NotFound(w, r)
				return
			}
		}
		if path == "/" {
			http.Redirect(w, r, home.Path, http.StatusFound)
			return
		}
		service, strip := home.Service, ""
		best := -1
		for _, sr := range routes {
			m := sr.Route.Match
			switch {
			case strings.HasSuffix(m, "*") && strings.HasPrefix(path, strings.TrimSuffix(m, "*")) && len(m) > best:
			case m == path && len(m)+1 > best:
			default:
				continue
			}
			best = len(m)
			if m == path {
				best++
			}
			service, strip = sr.Service, sr.Route.StripPrefix()
		}
		rp2 := httputil.NewSingleHostReverseProxy(target(service))
		if strip != "" {
			r.URL.Path = strings.TrimPrefix(r.URL.Path, strip)
			r.URL.RawPath = ""
		}
		rp2.ServeHTTP(w, r)
	})
	srv := &http.Server{Addr: "127.0.0.1:" + strconv.Itoa(rp.proxy), Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	l, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Log(err)
		}
	}()
	t.Cleanup(func() {
		if err := srv.Close(); err != nil {
			t.Log(err)
		}
	})
}
