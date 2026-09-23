// Package outbound decides whether this service may make an HTTP request to a
// given destination, and returns a client that keeps deciding after the call
// has started.
//
// # Why not a private-address denylist
//
// internal/handlers/ssrf.go already has ssrfBlockHost, which rejects hosts that
// resolve into private, loopback, link-local and metadata ranges. It is the
// wrong control for this deployment and applying it more widely would break the
// product: every DPG verifiably talks to -- certify-nginx, walt-issuer,
// credebl-minio, the Sunbird registries -- lives on a Docker bridge or a
// cluster-internal address, and VERIFIABLY_PUBLIC_HOST=172.24.0.1 is the
// documented localhost default. Here the legitimate destinations ARE the
// private addresses. A denylist of RFC1918 rejects the stack's own services and
// permits nothing useful.
//
// So the control is an allowlist, seeded from what the deployment has already
// declared, applied only to the two purposes whose destination comes from a
// request. Two things are denied for every purpose regardless: cloud metadata,
// which no legitimate destination here ever is, and this service's own public
// host, which would be a self-request loop.
//
// # What this package adds over a check before the call
//
//   - The address actually dialled is the one checked. A check that resolves a
//     host and then hands the name to an http.Client lets the client resolve
//     again, so a name that answers with an allowed address once and a metadata
//     address a moment later walks straight through it. Client pins the
//     connection to the address it approved.
//   - Redirects are re-checked. The shared client followed them unchecked, so
//     an allowed host redirecting to 169.254.169.254 succeeded.
//   - Resolve hands back a URL built from validated parts rather than the
//     caller's string, so the value that reaches http.NewRequest is derived
//     from the check. That is also what lets taint analysis see the boundary.
package outbound

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Purpose is why a request is being made. It selects which rules apply: the two
// purposes whose destination is derived from a request are allowlisted, the two
// whose destination comes from deployment config or an admin action are
// validated and rebuilt but not restricted to a list, because the config IS the
// list and adding a federation member is already a trust decision.
type Purpose int

const (
	// Registry is a Sunbird or similar registry named by VERIFIABLY_REGISTRIES.
	// Deployment configuration, not request input.
	Registry Purpose = iota
	// Federation is a federation member's serviceEndpoint, entered by an admin
	// and normalised on write.
	Federation
	// OperatorFetch is a URL an authenticated operator typed into a bulk-import
	// form. Allowlisted.
	OperatorFetch
	// Verifier is an OID4VP request_uri or response_uri, which originates with
	// whoever produced the QR code. Allowlisted.
	Verifier
)

func (p Purpose) String() string {
	switch p {
	case Registry:
		return "registry"
	case Federation:
		return "federation"
	case OperatorFetch:
		return "operator fetch"
	case Verifier:
		return "verifier"
	}
	return "unknown"
}

// allowlisted reports whether this purpose's destination must appear on the
// allowlist. The other two are validated and rebuilt, not restricted.
func (p Purpose) allowlisted() bool { return p == OperatorFetch || p == Verifier }

// widenVar names the environment variable an operator extends to permit a
// destination this purpose rejected, so the error can say what to do next.
func (p Purpose) widenVar() string {
	if p.allowlisted() {
		return envAllow
	}
	return ""
}

const (
	envAllow    = "VERIFIABLY_OUTBOUND_ALLOW"
	envDevOpen  = "VERIFIABLY_OUTBOUND_DEV_OPEN"
	envPublic   = "VERIFIABLY_PUBLIC_HOST"
	envRegistry = "VERIFIABLY_REGISTRIES"

	defaultTimeout = 30 * time.Second
	maxRedirects   = 5
)

// ErrBlocked is the class of every rejection this package makes, so callers can
// distinguish "we refused to fetch this" from "the fetch failed".
var ErrBlocked = errors.New("outbound destination not permitted")

// denied lists the ranges no purpose may reach. Deliberately short: cloud
// metadata (AWS, GCP, Azure and the IPv6 form AWS added), which is the address
// an SSRF is usually aimed at and never a destination this product has, and
// nothing else. Private ranges are absent by design -- see the package comment.
var denied = mustCIDRs(
	"169.254.0.0/16",         // link-local, incl. 169.254.169.254 metadata
	"fd00:ec2::/64",          // AWS IMDS over IPv6
	"::ffff:169.254.0.0/112", // IPv4-mapped form of the above, in case a name
	// resolves to a mapped address rather than a v4 one
)

func mustCIDRs(cidrs ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic("outbound: bad built-in CIDR " + c + ": " + err.Error())
		}
		out = append(out, n)
	}
	return out
}

// Config builds a Policy. The zero value denies both allowlisted purposes and
// permits the other two, which is the correct posture for a deployment that has
// declared nothing.
type Config struct {
	// Allow adds permitted destinations per purpose. An entry is an exact host
	// ("registry.example"), a host with a port ("registry.example:8081" or a
	// full URL), or a leading-dot suffix (".example" matches "a.example" but
	// not "example").
	//
	// An entry that names a port permits only that port. This matters on a
	// Docker network, where one address carries every service in the stack:
	// allowing the registry at 172.24.0.1:8081 must not also allow the
	// database at 172.24.0.1:5432.
	Allow map[Purpose][]string

	// Members supplies federation member service endpoints at call time rather
	// than at startup, because members are added while the process runs. Nil
	// means no members, which for the Verifier purpose means no verifier is
	// permitted unless DevOpen or Allow names one.
	Members func(context.Context) []string

	// DevOpen lifts the allowlist for OperatorFetch and Verifier, leaving the
	// denied ranges, the scheme check and the dial-time and redirect checks in
	// place. It exists so a deployment can interoperate with an arbitrary INJI
	// Verify instance during testing. It is off by default and FromEnv refuses
	// to enable it on a deployment whose public host is not local.
	DevOpen bool

	// SelfHosts are this deployment's own hostnames, denied for every purpose
	// so the service cannot be made to call itself.
	SelfHosts []string

	// Timeout bounds every request. Zero means 30s. A destination that accepts
	// the connection and never answers would otherwise pin the calling
	// goroutine indefinitely.
	Timeout time.Duration
}

// Policy answers whether a destination is permitted, and hands out clients that
// keep checking once the request is in flight.
type Policy struct {
	allow     map[Purpose][]hostRule
	members   func(context.Context) []string
	devOpen   bool
	selfHosts map[string]bool
	timeout   time.Duration

	// lookupIP is the resolver, replaceable in tests. It must return every
	// address the host resolves to, because the dial check rejects the request
	// if ANY of them is denied -- a name that answers with one good address and
	// one metadata address is not a host we will talk to.
	lookupIP func(ctx context.Context, host string) ([]net.IP, error)

	mu      sync.Mutex
	clients map[Purpose]*http.Client
}

type hostRule struct {
	host   string // exact host, lower-cased
	suffix string // ".example" form; empty for exact rules
	port   string // empty means any port on that host
}

func (r hostRule) match(host, port string) bool {
	if r.port != "" && r.port != port {
		return false
	}
	if r.suffix != "" {
		return strings.HasSuffix(host, r.suffix)
	}
	return r.host == host
}

// New builds a Policy from an explicit Config.
func New(cfg Config) *Policy {
	p := &Policy{
		allow:     map[Purpose][]hostRule{},
		members:   cfg.Members,
		devOpen:   cfg.DevOpen,
		selfHosts: map[string]bool{},
		timeout:   cfg.Timeout,
		lookupIP:  defaultLookupIP,
		clients:   map[Purpose]*http.Client{},
	}
	if p.timeout == 0 {
		p.timeout = defaultTimeout
	}
	for purpose, hosts := range cfg.Allow {
		for _, h := range hosts {
			if r, ok := parseRule(h); ok {
				p.allow[purpose] = append(p.allow[purpose], r)
			}
		}
	}
	for _, h := range cfg.SelfHosts {
		if h = normaliseHost(h); h != "" {
			p.selfHosts[h] = true
		}
	}
	return p
}

func defaultLookupIP(ctx context.Context, host string) ([]net.IP, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}
	return ips, nil
}

// parseRule turns one allowlist entry into a rule. An entry may be a bare host,
// a leading-dot suffix, or a URL, so an operator can paste what they already
// have in VERIFIABLY_REGISTRIES without editing it into a hostname.
func parseRule(entry string) (hostRule, bool) {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return hostRule{}, false
	}
	if strings.Contains(entry, "://") {
		u, err := url.Parse(entry)
		if err != nil || u.Hostname() == "" {
			return hostRule{}, false
		}
		return hostRule{host: normaliseHost(u.Hostname()), port: u.Port()}, true
	}
	if strings.HasPrefix(entry, ".") {
		return hostRule{suffix: normaliseHost(entry)}, true
	}
	var port string
	if h, pt, err := net.SplitHostPort(entry); err == nil {
		entry, port = h, pt
	}
	return hostRule{host: normaliseHost(entry), port: port}, true
}

func normaliseHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimSuffix(h, ".") // a trailing root label is the same host
	return strings.Trim(h, "[]")   // an IPv6 literal arrives bracketed
}

// Resolve checks raw for this purpose and returns the URL to fetch, built from
// the parts that passed the check rather than from the caller's string.
//
// Callers MUST use the returned URL. Passing raw on after calling this both
// discards the normalisation and leaves the taint path open.
func (p *Policy) Resolve(ctx context.Context, purpose Purpose, raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("%w: unparseable URL for %s", ErrBlocked, purpose)
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("%w: %s needs an http(s) URL, got %q", ErrBlocked, purpose, u.Scheme)
	}
	// Credentials in the authority are how "https://allowed.example@evil" reads
	// as an allowed host to a person and resolves to evil for a machine.
	if u.User != nil {
		return nil, fmt.Errorf("%w: %s URL must not carry credentials", ErrBlocked, purpose)
	}

	host := normaliseHost(u.Hostname())
	if host == "" {
		return nil, fmt.Errorf("%w: %s URL has no host", ErrBlocked, purpose)
	}
	if p.selfHosts[host] {
		return nil, fmt.Errorf("%w: %s must not call this deployment (%s)", ErrBlocked, purpose, host)
	}
	// A literal address skips DNS entirely, so check it here as well as at dial.
	if ip := net.ParseIP(host); ip != nil && isDenied(ip) {
		return nil, fmt.Errorf("%w: %s to a reserved address (%s)", ErrBlocked, purpose, ip)
	}

	if err := p.allowed(ctx, purpose, host, u.Port()); err != nil {
		return nil, err
	}

	// Rebuild. Everything below is a field we validated, in a struct we made:
	// the caller's string does not reach the request.
	out := &url.URL{
		Scheme:   scheme,
		Host:     hostPort(host, u.Port()),
		Path:     u.Path,
		RawQuery: u.RawQuery,
	}
	return out, nil
}

// allowed applies the allowlist, for the purposes that have one.
func (p *Policy) allowed(ctx context.Context, purpose Purpose, host, port string) error {
	if !purpose.allowlisted() || p.devOpen {
		return nil
	}
	for _, r := range p.allow[purpose] {
		if r.match(host, port) {
			return nil
		}
	}
	if purpose == Verifier && p.members != nil {
		for _, endpoint := range p.members(ctx) {
			if r, ok := parseRule(strings.TrimSpace(endpoint)); ok && r.match(host, port) {
				return nil
			}
		}
	}
	return fmt.Errorf("%w: %q is not a permitted %s destination (extend %s to allow it)",
		ErrBlocked, hostPort(host, port), purpose, purpose.widenVar())
}

func hostOf(rawURL string) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return ""
	}
	return normaliseHost(u.Hostname())
}

func hostPort(host, port string) string {
	if port == "" {
		return host
	}
	return net.JoinHostPort(host, port)
}

func isDenied(ip net.IP) bool {
	for _, n := range denied {
		if n.Contains(ip) {
			return true
		}
		// A v4 address and its v4-mapped v6 form are the same destination; test
		// both so "::ffff:169.254.169.254" cannot slip past a v4 CIDR.
		if v4 := ip.To4(); v4 != nil && n.Contains(v4) {
			return true
		}
	}
	return false
}

// Client returns the http.Client for this purpose. The client re-checks the
// address it is about to dial and re-runs Resolve on every redirect, so a
// destination that becomes disallowed after Resolve returned still does not get
// reached. Clients are built once per purpose and are safe for concurrent use.
func (p *Policy) Client(purpose Purpose) *http.Client {
	p.mu.Lock()
	defer p.mu.Unlock()
	if c, ok := p.clients[purpose]; ok {
		return c
	}
	c := &http.Client{
		Timeout:       p.timeout,
		Transport:     p.transport(),
		CheckRedirect: p.checkRedirect(purpose),
	}
	p.clients[purpose] = c
	return c
}

func (p *Policy) transport() http.RoundTripper {
	base, _ := http.DefaultTransport.(*http.Transport)
	t := base.Clone()
	t.DialContext = p.dial
	return t
}

// dial resolves the host itself, rejects the request if any returned address is
// denied, and then connects to the address it approved rather than to the name.
// Handing the name to the dialler would let it resolve a second time and reach
// an address this never saw.
func (p *Policy) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else if ips, err = p.lookupIP(ctx, host); err != nil {
		return nil, fmt.Errorf("resolve %q: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%w: %q resolves to nothing", ErrBlocked, host)
	}
	for _, ip := range ips {
		if isDenied(ip) {
			return nil, fmt.Errorf("%w: %q resolves to a reserved address (%s)", ErrBlocked, host, ip)
		}
	}
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	var lastErr error
	for _, ip := range ips {
		conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (p *Policy) checkRedirect(purpose Purpose) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return fmt.Errorf("%w: %s followed %d redirects", ErrBlocked, purpose, len(via))
		}
		// The hop is a fresh destination and gets the same decision the first
		// one got. Without this, an allowed host redirecting to metadata wins.
		if _, err := p.Resolve(req.Context(), purpose, req.URL.String()); err != nil {
			return fmt.Errorf("redirect: %w", err)
		}
		return nil
	}
}

// FromEnv builds the policy a running deployment uses, seeded from
// configuration the operator has already written:
//
//	VERIFIABLY_REGISTRIES        registry base URLs      -> OperatorFetch
//	VERIFIABLY_OUTBOUND_ALLOW    extra hosts, comma-separated -> both allowlisted purposes
//	VERIFIABLY_PUBLIC_HOST       this deployment          -> denied everywhere
//	VERIFIABLY_OUTBOUND_DEV_OPEN lifts the allowlist      -> local deployments only
//
// members supplies federation endpoints at call time and may be nil.
//
// It returns an error, rather than quietly degrading, when DEV_OPEN is set on a
// deployment whose public host is not local: that combination is a public
// service that will fetch any URL a stranger puts in a QR code.
func FromEnv(members func(context.Context) []string) (*Policy, error) {
	cfg := Config{
		Allow:   map[Purpose][]string{},
		Members: members,
	}

	var extra []string
	for _, h := range strings.Split(os.Getenv(envAllow), ",") {
		if r := strings.TrimSpace(h); r != "" {
			extra = append(extra, r)
		}
	}
	cfg.Allow[OperatorFetch] = append(cfg.Allow[OperatorFetch], extra...)
	cfg.Allow[Verifier] = append(cfg.Allow[Verifier], extra...)

	// An operator who has declared a registry has already said this deployment
	// talks to it, so a bulk import from it needs no second declaration.
	cfg.Allow[OperatorFetch] = append(cfg.Allow[OperatorFetch],
		registryHostsFromEnv(os.Getenv(envRegistry))...)

	public := strings.TrimSpace(os.Getenv(envPublic))
	if public != "" {
		cfg.SelfHosts = append(cfg.SelfHosts, hostOnly(public))
	}

	if devOpen := strings.TrimSpace(os.Getenv(envDevOpen)); devOpen == "1" || strings.EqualFold(devOpen, "true") {
		if public != "" && !isLocalHost(hostOnly(public)) {
			return nil, fmt.Errorf("%s is set on a deployment whose %s (%q) is not local: "+
				"that combination lets any request_uri reach any destination. "+
				"Name the verifiers in %s instead", envDevOpen, envPublic, public, envAllow)
		}
		cfg.DevOpen = true
	}

	return New(cfg), nil
}

// registryHostsFromEnv pulls the "url" of each entry out of VERIFIABLY_REGISTRIES
// without depending on the handler package's type. A malformed value yields no
// hosts, which fails closed.
func registryHostsFromEnv(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var entries []struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return nil
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		// The whole URL, so the rule keeps the registry's port.
		if hostOf(e.URL) != "" {
			out = append(out, e.URL)
		}
	}
	return out
}

func hostOnly(v string) string {
	if strings.Contains(v, "://") {
		return hostOf(v)
	}
	if h, _, err := net.SplitHostPort(v); err == nil {
		return normaliseHost(h)
	}
	return normaliseHost(v)
}

// isLocalHost reports whether a public host is one a developer runs on. Used
// only to decide whether DEV_OPEN is safe to honour.
func isLocalHost(host string) bool {
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".localhost") ||
		strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

var (
	defaultOnce sync.Once
	defaultMu   sync.RWMutex
	defaultPol  *Policy
)

// Default is the policy used by call sites that have no handler to carry one.
// It is built from the environment on first use; a configuration error there
// yields the zero-config policy, which denies both allowlisted purposes.
func Default() *Policy {
	defaultOnce.Do(func() {
		p, err := FromEnv(nil)
		if err != nil {
			p = New(Config{})
		}
		defaultMu.Lock()
		if defaultPol == nil {
			defaultPol = p
		}
		defaultMu.Unlock()
	})
	defaultMu.RLock()
	defer defaultMu.RUnlock()
	return defaultPol
}

// SetDefault installs the process-wide policy. main() calls this once, after
// FromEnv, so that the federation member source is wired in.
func SetDefault(p *Policy) {
	defaultMu.Lock()
	defaultPol = p
	defaultMu.Unlock()
	defaultOnce.Do(func() {})
}
