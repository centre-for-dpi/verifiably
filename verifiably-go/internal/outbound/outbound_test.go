package outbound

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func ctx() context.Context { return context.Background() }

// --- Resolve: scheme, credentials, host -------------------------------------

func TestResolveRejectsNonHTTPSchemes(t *testing.T) {
	p := New(Config{DevOpen: true})
	for _, raw := range []string{
		"file:///etc/passwd",
		"gopher://evil.example/_GET",
		"openid4vp://authorize?x=1",
		"//evil.example/no-scheme",
		"not a url at all",
	} {
		if _, err := p.Resolve(ctx(), Verifier, raw); err == nil {
			t.Errorf("Resolve(%q) = nil, want error", raw)
		} else if !errors.Is(err, ErrBlocked) {
			t.Errorf("Resolve(%q) error = %v, want ErrBlocked", raw, err)
		}
	}
}

func TestResolveRejectsCredentialsInAuthority(t *testing.T) {
	// Reads as "allowed.example" to a person; resolves to evil.example.
	p := New(Config{Allow: map[Purpose][]string{Verifier: {"allowed.example"}}})
	if _, err := p.Resolve(ctx(), Verifier, "https://allowed.example@evil.example/jar"); err == nil {
		t.Fatal("credentials in the authority were accepted")
	}
}

func TestResolveRejectsLiteralMetadataAddresses(t *testing.T) {
	p := New(Config{DevOpen: true})
	for _, raw := range []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://[::ffff:169.254.169.254]/latest/meta-data/",
		"http://[fd00:ec2::254]/latest/meta-data/",
	} {
		if _, err := p.Resolve(ctx(), Verifier, raw); err == nil {
			t.Errorf("Resolve(%q) = nil, want the metadata address blocked", raw)
		}
	}
}

func TestResolveRejectsSelfHost(t *testing.T) {
	p := New(Config{DevOpen: true, SelfHosts: []string{"hub.example"}})
	if _, err := p.Resolve(ctx(), Verifier, "https://hub.example/loop"); err == nil {
		t.Fatal("a self-request loop was permitted")
	}
	// Case and a trailing root label name the same host.
	if _, err := p.Resolve(ctx(), Verifier, "https://HUB.example./loop"); err == nil {
		t.Fatal("case/trailing-dot variation evaded the self-host check")
	}
}

// --- Resolve: the returned URL is rebuilt, not the caller's string ----------

func TestResolveReturnsRebuiltURL(t *testing.T) {
	p := New(Config{DevOpen: true})
	u, err := p.Resolve(ctx(), Verifier, "HTTPS://Registry.Example:8443/api/v1/x?a=1&b=2")
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "https" {
		t.Errorf("scheme = %q, want lower-cased https", u.Scheme)
	}
	if u.Host != "registry.example:8443" {
		t.Errorf("host = %q, want normalised host:port", u.Host)
	}
	if u.Path != "/api/v1/x" || u.RawQuery != "a=1&b=2" {
		t.Errorf("path/query = %q %q, want them preserved", u.Path, u.RawQuery)
	}
}

// --- The allowlist ----------------------------------------------------------

func TestAllowlistGovernsRequestDerivedPurposes(t *testing.T) {
	p := New(Config{Allow: map[Purpose][]string{
		OperatorFetch: {"registry.example", ".trusted.example", "https://config.example:9000/base"},
	}})

	permitted := []string{
		"https://registry.example/rows",
		"https://registry.example:8443/rows", // no port in the rule: any port
		"https://a.trusted.example/rows",     // suffix rule
		"https://config.example:9000/rows",   // the rule was given as a URL
	}
	for _, raw := range permitted {
		if _, err := p.Resolve(ctx(), OperatorFetch, raw); err != nil {
			t.Errorf("Resolve(%q) = %v, want permitted", raw, err)
		}
	}
	for _, raw := range []string{
		"https://evil.example/rows",
		"https://trusted.example.evil/rows", // suffix rule must not match this
		"https://nottrusted.example/rows",
		// The rule named port 9000. One address carries every service on a
		// Docker network, so another port on it is another service.
		"https://config.example:5432/rows",
		"https://config.example/rows",
	} {
		if _, err := p.Resolve(ctx(), OperatorFetch, raw); err == nil {
			t.Errorf("Resolve(%q) = nil, want denied", raw)
		}
	}
}

func TestAllowlistErrorNamesTheVariableToExtend(t *testing.T) {
	p := New(Config{})
	_, err := p.Resolve(ctx(), OperatorFetch, "https://evil.example/rows")
	if err == nil {
		t.Fatal("want an error")
	}
	if !strings.Contains(err.Error(), envAllow) {
		t.Errorf("error %q does not tell the operator which variable to extend", err)
	}
}

func TestConfiguredPurposesNeedNoAllowlist(t *testing.T) {
	// The config IS the allowlist for these two: a registry named in
	// VERIFIABLY_REGISTRIES and an admin-entered member endpoint are not
	// request input, so they are validated and rebuilt, not restricted.
	p := New(Config{})
	for _, purpose := range []Purpose{Registry, Federation} {
		if _, err := p.Resolve(ctx(), purpose, "http://sunbird.internal:8081/api/v1"); err != nil {
			t.Errorf("Resolve(%s) = %v, want permitted without an allowlist", purpose, err)
		}
	}
	// ...but the denied ranges still apply to them.
	if _, err := p.Resolve(ctx(), Registry, "http://169.254.169.254/"); err == nil {
		t.Error("metadata was reachable for a configured purpose")
	}
}

func TestPrivateDestinationsArePermitted(t *testing.T) {
	// The whole point: this stack's real backends are on private addresses.
	p := New(Config{Allow: map[Purpose][]string{OperatorFetch: {"172.24.0.1"}}})
	for _, raw := range []string{
		"http://172.24.0.1:8081/api/v1/Entity/search",
		"http://10.0.0.5/x",
		"http://192.168.1.10/x",
		"http://127.0.0.1:9000/x",
	} {
		purpose := Registry
		if strings.Contains(raw, "172.24") {
			purpose = OperatorFetch
		}
		if _, err := p.Resolve(ctx(), purpose, raw); err != nil {
			t.Errorf("Resolve(%q) = %v, want permitted (private is not denied here)", raw, err)
		}
	}
}

func TestVerifierAllowlistReadsFederationMembersAtCallTime(t *testing.T) {
	members := []string{}
	p := New(Config{Members: func(context.Context) []string { return members }})

	if _, err := p.Resolve(ctx(), Verifier, "https://member.example/jar"); err == nil {
		t.Fatal("an unknown verifier was permitted")
	}
	// A member added after the policy was built must be honoured without a
	// restart -- members are registered while the process runs.
	members = append(members, "https://member.example")
	if _, err := p.Resolve(ctx(), Verifier, "https://member.example/jar"); err != nil {
		t.Fatalf("a registered member was rejected: %v", err)
	}
}

func TestDevOpenLiftsTheAllowlistOnly(t *testing.T) {
	p := New(Config{DevOpen: true, SelfHosts: []string{"hub.example"}})
	if _, err := p.Resolve(ctx(), Verifier, "https://anything.example/jar"); err != nil {
		t.Fatalf("dev-open should permit an arbitrary verifier: %v", err)
	}
	// It lifts the list, not the rest of the checks.
	for _, raw := range []string{
		"http://169.254.169.254/",
		"https://hub.example/loop",
		"file:///etc/passwd",
	} {
		if _, err := p.Resolve(ctx(), Verifier, raw); err == nil {
			t.Errorf("dev-open wrongly permitted %q", raw)
		}
	}
}

// --- Dial-time re-check (DNS rebinding) -------------------------------------

func TestDialRejectsRebindingToMetadata(t *testing.T) {
	p := New(Config{DevOpen: true})
	// The name passed Resolve; by the time it is dialled it answers with the
	// metadata address. Checking at Resolve alone would have let this through.
	p.lookupIP = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("169.254.169.254")}, nil
	}
	_, err := p.dial(ctx(), "tcp", "rebind.example:443")
	if err == nil || !errors.Is(err, ErrBlocked) {
		t.Fatalf("dial to a rebound host = %v, want ErrBlocked", err)
	}
}

func TestDialRejectsWhenAnyAnswerIsDenied(t *testing.T) {
	p := New(Config{DevOpen: true})
	// One good address and one metadata address is not a host we talk to.
	p.lookupIP = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("93.184.216.34"), net.ParseIP("169.254.169.254")}, nil
	}
	if _, err := p.dial(ctx(), "tcp", "mixed.example:443"); err == nil {
		t.Fatal("a host answering with a denied address among others was dialled")
	}
}

func TestDialRejectsHostThatResolvesToNothing(t *testing.T) {
	p := New(Config{DevOpen: true})
	p.lookupIP = func(context.Context, string) ([]net.IP, error) { return nil, nil }
	if _, err := p.dial(ctx(), "tcp", "empty.example:443"); err == nil {
		t.Fatal("a host with no addresses was dialled")
	}
}

func TestDialReachesAPermittedAddress(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	p := New(Config{DevOpen: true})
	u, err := p.Resolve(ctx(), Verifier, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := p.Client(Verifier).Get(u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

// --- Redirect re-check ------------------------------------------------------

func TestClientRejectsRedirectToDeniedAddress(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer srv.Close()

	p := New(Config{DevOpen: true})
	u, err := p.Resolve(ctx(), Verifier, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := p.Client(Verifier).Get(u.String())
	if err == nil {
		resp.Body.Close()
		t.Fatal("a redirect to metadata was followed")
	}
	if !strings.Contains(err.Error(), "redirect") {
		t.Errorf("error = %v, want it to name the redirect", err)
	}
}

func TestClientRejectsRedirectOffTheAllowlist(t *testing.T) {
	away := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("should not be reached"))
	}))
	defer away.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, away.URL, http.StatusFound)
	}))
	defer srv.Close()

	// Only the first server's host AND port are permitted. Both servers are on
	// 127.0.0.1, so without port precision the redirect would be permitted --
	// which is exactly the Docker-network case this guards.
	p := New(Config{Allow: map[Purpose][]string{OperatorFetch: {srv.URL}}})
	u, err := p.Resolve(ctx(), OperatorFetch, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := p.Client(OperatorFetch).Get(u.String()); err == nil {
		resp.Body.Close()
		t.Fatal("a redirect off the allowlist was followed")
	}
}

func TestClientStopsAfterTooManyRedirects(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+"/again", http.StatusFound)
	}))
	defer srv.Close()

	p := New(Config{DevOpen: true})
	u, err := p.Resolve(ctx(), Verifier, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := p.Client(Verifier).Get(u.String()); err == nil {
		resp.Body.Close()
		t.Fatal("a redirect loop was followed indefinitely")
	}
}

func TestClientIsReusedPerPurpose(t *testing.T) {
	p := New(Config{})
	first, second := p.Client(Verifier), p.Client(Verifier)
	if first != second {
		t.Error("Client built a second client for the same purpose")
	}
	// Each purpose needs its own client because the redirect check is bound to
	// the purpose; sharing one would check redirects against the wrong rules.
	if first == p.Client(Registry) {
		t.Error("two purposes share one client, so they share a redirect check")
	}
}

// --- FromEnv ----------------------------------------------------------------

func TestFromEnvSeedsFromDeclaredConfiguration(t *testing.T) {
	t.Setenv(envAllow, "extra.example, .wild.example ")
	t.Setenv(envRegistry, `[{"id":"sunbird","url":"http://172.24.0.1:8081"},{"id":"bad","url":"%%"}]`)
	t.Setenv(envPublic, "hub.example")

	p, err := FromEnv(nil)
	if err != nil {
		t.Fatal(err)
	}
	// Declared registries need no second declaration to be bulk-importable.
	if _, err := p.Resolve(ctx(), OperatorFetch, "http://172.24.0.1:8081/rows"); err != nil {
		t.Errorf("a configured registry was not permitted for operator fetch: %v", err)
	}
	// ...but only on the port it declared. 5432 on that address is Postgres.
	if _, err := p.Resolve(ctx(), OperatorFetch, "http://172.24.0.1:5432/rows"); err == nil {
		t.Error("a configured registry's address opened every port on that host")
	}
	if _, err := p.Resolve(ctx(), OperatorFetch, "https://extra.example/rows"); err != nil {
		t.Errorf("an explicitly allowed host was rejected: %v", err)
	}
	if _, err := p.Resolve(ctx(), Verifier, "https://a.wild.example/jar"); err != nil {
		t.Errorf("a suffix rule was not applied to the verifier purpose: %v", err)
	}
	if _, err := p.Resolve(ctx(), Verifier, "https://hub.example/loop"); err == nil {
		t.Error("the public host was not denied")
	}
}

func TestFromEnvRefusesDevOpenOnAPublicDeployment(t *testing.T) {
	t.Setenv(envDevOpen, "1")
	t.Setenv(envPublic, "hub.gov.example")
	if _, err := FromEnv(nil); err == nil {
		t.Fatal("dev-open on a public deployment was accepted")
	}
}

func TestFromEnvAllowsDevOpenLocally(t *testing.T) {
	for _, host := range []string{"localhost", "172.24.0.1", "127.0.0.1", "dev.local", ""} {
		t.Run(host, func(t *testing.T) {
			t.Setenv(envDevOpen, "true")
			t.Setenv(envPublic, host)
			p, err := FromEnv(nil)
			if err != nil {
				t.Fatalf("dev-open refused on a local deployment (%q): %v", host, err)
			}
			if !p.devOpen {
				t.Error("dev-open was not enabled")
			}
		})
	}
}

func TestFromEnvWithNoConfigurationDeniesRequestDerivedDestinations(t *testing.T) {
	t.Setenv(envAllow, "")
	t.Setenv(envRegistry, "")
	t.Setenv(envPublic, "")
	t.Setenv(envDevOpen, "")

	p, err := FromEnv(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Resolve(ctx(), Verifier, "https://stranger.example/jar"); err == nil {
		t.Error("a deployment that declared nothing still fetched a stranger's request_uri")
	}
	if _, err := p.Resolve(ctx(), Registry, "http://sunbird.internal/api"); err != nil {
		t.Errorf("a configured-purpose destination was denied: %v", err)
	}
}

func TestDefaultIsUsableAndReplaceable(t *testing.T) {
	if Default() == nil {
		t.Fatal("Default() = nil")
	}
	custom := New(Config{DevOpen: true})
	SetDefault(custom)
	if Default() != custom {
		t.Error("SetDefault did not install the policy")
	}
}

// --- helpers ----------------------------------------------------------------

func TestParseRuleForms(t *testing.T) {
	for _, tc := range []struct {
		entry string
		host  string
		sfx   string
		port  string
		ok    bool
	}{
		{entry: "registry.example", host: "registry.example", ok: true},
		{entry: "Registry.Example.", host: "registry.example", ok: true},
		{entry: "registry.example:8081", host: "registry.example", port: "8081", ok: true},
		{entry: ".wild.example", sfx: ".wild.example", ok: true},
		{entry: "https://config.example:9000/base", host: "config.example", port: "9000", ok: true},
		{entry: "  "},
		{entry: "://nonsense"},
	} {
		got, ok := parseRule(tc.entry)
		if ok != tc.ok {
			t.Errorf("parseRule(%q) ok = %v, want %v", tc.entry, ok, tc.ok)
			continue
		}
		if ok && (got.host != tc.host || got.suffix != tc.sfx || got.port != tc.port) {
			t.Errorf("parseRule(%q) = %+v, want host %q suffix %q port %q", tc.entry, got, tc.host, tc.sfx, tc.port)
		}
	}
}

func TestPurposeString(t *testing.T) {
	for p, want := range map[Purpose]string{
		Registry: "registry", Federation: "federation",
		OperatorFetch: "operator fetch", Verifier: "verifier", Purpose(99): "unknown",
	} {
		if got := p.String(); got != want {
			t.Errorf("Purpose(%d).String() = %q, want %q", p, got, want)
		}
	}
}

func TestIsLocalHost(t *testing.T) {
	for _, h := range []string{"", "localhost", "app.localhost", "svc.local", "db.internal", "127.0.0.1", "172.24.0.1", "10.1.2.3", "169.254.1.1"} {
		if !isLocalHost(h) {
			t.Errorf("isLocalHost(%q) = false, want true", h)
		}
	}
	for _, h := range []string{"hub.gov.example", "93.184.216.34"} {
		if isLocalHost(h) {
			t.Errorf("isLocalHost(%q) = true, want false", h)
		}
	}
}
