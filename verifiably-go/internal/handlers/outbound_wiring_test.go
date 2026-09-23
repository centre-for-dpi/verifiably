package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/verifiably/verifiably-go/internal/outbound"
)

// These cover the boundary between the handlers and the outbound policy: the
// URL builders that registry calls go through, and the normalisation a
// federation member endpoint gets on write.

func TestRegistryURLBuildsFromValidatedParts(t *testing.T) {
	u, err := registryURL(context.Background(), "http://sunbird.internal:8081/", "api", "v1", "PersonCard", "search")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := u.String(), "http://sunbird.internal:8081/api/v1/PersonCard/search"; got != want {
		t.Errorf("registryURL = %q, want %q", got, want)
	}
}

func TestRegistryURLRejectsTraversalInASegment(t *testing.T) {
	// ".." is a legal single path segment. Joined unchecked it walks out of the
	// registry's namespace, which is the whole reason segments are validated.
	for _, entity := range []string{"..", "../../admin", "Person/../../x", "", "-leading", strings.Repeat("a", 129)} {
		if _, err := registryURL(context.Background(), "http://sunbird.internal", "api", "v1", entity, "search"); err == nil {
			t.Errorf("registryURL accepted entity %q", entity)
		}
	}
}

func TestRegistryURLRejectsUnusableBase(t *testing.T) {
	for _, base := range []string{
		"",
		"not a url",
		"file:///etc/passwd",
		"http://169.254.169.254", // metadata is denied for every purpose
		"http://user:pw@registry.example",
	} {
		if _, err := registryURL(context.Background(), base, "api"); err == nil {
			t.Errorf("registryURL accepted base %q", base)
		}
	}
}

func TestRegistryURLAcceptsPrivateBackends(t *testing.T) {
	// A registry on a Docker bridge is the normal case here, not an attack.
	for _, base := range []string{"http://172.24.0.1:8081", "http://10.0.0.7", "http://certify-nginx:8090"} {
		if _, err := registryURL(context.Background(), base, "api", "v1", "E", "search"); err != nil {
			t.Errorf("registryURL(%q) = %v, want permitted", base, err)
		}
	}
}

func TestRegistryPathURLKeepsConfiguredTemplateAndChecksID(t *testing.T) {
	u, err := registryPathURL(context.Background(), "http://reg.internal", "/record/", "ID-42")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := u.String(), "http://reg.internal/record/ID-42"; got != want {
		t.Errorf("registryPathURL = %q, want %q", got, want)
	}
	for _, id := range []string{"", "..", "a/b", "x?y"} {
		if _, err := registryPathURL(context.Background(), "http://reg.internal", "/record/", id); err == nil {
			t.Errorf("registryPathURL accepted id %q", id)
		}
	}
}

func TestNormaliseServiceEndpointRebuildsWhatItStores(t *testing.T) {
	got, err := normaliseServiceEndpoint(context.Background(), "HTTPS://Member.Example:8443/base/?token=abc#frag")
	if err != nil {
		t.Fatal(err)
	}
	// Lower-cased, and the query and fragment dropped: what gets stored is a
	// base URL, because that is what every later use treats it as.
	if want := "https://member.example:8443/base"; got != want {
		t.Errorf("normaliseServiceEndpoint = %q, want %q", got, want)
	}
}

func TestNormaliseServiceEndpointRejectsUnusableValues(t *testing.T) {
	for _, raw := range []string{
		"",
		"member.example",           // no scheme
		"javascript:alert(1)",      // not http(s)
		"https://a@member.example", // credentials in the authority
		"http://169.254.169.254/x", // metadata
	} {
		if _, err := normaliseServiceEndpoint(context.Background(), raw); err == nil {
			t.Errorf("normaliseServiceEndpoint accepted %q", raw)
		}
	}
}

func TestFederationHealthzGoesThroughThePolicy(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := federationHealthz(context.Background(), srv.URL); err != nil {
		t.Fatalf("federationHealthz = %v", err)
	}
	if gotPath != "/healthz" {
		t.Errorf("probed %q, want /healthz", gotPath)
	}
	// A non-200 is still a failed member, and an unusable endpoint never gets
	// as far as a request.
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer down.Close()
	if err := federationHealthz(context.Background(), down.URL); err == nil {
		t.Error("a member returning 503 passed the health check")
	}
	if err := federationHealthz(context.Background(), "http://169.254.169.254"); err == nil {
		t.Error("a metadata endpoint passed the health check")
	}
}

func TestFetchJSONRowsIsAllowlisted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"individualId":"1","name":"A"}]`))
	}))
	defer srv.Close()

	// The process-wide policy has declared nothing, so an operator-typed URL is
	// refused: this is the posture a deployment starts in.
	outbound.SetDefault(outbound.New(outbound.Config{}))
	if _, err := fetchJSONRows(context.Background(), srv.URL, "", ""); err == nil {
		t.Error("an undeclared destination was fetched")
	}

	// Naming it -- as VERIFIABLY_OUTBOUND_ALLOW or a configured registry would
	// -- permits it, and nothing else about the fetch changes.
	outbound.SetDefault(outbound.New(outbound.Config{
		Allow: map[outbound.Purpose][]string{outbound.OperatorFetch: {srv.URL}},
	}))
	t.Cleanup(func() { outbound.SetDefault(outbound.New(outbound.Config{})) })

	rows, err := fetchJSONRows(context.Background(), srv.URL, "", "")
	if err != nil {
		t.Fatalf("fetchJSONRows = %v", err)
	}
	if len(rows) != 1 || rows[0]["name"] != "A" {
		t.Errorf("rows = %v", rows)
	}
}

func TestHandlerOutboundFallsBackToTheProcessPolicy(t *testing.T) {
	scoped := outbound.New(outbound.Config{DevOpen: true})
	if got := (&H{Outbound: scoped}).outbound(); got != scoped {
		t.Error("a handler with its own policy did not use it")
	}
	if got := (&H{}).outbound(); got != outbound.Default() {
		t.Error("a handler without one did not fall back to the process policy")
	}
}
