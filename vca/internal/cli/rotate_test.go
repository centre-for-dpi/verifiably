// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// rotationSecret and rotationVector are the vector of the rotation
// token. The adapter test holds the same pair (ADR-056 decision 6).
const (
	rotationSecret = "0123456789abcdef0123456789abcdef"
	rotationVector = "4c0348ddce94c73e91889f24f0332df15fa06b52c2a6878f3733b4449fe3b0b3"
)

// fakeRotation is the rotation endpoint of the Inji adapter.
func fakeRotation(t *testing.T, status int, body string) (*httptest.Server, *[]string) {
	t.Helper()
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
		if r.Header.Get("Authorization") != "Bearer "+rotationVector {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(status)
		if _, err := io.WriteString(w, body); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &seen
}

// TestRotateAuthzKeyCallsTheAdapter: the command proves that it holds
// the pair session key with the rotation token, asks the adapter on its
// host port, and prints when the new key signs and when the old one
// goes (ADR-056 decision 6).
func TestRotateAuthzKeyCallsTheAdapter(t *testing.T) {
	answer := `{"kid":"new-kid","active_from":"2026-09-26T12:06:00Z","retiring":{"old-kid":"2026-09-26T12:12:00Z"}}`
	srv, seen := fakeRotation(t, http.StatusOK, answer)
	var out bytes.Buffer
	opts := RotateOptions{BootstrapOptions: BootstrapOptions{
		Pair:   Pair{Role: commonv1.Role_ROLE_ISSUER, Dpg: configv1.Dpg_DPG_INJI},
		Values: map[string]string{"VCA_INJI_AUTHZ_KEY_SECRET": rotationSecret, EnvBootstrapAdapterURL: srv.URL},
		Client: srv.Client(), Out: &out,
	}}
	got, err := RotateAuthzKey(context.Background(), opts)
	if err != nil {
		t.Fatalf("RotateAuthzKey: %v", err)
	}
	if got.Kid != "new-kid" || strings.Join(*seen, " ") != "POST /internal/authz/rotate-key?" {
		t.Fatalf("result = %+v, calls = %v", got, *seen)
	}
	for _, want := range []string{"new-kid", "2026-09-26T12:06:00Z", "old-kid", "2026-09-26T12:12:00Z"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the output lacks %q:\n%s", want, out.String())
		}
	}
	// --now asks for an immediate rotation. The session key serves when
	// the adapter setting is absent.
	opts.Immediate = true
	opts.Values = map[string]string{"VCA_SECRETS_SESSION_KEY": rotationSecret, EnvBootstrapAdapterURL: srv.URL}
	if _, err := RotateAuthzKey(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	if (*seen)[1] != "POST /internal/authz/rotate-key?immediate=true" {
		t.Fatalf("calls = %v", *seen)
	}
}

// TestRotateAuthzKeyRefusals: another stack, no key, an adapter that
// refuses, an answer that does not read, and no adapter each end in an
// error that says what to do.
func TestRotateAuthzKeyRefusals(t *testing.T) {
	good := map[string]string{"VCA_INJI_AUTHZ_KEY_SECRET": rotationSecret}
	refusing, _ := fakeRotation(t, http.StatusInternalServerError, "The rotation failed.\n")
	garbled, _ := fakeRotation(t, http.StatusOK, "{")
	for name, tc := range map[string]struct {
		dpg    configv1.Dpg
		values map[string]string
		url    string
		want   string
	}{
		"walt.id":          {configv1.Dpg_DPG_WALTID, good, refusing.URL, "Inji"},
		"no key":           {configv1.Dpg_DPG_INJI, map[string]string{}, refusing.URL, "VCA_INJI_AUTHZ_KEY_SECRET"},
		"a wrong key":      {configv1.Dpg_DPG_INJI, map[string]string{"VCA_INJI_AUTHZ_KEY_SECRET": "another"}, refusing.URL, "401"},
		"a failure":        {configv1.Dpg_DPG_INJI, good, refusing.URL, "The rotation failed."},
		"a garbled answer": {configv1.Dpg_DPG_INJI, good, garbled.URL, "read the answer"},
		"no adapter":       {configv1.Dpg_DPG_INJI, good, "http://127.0.0.1:1", "the adapter at"},
		"a bad URL":        {configv1.Dpg_DPG_INJI, good, "nope", EnvBootstrapAdapterURL},
	} {
		values := map[string]string{EnvBootstrapAdapterURL: tc.url}
		for k, v := range tc.values {
			values[k] = v
		}
		_, err := RotateAuthzKey(context.Background(), RotateOptions{BootstrapOptions: BootstrapOptions{
			Pair: Pair{Role: commonv1.Role_ROLE_ISSUER, Dpg: tc.dpg}, Values: values,
		}})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
}

// TestDpgRotateAuthzKeyCommand drives vca dpg rotate-authz-key inji
// through the .env of the issuer pair.
func TestDpgRotateAuthzKeyCommand(t *testing.T) {
	status, out, _ := run(t, Environment{Root: t.TempDir()}, "dpg", "rotate-authz-key", "--help")
	if status != 0 || !strings.Contains(out, "--now") || !strings.Contains(out, "key set") {
		t.Fatalf("help = %d %s", status, out)
	}
	srv, seen := fakeRotation(t, http.StatusOK, `{"kid":"k2","active_from":"2026-09-26T12:06:00Z"}`)
	root := t.TempDir()
	pair := Pair{Role: commonv1.Role_ROLE_ISSUER, Dpg: configv1.Dpg_DPG_INJI}
	dir := filepath.Join(root, "deploy", pair.Name())
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	body := "VCA_INJI_AUTHZ_KEY_SECRET=" + rotationSecret + "\n"
	if err := os.WriteFile(filepath.Join(dir, EnvFileName), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	getenv := func(k string) string {
		if k == EnvBootstrapAdapterURL {
			return srv.URL
		}
		return ""
	}
	status, out, errOut := run(t, Environment{Root: root, Getenv: getenv, HTTP: srv.Client()}, "dpg", "rotate-authz-key", "inji", "--now")
	if status != 0 || !strings.Contains(out, "k2") || len(*seen) != 1 || !strings.Contains((*seen)[0], "immediate=true") {
		t.Fatalf("status %d, out %s, err %s, calls %v", status, out, errOut, *seen)
	}
	if status, _, errOut = run(t, Environment{Root: root}, "dpg", "rotate-authz-key", "waltid"); status == 0 || !strings.Contains(errOut, "Inji") {
		t.Errorf("walt.id = %d %s", status, errOut)
	}
	if status, _, _ = run(t, Environment{Root: root}, "dpg", "rotate-authz-key", "nothing"); status == 0 {
		t.Error("an unknown stack passed")
	}
}

// TestNoPublicRouteReachesTheRotation: the rotation of the token key
// stays on the host port of the adapter. No route of the proxy leads
// there (ADR-047, ADR-056 decision 6).
func TestNoPublicRouteReachesTheRotation(t *testing.T) {
	for _, p := range AllPairs() {
		for _, sr := range PairRoutes(p, nil) {
			if !strings.HasPrefix(sr.Service, "dpg-adapter-") {
				continue
			}
			m := strings.TrimSuffix(sr.Route.Match, "*")
			if strings.HasPrefix(injiRotatePath, m) {
				t.Errorf("%s: %s routes %s, which covers the rotation", p.Name(), sr.Service, sr.Route.Match)
			}
		}
	}
}

// TestInjiPairsPublishTheRfc8414Metadata is finding 10 of the review:
// RFC 8414 section 3 puts the metadata of the issuer https://host/authz
// at https://host/.well-known/oauth-authorization-server/authz. The
// proxy of an Inji pair sends that path and its openid-configuration
// twin to the adapter, next to /authz/*.
func TestInjiPairsPublishTheRfc8414Metadata(t *testing.T) {
	issuer := Pair{Role: commonv1.Role_ROLE_ISSUER, Dpg: configv1.Dpg_DPG_INJI}
	want := []string{
		"/.well-known/oauth-authorization-server" + InjiAuthzPath,
		"/.well-known/openid-configuration" + InjiAuthzPath,
	}
	routed := map[string]string{}
	for _, sr := range PairRoutes(issuer, nil) {
		routed[sr.Route.Match] = sr.Service
	}
	caddy := Caddyfile(issuer, map[string]string{"VCA_PUBLIC_URL": "https://issuer-inji.labs.example"})
	table := RouteTable()
	for _, match := range want {
		if routed[match] != "dpg-adapter-inji" {
			t.Errorf("%s goes to %q, want dpg-adapter-inji", match, routed[match])
		}
		if !strings.Contains(caddy, "\thandle "+match+" {\n") {
			t.Errorf("the issuer Caddyfile has no handle for %s", match)
		}
		if !strings.Contains(table, "| `"+match+"` | `dpg-adapter-<dpg>` | Only the `inji` adapter. |") {
			t.Errorf("the route table has no row for %s", match)
		}
	}
	// The eSignet metadata of the stack keeps its own exact paths, when
	// eSignet runs.
	withEsignet := map[string]string{}
	for _, sr := range PairRoutes(issuer, map[string]string{EsignetAuthenticatorEnv: "mosip-ida"}) {
		withEsignet[sr.Route.Match] = sr.Service
	}
	if withEsignet["/.well-known/oauth-authorization-server"] != EsignetUIContainer {
		t.Errorf("the eSignet metadata goes to %q", withEsignet["/.well-known/oauth-authorization-server"])
	}
	if _, ok := routed["/.well-known/oauth-authorization-server"]; ok {
		t.Error("a pair without eSignet publishes the eSignet metadata")
	}
}
