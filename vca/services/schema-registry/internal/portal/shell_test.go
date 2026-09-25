// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffshell"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// TestUsesIssuerShell checks that every schema page draws inside the
// issuer shell: the role chip, the stack switcher of the live issuer
// pairs, the user menu of the session, and the side navigation of the
// issuer with the schemas page current (ADR-044 decision 5).
func TestUsesIssuerShell(t *testing.T) {
	svc, id := registry(t)
	waltid := topology.Peer{Pair: "issuer-waltid", Role: commonv1.Role_ROLE_ISSUER, Dpg: configv1.Dpg_DPG_WALTID,
		PublicURL: "https://issuer-waltid.labs.example", Services: map[string]string{"issuer-auth": "http://auth:8081"}}
	inji := topology.Peer{Pair: "issuer-inji", Role: commonv1.Role_ROLE_ISSUER, Dpg: configv1.Dpg_DPG_INJI,
		PublicURL: "https://issuer-inji.labs.example", Services: map[string]string{"issuer-auth": "http://auth-inji:8081"}}
	snap := topology.Snapshot{Peers: []topology.Status{{Peer: waltid, State: topology.Live}, {Peer: inji, State: topology.Live}}}
	shell := staffshell.New(staffshell.Options{
		Role: commonv1.Role_ROLE_ISSUER, Peers: []topology.Peer{waltid, inji},
		Snapshot: func(context.Context) topology.Snapshot { return snap },
		JWKSURL:  "http://auth:8081" + staffshell.JWKSPath, SignOut: "/portal/signout",
	})
	signedOut := false
	p, err := New(Options{Client: svc, Shell: shell, SignOut: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		signedOut = true
		w.WriteHeader(http.StatusSeeOther)
	})})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	p.Register(mux)
	sess := staffsession.Session{Subject: "kc|wanjiru", Name: "Wanjiru Kamau", CSRF: "c"}
	for _, path := range []string{"/portal/", "/portal/schemas/" + id, "/portal/schemas/" + id + "/versions"} {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r = r.WithContext(staffsession.With(r.Context(), sess))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, r)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d", path, rec.Code)
		}
		doc := rec.Body.String()
		a11ytest.AssertPage(t, doc)
		for _, want := range []string{
			`<span class="role-chip">Issuer</span>`, `href="/portal/" aria-current="page"`, `href="/issuer/"`,
			`href="https://issuer-inji.labs.example/issuer/"`, "Wanjiru Kamau", `action="/portal/signout"`,
		} {
			if !strings.Contains(doc, want) {
				t.Errorf("%s: the page lacks %q", path, want)
			}
		}
		if strings.Contains(doc, `aria-label="Schema registry"`) {
			t.Errorf("%s: the page still draws its own navigation", path)
		}
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/portal/signout", nil))
	if !signedOut {
		t.Fatal("the sign out form is not routed")
	}
}
