// SPDX-License-Identifier: Apache-2.0

package peertest_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	// Open lists the Connect services linked into the test.
	_ "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/peerauth"
	"github.com/centre-for-dpi/vc-adapters/internal/peerauth/peertest"
)

func TestTheKitSignsWhatItsServicesTrust(t *testing.T) {
	k := peertest.New(t)
	callee := k.Open("trust-registry", "admin")
	var got []http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = append(got, r.Header.Clone())
	}))
	defer srv.Close()
	for _, c := range []*http.Client{k.Client(srv.Client()), k.Client(nil)} {
		for _, path := range []string{"/readyz", "/vca.trust.v1.TrustService/GetEntry"} {
			res, err := c.Post(srv.URL+path, "application/json", strings.NewReader("{}"))
			if err != nil {
				t.Fatal(err)
			}
			if err := res.Body.Close(); err != nil {
				t.Fatal(err)
			}
		}
	}
	if got[0].Get(peerauth.TokenHeader) != "" || got[2].Get(peerauth.TokenHeader) != "" {
		t.Error("a plain path was signed")
	}
	for _, h := range []http.Header{got[1], got[3]} {
		if id, err := callee.Check(h, "/vca.trust.v1.TrustService/GetEntry"); err != nil || id.Service != peertest.Caller {
			t.Errorf("Check = %v, %v", id, err)
		}
	}
	admin := k.Identity("admin", nil)
	h, err := admin.Header("/vca.trust.v1.TrustService/GetEntry")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := callee.Check(h, "/vca.trust.v1.TrustService/GetEntry"); err != nil {
		t.Errorf("an extra caller was refused: %v", err)
	}
}

func TestAFixedKitWorksWithoutATest(t *testing.T) {
	k := peertest.Fixed()
	callee := k.Open("trust-registry")
	h, err := k.Identity(peertest.Caller, nil).Header("/vca.trust.v1.TrustService/GetEntry")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := callee.Check(h, "/vca.trust.v1.TrustService/GetEntry"); err != nil {
		t.Fatal(err)
	}
	if k.Client(nil) == nil {
		t.Fatal("no client")
	}
}

// recorder notes a fatal failure instead of stopping the test.
type recorder struct {
	testing.TB
	failed bool
}

func (r *recorder) Fatal(...any) { r.failed = true }
func (r *recorder) Helper()      {}

func TestAKitReportsAFailedIssue(t *testing.T) {
	r := &recorder{TB: t}
	peertest.New(r).Identity("", nil)
	if !r.failed {
		t.Error("an identity with no name did not fail the test")
	}
	defer func() {
		if recover() == nil {
			t.Error("a fixed kit did not panic")
		}
	}()
	peertest.Fixed().Identity("", nil)
}

func TestSignPutsTheHeadersOnARequest(t *testing.T) {
	k := peertest.New(t)
	r := httptest.NewRequest(http.MethodPost, "/vca.trust.v1.TrustService/GetEntry", nil)
	k.Sign(r)
	if _, err := k.Open("trust-registry").Check(r.Header, r.URL.Path); err != nil {
		t.Fatal(err)
	}
}
