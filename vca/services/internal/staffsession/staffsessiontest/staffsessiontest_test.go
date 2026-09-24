// SPDX-License-Identifier: Apache-2.0

package staffsessiontest_test

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession/staffsessiontest"
)

var now = time.Date(2026, 9, 24, 9, 0, 0, 0, time.UTC)

func TestIssuerMintsVerifiableTokens(t *testing.T) {
	issuer := staffsessiontest.New(t, staffsession.VerifierAudience, now)
	g, err := staffsession.New(staffsession.Options{
		Keys: issuer.Keys(), Audience: staffsession.VerifierAudience, Cookie: staffsession.VerifierCookie,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	s, err := g.Verify(context.Background(), issuer.Token(t, "kc|carol", "verifier-admin"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Subject != "kc|carol" || !s.HasRole("verifier-admin") || s.ID == "" {
		t.Fatalf("session %+v", s)
	}
	if !s.ExpiresAt.Equal(now.Add(staffsessiontest.TTL)) {
		t.Fatalf("expires %v", s.ExpiresAt)
	}
	if issuer.Issuer == "" || !strings.HasPrefix(issuer.Issuer, "https://") {
		t.Fatalf("issuer %q", issuer.Issuer)
	}
}

func TestJWKSFileAndServer(t *testing.T) {
	issuer := staffsessiontest.New(t, staffsession.IssuerAudience, now)
	raw, err := os.ReadFile(issuer.JWKSFile(t))
	if err != nil {
		t.Fatal(err)
	}
	set, err := jose.ParseJWKS(raw)
	if err != nil || len(set.Keys) != 1 {
		t.Fatalf("file: %v %d", err, len(set.Keys))
	}
	srv := issuer.Server(t)
	res, err := http.Get(srv.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cerr := res.Body.Close(); cerr != nil {
			t.Errorf("the close failed: %v", cerr)
		}
	}()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d", res.StatusCode)
	}
	if cookie := issuer.Cookie(staffsession.IssuerCookie, "tok"); cookie.Name != staffsession.IssuerCookie || cookie.Value != "tok" {
		t.Fatalf("cookie %+v", cookie)
	}
}
