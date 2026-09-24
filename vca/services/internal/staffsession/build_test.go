// SPDX-License-Identifier: Apache-2.0

package staffsession_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	sharedconfig "github.com/centre-for-dpi/vc-adapters/services/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession/staffsessiontest"
)

func TestSettingsLoadUnderAPrefix(t *testing.T) {
	values := map[string]string{
		"VCA_SCHEMA_AUTH_JWKS_URL": "http://issuer-auth:8081/.well-known/jwks.json",
		"VCA_SCHEMA_LOGIN_URL":     "https://issuer-waltid.example/auth/",
	}
	var s staffsession.Settings
	if err := sharedconfig.Load("VCA_SCHEMA_", &s, func(k string) string { return values[k] }); err != nil {
		t.Fatal(err)
	}
	if s.JWKSURL != values["VCA_SCHEMA_AUTH_JWKS_URL"] || s.LoginURL != values["VCA_SCHEMA_LOGIN_URL"] || s.JWKSTTL != 10*time.Minute {
		t.Fatalf("settings %+v", s)
	}
	if !s.Configured() || (staffsession.Settings{}).Configured() {
		t.Fatal("configured")
	}
	if err := s.Check("VCA_SCHEMA_"); err != nil {
		t.Fatal(err)
	}
	s.JWKSTTL = 0
	if err := s.Check("VCA_SCHEMA_"); err == nil || !strings.Contains(err.Error(), "VCA_SCHEMA_AUTH_JWKS_TTL") {
		t.Fatalf("check: %v", err)
	}
}

func TestBuildFromSettings(t *testing.T) {
	issuer := staffsessiontest.New(t, staffsession.VerifierAudience, now)
	realm, _ := staffsession.RealmOf(commonv1.Role_ROLE_VERIFIER)
	clock := func() time.Time { return now }
	token := issuer.Token(t, "kc|carol")

	t.Run("a JWKS URL", func(t *testing.T) {
		srv := issuer.Server(t)
		s := staffsession.Settings{JWKSURL: srv.URL + "/.well-known/jwks.json", JWKSTTL: time.Minute, Issuer: issuer.Issuer + "/"}
		g, err := staffsession.Build(s, realm, "VCA_INGEST_", staffsession.Deps{Client: srv.Client(), Now: clock})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := g.Verify(context.Background(), token); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("a JWKS file", func(t *testing.T) {
		s := staffsession.Settings{JWKSFile: issuer.JWKSFile(t), JWKSTTL: time.Minute}
		g, err := staffsession.Build(s, realm, "VCA_INGEST_", staffsession.Deps{Now: clock})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := g.Verify(context.Background(), token); err != nil {
			t.Fatal(err)
		}
		s.JWKSFile += ".missing"
		if _, err := staffsession.Build(s, realm, "VCA_INGEST_", staffsession.Deps{}); err == nil {
			t.Fatal("a missing file built")
		}
	})

	t.Run("injected keys win", func(t *testing.T) {
		s := staffsession.Settings{JWKSURL: "http://down.invalid/jwks", JWKSTTL: time.Minute}
		g, err := staffsession.Build(s, realm, "VCA_INGEST_", staffsession.Deps{Keys: issuer.Keys(), Now: clock})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := g.Verify(context.Background(), token); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("no key source fails closed", func(t *testing.T) {
		var logs bytes.Buffer
		log := slog.New(slog.NewTextHandler(&logs, nil))
		g, err := staffsession.Build(staffsession.Settings{JWKSTTL: time.Minute}, realm, "VCA_INGEST_", staffsession.Deps{Log: log, Now: clock})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := g.Verify(context.Background(), token); !errors.Is(err, staffsession.ErrNotConfigured) {
			t.Fatalf("verify: %v", err)
		}
		if !strings.Contains(logs.String(), "VCA_INGEST_AUTH_JWKS_URL") {
			t.Fatalf("log %q", logs.String())
		}
		rec := get(g.Wrap(echo()), "/scan/", token, nil)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status %d, want 401", rec.Code)
		}
	})

	t.Run("a bad TTL is a config error", func(t *testing.T) {
		if _, err := staffsession.Build(staffsession.Settings{}, realm, "VCA_INGEST_", staffsession.Deps{}); err == nil {
			t.Fatal("a zero TTL built")
		}
	})
}
