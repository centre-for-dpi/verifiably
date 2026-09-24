// SPDX-License-Identifier: Apache-2.0

// Package staffsessiontest mints staff session tokens for the tests of
// the guarded services. It stands in for the auth service of a role: it
// holds one ES256 key, signs session JWTs with it, and serves or writes
// the matching key set.
package staffsessiontest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
)

// TTL is the lifetime of every token an Issuer mints.
const TTL = 15 * time.Minute

// DefaultIssuer is the iss claim of the tokens of New.
const DefaultIssuer = "https://auth.test"

// Issuer signs session tokens like an auth service.
type Issuer struct {
	// Issuer is the iss claim of every token.
	Issuer string
	// Audience is the aud claim of every token.
	Audience string
	signer   *oidcflow.Signer
}

// New returns an issuer for audience whose clock stands at now.
func New(t testing.TB, audience string, now time.Time) *Issuer {
	t.Helper()
	return NewWithIssuer(t, DefaultIssuer, audience, now)
}

// NewWithIssuer is New with an explicit iss claim.
func NewWithIssuer(t testing.TB, issuer, audience string, now time.Time) *Issuer {
	t.Helper()
	// A fresh P-256 key always signs, so neither call can fail.
	key := anyval.Must(oidcflow.GenerateKey())
	signer := anyval.Must(oidcflow.NewSigner(key, issuer, audience, TTL, nil))
	signer.WithClock(func() time.Time { return now })
	return &Issuer{Issuer: issuer, Audience: audience, signer: signer}
}

// Token mints a session token for subject with roles.
func (i *Issuer) Token(t testing.TB, subject string, roles ...string) string {
	t.Helper()
	token, _, err := i.signer.Issue(oidcflow.Claims{Subject: subject, Roles: roles, Name: subject})
	anyval.MustDo(err)
	return token
}

// JWKS returns the public key set.
func (i *Issuer) JWKS() jose.JWKS { return i.signer.JWKS() }

// Keys returns the key set as a static key source.
func (i *Issuer) Keys() staffsession.Keys { return staffsession.StaticKeys(i.JWKS()) }

// JWKSFile writes the key set to a file in a test directory and
// returns its path.
func (i *Issuer) JWKSFile(t testing.TB) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "jwks.json")
	anyval.MustDo(os.WriteFile(path, anyval.Must(json.Marshal(i.JWKS())), 0o600))
	return path
}

// Server serves the key set at /.well-known/jwks.json until the test
// ends.
func (i *Issuer) Server(t testing.TB) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle("GET /.well-known/jwks.json", i.signer.JWKSHandler())
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// Cookie returns the session cookie a browser would send.
func (i *Issuer) Cookie(name, token string) *http.Cookie {
	return &http.Cookie{Name: name, Value: token}
}
