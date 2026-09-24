// SPDX-License-Identifier: Apache-2.0

package staffsession

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
)

// Settings are the variables of the guard. A service loads them with the
// shared config package under its own prefix, so the variables read
// VCA_<SERVICE>_AUTH_JWKS_URL and so on.
type Settings struct {
	// JWKSURL is the key set of the auth service of the role. The staff
	// pages accept only a session it signed (ADR-036 decisions 2 and 3).
	JWKSURL string `env:"AUTH_JWKS_URL"`
	// JWKSFile is a JWKS file that replaces JWKSURL, for a test or an
	// offline check.
	JWKSFile string `env:"AUTH_JWKS_FILE"`
	// JWKSTTL is how long a fetched key set stays fresh.
	JWKSTTL time.Duration `env:"AUTH_JWKS_TTL" default:"10m"`
	// Issuer is the iss claim every session must carry. Empty accepts
	// every issuer the key set signs for.
	Issuer string `env:"AUTH_ISSUER"`
	// LoginURL is the sign in chooser of the pair. A page request with
	// no session goes there with return_to. Empty answers 401 instead.
	LoginURL string `env:"LOGIN_URL"`
}

// Check reports a setting that is out of range. prefix names the
// variables in the message.
func (s Settings) Check(prefix string) error {
	if s.JWKSTTL <= 0 {
		return fmt.Errorf("config: %sAUTH_JWKS_TTL must be a positive duration such as 10m", prefix)
	}
	return nil
}

// Configured reports whether the settings name a key source.
func (s Settings) Configured() bool { return s.JWKSURL != "" || s.JWKSFile != "" }

// Deps are the side effects of Build. Tests inject fakes.
type Deps struct {
	// Keys replaces the key source of the settings. Tests set it.
	Keys Keys
	// ReadFile reads the JWKS file. Nil means os.ReadFile.
	ReadFile func(string) ([]byte, error)
	// Client fetches the JWKS URL. Nil means a client with a 10 second
	// timeout.
	Client *http.Client
	// MaxFormBytes caps the body the guard reads for the token of a
	// POST. Zero means DefaultMaxFormBytes.
	MaxFormBytes int64
	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
	// Log receives the start warning. Nil means slog.Default.
	Log *slog.Logger
}

// ErrNotConfigured reports a service with no auth service to check
// sessions against. The guard then lets no staff request through.
var ErrNotConfigured = errors.New("staffsession: no auth service key set is configured")

// Build returns the guard of a service from its settings. Without a key
// source the guard fails closed: every staff request goes to the sign
// in chooser or gets 401, and the log says which variable to set.
func Build(s Settings, realm Realm, prefix string, d Deps) (*Guard, error) {
	if err := s.Check(prefix); err != nil {
		return nil, err
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	keys := d.Keys
	var err error
	switch {
	case keys != nil:
	case s.JWKSFile != "":
		if keys, err = FileKeys(s.JWKSFile, d.ReadFile); err != nil {
			return nil, err
		}
	case s.JWKSURL != "":
		keys = CachedKeys(s.JWKSURL, s.JWKSTTL, d.Client, d.Now)
	default:
		d.Log.Warn("no auth service key set: the staff pages accept no session",
			"setting", prefix+"AUTH_JWKS_URL")
		keys = func(context.Context, bool) (jose.JWKS, error) { return jose.JWKS{}, ErrNotConfigured }
	}
	return New(Options{
		Keys: keys, Audience: realm.Audience, Issuer: strings.TrimRight(s.Issuer, "/"), Cookie: realm.Cookie,
		LoginURL: s.LoginURL, MaxFormBytes: d.MaxFormBytes, Now: d.Now,
	})
}
