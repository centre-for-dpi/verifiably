// SPDX-License-Identifier: Apache-2.0

// Package authz is the holder authorization server of the Inji adapter
// (ADR-052). Inji Certify checks every access token against one issuer
// and one key set. The container inji-certify-authcode trusts this
// server: a wallet or Inji Web signs the holder in here, and the token
// names the row of the VCA claims store that the adapter wrote for that
// holder (ADR-051 decision 5).
//
// The server speaks the authorization code grant of RFC 6749 with PKCE
// S256 only (RFC 7636), publishes RFC 8414 metadata and a key set, and
// authenticates a wallet client as a public client or with
// private_key_jwt (RFC 7523). It signs the holder in at the holder
// provider of the provider registry through oidcflow. It hands out one
// time codes bound to the client, the redirect URI and the PKCE
// challenge of the request, and RS256 access tokens from a key that it
// keeps sealed with the pair session key.
package authz

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// Scope is the one scope of every credential configuration the adapter
// registers (ADR-051 decision 3). A token of this server carries it.
const Scope = "vca_credential"

// The lifetimes of the records of a claim.
const (
	// RequestTTL bounds the sign in of the holder: from the authorization
	// request to the callback of the provider.
	RequestTTL = 10 * time.Minute
	// CodeTTL bounds an authorization code. RFC 6749 section 4.1.2
	// recommends at most ten minutes. A wallet trades it at once.
	CodeTTL = time.Minute
	// TokenTTL bounds an access token. The wallet calls the credential
	// endpoint of Certify right after the token endpoint.
	TokenTTL = 5 * time.Minute
	// NonceTTL is the life of the c_nonce of a token.
	NonceTTL = 5 * time.Minute
	// maxAssertionLife bounds the exp of a client assertion, so a stolen
	// assertion works for minutes at most.
	maxAssertionLife = 10 * time.Minute
	// minKeySecret is the least length of the pair session key.
	minKeySecret = 16
)

// The paths of the server under its issuer.
const (
	MetadataPath  = "/.well-known/oauth-authorization-server"
	JWKSPath      = "/.well-known/jwks.json"
	AuthorizePath = "/authorize"
	CallbackPath  = "/callback"
	TokenPath     = "/token"
)

// Binding ties an offer to one person: the value of a claim of the ID
// token of the holder must equal the value of a claim of the subject.
type Binding struct {
	// TokenClaim is the claim of the ID token.
	TokenClaim string
	// SubjectClaim is the claim of the staged subject.
	SubjectClaim string
}

// Offer is an open authorization code offer of the issuer.
type Offer struct {
	// ConfigID is the credential configuration of the offer.
	ConfigID string
	// Subject holds the staged claims.
	Subject map[string]any
	// Binding says who may claim it.
	Binding Binding
}

// Offers is the issuer side of a claim. The service of the adapter
// implements it.
type Offers interface {
	// Offer returns an open offer by its id, the issuer_state of the
	// offer document. A claimed or expired offer is not open.
	Offer(ctx context.Context, id string) (Offer, bool)
	// StageOffer writes the claims row of the offer under key and
	// closes the offer. A second call for the same offer fails.
	StageOffer(ctx context.Context, id, key string) error
	// StageSubject writes a claims row of one configuration under key.
	// subject is a JSON object of the claims.
	StageSubject(ctx context.Context, configID, subject, key string) error
	// Unstage removes the claims row under key.
	Unstage(ctx context.Context, key string) error
}

// SignInSource says how a claim that no offer names finds its subject:
// the source field whose value equals a claim of the ID token.
type SignInSource struct {
	// ConfigID is the credential configuration.
	ConfigID string `json:"config_id"`
	// SourceID is the VCA data source.
	SourceID string `json:"source_id"`
	// Field is the source field that identifies the person.
	Field string `json:"field"`
	// TokenClaim is the claim of the ID token that holds the value.
	TokenClaim string `json:"token_claim"`
	// SchemaID and SchemaVersion name the field map of the source.
	SchemaID      string `json:"schema_id,omitempty"`
	SchemaVersion int32  `json:"schema_version,omitempty"`
}

// Lookup finds the subject of a claim that no offer names. The data
// source service implements it through DataSourceService.Lookup.
type Lookup interface {
	// Lookup returns the claims of the row whose field holds value, as
	// a JSON object, and false when no single row holds it.
	Lookup(ctx context.Context, src SignInSource, value string) (string, bool, error)
}

// Options configure a Server.
type Options struct {
	// Issuer is the public address of the server: the public URL of the
	// adapter with /authz. Tokens and metadata carry it. Required.
	Issuer string
	// Audience is the credential endpoint of the Certify that trusts
	// the server. Required.
	Audience string
	// Store keeps the token key, the clients, and the short lived
	// records. Required.
	Store store.KeyValue
	// KeySecret is the pair session key. It seals the token key in the
	// store. At least 16 bytes.
	KeySecret []byte
	// Clients are the wallet clients the operator registered.
	Clients []Client
	// Registry holds the login providers. The server signs the holder in
	// at the default enabled provider of the holder role. Required.
	Registry *oidcflow.Registry
	// Flow runs the login at the provider. Required.
	Flow *oidcflow.Flow
	// Offers is the issuer side of a claim. Required.
	Offers Offers
	// Lookup finds the subject of a wallet initiated claim. Nil turns
	// that mode off.
	Lookup Lookup
	// Stack is the short name of the stack. A provider limited to other
	// stacks does not serve it. Empty means inji.
	Stack string
	// Now reads the clock. Nil reads the real clock.
	Now func() time.Time
	// Log receives the refusals. Nil means slog.Default.
	Log *slog.Logger
}

// Server is the holder authorization server.
type Server struct {
	issuer   string
	audience string
	kv       store.KeyValue
	registry *oidcflow.Registry
	flow     *oidcflow.Flow
	offers   Offers
	lookup   Lookup
	stack    string
	now      func() time.Time
	log      *slog.Logger
	key      tokenKey
	clients  map[string]Client
}

// New checks the options and loads the token key, or makes and seals
// one on the first start.
func New(ctx context.Context, opts Options) (*Server, error) {
	issuer := strings.TrimRight(strings.TrimSpace(opts.Issuer), "/")
	if u, err := url.Parse(issuer); issuer == "" || err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("authz: the issuer %q is not an absolute URL", opts.Issuer)
	}
	switch {
	case strings.TrimSpace(opts.Audience) == "":
		return nil, errors.New("authz: no audience; name the credential endpoint of the Certify that trusts this server")
	case opts.Store == nil:
		return nil, errors.New("authz: no store")
	case len(opts.KeySecret) < minKeySecret:
		return nil, fmt.Errorf("authz: the pair session key has %d bytes, fewer than %d", len(opts.KeySecret), minKeySecret)
	case opts.Registry == nil:
		return nil, errors.New("authz: no provider registry")
	case opts.Flow == nil:
		return nil, errors.New("authz: no login flow")
	case opts.Offers == nil:
		return nil, errors.New("authz: no issuer side")
	}
	clients := map[string]Client{}
	for _, c := range opts.Clients {
		if err := c.validate(); err != nil {
			return nil, err
		}
		clients[c.ID] = c
	}
	s := &Server{
		issuer: issuer, audience: opts.Audience, kv: opts.Store, registry: opts.Registry, flow: opts.Flow,
		offers: opts.Offers, lookup: opts.Lookup, stack: opts.Stack, now: opts.Now, log: opts.Log, clients: clients,
	}
	if s.stack == "" {
		s.stack = "inji"
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	key, err := loadKey(ctx, opts.Store, opts.KeySecret)
	if err != nil {
		return nil, err
	}
	s.key = key
	return s, nil
}

// Issuer returns the issuer of the server. An authorization code offer
// names it as its authorization server.
func (s *Server) Issuer() string { return s.issuer }

// Handler serves the endpoints at the paths under the issuer. The
// caller strips the path of the issuer.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+MetadataPath, s.metadata)
	mux.HandleFunc("GET "+JWKSPath, s.jwks)
	mux.HandleFunc("GET "+AuthorizePath, s.authorize)
	mux.HandleFunc("GET "+CallbackPath, s.callback)
	mux.HandleFunc("POST "+TokenPath, s.token)
	return mux
}

// metadata serves the RFC 8414 document. Mimoto 0.21.0 reads the
// authorization and token endpoints and the grant types here.
func (s *Server) metadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                s.issuer,
		"authorization_endpoint":                s.issuer + AuthorizePath,
		"token_endpoint":                        s.issuer + TokenPath,
		"jwks_uri":                              s.issuer + JWKSPath,
		"grant_types_supported":                 []string{"authorization_code"},
		"response_types_supported":              []string{"code"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none", "private_key_jwt"},
		"token_endpoint_auth_signing_alg_values_supported": assertionAlgNames(),
		"scopes_supported": []string{Scope},
		"authorization_response_iss_parameter_supported": true,
	})
}

// jwks serves the public key of the token key.
func (s *Server) jwks(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"keys": []any{s.key.public}})
}

// holderProvider returns the provider the holder signs in at: the
// enabled provider of the holder role for this stack that setup seeded,
// else the first one by id.
func (s *Server) holderProvider() (oidcflow.Provider, bool) {
	var found []oidcflow.Provider
	for _, p := range s.registry.Enabled() {
		if !contains(p.Roles, "holder") {
			continue
		}
		if len(p.Stacks) > 0 && !contains(p.Stacks, s.stack) {
			continue
		}
		if p.IsDefault {
			return p, true
		}
		found = append(found, p)
	}
	if len(found) == 0 {
		return oidcflow.Provider{}, false
	}
	return found[0], true
}

func contains(list []string, v string) bool {
	for _, item := range list {
		if strings.EqualFold(item, v) {
			return true
		}
	}
	return false
}

// SetSignInSource stores the holder sign in source of one credential
// configuration (ADR-052 decision 3).
func (s *Server) SetSignInSource(ctx context.Context, src SignInSource) error {
	if strings.TrimSpace(src.ConfigID) == "" || strings.TrimSpace(src.SourceID) == "" ||
		strings.TrimSpace(src.Field) == "" || strings.TrimSpace(src.TokenClaim) == "" {
		return errors.New("authz: a sign in source needs the configuration, the source, the field, and the ID token claim")
	}
	return putJSON(ctx, s.kv, signInKey(src.ConfigID), src)
}

// signInSources returns every stored sign in source.
func (s *Server) signInSources(ctx context.Context) ([]SignInSource, error) {
	keys, err := s.kv.List(ctx, signInPrefix)
	if err != nil {
		return nil, err
	}
	out := make([]SignInSource, 0, len(keys))
	for _, k := range keys {
		var src SignInSource
		if ok, gerr := getJSON(ctx, s.kv, k, &src); gerr != nil || !ok {
			continue
		}
		out = append(out, src)
	}
	return out, nil
}

// writeJSON answers with a JSON body that no cache keeps.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	// A failed write leaves the client without an answer; nothing else
	// can be done.
	anyval.Discard(json.NewEncoder(w).Encode(v))
}
