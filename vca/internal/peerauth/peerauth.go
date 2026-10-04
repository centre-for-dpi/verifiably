// SPDX-License-Identifier: Apache-2.0

// Package peerauth checks which service of the deployment calls an
// internal Connect service (ADR-075). Setup makes one authority key per
// deployment and gives each service an identity: a key of its own and a
// statement, signed by the authority, that binds the name of the
// service to that key. A caller signs a token of 60 seconds for each
// call, with the procedure and the host of the callee as its audience.
// The callee checks the statement with the public key of the authority,
// the token with the key of the statement, the host against its own
// names, and the name of the caller against the callers it lists for
// the Connect service.
//
// The package holds no state. A Settings value carries everything.
package peerauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
)

// The variables of the identity file of one service. Each service gets
// a file of its own, so the names carry no service prefix.
const (
	// KeyFileEnv names the file that holds the private key of the
	// service, a JWK. The vca CLI mounts the file read only, as compose
	// and Helm allow, so the key stays out of the environment of the
	// container.
	KeyFileEnv = "VCA_PEER_KEY_FILE"
	// KeyEnv holds the private key itself, a JWK as base64url. It is the
	// fallback for a platform that cannot mount a file. The CLI never
	// writes it, because the environment shows in docker inspect and in
	// /proc/1/environ.
	KeyEnv = "VCA_PEER_KEY"
	// IdentityEnv holds the statement of the authority.
	IdentityEnv = "VCA_PEER_IDENTITY"
	// AuthorityEnv holds the public key set of the authority, as base64url.
	AuthorityEnv = "VCA_PEER_AUTHORITY"
	// CallersEnv holds the callers of each Connect service, as Callers
	// formats them.
	CallersEnv = "VCA_PEER_CALLERS"
	// HostsEnv names more hosts under which the callers reach the
	// service, joined by commas.
	HostsEnv = "VCA_PEER_HOSTS"
)

// The headers of a call.
const (
	// IdentityHeader carries the statement of the caller.
	IdentityHeader = "Vca-Peer-Identity"
	// TokenHeader carries the token of the call.
	TokenHeader = "Vca-Peer-Token" // #nosec G101 -- the name of a header, not a credential
)

// The token types and the issuer of a statement.
const (
	statementType = "vca-peer-id+jwt"
	tokenType     = "vca-peer+jwt" // #nosec G101 -- the type of a token, not a credential
	authorityName = "vca-peer-authority"
)

// TokenTTL is the life of the token of one call.
const TokenTTL = 60 * time.Second

// ClockSkew is the clock difference between two services that a token
// survives.
const ClockSkew = 30 * time.Second

// ErrNoIdentity reports a service that holds no identity, so it cannot
// sign a call.
var ErrNoIdentity = errors.New("peerauth: this service holds no peer identity")

var es256 = []jose.Algorithm{jose.ES256}

// ID names one service of a deployment.
type ID struct {
	// Service is the name of the service in the catalogue, such as
	// issuance. The callers lists name services this way.
	Service string
	// Pair is the role and DPG pair of the service under compose, or
	// the release under Helm. With Service it makes the default host
	// name of the service.
	Pair string
	// Deployment marks a deployment scoped caller, such as the vca
	// command or the landing. The authority writes it into the
	// statement. A callee takes the token of such a caller only at a
	// name of its own too. The vca command calls through a port that the
	// host publishes, so each service lists that port in Hosts.
	Deployment bool
}

// String names the caller for a log line.
func (id ID) String() string {
	if id.Pair == "" {
		return id.Service
	}
	return id.Pair + "/" + id.Service
}

// Settings are the peer settings of one service. The zero value signs
// nothing and refuses every caller.
type Settings struct {
	// Key signs the token of each call. Nil means no identity.
	Key *ecdsa.PrivateKey
	// Statement is the statement of the authority on Key.
	Statement string
	// ID is the subject of Statement.
	ID ID
	// Authority holds the public keys of the authority. A callee checks
	// each statement with them.
	Authority jose.JWKS
	// Callers lists the services that may call each Connect service of
	// this service.
	Callers Callers
	// Hosts are more names under which the callers reach this service,
	// beside the default name <pair>-<service>. A name with no port
	// stands for any port.
	Hosts []string
	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
}

// Configured reports whether the service holds an identity, so it can
// sign calls.
func (s Settings) Configured() bool { return s.Key != nil && s.Statement != "" }

func (s Settings) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// statementClaims is the payload of a statement.
type statementClaims struct {
	Issuer   string         `json:"iss"`
	Subject  string         `json:"sub"`
	Pair     string         `json:"pair,omitempty"`
	Scope    string         `json:"scope,omitempty"`
	IssuedAt int64          `json:"iat"`
	Confirm  map[string]any `json:"cnf"`
}

// deploymentScope is the scope claim of a deployment scoped statement.
const deploymentScope = "deployment"

// tokenClaims is the payload of the token of one call. The audience
// holds the procedure, then the host of the callee.
type tokenClaims struct {
	Issuer    string   `json:"iss"`
	Audience  []string `json:"aud"`
	IssuedAt  int64    `json:"iat"`
	ExpiresAt int64    `json:"exp"`
	ID        string   `json:"jti"`
}

// Authority is the key that vouches for every service of a deployment.
// Only the CLI on the machine of the operator holds it.
type Authority struct {
	key *ecdsa.PrivateKey
}

// NewAuthority makes a new authority key.
func NewAuthority(random io.Reader) (Authority, error) {
	key, err := newKey(random)
	if err != nil {
		return Authority{}, err
	}
	return Authority{key: key}, nil
}

// ParseAuthority reads an authority key in PKCS#8 PEM form.
func ParseAuthority(pemBytes []byte) (Authority, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return Authority{}, errors.New("peerauth: the authority key is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return Authority{}, fmt.Errorf("peerauth: the authority key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return Authority{}, errors.New("peerauth: the authority key is not an ECDSA key on P-256")
	}
	return Authority{key: key}, nil
}

// PEM returns the authority key in PKCS#8 PEM form.
func (a Authority) PEM() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(a.key)
	if err != nil {
		return nil, fmt.Errorf("peerauth: encode the authority key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// publicJWK returns the public key of the authority with its thumbprint
// as the key id.
func (a Authority) publicJWK() jose.JWK {
	// A P-256 key always gives a JWK and a thumbprint.
	jwk := anyval.Must(jose.PublicJWK(a.key, ""))
	jwk.KeyID = anyval.Must(jose.Thumbprint(jwk))
	return jwk
}

// PublicSet returns the public key set of the authority as the value of
// AuthorityEnv.
func (a Authority) PublicSet() string {
	// A set of one public key always encodes.
	raw := anyval.Must(json.Marshal(jose.JWKS{Keys: []jose.JWK{a.publicJWK()}}))
	return base64.RawURLEncoding.EncodeToString(raw)
}

// Issue makes the identity of one service: a new key and the statement
// of the authority on it. The settings it returns trust the authority
// and list no callers.
func (a Authority) Issue(id ID, random io.Reader, now time.Time) (Settings, error) {
	if strings.TrimSpace(id.Service) == "" {
		return Settings{}, errors.New("peerauth: an identity needs the name of the service")
	}
	key, err := newKey(random)
	if err != nil {
		return Settings{}, err
	}
	jwk, err := jose.PublicJWK(key, "")
	if err != nil {
		return Settings{}, fmt.Errorf("peerauth: %w", err)
	}
	cnf, err := jose.JWKToMap(jwk)
	if err != nil {
		return Settings{}, fmt.Errorf("peerauth: %w", err)
	}
	auth := a.publicJWK()
	claims := statementClaims{
		Issuer: authorityName, Subject: id.Service, Pair: id.Pair, IssuedAt: now.Unix(),
		Confirm: map[string]any{"jwk": cnf},
	}
	if id.Deployment {
		claims.Scope = deploymentScope
	}
	statement, err := jose.Sign(a.key, auth.KeyID, statementType, claims)
	if err != nil {
		return Settings{}, fmt.Errorf("peerauth: sign the statement: %w", err)
	}
	return Settings{Key: key, Statement: statement, ID: id, Authority: jose.JWKS{Keys: []jose.JWK{auth}}}, nil
}

// newKey makes an ECDSA key on P-256.
func newKey(random io.Reader) (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), random)
	if err != nil {
		return nil, fmt.Errorf("peerauth: generate a key: %w", err)
	}
	return key, nil
}

// Env returns the variables of the identity file of the service. The
// private key is not one of them: KeyJWK returns it for a file of its
// own, which KeyFileEnv names.
func (s Settings) Env() map[string]string {
	out := map[string]string{CallersEnv: s.Callers.String()}
	if len(s.Hosts) > 0 {
		out[HostsEnv] = strings.Join(s.Hosts, ",")
	}
	if len(s.Authority.Keys) > 0 {
		// Parsed or issued keys always encode.
		raw := anyval.Must(json.Marshal(s.Authority))
		out[AuthorityEnv] = base64.RawURLEncoding.EncodeToString(raw)
	}
	if s.Configured() {
		out[IdentityEnv] = s.Statement
	}
	return out
}

// KeyJWK returns the private key of the service as a JWK.
func (s Settings) KeyJWK() ([]byte, error) {
	if !s.Configured() {
		return nil, ErrNoIdentity
	}
	return json.Marshal(jose.JWK{Key: s.Key})
}

// Load reads the settings of a service with getenv, for example
// os.Getenv. No variable at all gives the zero value: a service with no
// identity, which refuses every caller. A key needs its statement and
// the authority, and the statement must name the key.
func Load(getenv func(string) string) (Settings, error) {
	var s Settings
	keyFile := strings.TrimSpace(getenv(KeyFileEnv))
	keyRaw := strings.TrimSpace(getenv(KeyEnv))
	statement := strings.TrimSpace(getenv(IdentityEnv))
	authRaw := strings.TrimSpace(getenv(AuthorityEnv))
	callers, err := ParseCallers(getenv(CallersEnv))
	if err != nil {
		return Settings{}, err
	}
	s.Callers = callers
	if s.Hosts, err = parseHosts(getenv(HostsEnv)); err != nil {
		return Settings{}, err
	}
	if authRaw != "" {
		raw, derr := base64.RawURLEncoding.DecodeString(authRaw)
		if derr != nil {
			return Settings{}, fmt.Errorf("peerauth: %s is not base64url: %w", AuthorityEnv, derr)
		}
		if s.Authority, err = jose.ParseJWKS(raw); err != nil {
			return Settings{}, fmt.Errorf("peerauth: %s: %w", AuthorityEnv, err)
		}
	}
	if keyFile != "" && keyRaw != "" {
		return Settings{}, fmt.Errorf("peerauth: set %s or %s, not both", KeyFileEnv, KeyEnv)
	}
	if keyFile == "" && keyRaw == "" && statement == "" {
		return s, nil
	}
	if (keyFile == "" && keyRaw == "") || statement == "" || authRaw == "" {
		return Settings{}, fmt.Errorf("peerauth: an identity needs %s, %s, and %s", KeyFileEnv, IdentityEnv, AuthorityEnv)
	}
	if keyFile != "" {
		data, rerr := os.ReadFile(keyFile) // #nosec G304 -- the operator names the file of the key
		if rerr != nil {
			return Settings{}, fmt.Errorf("peerauth: %s: %w", KeyFileEnv, rerr)
		}
		s.Key, err = parseJWK(data, KeyFileEnv)
	} else {
		s.Key, err = parseKey(keyRaw)
	}
	if err != nil {
		return Settings{}, err
	}
	id, pub, err := s.verifyStatement(statement)
	if err != nil {
		return Settings{}, fmt.Errorf("peerauth: %s: %w", IdentityEnv, err)
	}
	if !pub.Equal(s.Key.Public()) {
		return Settings{}, fmt.Errorf("peerauth: %s names another key than the key of the service", IdentityEnv)
	}
	s.Statement, s.ID = statement, id
	return s, nil
}

// parseHosts reads the value of HostsEnv. Empty gives no host.
func parseHosts(raw string) ([]string, error) {
	var out []string
	for _, h := range strings.Split(raw, ",") {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		if strings.ContainsAny(h, " \t/") {
			return nil, fmt.Errorf("peerauth: %s host %q is not a host", HostsEnv, h)
		}
		out = append(out, h)
	}
	return out, nil
}

// parseKey reads the private JWK of KeyEnv, as base64url.
func parseKey(raw string) (*ecdsa.PrivateKey, error) {
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("peerauth: %s is not base64url: %w", KeyEnv, err)
	}
	return parseJWK(data, KeyEnv)
}

// parseJWK reads a private JWK. from names its source in an error.
func parseJWK(data []byte, from string) (*ecdsa.PrivateKey, error) {
	var jwk jose.JWK
	if err := json.Unmarshal(data, &jwk); err != nil {
		return nil, fmt.Errorf("peerauth: %s is not a JWK: %w", from, err)
	}
	key, ok := jwk.Key.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("peerauth: %s is not a private ECDSA key on P-256", from)
	}
	return key, nil
}

// verifyStatement checks a statement with the authority and returns its
// subject and the key it names.
func (s Settings) verifyStatement(statement string) (ID, *ecdsa.PublicKey, error) {
	if len(s.Authority.Keys) == 0 {
		return ID{}, nil, errors.New("no authority to check the statement")
	}
	payload, hdr, err := jose.VerifyWithJWKS(statement, s.Authority, es256)
	if err != nil {
		return ID{}, nil, err
	}
	var c statementClaims
	if uerr := json.Unmarshal(payload, &c); uerr != nil {
		return ID{}, nil, fmt.Errorf("the statement: %w", uerr)
	}
	if hdr.Typ != statementType || c.Issuer != authorityName || c.Subject == "" {
		return ID{}, nil, errors.New("not a statement of the authority")
	}
	cnf := anyval.As[map[string]any](c.Confirm["jwk"])
	jwk, err := jose.JWKFromMap(cnf)
	if err != nil {
		return ID{}, nil, fmt.Errorf("the key of the statement: %w", err)
	}
	pub, ok := jwk.Key.(*ecdsa.PublicKey)
	if !ok || !jwk.IsPublic() {
		return ID{}, nil, errors.New("the statement names no public ECDSA key")
	}
	return ID{Service: c.Subject, Pair: c.Pair, Deployment: c.Scope == deploymentScope}, pub, nil
}

// Header returns the identity headers of one call of procedure to the
// callee at host, the host and port of the URL of the call.
func (s Settings) Header(procedure, host string) (http.Header, error) {
	if !s.Configured() {
		return nil, ErrNoIdentity
	}
	jti := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, jti); err != nil {
		return nil, fmt.Errorf("peerauth: %w", err)
	}
	now := s.now()
	token, err := jose.Sign(s.Key, "", tokenType, tokenClaims{
		Issuer: s.ID.Service, Audience: []string{procedure, strings.ToLower(host)}, IssuedAt: now.Unix(),
		ExpiresAt: now.Add(TokenTTL).Unix(), ID: base64.RawURLEncoding.EncodeToString(jti),
	})
	if err != nil {
		return nil, fmt.Errorf("peerauth: sign the token: %w", err)
	}
	h := http.Header{}
	h.Set(IdentityHeader, s.Statement)
	h.Set(TokenHeader, token)
	return h, nil
}

// unauthenticated wraps a reason as the Connect error of a caller with
// no valid identity.
func unauthenticated(format string, args ...any) error {
	return connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("peerauth: "+format, args...))
}

// Check returns the caller of one call of procedure from its headers.
// A missing or bad identity gives a Connect error with the code
// unauthenticated. A caller that the list does not name for the Connect
// service of procedure gives permission_denied.
func (s Settings) Check(h http.Header, procedure string) (ID, error) {
	if len(s.Authority.Keys) == 0 {
		return ID{}, unauthenticated("this service trusts no peer authority, so it refuses every caller")
	}
	statement, token := h.Get(IdentityHeader), h.Get(TokenHeader)
	if statement == "" || token == "" {
		return ID{}, unauthenticated("the call carries no peer identity")
	}
	id, pub, err := s.verifyStatement(statement)
	if err != nil {
		return ID{}, unauthenticated("the peer identity: %v", err)
	}
	payload, hdr, err := jose.Verify(token, pub, es256)
	if err != nil {
		return ID{}, unauthenticated("the token of %s: %v", id, err)
	}
	var c tokenClaims
	if err := json.Unmarshal(payload, &c); err != nil || hdr.Typ != tokenType {
		return ID{}, unauthenticated("the token of %s is not a peer token", id)
	}
	now := s.now()
	issued, expires := time.Unix(c.IssuedAt, 0), time.Unix(c.ExpiresAt, 0)
	audience, host := "", ""
	if len(c.Audience) == 2 {
		audience, host = c.Audience[0], c.Audience[1]
	}
	switch {
	case c.Issuer != id.Service:
		return ID{}, unauthenticated("the token names %q, the identity %q", c.Issuer, id.Service)
	case audience != procedure:
		return ID{}, unauthenticated("the token of %s is for %q, not %q", id, audience, procedure)
	case !s.ownHost(host):
		return ID{}, unauthenticated("the token of %s is for the host %q, which is no name of %s", id, host, s.ID)
	case expires.Sub(issued) > TokenTTL || expires.Before(issued):
		return ID{}, unauthenticated("the token of %s lives longer than %s", id, TokenTTL)
	case issued.After(now.Add(ClockSkew)), !now.Before(expires.Add(ClockSkew)):
		return ID{}, unauthenticated("the token of %s is outside its time: issued %s from now, the clocks may differ by %s",
			id, issued.Sub(now).Round(time.Second), ClockSkew)
	}
	service, _, _ := strings.Cut(strings.TrimPrefix(procedure, "/"), "/")
	if !s.Callers.Allows(service, id.Service) {
		return ID{}, connect.NewError(connect.CodePermissionDenied,
			fmt.Errorf("peerauth: %s may not call %s", id, service))
	}
	return id, nil
}

// ownHost reports whether host, as a token names it, is a name of this
// service: its default name <pair>-<service> as the first label, or one
// of Hosts. A name of Hosts with no port stands for any port.
func (s Settings) ownHost(host string) bool {
	if host == "" {
		return false
	}
	name := host
	if i := strings.LastIndex(host, ":"); i >= 0 && !strings.Contains(host[i:], "]") {
		name = host[:i]
	}
	label, _, _ := strings.Cut(name, ".")
	if own := s.defaultHost(); own != "" && label == own {
		return true
	}
	for _, h := range s.Hosts {
		if h == host || h == name {
			return true
		}
	}
	return false
}

// defaultHost is the name the compose file and the Helm charts give the
// service: <pair>-<service>, or the service alone with no pair.
func (s Settings) defaultHost() string {
	switch {
	case s.ID.Service == "":
		return ""
	case s.ID.Pair == "" || s.ID.Pair == s.ID.Service:
		return s.ID.Service
	}
	return s.ID.Pair + "-" + s.ID.Service
}

// Client returns a copy of c whose transport signs every Connect call.
// A nil c stands for a client with no timeout. A service with no
// identity gets a client that signs nothing.
func (s Settings) Client(c *http.Client) *http.Client {
	out := &http.Client{}
	if c != nil {
		copied := *c
		out = &copied
	}
	out.Transport = s.Transport(out.Transport)
	return out
}

// Sign returns a client that signs every Connect call of c. A
// *http.Client gets a copy with the transport of Transport; any other
// client gets a wrapper of its Do. A nil c stands for a client with no
// timeout.
func (s Settings) Sign(c connect.HTTPClient) connect.HTTPClient {
	switch hc := c.(type) {
	case nil:
		return s.Client(nil)
	case *http.Client:
		return s.Client(hc)
	default:
		return doer{next: c, rt: s.Transport(roundTripper{c})}
	}
}

// roundTripper sends a request with the Do of a Connect client.
type roundTripper struct{ c connect.HTTPClient }

// RoundTrip implements http.RoundTripper.
func (r roundTripper) RoundTrip(req *http.Request) (*http.Response, error) { return r.c.Do(req) }

// doer is the client of Sign for a client that is no *http.Client.
type doer struct {
	next connect.HTTPClient
	rt   http.RoundTripper
}

// Do signs a Connect call and sends it with the wrapped client.
func (d doer) Do(req *http.Request) (*http.Response, error) { return d.rt.RoundTrip(req) }

// Transport wraps base, or http.DefaultTransport when base is nil. It
// adds the identity headers to every Connect, gRPC, or gRPC-Web call
// whose path names a VCA procedure, and to no other request. A page
// fetch or a call of a DPG never carries the identity.
func (s Settings) Transport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return signer{base: base, s: s}
}

// signer is the transport of Transport.
type signer struct {
	base http.RoundTripper
	s    Settings
}

// RoundTrip signs a Connect call and sends it.
func (t signer) RoundTrip(r *http.Request) (*http.Response, error) {
	if !t.s.Configured() || !connectCall(r) {
		return t.base.RoundTrip(r)
	}
	h, err := t.s.Header(r.URL.Path, r.URL.Host)
	if err != nil {
		return nil, err
	}
	signed := r.Clone(r.Context())
	for name, values := range h {
		signed.Header[name] = values
	}
	return t.base.RoundTrip(signed)
}

// connectCall reports whether r is an RPC of a VCA Connect service, as
// a Connect client sends it.
func connectCall(r *http.Request) bool {
	if !strings.HasPrefix(r.URL.Path, "/vca.") {
		return false
	}
	ct := r.Header.Get("Content-Type")
	return r.Header.Get("Connect-Protocol-Version") != "" ||
		strings.HasPrefix(ct, "application/grpc") || strings.HasPrefix(ct, "application/connect+")
}

// callerKey keys the caller in a context.
type callerKey struct{}

// CallerFrom returns the caller that the interceptor checked.
func CallerFrom(ctx context.Context) (ID, bool) {
	id, ok := ctx.Value(callerKey{}).(ID)
	return id, ok
}

// Require returns the handler option that checks the caller of every
// RPC of a Connect service. Every Connect handler that stays on the
// compose network takes it (ADR-075 decision 3).
func Require(s Settings) connect.HandlerOption {
	return connect.WithInterceptors(guard{s: s})
}

// guard is the interceptor of Require.
type guard struct {
	s Settings
}

// WrapUnary checks the caller of a unary RPC.
func (g guard) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		id, err := g.s.Check(req.Header(), req.Spec().Procedure)
		if err != nil {
			return nil, err
		}
		return next(context.WithValue(ctx, callerKey{}, id), req)
	}
}

// WrapStreamingClient leaves a client stream as it is.
func (g guard) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

// WrapStreamingHandler checks the caller of a streaming RPC.
func (g guard) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		id, err := g.s.Check(conn.RequestHeader(), conn.Spec().Procedure)
		if err != nil {
			return err
		}
		return next(context.WithValue(ctx, callerKey{}, id), conn)
	}
}

// Callers maps the full name of a Connect service onto the services
// that may call it. A Connect service with no entry has no caller.
type Callers map[string][]string

// Allows reports whether caller may call the Connect service.
func (c Callers) Allows(service, caller string) bool {
	return caller != "" && slices.Contains(c[service], caller)
}

// String formats the list as the value of CallersEnv: one
// "<service>=<caller>,<caller>" item per Connect service, joined by
// semicolons, both in name order.
func (c Callers) String() string {
	names := make([]string, 0, len(c))
	for name := range c {
		names = append(names, name)
	}
	sort.Strings(names)
	items := make([]string, 0, len(names))
	for _, name := range names {
		callers := slices.Clone(c[name])
		sort.Strings(callers)
		items = append(items, name+"="+strings.Join(callers, ","))
	}
	return strings.Join(items, ";")
}

// ParseCallers reads the value of CallersEnv. Empty gives no callers.
func ParseCallers(raw string) (Callers, error) {
	out := Callers{}
	for _, item := range strings.Split(raw, ";") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		name, list, ok := strings.Cut(item, "=")
		name = strings.TrimSpace(name)
		if !ok || name == "" {
			return nil, fmt.Errorf("peerauth: %s item %q is not <service>=<callers>", CallersEnv, item)
		}
		if _, dup := out[name]; dup {
			return nil, fmt.Errorf("peerauth: %s names %s twice", CallersEnv, name)
		}
		callers := []string{}
		for _, caller := range strings.Split(list, ",") {
			caller = strings.TrimSpace(caller)
			if caller == "" {
				continue
			}
			if strings.ContainsAny(caller, " \t") {
				return nil, fmt.Errorf("peerauth: %s caller %q holds a space", CallersEnv, caller)
			}
			callers = append(callers, caller)
		}
		out[name] = callers
	}
	return out, nil
}
