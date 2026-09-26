// SPDX-License-Identifier: Apache-2.0

// Package issuers reads the credentials that issuers publish when the
// deployment runs no verifier discovery service (spec HO1). It crawls
// the OpenID4VCI issuer metadata of the live issuer pairs and of the
// issuers on the trust list, and it names the ways a holder can claim
// each credential from the grants the metadata names.
//
// Every read goes through a fetcher of core/fetchguard, which guards
// against server side request forgery and caches each document. A live
// pair is read at its internal address, which the operator names in
// VCA_PEERS. A trusted issuer is read at its public address.
package issuers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/fetchguard"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1/trustv1connect"
	walletportalv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/cards"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/present"
)

// Well known paths of the documents the crawler reads.
const (
	// MetadataPath is the OpenID4VCI credential issuer metadata.
	MetadataPath = "/.well-known/openid-credential-issuer"
	// OAuthPath is the metadata of an OAuth authorization server (RFC 8414).
	OAuthPath = "/.well-known/oauth-authorization-server"
	// OpenIDPath is the metadata of an OpenID provider.
	OpenIDPath = "/.well-known/openid-configuration"
)

// Grant types of OAuth and OpenID4VCI.
const (
	GrantAuthorizationCode = "authorization_code"
	GrantPreAuthorized     = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
)

// PageSize and MaxPages bound the read of the trust list.
const (
	PageSize = 100
	MaxPages = 20
)

// Getter reads one document. A fetchguard.Fetcher is one.
type Getter interface {
	Get(ctx context.Context, url string) (fetchguard.Doc, error)
}

// Source is one issuer the crawler reads.
type Source struct {
	// Endpoint is the base URL the crawler reads the metadata from.
	Endpoint string
	// Public is the public URL of the issuer, when it differs from
	// Endpoint. The trust list names this address.
	Public string
	// Name is the name of the trust list entry, when any.
	Name string
	// Trusted says that an active trust list entry names the issuer.
	Trusted bool
	// Peer says that the source is a live pair of the deployment, read
	// through the internal fetcher.
	Peer bool
	// Channels are the issuance channels the adapter of a live pair lists.
	Channels []backendv1.Channel
}

// Options configure a Crawler.
type Options struct {
	// Peers returns the live issuer pairs. Nil means none.
	Peers func(ctx context.Context) []Source
	// Trust lists the trusted issuers. Nil means none.
	Trust trustv1connect.TrustServiceClient
	// Lookup asks the trust registry about an issuer that no entry of the
	// list names by address. Nil leaves the outcome unknown.
	Lookup cards.TrustLookup
	// Internal reads the documents of a live pair. Nil skips the pairs.
	Internal Getter
	// Public reads the documents of a trusted issuer and of an
	// authorization server. Nil skips them.
	Public Getter
}

// Crawler reads the issuers.
type Crawler struct {
	opts Options
}

// New returns a crawler.
func New(opts Options) (*Crawler, error) {
	return &Crawler{opts: opts}, nil
}

// Offerings returns one offering per credential configuration of every
// issuer that answers. An issuer that does not answer drops out, so one
// broken issuer does not hide the others.
func (c *Crawler) Offerings(ctx context.Context) ([]*walletportalv1.Offering, error) {
	var out []*walletportalv1.Offering
	for _, src := range c.sources(ctx) {
		getter := c.opts.Public
		if src.Peer {
			getter = c.opts.Internal
		}
		m, err := c.metadata(ctx, getter, src.Endpoint)
		if err != nil {
			continue
		}
		out = append(out, c.offerings(ctx, src, m)...)
	}
	return out, nil
}

// Methods returns the ways to claim from one issuer, from its metadata
// and the metadata of its authorization server. A live pair is read at
// its internal address. An issuer that does not answer gives none.
func (c *Crawler) Methods(ctx context.Context, issuer string) []walletportalv1.ClaimMethod {
	src := c.source(ctx, issuer)
	m, err := c.metadata(ctx, src.getter, src.endpoint)
	if err != nil {
		return nil
	}
	return merge(c.grants(ctx, m, issuer), src.channels)
}

// located is where the crawler reads one issuer.
type located struct {
	getter   Getter
	endpoint string
	channels []backendv1.Channel
}

// source returns where to read an issuer: the internal address of a live
// pair whose public URL it is, or else the issuer URL itself.
func (c *Crawler) source(ctx context.Context, issuer string) located {
	out := located{getter: c.opts.Public, endpoint: issuer}
	if c.opts.Peers != nil {
		for _, src := range c.opts.Peers(ctx) {
			if same(src.Public, issuer) {
				out = located{getter: c.opts.Internal, endpoint: src.Endpoint, channels: src.Channels}
			}
		}
	}
	return out
}

// sources returns the live pairs and the trusted issuers. A trusted
// issuer that is also a live pair counts once, with the name and the
// trust of the list.
func (c *Crawler) sources(ctx context.Context) []Source {
	var out []Source
	if c.opts.Peers != nil {
		out = append(out, c.opts.Peers(ctx)...)
	}
	for _, e := range c.trusted(ctx) {
		merged := false
		for i := range out {
			if same(out[i].Public, e.Endpoint) || same(out[i].Endpoint, e.Endpoint) {
				out[i].Name, out[i].Trusted, merged = e.Name, true, true
			}
		}
		if !merged {
			out = append(out, e)
		}
	}
	return out
}

// trusted reads the active issuer entries of the trust list that name
// a service endpoint. A trust registry that does not answer gives none.
func (c *Crawler) trusted(ctx context.Context) []Source {
	if c.opts.Trust == nil {
		return nil
	}
	var out []Source
	token := ""
	for page := 0; page < MaxPages; page++ {
		resp, err := c.opts.Trust.ListEntries(ctx, connect.NewRequest(&trustv1.ListEntriesRequest{
			Page: &commonv1.Pagination{PageSize: PageSize, PageToken: token},
			Role: commonv1.Role_ROLE_ISSUER, Status: trustv1.Status_STATUS_ACTIVE,
		}))
		if err != nil {
			return out
		}
		for _, e := range resp.Msg.GetEntries() {
			if e.GetServiceEndpoint() == "" {
				continue
			}
			endpoint := strings.TrimRight(e.GetServiceEndpoint(), "/")
			out = append(out, Source{Endpoint: endpoint, Public: endpoint, Name: e.GetDisplayName(), Trusted: true})
		}
		if token = resp.Msg.GetPage().GetNextPageToken(); token == "" {
			break
		}
	}
	return out
}

// offerings maps the configurations of one issuer onto offerings.
func (c *Crawler) offerings(ctx context.Context, src Source, m Metadata) []*walletportalv1.Offering {
	issuer := m.CredentialIssuer
	if issuer == "" {
		issuer = strings.TrimRight(firstOf(src.Public, src.Endpoint), "/")
	}
	name := firstOf(src.Name, m.Name, hostOf(issuer))
	trust := trustv1.TrustLookupResponse_OUTCOME_UNKNOWN
	if src.Trusted {
		trust = trustv1.TrustLookupResponse_OUTCOME_TRUSTED
	} else if c.opts.Lookup != nil {
		if got, err := c.opts.Lookup(ctx, issuer, ""); err == nil && got.Outcome != trustv1.TrustLookupResponse_OUTCOME_UNSPECIFIED {
			trust = got.Outcome
			name = firstOf(src.Name, got.Name, m.Name, hostOf(issuer))
		}
	}
	methods := merge(c.grants(ctx, m, issuer), src.Channels)
	out := make([]*walletportalv1.Offering, 0, len(m.Configurations))
	for _, conf := range m.Configurations {
		format := present.FormatOf(conf.Format)
		schema := &schemav1.PublicSchema{
			Id: conf.ID, Type: conf.Type, Formats: []commonv1.Format{format},
			ConfigurationIds: map[string]string{format.String(): conf.ID},
		}
		for _, d := range conf.Display {
			schema.Display = append(schema.Display, &schemav1.Display{Name: d.Name, Locale: d.Locale})
		}
		out = append(out, &walletportalv1.Offering{
			CredentialIssuer: issuer, IssuerName: name, Trust: trust, Schema: schema,
			ClaimMethods: methods,
		})
	}
	return out
}

// grants returns the ways to claim that the metadata of the issuer, or
// else of its authorization server, names.
func (c *Crawler) grants(ctx context.Context, m Metadata, issuer string) []walletportalv1.ClaimMethod {
	if len(m.GrantTypes) > 0 || m.AnonymousPreAuth {
		return MethodsOf(m.GrantTypes, m.AnonymousPreAuth)
	}
	server := issuer
	if len(m.AuthorizationServers) > 0 {
		server = m.AuthorizationServers[0]
	}
	for _, path := range []string{OAuthPath, OpenIDPath} {
		doc, err := get(ctx, c.opts.Public, strings.TrimRight(server, "/")+path)
		if err != nil {
			continue
		}
		var as authServer
		if json.Unmarshal(doc.Body, &as) != nil {
			continue
		}
		if len(as.GrantTypes) == 0 {
			// RFC 8414 section 2: an authorization server that names no
			// grant type supports the authorization code grant.
			as.GrantTypes = []string{GrantAuthorizationCode}
		}
		return MethodsOf(as.GrantTypes, as.AnonymousPreAuth)
	}
	return nil
}

// metadata reads and parses the issuer metadata under one endpoint.
func (c *Crawler) metadata(ctx context.Context, getter Getter, endpoint string) (Metadata, error) {
	doc, err := get(ctx, getter, strings.TrimRight(endpoint, "/")+MetadataPath)
	if err != nil {
		return Metadata{}, err
	}
	return ReadMetadata(doc.Body)
}

// errNoFetcher reports a read with no fetcher.
var errNoFetcher = errors.New("issuers: no fetcher for this source")

// get reads one document with getter, or fails without one.
func get(ctx context.Context, getter Getter, url string) (fetchguard.Doc, error) {
	if getter == nil {
		return fetchguard.Doc{}, errNoFetcher
	}
	return getter.Get(ctx, url)
}

// MethodsOf maps OAuth grant types onto the ways to claim, sign in at
// the issuer first. anonymous is the pre-authorized_grant_anonymous_access_supported
// flag of the authorization server.
func MethodsOf(grants []string, anonymous bool) []walletportalv1.ClaimMethod {
	var code, preAuth bool
	for _, g := range grants {
		switch g {
		case GrantAuthorizationCode:
			code = true
		case GrantPreAuthorized:
			preAuth = true
		}
	}
	var out []walletportalv1.ClaimMethod
	if code {
		out = append(out, walletportalv1.ClaimMethod_CLAIM_METHOD_AUTHORIZATION_CODE)
	}
	if preAuth || anonymous {
		out = append(out, walletportalv1.ClaimMethod_CLAIM_METHOD_PRE_AUTHORIZED_CODE)
	}
	return out
}

// merge adds the channels a live adapter lists to the ways to claim, in
// the order of MethodsOf.
func merge(methods []walletportalv1.ClaimMethod, channels []backendv1.Channel) []walletportalv1.ClaimMethod {
	var grants []string
	for _, m := range methods {
		switch m {
		case walletportalv1.ClaimMethod_CLAIM_METHOD_AUTHORIZATION_CODE:
			grants = append(grants, GrantAuthorizationCode)
		case walletportalv1.ClaimMethod_CLAIM_METHOD_PRE_AUTHORIZED_CODE:
			grants = append(grants, GrantPreAuthorized)
		}
	}
	for _, ch := range channels {
		switch ch {
		case backendv1.Channel_CHANNEL_OID4VCI_AUTHCODE:
			grants = append(grants, GrantAuthorizationCode)
		case backendv1.Channel_CHANNEL_OID4VCI_PREAUTH:
			grants = append(grants, GrantPreAuthorized)
		}
	}
	return MethodsOf(grants, false)
}

// Metadata is the part of the issuer metadata the wallet reads.
type Metadata struct {
	// CredentialIssuer is the issuer URL.
	CredentialIssuer string
	// Name is the display name of the issuer, when the metadata has one.
	Name string
	// AuthorizationServers lists the authorization servers of the issuer.
	AuthorizationServers []string
	// GrantTypes lists the grant types, when the issuer names them in
	// its own metadata.
	GrantTypes []string
	// AnonymousPreAuth says that a pre-authorized code needs no client.
	AnonymousPreAuth bool
	// Configurations are the credential configurations, by id.
	Configurations []Configuration
}

// Configuration is one credential configuration.
type Configuration struct {
	// ID is the configuration id.
	ID string
	// Type is the credential type: the vct, the doctype, the last W3C
	// type, the scope, or the id.
	Type string
	// Format is the OID4VCI format identifier.
	Format string
	// Display is the display metadata.
	Display []Display
}

// Display is one display entry.
type Display struct {
	Name   string `json:"name"`
	Locale string `json:"locale"`
}

// document is the JSON shape of the metadata.
type document struct {
	CredentialIssuer     string                     `json:"credential_issuer"`
	Display              []Display                  `json:"display"`
	AuthorizationServers []string                   `json:"authorization_servers"`
	GrantTypes           []string                   `json:"grant_types_supported"`
	AnonymousPreAuth     bool                       `json:"pre-authorized_grant_anonymous_access_supported"`
	Configurations       map[string]json.RawMessage `json:"credential_configurations_supported"`
	Legacy               map[string]json.RawMessage `json:"credentials_supported"`
}

// authServer is the part of the authorization server metadata the
// wallet reads.
type authServer struct {
	GrantTypes       []string `json:"grant_types_supported"`
	AnonymousPreAuth bool     `json:"pre-authorized_grant_anonymous_access_supported"`
	Authorization    string   `json:"authorization_endpoint"`
	Token            string   `json:"token_endpoint"`
	Interactive      string   `json:"interactive_authorization_endpoint"`
}

// Endpoints are the two addresses of the authorization code flow.
type Endpoints struct {
	// Authorization is where the browser signs in.
	Authorization string
	// Token is where the wallet trades the code for an access token.
	Token string
	// Interactive is the interactive authorization endpoint of OID4VCI,
	// where an issuer asks for a presentation before it gives a code.
	// Empty when the server has none.
	Interactive string
}

// ErrNoEndpoints reports an issuer whose authorization server names no
// authorization endpoint or no token endpoint.
var ErrNoEndpoints = errors.New("issuers: the authorization server names no endpoints")

// Endpoints returns the authorization and token endpoints of the first
// authorization server of an issuer, or of the issuer itself.
func (c *Crawler) Endpoints(ctx context.Context, issuer string) (Endpoints, error) {
	src := c.source(ctx, issuer)
	m, err := c.metadata(ctx, src.getter, src.endpoint)
	if err != nil {
		return Endpoints{}, err
	}
	server := issuer
	if len(m.AuthorizationServers) > 0 {
		server = m.AuthorizationServers[0]
	}
	for _, path := range []string{OAuthPath, OpenIDPath} {
		doc, err := get(ctx, c.opts.Public, strings.TrimRight(server, "/")+path)
		if err != nil {
			continue
		}
		var as authServer
		if json.Unmarshal(doc.Body, &as) != nil || as.Authorization == "" || as.Token == "" {
			continue
		}
		return Endpoints{Authorization: as.Authorization, Token: as.Token, Interactive: as.Interactive}, nil
	}
	return Endpoints{}, ErrNoEndpoints
}

// Server returns the endpoints of one authorization server, as a
// credential offer names it. It reads the metadata under the address
// rules of the public fetcher. A server with a token endpoint and an
// interactive endpoint needs no authorization endpoint.
func (c *Crawler) Server(ctx context.Context, server string) (Endpoints, error) {
	for _, path := range []string{OAuthPath, OpenIDPath} {
		doc, err := get(ctx, c.opts.Public, strings.TrimRight(server, "/")+path)
		if err != nil {
			continue
		}
		var as authServer
		if json.Unmarshal(doc.Body, &as) != nil || as.Token == "" || (as.Authorization == "" && as.Interactive == "") {
			continue
		}
		return Endpoints{Authorization: as.Authorization, Token: as.Token, Interactive: as.Interactive}, nil
	}
	return Endpoints{}, ErrNoEndpoints
}

// configuration is the JSON shape of one configuration.
type configuration struct {
	Format     string    `json:"format"`
	Vct        string    `json:"vct"`
	Doctype    string    `json:"doctype"`
	Scope      string    `json:"scope"`
	Display    []Display `json:"display"`
	Definition struct {
		Type []string `json:"type"`
	} `json:"credential_definition"`
}

// ReadMetadata parses the issuer metadata. A configuration with no
// format drops out. The configurations come in id order.
func ReadMetadata(raw []byte) (Metadata, error) {
	var d document
	if err := json.Unmarshal(raw, &d); err != nil {
		return Metadata{}, fmt.Errorf("issuers: the metadata does not parse: %w", err)
	}
	m := Metadata{
		CredentialIssuer: strings.TrimRight(d.CredentialIssuer, "/"), AuthorizationServers: d.AuthorizationServers,
		GrantTypes: d.GrantTypes, AnonymousPreAuth: d.AnonymousPreAuth,
	}
	if len(d.Display) > 0 {
		m.Name = d.Display[0].Name
	}
	configs := d.Configurations
	if len(configs) == 0 {
		configs = d.Legacy
	}
	ids := make([]string, 0, len(configs))
	for id := range configs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		var c configuration
		if json.Unmarshal(configs[id], &c) != nil || c.Format == "" {
			continue
		}
		conf := Configuration{ID: id, Format: c.Format, Display: c.Display}
		switch {
		case c.Vct != "":
			conf.Type = c.Vct
		case c.Doctype != "":
			conf.Type = c.Doctype
		case len(c.Definition.Type) > 0:
			conf.Type = c.Definition.Type[len(c.Definition.Type)-1]
		case c.Scope != "":
			conf.Type = c.Scope
		default:
			conf.Type = id
		}
		m.Configurations = append(m.Configurations, conf)
	}
	return m, nil
}

// same reports whether two base URLs name the same place.
func same(a, b string) bool {
	return a != "" && strings.TrimRight(a, "/") == strings.TrimRight(b, "/")
}

// firstOf returns the first value that is not empty.
func firstOf(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// hostOf returns the host of a URL, or the URL when it has none.
func hostOf(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Host
	}
	return raw
}
