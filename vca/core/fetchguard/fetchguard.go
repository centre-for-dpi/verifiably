// SPDX-License-Identifier: Apache-2.0

// Package fetchguard reads documents over HTTP with a guard against
// server side request forgery and a cache with a time to live and an
// entity tag (ADR-022 decision 1). Every service that reads a URL from
// a user or from another service shares it (ADR-002 decision 7).
//
// The guard refuses a URL that is not http or https, a URL with a user
// name, a port outside the allowed set, a host outside the allowed list,
// and a host that resolves to a private, loopback, link local, or
// multicast address. A deployment turns the private address rule off for
// development only.
package fetchguard

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ErrRefused reports that the guard refused the URL.
var ErrRefused = errors.New("fetchguard: the guard refused the URL")

// DefaultMaxBytes caps one document when the caller sets no limit.
const DefaultMaxBytes = 1 << 20

// Guard holds the rules of the fetcher.
type Guard struct {
	// AllowedHosts lists the host names the fetcher may reach. Empty
	// allows every host the address rules accept.
	AllowedHosts []string
	// AllowPrivateNetwork lets the fetcher reach private and loopback
	// addresses.
	AllowPrivateNetwork bool
	// AllowPlainHTTP lets the fetcher use http as well as https.
	AllowPlainHTTP bool
	// Resolve returns the addresses of a host. Nil means the system
	// resolver. Tests inject a fake.
	Resolve func(ctx context.Context, host string) ([]netip.Addr, error)
}

// Check reads the URL and reports whether the fetcher may reach it.
func (g Guard) Check(ctx context.Context, raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("%w: %s is not a URL", ErrRefused, raw)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !g.AllowPlainHTTP {
			return nil, fmt.Errorf("%w: %s is not https", ErrRefused, raw)
		}
	default:
		return nil, fmt.Errorf("%w: the scheme %q is not http or https", ErrRefused, u.Scheme)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%w: a URL with a user name is not allowed", ErrRefused)
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("%w: the URL has no host", ErrRefused)
	}
	if !g.hostAllowed(host) {
		return nil, fmt.Errorf("%w: the host %q is not on the allowed list", ErrRefused, host)
	}
	addrs, err := g.addresses(ctx, host)
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		if err := g.checkAddress(addr); err != nil {
			return nil, err
		}
	}
	return u, nil
}

// hostAllowed reports whether the host is on the allowed list. An empty
// list allows every host. An entry that starts with a dot matches the
// domain and every name below it.
func (g Guard) hostAllowed(host string) bool {
	if len(g.AllowedHosts) == 0 {
		return true
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, allowed := range g.AllowedHosts {
		allowed = strings.ToLower(strings.TrimSpace(allowed))
		if allowed == host {
			return true
		}
		if strings.HasPrefix(allowed, ".") && strings.HasSuffix(host, allowed) {
			return true
		}
	}
	return false
}

// addresses resolves the host, or reads it as a literal address.
func (g Guard) addresses(ctx context.Context, host string) ([]netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{addr}, nil
	}
	resolve := g.Resolve
	if resolve == nil {
		resolve = systemResolve
	}
	addrs, err := resolve(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot resolve %q: %v", ErrRefused, host, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("%w: %q resolves to no address", ErrRefused, host)
	}
	return addrs, nil
}

// systemResolve resolves a host with the system resolver.
func systemResolve(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// checkAddress reports whether the fetcher may reach one address.
func (g Guard) checkAddress(addr netip.Addr) error {
	if g.AllowPrivateNetwork {
		return nil
	}
	addr = addr.Unmap()
	switch {
	case addr.IsLoopback(), addr.IsPrivate(), addr.IsLinkLocalUnicast(), addr.IsLinkLocalMulticast(),
		addr.IsInterfaceLocalMulticast(), addr.IsMulticast(), addr.IsUnspecified():
		return fmt.Errorf("%w: %s is not a public address", ErrRefused, addr)
	}
	// 100.64.0.0/10 is the shared address space of carrier networks.
	if addr.Is4() && addr.As4()[0] == 100 && addr.As4()[1] >= 64 && addr.As4()[1] <= 127 {
		return fmt.Errorf("%w: %s is not a public address", ErrRefused, addr)
	}
	return nil
}

// Doc is one fetched document.
type Doc struct {
	// URL is the URL the fetcher read.
	URL string
	// Body is the document.
	Body []byte
	// ETag is the entity tag of the response, when the server sent one.
	ETag string
	// FetchedAt is the time of the last read from the server.
	FetchedAt time.Time
	// FromCache reports that the fetcher answered from its cache.
	FromCache bool
	// NotModified reports that the server answered 304 Not Modified.
	NotModified bool
}

// Options configure a fetcher.
type Options struct {
	// Guard holds the rules. The zero value allows every public host
	// over https.
	Guard Guard
	// Client performs the request. Nil means a client with Timeout.
	Client *http.Client
	// Timeout bounds one request. Zero means 10 seconds.
	Timeout time.Duration
	// TTL is how long a cached document stays fresh. Zero means the
	// fetcher always asks the server.
	TTL time.Duration
	// MaxBytes caps one document. Zero means DefaultMaxBytes.
	MaxBytes int
	// Accept is the Accept header. Empty means application/json.
	Accept string
	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
}

// Fetcher reads documents and caches them.
type Fetcher struct {
	opts  Options
	mu    sync.Mutex
	cache map[string]Doc
}

// New builds a fetcher.
func New(opts Options) *Fetcher {
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	if opts.Client == nil {
		opts.Client = &http.Client{Timeout: opts.Timeout}
	}
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = DefaultMaxBytes
	}
	if opts.Accept == "" {
		opts.Accept = "application/json"
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Fetcher{opts: opts, cache: map[string]Doc{}}
}

// Get reads one document. It answers from the cache while the document
// is fresh. It sends If-None-Match with the cached entity tag, so a
// server that answers 304 Not Modified costs one small response.
func (f *Fetcher) Get(ctx context.Context, raw string) (Doc, error) {
	u, err := f.opts.Guard.Check(ctx, raw)
	if err != nil {
		return Doc{}, err
	}
	key := u.String()
	now := f.opts.Now()
	cached, ok := f.cached(key)
	if ok && now.Sub(cached.FetchedAt) < f.opts.TTL {
		cached.FromCache = true
		return cached, nil
	}
	// The guard parsed the URL already, so the request needs no parse.
	req := (&http.Request{Method: http.MethodGet, URL: u, Header: http.Header{}}).WithContext(ctx)
	req.Header.Set("Accept", f.opts.Accept)
	if ok && cached.ETag != "" {
		req.Header.Set("If-None-Match", cached.ETag)
	}
	resp, err := f.opts.Client.Do(req)
	if err != nil {
		return Doc{}, fmt.Errorf("fetchguard: get %s: %w", key, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotModified && ok {
		cached.FetchedAt = now
		cached.NotModified = true
		f.store(key, cached)
		return cached, nil
	}
	if resp.StatusCode != http.StatusOK {
		return Doc{}, fmt.Errorf("fetchguard: %s answered %d", key, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(f.opts.MaxBytes)+1))
	if err != nil {
		return Doc{}, fmt.Errorf("fetchguard: read %s: %w", key, err)
	}
	if len(body) > f.opts.MaxBytes {
		return Doc{}, fmt.Errorf("fetchguard: %s is larger than %d bytes", key, f.opts.MaxBytes)
	}
	doc := Doc{URL: key, Body: body, ETag: resp.Header.Get("ETag"), FetchedAt: now}
	f.store(key, doc)
	return doc, nil
}

// cached returns the cached document of a key.
func (f *Fetcher) cached(key string) (Doc, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	doc, ok := f.cache[key]
	return doc, ok
}

// store writes one document into the cache.
func (f *Fetcher) store(key string, doc Doc) {
	f.mu.Lock()
	defer f.mu.Unlock()
	doc.FromCache = false
	f.cache[key] = doc
}

// Forget removes one URL from the cache. The Crawl RPC uses it to force
// a read from the server.
func (f *Fetcher) Forget(raw string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.cache, raw)
}

// Size returns the number of cached documents.
func (f *Fetcher) Size() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.cache)
}
