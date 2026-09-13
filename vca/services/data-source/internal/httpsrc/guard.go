// SPDX-License-Identifier: Apache-2.0

// Package httpsrc reads rows from an HTTP API behind an SSRF guard
// (ADR-015 decisions 1 and 6). The guard allows https only by default,
// checks the host against an allowlist, resolves the host, and refuses
// private, loopback, link local, and other special addresses. The client
// dials the checked address, so a DNS change after the check has no
// effect. Redirects are off. The body size and the request time have
// limits.
package httpsrc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Errors the guard returns.
var (
	ErrScheme      = errors.New("httpsrc: the URL scheme is not allowed")
	ErrHost        = errors.New("httpsrc: the host is not on the allowlist")
	ErrUserInfo    = errors.New("httpsrc: the URL must not carry a user name or password")
	ErrResolve     = errors.New("httpsrc: the host does not resolve")
	ErrPrivateIP   = errors.New("httpsrc: the host resolves to a private or special address")
	ErrNoAllowlist = errors.New("httpsrc: the allowlist is empty, the deployment allows no host")
)

// Guard decides which URLs the service may fetch.
type Guard struct {
	// AllowHosts lists the hosts the service may reach. An entry that
	// starts with a dot matches every subdomain, for example
	// ".gov.example". Other entries match one host. A host may carry
	// a port.
	AllowHosts []string
	// AllowHTTP permits the http scheme. Off by default.
	AllowHTTP bool
	// AllowPrivate permits private and loopback addresses. Off by
	// default. Turn it on only in a lab.
	AllowPrivate bool
	// LookupIP resolves a host name. Nil means net.DefaultResolver.
	LookupIP func(ctx context.Context, host string) ([]net.IP, error)
}

// Check parses rawURL and returns it with the addresses the client may
// dial. Every returned address passed the checks.
func (g Guard) Check(ctx context.Context, rawURL string) (*url.URL, []net.IP, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, nil, fmt.Errorf("httpsrc: parse URL: %w", err)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !g.AllowHTTP {
			return nil, nil, fmt.Errorf("%w: %s, use https", ErrScheme, u.Scheme)
		}
	default:
		return nil, nil, fmt.Errorf("%w: %q", ErrScheme, u.Scheme)
	}
	if u.User != nil {
		return nil, nil, ErrUserInfo
	}
	if u.Hostname() == "" {
		return nil, nil, fmt.Errorf("%w: empty host", ErrHost)
	}
	if err := g.checkAllowlist(u); err != nil {
		return nil, nil, err
	}
	ips, err := g.Resolve(ctx, u.Hostname())
	if err != nil {
		return nil, nil, err
	}
	return u, ips, nil
}

func (g Guard) checkAllowlist(u *url.URL) error {
	if len(g.AllowHosts) == 0 {
		return ErrNoAllowlist
	}
	host := strings.ToLower(u.Hostname())
	hostPort := strings.ToLower(u.Host)
	for _, a := range g.AllowHosts {
		a = strings.ToLower(strings.TrimSpace(a))
		switch {
		case a == "":
		case strings.HasPrefix(a, "."):
			if strings.HasSuffix(host, a) || host == a[1:] {
				return nil
			}
		case a == host || a == hostPort:
			return nil
		}
	}
	return fmt.Errorf("%w: %s", ErrHost, host)
}

// Resolve returns the addresses of host that pass the address checks.
// It fails when any address fails, so a host with one private address
// is refused as a whole.
func (g Guard) Resolve(ctx context.Context, host string) ([]net.IP, error) {
	var ips []net.IP
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		ips = []net.IP{ip}
	} else {
		lookup := g.LookupIP
		if lookup == nil {
			lookup = func(ctx context.Context, host string) ([]net.IP, error) {
				return net.DefaultResolver.LookupIP(ctx, "ip", host)
			}
		}
		var err error
		ips, err = lookup(ctx, host)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("%w: %s", ErrResolve, host)
		}
	}
	for _, ip := range ips {
		if !g.AllowPrivate && !IsPublic(ip) {
			return nil, fmt.Errorf("%w: %s", ErrPrivateIP, host)
		}
	}
	return ips, nil
}

// specialRanges are the address blocks IsPublic refuses beyond what the
// net package classifies.
var specialRanges = mustCIDRs(
	"0.0.0.0/8",          // this network
	"100.64.0.0/10",      // shared address space (RFC 6598)
	"192.0.0.0/24",       // IETF protocol assignments
	"192.0.2.0/24",       // documentation
	"198.18.0.0/15",      // benchmarking
	"198.51.100.0/24",    // documentation
	"203.0.113.0/24",     // documentation
	"240.0.0.0/4",        // reserved
	"255.255.255.255/32", // broadcast
	"64:ff9b::/96",       // NAT64
	"2001:db8::/32",      // documentation
)

// mustCIDRs parses fixed, well formed prefixes.
func mustCIDRs(cidrs ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, _ := net.ParseCIDR(c)
		out = append(out, n)
	}
	return out
}

// IsPublic reports whether ip is a global unicast address outside every
// private, loopback, link local, multicast, and special block.
func IsPublic(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() ||
		ip.IsInterfaceLocalMulticast() {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	for _, n := range specialRanges {
		if n.Contains(ip) {
			return false
		}
	}
	return true
}
