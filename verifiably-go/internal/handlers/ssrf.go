package handlers

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/verifiably/verifiably-go/internal/outbound"
)

// ssrfBlockHost looks up host and returns an error if any resolved IP falls
// in a private, loopback, link-local, or cloud-metadata range.
// Call this before making any outbound HTTP request whose destination is
// user-controlled (SSRF prevention).
func ssrfBlockHost(host string) error {
	addrs, err := net.LookupHost(host)
	if err != nil {
		return fmt.Errorf("cannot resolve %q: %w", host, err)
	}
	blocked := []string{
		"127.0.0.0/8",    // loopback
		"::1/128",        // IPv6 loopback
		"169.254.0.0/16", // link-local / cloud metadata (AWS, GCP, Azure)
		"fe80::/10",      // IPv6 link-local
		"10.0.0.0/8",     // private
		"172.16.0.0/12",  // private
		"192.168.0.0/16", // private
		"fc00::/7",       // IPv6 unique local
		"0.0.0.0/8",      // this network
		"100.64.0.0/10",  // shared address space (carrier-grade NAT)
	}
	for _, cidr := range blocked {
		_, network, _ := net.ParseCIDR(cidr)
		for _, addr := range addrs {
			if network.Contains(net.ParseIP(addr)) {
				return fmt.Errorf("host %q resolves to a reserved address", host)
			}
		}
	}
	return nil
}

// validateOfferURL returns an error if raw is an https:// URL whose host
// resolves to a private address. openid-credential-offer:// URIs pass
// through without validation — they carry the offer payload inline and
// do not trigger an outbound HTTP fetch.
func validateOfferURL(raw string) error {
	if !strings.HasPrefix(raw, "https://") {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("missing host")
	}
	return ssrfBlockHost(host)
}

// The shared 30s client that used to live here is gone: every outbound call it
// served now goes through internal/outbound, which keeps the timeout and adds
// the checks a bare client cannot make -- the address is re-checked at dial
// time, and redirects are re-checked per hop. See (*H).outbound below.

// outbound returns the policy this handler set makes requests under: its own
// when a caller (or a test) supplied one, otherwise the process-wide policy
// main() installed from the environment.
func (h *H) outbound() *outbound.Policy {
	if h != nil && h.Outbound != nil {
		return h.Outbound
	}
	return outbound.Default()
}
