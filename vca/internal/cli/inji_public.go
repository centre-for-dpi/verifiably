// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"net/url"
	"strings"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// The browser reaches some containers of the Inji stack itself: the
// eSignet login page, Inji Web, and Inji Verify. Their addresses follow
// the deployment, a base domain or the host ports, so vca setup writes
// them into the .env of each Inji pair that runs the container. Compose
// reads the .env of the pair, so every pair that starts a container
// passes it the same address.
const (
	// EsignetPublicURLEnv is the compose variable of the address of the
	// eSignet login page. eSignet puts it in its tokens and its
	// metadata, and Certify checks the issuer of a token against it.
	EsignetPublicURLEnv = "INJI_ESIGNET_PUBLIC_URL"
	// injiAuthorizationServerEnv names eSignet in an authorization code
	// offer of the Inji adapter.
	injiAuthorizationServerEnv = "VCA_INJI_AUTHORIZATION_SERVER"
)

// injiIssuer is the Inji issuer pair. It publishes the eSignet login
// page on its host, as it owns the Keycloak site of the stack.
var injiIssuer = Pair{Role: commonv1.Role_ROLE_ISSUER, Dpg: configv1.Dpg_DPG_INJI}

// runsEsignet reports an Inji pair whose profile runs eSignet and its
// login page.
func runsEsignet(p Pair) bool {
	return p.Dpg == configv1.Dpg_DPG_INJI && (p.Role == commonv1.Role_ROLE_ISSUER || p.Role == commonv1.Role_ROLE_HOLDER)
}

// InjiPublicValues returns the compose variables and adapter settings
// that carry the browser addresses of the Inji stack for one pair.
// values are the settings of the run, domain the base domain, and peers
// the .env values of the other pair directories.
func InjiPublicValues(p Pair, values map[string]string, domain string, peers PeerOverrides) map[string]string {
	out := map[string]string{}
	if !runsEsignet(p) {
		return out
	}
	esignet := esignetPublicURL(p, values, domain, peers)
	out[EsignetPublicURLEnv] = esignet
	if p.Role == commonv1.Role_ROLE_ISSUER {
		out[injiAuthorizationServerEnv] = esignet
	}
	return out
}

// esignetPublicURL returns the address of the eSignet login page. The
// Inji issuer pair publishes the page on its host. A pair that knows no
// issuer host, or an issuer on a local host, names the host port.
func esignetPublicURL(p Pair, values map[string]string, domain string, peers PeerOverrides) string {
	issuerURL := ""
	switch {
	case p == injiIssuer:
		issuerURL = values["VCA_PUBLIC_URL"]
	case peers[injiIssuer.Name()]["VCA_PUBLIC_URL"] != "":
		issuerURL = peers[injiIssuer.Name()]["VCA_PUBLIC_URL"]
	case domain != "":
		issuerURL = PairPublicURL(injiIssuer, domain)
	}
	if origin := originOf(issuerURL); origin != "" && !isLocalHost(hostOf(origin)) {
		return origin
	}
	return hostPortURL(values["VCA_PUBLIC_URL"], esignetUIPort.Host)
}

// originOf returns the scheme and the host of an absolute URL, or empty.
func originOf(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// hostPortURL returns the address of a host port on the host of the
// public URL, or on localhost for a local or missing host.
func hostPortURL(public string, port int) string {
	host := hostOf(public)
	if host == "" || isLocalHost(host) {
		host = "localhost"
	}
	return fmt.Sprintf("http://%s:%d", host, port)
}
