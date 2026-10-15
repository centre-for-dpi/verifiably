// SPDX-License-Identifier: Apache-2.0

package cli

import (
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// A wallet opens some containers of the walt.id stack itself: the
// issuer API names itself in every credential offer and in its issuer
// metadata, and the verifier APIs name themselves in every presentation
// request. Their addresses follow the deployment, a base domain or the
// host ports, so vca setup writes them into the .env of the pair that
// runs the container, and the stack file passes each one as the base
// URL of its container.
const (
	// WaltidIssuerBaseURLEnv is the compose variable of the address of
	// the walt.id issuer API that a wallet opens.
	WaltidIssuerBaseURLEnv = "WALTID_ISSUER_BASE_URL"
	// WaltidVerifierBaseURLEnv is the compose variable of the address of
	// the walt.id verifier API that a wallet opens.
	WaltidVerifierBaseURLEnv = "WALTID_VERIFIER_BASE_URL"
	// WaltidVerifier2BaseURLEnv is the compose variable of the address of
	// walt.id verifier API 2 that a wallet opens.
	WaltidVerifier2BaseURLEnv = "WALTID_VERIFIER2_BASE_URL"
)

// The containers of the walt.id stack that a wallet opens, with the host
// ports of the stack file.
var (
	waltidIssuerPort    = DpgPort{Container: "waltid-issuer-api", Host: 17002, Env: "WALTID_ISSUER_HOST_PORT", Port: 7002}
	waltidVerifierPort  = DpgPort{Container: "waltid-verifier-api", Host: 17003, Env: "WALTID_VERIFIER_HOST_PORT", Port: 7003}
	waltidVerifier2Port = DpgPort{Container: "waltid-verifier-api2", Host: 17004, Env: "WALTID_VERIFIER2_HOST_PORT", Port: 7004}
)

// waltidSites lists the containers of a walt.id pair that a wallet
// opens: the issuer API of the issuer pair, and both verifier APIs of
// the verifier pair. Under a base domain each gets a host of its own.
func waltidSites(p Pair) []dpgSite {
	if p.Dpg != configv1.Dpg_DPG_WALTID {
		return nil
	}
	switch p.Role {
	case commonv1.Role_ROLE_ISSUER:
		return []dpgSite{{Env: WaltidIssuerBaseURLEnv, Port: waltidIssuerPort}}
	case commonv1.Role_ROLE_VERIFIER:
		return []dpgSite{{Env: WaltidVerifierBaseURLEnv, Port: waltidVerifierPort}, {Env: WaltidVerifier2BaseURLEnv, Port: waltidVerifier2Port}}
	default:
		return nil
	}
}

// WaltidPublicValues returns the compose variables that carry the
// wallet facing addresses of the walt.id stack for one pair: the base
// URL of each container of waltidSites. values are the settings of the
// run and domain the base domain. A pair of another DPG gets nothing.
func WaltidPublicValues(p Pair, values map[string]string, domain string) map[string]string {
	out := map[string]string{}
	for _, site := range waltidSites(p) {
		out[site.Env] = containerPublicURL(site.Port, domain, values["VCA_PUBLIC_URL"])
	}
	return out
}
