// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"slices"
	"sort"
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
	// InjiWebPublicURLEnv is the compose variable of the address of Inji
	// Web. Mimoto builds its redirects from it.
	InjiWebPublicURLEnv = "INJI_WEB_PUBLIC_URL"
	// injiWebURLEnv tells the Inji adapter where a holder claims.
	injiWebURLEnv = "VCA_INJI_WEB_URL"
	// mimotoLoginURLEnv is the browser address of the stack Keycloak,
	// where Inji Web signs the holder in through Mimoto.
	mimotoLoginURLEnv = "INJI_MIMOTO_HOLDER_LOGIN_URL"
	// InjiVerifyPublicURLEnv is the compose variable of the address of
	// the Inji Verify service. A wallet posts its presentation there.
	InjiVerifyPublicURLEnv = "INJI_VERIFY_PUBLIC_URL"
	// injiVerifyDidHostEnv is the host of the did:web of Inji Verify.
	injiVerifyDidHostEnv = "INJI_VERIFY_DID_HOST"
	// InjiVerifyUIPublicURLEnv is the address of the Inji Verify page.
	// The trusted verifiers of Mimoto name it as the client.
	InjiVerifyUIPublicURLEnv = "INJI_VERIFY_UI_PUBLIC_URL"
)

// The containers of the Inji stack that a browser or a wallet opens,
// with the host ports of the stack file.
var (
	injiWebPort      = DpgPort{Container: "inji-web", Host: 17085, Env: "INJI_WEB_HOST_PORT", Port: 3004}
	injiVerifyPort   = DpgPort{Container: "inji-verify-service", Host: 17086, Env: "INJI_VERIFY_SERVICE_HOST_PORT", Port: 8080}
	injiVerifyUIPort = DpgPort{Container: "inji-verify-ui", Host: 17087, Env: "INJI_VERIFY_UI_HOST_PORT", Port: 8000}
	injiVerifyRoles  = []commonv1.Role{commonv1.Role_ROLE_ISSUER, commonv1.Role_ROLE_VERIFIER}
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
	if p.Dpg != configv1.Dpg_DPG_INJI {
		return out
	}
	public := values["VCA_PUBLIC_URL"]
	if runsEsignet(p) {
		esignet := esignetPublicURL(p, values, domain, peers)
		out[EsignetPublicURLEnv] = esignet
		if p.Role == commonv1.Role_ROLE_ISSUER {
			out[injiAuthorizationServerEnv] = esignet
		}
	}
	if isInjiHolder(p) {
		web := containerPublicURL(injiWebPort, domain, public)
		out[InjiWebPublicURLEnv] = web
		out[injiWebURLEnv] = web
		if login := strings.TrimRight(values["VCA_OIDC_PUBLIC_URL"], "/"); login != "" {
			out[mimotoLoginURLEnv] = login
		}
	}
	if slices.Contains(injiVerifyRoles, p.Role) {
		verify := verifyPublicURL(InjiVerifyPublicURLEnv, injiVerifyPort, domain, public, peers)
		out[InjiVerifyPublicURLEnv] = verify
		out[injiVerifyDidHostEnv] = didWebHost(verify)
	}
	if p.Role == commonv1.Role_ROLE_VERIFIER {
		out[InjiVerifyUIPublicURLEnv] = containerPublicURL(injiVerifyUIPort, domain, public)
	}
	return out
}

// injiVerifier is the Inji verifier pair. It publishes Inji Verify and
// its page under a base domain.
var injiVerifier = Pair{Role: commonv1.Role_ROLE_VERIFIER, Dpg: configv1.Dpg_DPG_INJI}

// verifyPublicURL returns an address of Inji Verify. The verifier pair
// of the deployment decides it, so a pair that finds the verifier pair
// directory takes its value. Otherwise the domain or the host port does.
func verifyPublicURL(env string, port DpgPort, domain, public string, peers PeerOverrides) string {
	if v := strings.TrimRight(peers[injiVerifier.Name()][env], "/"); v != "" {
		return v
	}
	return containerPublicURL(port, domain, public)
}

// containerPublicURL returns the address of a container of the stack
// that a browser opens. A base domain gives the container a host name
// of its own, which the Caddyfile of the pair that runs it publishes.
// Without one, the browser opens the host port on the host of the pair.
func containerPublicURL(port DpgPort, domain, public string) string {
	if domain != "" {
		return "https://" + port.Container + "." + domain
	}
	return hostPortURL(public, port.Host)
}

// didWebHost returns the host part of a did:web for an address: the
// host, and the port encoded as %3A when the address names one.
func didWebHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	if port := u.Port(); port != "" {
		return u.Hostname() + "%3A" + port
	}
	return u.Hostname()
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

// The files of Mimoto that vca setup writes into MimotoDir. The stack
// file mounts them in Mimoto and in Inji Web (P6-I7h).
const (
	// MimotoIssuersFile is the issuer list of Mimoto and Inji Web.
	MimotoIssuersFile = "mimoto-issuers-config.json"
	// MimotoVerifiersFile is the list of verifiers that Mimoto trusts.
	MimotoVerifiersFile = "mimoto-trusted-verifiers.json"
	// injiCertifyEsignetURL is the root of inji-certify-esignet on the
	// compose network, where Mimoto reads the issuer metadata.
	injiCertifyEsignetURL = "http://inji-certify-nginx:8091"
	// esignetInternalURL is eSignet on the compose network.
	esignetInternalURL = "http://inji-esignet:8088"
	// mimotoIssuerID names the Certify of the stack in Inji Web.
	mimotoIssuerID = "InjiCertify"
)

// mimotoIssuer is one issuer of the issuer list, in the structure of the
// "Mimoto Issuers Configuration" of the Inji Web 0.16.0 compose README.
type mimotoIssuer struct {
	IssuerID              string          `json:"issuer_id"`
	CredentialIssuer      string          `json:"credential_issuer"`
	Display               []mimotoDisplay `json:"display"`
	Protocol              string          `json:"protocol"`
	ClientID              string          `json:"client_id"`
	ClientAlias           string          `json:"client_alias"`
	WellknownEndpoint     string          `json:"wellknown_endpoint"`
	RedirectURI           string          `json:"redirect_uri"`
	AuthorizationAudience string          `json:"authorization_audience"`
	TokenEndpoint         string          `json:"token_endpoint"`
	ProxyTokenEndpoint    string          `json:"proxy_token_endpoint"`
	QRCodeType            string          `json:"qr_code_type"`
	CredentialIssuerHost  string          `json:"credential_issuer_host"`
	Enabled               string          `json:"enabled"`
}

// mimotoDisplay is the display of one issuer in Inji Web.
type mimotoDisplay struct {
	Name string `json:"name"`
	Logo struct {
		URL     string `json:"url"`
		AltText string `json:"alt_text"`
	} `json:"logo"`
	Language    string `json:"language"`
	Title       string `json:"title"`
	Description string `json:"description"`
}

// mimotoVerifier is one verifier that Mimoto trusts, in the structure of
// mimoto-trusted-verifiers.json of the Mimoto 0.21.0 compose folder.
type mimotoVerifier struct {
	ClientID      string   `json:"client_id"`
	RedirectURIs  []string `json:"redirect_uris"`
	ResponseURIs  []string `json:"response_uris"`
	JwksURI       string   `json:"jwks_uri"`
	AllowUnsigned bool     `json:"allow_unsigned_request"`
}

// mimotoFiles renders the issuer list and the trusted verifiers of the
// Inji holder pair from the addresses of the deployment. values holds
// the settings of the run with the values of InjiPublicValues.
func mimotoFiles(values map[string]string, domain string, peers PeerOverrides) ([]File, error) {
	web := injiWebURL(values)
	esignet := strings.TrimRight(values[EsignetPublicURLEnv], "/")
	if esignet == "" {
		esignet = hostPortURL("", esignetUIPort.Host)
	}
	display := mimotoDisplay{
		Name: "Inji Certify", Language: "en", Title: "Inji Certify of this stack",
		Description: "Claim a credential of the Inji Certify of this stack",
	}
	display.Logo.URL = "https://inji.github.io/inji-config/logos/mosipid-logo.png"
	display.Logo.AltText = "The logo of the issuer"
	issuers := map[string][]mimotoIssuer{"issuers": {{
		IssuerID: mimotoIssuerID, CredentialIssuer: mimotoIssuerID, Display: []mimotoDisplay{display},
		Protocol: "OpenId4VCI", ClientID: EsignetClientID, ClientAlias: EsignetClientID,
		WellknownEndpoint:     injiCertifyEsignetURL + "/.well-known/openid-credential-issuer",
		RedirectURI:           web + "/redirect",
		AuthorizationAudience: esignet + esignetPath + "/oauth/v2/token",
		TokenEndpoint:         web + "/v1/mimoto/get-token/" + mimotoIssuerID,
		ProxyTokenEndpoint:    esignetInternalURL + esignetPath + "/oauth/v2/token",
		QRCodeType:            "EmbeddedVC", CredentialIssuerHost: injiCertifyEsignetURL, Enabled: "true",
	}}}
	public := values["VCA_PUBLIC_URL"]
	service := verifyPublicURL(InjiVerifyPublicURLEnv, injiVerifyPort, domain, public, peers)
	page := verifyPublicURL(InjiVerifyUIPublicURLEnv, injiVerifyUIPort, domain, public, peers)
	verifiers := map[string][]mimotoVerifier{"verifiers": {{
		ClientID: page, RedirectURIs: []string{page + "/"},
		ResponseURIs: []string{service + "/v1/verify/vp-submission/vp-direct-post"},
		JwksURI:      service + "/.well-known/jwks.json",
		// Inji Verify 0.16.0 sends an unsigned request when its page
		// takes no submission (VP_SUBMISSION_SUPPORTED=false).
		AllowUnsigned: true,
	}}}
	var out []File
	for name, doc := range map[string]any{MimotoIssuersFile: issuers, MimotoVerifiersFile: verifiers} {
		raw, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("render %s: %w", name, err)
		}
		// Mimoto and the nginx of Inji Web read the files, and neither
		// holds a secret.
		out = append(out, File{Name: filepath.Join(MimotoDir, name), Data: append(raw, '\n'), Mode: 0o644})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// dpgSite is a container of the stack that a base domain puts on a host
// of its own.
type dpgSite struct {
	// Env is the variable of its public address.
	Env string
	// Port is the container and its host port.
	Port DpgPort
}

// dpgSites lists the containers of a pair that get a host of their own
// under a base domain: Inji Web for the Inji holder, and Inji Verify and
// its page for the Inji verifier.
func dpgSites(p Pair) []dpgSite {
	switch {
	case isInjiHolder(p):
		return []dpgSite{{Env: InjiWebPublicURLEnv, Port: injiWebPort}}
	case p == injiVerifier:
		return []dpgSite{{Env: InjiVerifyPublicURLEnv, Port: injiVerifyPort}, {Env: InjiVerifyUIPublicURLEnv, Port: injiVerifyUIPort}}
	default:
		return nil
	}
}

// dpgSiteBlocks renders the site of each container of dpgSites whose
// public address is a host of its own. A local address needs none.
func dpgSiteBlocks(p Pair, values map[string]string) string {
	var b strings.Builder
	for _, site := range dpgSites(p) {
		public := values[site.Env]
		host := hostOf(public)
		if host == "" || isLocalHost(host) || !strings.HasPrefix(public, "https://") {
			continue
		}
		fmt.Fprintf(&b, "\n# %s of the %s stack. The browser reaches it here.\n", site.Port.Container, ShortName(p.Dpg.String()))
		fmt.Fprintf(&b, "%s {\n\treverse_proxy 127.0.0.1:%d\n}\n", host, portFrom(values, site.Port.Env, site.Port.Host))
	}
	return b.String()
}
