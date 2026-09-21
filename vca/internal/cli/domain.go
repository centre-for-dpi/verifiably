// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// DomainEnv is the variable that carries the base domain of a
// deployment. One wildcard DNS record, *.<domain>, then serves every
// pair on its own host name (ADR-007 decision 2, ADR-008 decision 2).
const DomainEnv = "VCA_DOMAIN"

// domainPattern is one DNS label, followed by one or more dotted labels.
var domainPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// ErrBadDomain reports a base domain that is not a bare DNS name.
var ErrBadDomain = errors.New("the domain must be a DNS name with no scheme, no port, and no path, for example labs.example")

// NormalizeDomain reads a base domain the operator typed. It drops a
// leading "*." or "https://", a trailing dot, and surrounding space, and
// lowers the case. An empty answer means no domain.
func NormalizeDomain(raw string) (string, error) {
	d := strings.ToLower(strings.TrimSpace(raw))
	if d == "" {
		return "", nil
	}
	for _, prefix := range []string{"https://", "http://", "*."} {
		d = strings.TrimPrefix(d, prefix)
	}
	d = strings.TrimSuffix(d, ".")
	if !domainPattern.MatchString(d) {
		return "", fmt.Errorf("%w: got %q", ErrBadDomain, raw)
	}
	return d, nil
}

// PairHost returns the host name of one pair under the base domain,
// for example issuer-waltid.labs.example.
func PairHost(p Pair, domain string) string { return p.Name() + "." + domain }

// PairPublicURL returns the public URL of one pair under the base
// domain. The reverse proxy of the host terminates TLS, so the scheme
// is https.
func PairPublicURL(p Pair, domain string) string { return "https://" + PairHost(p, domain) }

// KeycloakHost returns the host name of the Keycloak of one DPG stack
// under the base domain, for example waltid-keycloak.labs.example. It
// is empty for a DPG with no Keycloak.
func KeycloakHost(d configv1.Dpg, domain string) string {
	name := KeycloakContainer(d)
	if name == "" {
		return ""
	}
	return name + "." + domain
}

// KeycloakPublicURL returns the browser facing URL of the Keycloak of
// one DPG stack under the base domain.
func KeycloakPublicURL(d configv1.Dpg, domain string) string {
	host := KeycloakHost(d, domain)
	if host == "" {
		return ""
	}
	return "https://" + host
}

// applyDomain gives the public URL of the pair its host name under the
// base domain, unless a flag, the environment, an env file, or an
// answer named one. An empty domain changes nothing.
func applyDomain(list []Resolution, p Pair, domain string) []Resolution {
	if domain == "" {
		return list
	}
	out := make([]Resolution, len(list))
	copy(out, list)
	for i := range out {
		if out[i].Setting.Path != "public_url" || !opensAQuestion(out[i].Origin) {
			continue
		}
		out[i].Value, out[i].Origin = PairPublicURL(p, domain), OriginDomain
	}
	return out
}

// domainQuestion is the text of the one base domain question of a
// multi pair run.
const domainQuestion = "\nThe base domain of the deployment. Every pair gets its own host name " +
	"under it, for example https://issuer-waltid.<domain>. One wildcard DNS " +
	"record, *.<domain>, must point at this host.\n" +
	"Leave blank to answer one public URL per pair instead.\n" +
	"  Variable: " + DomainEnv + "\n" +
	"Base domain []: "

// AskDomain asks the base domain once. An empty answer means none.
func (p Prompter) AskDomain() (string, error) {
	for try := 0; try < maxTries; try++ {
		if _, err := fmt.Fprint(p.Out, domainQuestion); err != nil {
			return "", err
		}
		line, readErr := p.In.ReadString('\n')
		answer := strings.TrimSpace(line)
		if answer == "" && readErr != nil {
			// An ended input means no domain, the same as an empty
			// answer, so a piped run keeps the per pair question.
			return "", nil //nolint:nilerr // the end of the input is an answer
		}
		domain, nerr := NormalizeDomain(answer)
		if nerr != nil {
			if _, werr := fmt.Fprintf(p.Out, "  %s\n", nerr); werr != nil {
				return "", werr
			}
			continue
		}
		return domain, nil
	}
	return "", fmt.Errorf("setup: %s got %d bad answers", DomainEnv, maxTries)
}
