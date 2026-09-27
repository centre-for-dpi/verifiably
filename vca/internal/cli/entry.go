// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
)

// EntryPoint is one address an operator opens after a deploy.
type EntryPoint struct {
	// Pair is the role and DPG pair.
	Pair Pair
	// Portal is the home service, which answers at the public URL.
	Portal string
	// URL is the public URL of the pair.
	URL string
	// Pages lists the HTML pages of the pair, from the route table.
	// The home page comes first.
	Pages []PageLink
	// Login is the browser facing URL of the identity provider.
	Login string
	// Console is the administration console of the Keycloak of the
	// stack, when the pair signs in there. Empty for another provider.
	Console string
	// AdminEnv is the file that holds the administrator of that
	// Keycloak, relative to the deploy directory (ADR-035 decision 7).
	AdminEnv string
	// Local reports a localhost URL, which needs no reverse proxy.
	Local bool
}

// EntryPoints reads the public URL of every pair out of its .env file.
// A pair with no .env file is left out.
func EntryPoints(root string, pairs []Pair) ([]EntryPoint, error) {
	var out []EntryPoint
	for _, p := range pairs {
		values, err := ReadExisting(filepath.Join(root, "deploy"), p)
		if err != nil {
			return nil, err
		}
		url := strings.TrimRight(values["VCA_PUBLIC_URL"], "/")
		if url == "" {
			continue
		}
		host := hostOf(url)
		e := EntryPoint{
			Pair:   p,
			Portal: HomeOf(p.Role).Service,
			URL:    url,
			Pages:  Pages(p, url),
			Login:  strings.TrimRight(values["VCA_OIDC_PUBLIC_URL"], "/"),
			Local:  host == "" || isLocalHost(host),
		}
		if e.Login != "" && values["VCA_OIDC_DISCOVERY_URL"] == DefaultDiscoveryURL(p) {
			e.Console = e.Login + "/admin/"
			e.AdminEnv = KeycloakEnvFile(p.Dpg)
		}
		out = append(out, e)
	}
	return out, nil
}

// ReadLandingEnv reads deploy/landing/.env under the root. A missing
// file gives an empty map, because a deployment that setup wrote before
// the landing existed has none yet.
func ReadLandingEnv(root string) (map[string]string, error) {
	path := LandingEnvPath(root)
	f, err := os.Open(path) // #nosec G304 -- a fixed path under the root
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return map[string]string{}, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	defer func() { anyval.Discard(f.Close()) }()
	values, err := ParseDotenv(f)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return values, nil
}

// LandingURL reads the public URL of the landing out of its .env file.
// It is empty when the file is missing (ADR-033 decision 2).
func LandingURL(root string) (string, error) {
	values, err := ReadLandingEnv(root)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(values[LandingPublicURLEnv], "/"), nil
}

// EntryReport renders the address that starts every journey, the pages
// to open after a deploy, and the one step a public host still needs:
// the reverse proxy snippet. The pages come from the route table, so the
// report and the Caddyfile agree. An empty landing leaves the first
// block out.
func EntryReport(landing string, points []EntryPoint) string {
	if len(points) == 0 && landing == "" {
		return ""
	}
	var b strings.Builder
	if landing != "" {
		fmt.Fprintf(&b, "\nStart here\n  %s\n", landing)
	}
	if len(points) == 0 {
		return b.String()
	}
	b.WriteString("\nOpen\n")
	public := false
	for _, e := range points {
		fmt.Fprintf(&b, "  %s\n", e.Pair.Name())
		for _, page := range e.Pages {
			fmt.Fprintf(&b, "    %-22s %-19s %s\n", page.Title, page.Service, page.URL)
		}
		if line := signInLine(e); line != "" {
			fmt.Fprintf(&b, "    %s\n", line)
		}
		if !e.Local {
			public = true
		}
	}
	logins := map[string]EntryPoint{}
	for _, e := range points {
		if _, seen := logins[e.Login]; e.Login != "" && !seen {
			logins[e.Login] = e
		}
	}
	if len(logins) > 0 {
		names := make([]string, 0, len(logins))
		for l := range logins {
			names = append(names, l)
		}
		sort.Strings(names)
		b.WriteString("Login\n")
		for _, l := range names {
			fmt.Fprintf(&b, "  %s\n", l)
			if e := logins[l]; e.Console != "" {
				fmt.Fprintf(&b, "    console %s, administrator in deploy/%s\n", e.Console, e.AdminEnv)
			}
		}
	}
	b.WriteString(firstRun(landing, points))
	if public {
		b.WriteString("The public names answer once the reverse proxy of the host has the snippet:\n")
		b.WriteString("  vca proxy --all | sudo tee /etc/caddy/vca.caddy >/dev/null\n")
		b.WriteString("  echo 'import /etc/caddy/vca.caddy' | sudo tee -a /etc/caddy/Caddyfile\n")
		b.WriteString("  sudo systemctl reload caddy\n")
	}
	return b.String()
}

// signInPage returns the page where a person of the pair signs in: the
// page titled "Sign in" when the pair has one, else its home page.
func signInPage(e EntryPoint) string {
	for _, page := range e.Pages {
		if page.Title == signInTitle {
			return page.URL
		}
	}
	if len(e.Pages) > 0 {
		return e.Pages[0].URL
	}
	return e.URL
}

// signInTitle is the page title of the login service of a pair.
const signInTitle = "Sign in"

// BootstrapTokenEnv is the variable of the .env of an admin pair that
// holds the one time token which binds the first admin.
const BootstrapTokenEnv = "VCA_SECRETS_BOOTSTRAP_TOKEN" //nolint:gosec // G101: this is a variable name, not a credential.

// signInLine names the realm of a pair at the Keycloak of its stack, or
// the provider it signs in with, and the page where a person signs in
// (P7-01, ADR-035 decision 1).
func signInLine(e EntryPoint) string {
	switch {
	case e.Console != "":
		return fmt.Sprintf("realm %s, sign in at %s", RealmName(e.Pair.Role), signInPage(e))
	case e.Login != "":
		return fmt.Sprintf("provider %s, sign in at %s", e.Login, signInPage(e))
	}
	return ""
}

// firstRun lists the first run steps of the pairs in order: open the
// landing, bind the first admin with the bootstrap token, run the
// bootstrap of each pair, and turn self registration off in each realm
// once the first people signed up (P7-01, ADR-035 decisions 1 and 6).
func firstRun(landing string, points []EntryPoint) string {
	var steps []string
	if landing != "" {
		steps = append(steps, fmt.Sprintf("Open %s and pick a role.", landing))
	}
	var bootstraps, realms []string
	for _, e := range points {
		dpg, role := ShortName(e.Pair.Dpg.String()), ShortName(e.Pair.Role.String())
		if e.Pair.Role == commonv1.Role_ROLE_ADMIN {
			steps = append(steps, fmt.Sprintf("Bind the first admin at %s with %s of deploy/%s/%s.",
				signInPage(e), BootstrapTokenEnv, e.Pair.Name(), EnvFileName))
		} else {
			bootstraps = append(bootstraps, fmt.Sprintf("vca dpg bootstrap %s --role %s", dpg, role))
		}
		if e.Console != "" {
			realms = append(realms, fmt.Sprintf("vca dpg realm --role %s --dpg %s --registration off", role, dpg))
		}
	}
	if len(bootstraps) > 0 {
		steps = append(steps, "Run the bootstrap of each pair once: "+strings.Join(bootstraps, "\n     "))
	}
	if len(realms) > 0 {
		steps = append(steps, "After the first sign ups, turn self registration off: "+strings.Join(realms, "\n     "))
	}
	if len(steps) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("First run\n")
	for i, s := range steps {
		fmt.Fprintf(&b, "  %d. %s\n", i+1, s)
	}
	return b.String()
}

// ProxySnippet concatenates the Caddyfile of every pair that has one,
// in pair order, so one file feeds the reverse proxy of the host. A
// pair with no Caddyfile is named in skipped.
func ProxySnippet(root string, pairs []Pair) (snippet string, skipped []string, err error) {
	var b strings.Builder
	b.WriteString("# Every VCA pair of this host. The vca proxy command generated it.\n")
	b.WriteString("# Run vca proxy again after vca setup, then reload the proxy.\n")
	// The landing site comes first: it is the front door of every pair
	// (ADR-033 decision 2).
	landing, err := ReadLandingEnv(root)
	if err != nil {
		return "", nil, err
	}
	if site := LandingCaddyfile(landing); site != "" {
		b.WriteString("\n" + site)
	}
	for _, p := range pairs {
		path := filepath.Join(OutputDir(filepath.Join(root, "deploy"), p), CaddyFile)
		data, readErr := os.ReadFile(path) // #nosec G304 -- the path comes from the pair name
		if readErr != nil {
			if errors.Is(readErr, fs.ErrNotExist) {
				skipped = append(skipped, p.Name())
				continue
			}
			return "", nil, fmt.Errorf("read %s: %w", path, readErr)
		}
		b.WriteString("\n")
		b.Write(data)
	}
	return b.String(), skipped, nil
}

// writeEntryReport prints the entry points of the pairs after a deploy.
// A read error is reported but does not fail the deploy, which already
// happened.
func writeEntryReport(out io.Writer, root string, pairs []Pair) {
	points, err := EntryPoints(root, pairs)
	if err != nil {
		anyval.DiscardWrite(fmt.Fprintf(out, "\n%v\n", err))
		return
	}
	landing, err := LandingURL(root)
	if err != nil {
		anyval.DiscardWrite(fmt.Fprintf(out, "\n%v\n", err))
		return
	}
	anyval.DiscardWrite(io.WriteString(out, EntryReport(landing, points)))
}
