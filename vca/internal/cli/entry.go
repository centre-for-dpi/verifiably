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
)

// EntryPoint is one address an operator opens after a deploy.
type EntryPoint struct {
	// Pair is the role and DPG pair.
	Pair Pair
	// Portal is the service that answers at the public URL.
	Portal string
	// URL is the public URL of the pair.
	URL string
	// Login is the browser facing URL of the identity provider.
	Login string
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
		out = append(out, EntryPoint{
			Pair:   p,
			Portal: portalService(p.Role),
			URL:    url,
			Login:  strings.TrimRight(values["VCA_OIDC_PUBLIC_URL"], "/"),
			Local:  host == "" || isLocalHost(host),
		})
	}
	return out, nil
}

// EntryReport renders the addresses to open after a deploy, and the
// one step a public host still needs: the reverse proxy snippet.
func EntryReport(points []EntryPoint) string {
	if len(points) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\nOpen\n")
	public := false
	for _, e := range points {
		fmt.Fprintf(&b, "  %-18s %-17s %s\n", e.Pair.Name(), e.Portal, e.URL)
		if !e.Local {
			public = true
		}
	}
	logins := map[string]bool{}
	for _, e := range points {
		if e.Login != "" && !logins[e.Login] {
			logins[e.Login] = true
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
		}
	}
	if public {
		b.WriteString("The public names answer once the reverse proxy of the host has the snippet:\n")
		b.WriteString("  vca proxy --all | sudo tee /etc/caddy/vca.caddy >/dev/null\n")
		b.WriteString("  echo 'import /etc/caddy/vca.caddy' | sudo tee -a /etc/caddy/Caddyfile\n")
		b.WriteString("  sudo systemctl reload caddy\n")
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
	anyval.DiscardWrite(io.WriteString(out, EntryReport(points)))
}
