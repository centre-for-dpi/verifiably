// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// cdnHosts are runtime asset hosts that no deployment file may name.
// Every image carries its own web assets (ADR-005 decision 7).
var cdnHosts = []string{
	"cdn.jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
	"fonts.googleapis.com", "fonts.gstatic.com", "ajax.googleapis.com",
	"stackpath.bootstrapcdn.com", "github.io",
}

// pendingCdn lists the deployment files that still load an asset from
// a CDN host, by file and host, with the unit of the no mock plan that
// removes the line (ADR-050). TestPendingCdnEntriesStillMatch fails
// when an entry no longer matches, so the entry goes with the fix.
var pendingCdn = []nomockException{
	{"deploy/vca/dpg/inji/certify/certify_init.sql", "github.io", "N4"},
	{"deploy/vca/dpg/inji/mimoto/credential-template.html", "github.io", "N8"},
}

// pendingCdnCovers says whether a pending entry covers a file and host.
func pendingCdnCovers(path, host string) bool {
	rel, err := filepath.Rel(repoRoot(), path)
	if err != nil {
		return false
	}
	for _, e := range pendingCdn {
		if e.path == filepath.ToSlash(rel) && e.token == host {
			return true
		}
	}
	return false
}

// deployFiles lists every committed file under deploy/.
func deployFiles(t *testing.T) []string {
	t.Helper()
	var out []string
	root := filepath.Join(repoRoot(), "deploy")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || strings.HasSuffix(path, ".tgz") {
			return nil
		}
		out = append(out, path)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return out
}

func TestNoDeployFileLoadsFromACdn(t *testing.T) {
	for _, path := range deployFiles(t) {
		data, err := os.ReadFile(path) // #nosec G304 -- a path under deploy
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for _, host := range cdnHosts {
			if strings.Contains(string(data), host) && !pendingCdnCovers(path, host) {
				t.Errorf("%s names the CDN %s", path, host)
			}
		}
	}
}

func TestPendingCdnEntriesStillMatch(t *testing.T) {
	for _, e := range pendingCdn {
		data, err := os.ReadFile(filepath.Join(repoRoot(), e.path)) // #nosec G304 -- a path under deploy
		if err != nil {
			t.Errorf("pending CDN entry %s: %v; delete the entry", e.path, err)
			continue
		}
		if !strings.Contains(string(data), e.token) {
			t.Errorf("pending CDN entry %s no longer names %s; delete the entry", e.path, e.token)
		}
	}
}

func TestNoDeployFileMountsTheDockerSocket(t *testing.T) {
	for _, path := range deployFiles(t) {
		data, err := os.ReadFile(path) // #nosec G304 -- a path under deploy
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		text := string(data)
		for _, bad := range []string{"docker.sock", "privileged: true", "hostNetwork: true", "hostPID"} {
			if strings.Contains(text, bad) {
				t.Errorf("%s holds %q", path, bad)
			}
		}
	}
}

func TestEveryVcaComposeServiceExposesOnePort(t *testing.T) {
	// ADR-005 decision 6: one image, one port.
	for _, p := range AllPairs() {
		for _, a := range AssignPorts(p, nil) {
			if a.Listen < 1024 || a.Listen > 65535 {
				t.Errorf("%s/%s listens on %d", p.Name(), a.Service.Name, a.Listen)
			}
		}
	}
}
