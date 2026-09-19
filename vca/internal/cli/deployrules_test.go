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
	"stackpath.bootstrapcdn.com",
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
			if strings.Contains(string(data), host) {
				t.Errorf("%s names the CDN %s", path, host)
			}
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
