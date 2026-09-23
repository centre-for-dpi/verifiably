// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// rootAdrSHA256 is the SHA-256 of ADR.md at commit e886702. The root
// record set is read only. A change to a decision is a new record under
// vca/docs/adr, so this sum never changes.
const rootAdrSHA256 = "7b0508a4d65bcf139b7a1e1f8d9fe215cadfafa5bd7958afb8a5b09addc87622"

// firstNewAdr is the number of the first record under vca/docs/adr.
// ADR.md holds ADR-001 to ADR-031.
const firstNewAdr = 32

// adrFileRe matches the file name of one record under vca/docs/adr.
var adrFileRe = regexp.MustCompile(`^ADR-(\d{3})-[a-z0-9]+(?:-[a-z0-9]+)*\.md$`)

// adrRecordLines are the lines every record holds, in the record
// format of ADR.md.
var adrRecordLines = []string{"- Status:", "- Owner:", "- Scope:", "- Decision:", "- Consequences:"}

func docsDir() string { return filepath.Join("..", "..", "docs") }

func readText(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- a fixed test path
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

// adrRecordFiles returns the record file names under vca/docs/adr,
// sorted by number.
func adrRecordFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(docsDir(), "adr"))
	if err != nil {
		t.Fatalf("read docs/adr: %v", err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			t.Errorf("docs/adr/%s: a folder, want record files only", e.Name())
			continue
		}
		if !adrFileRe.MatchString(e.Name()) {
			t.Errorf("docs/adr/%s: name is not ADR-0NN-<slug>.md", e.Name())
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

func adrNumber(name string) int {
	n, err := strconv.Atoi(adrFileRe.FindStringSubmatch(name)[1])
	if err != nil {
		return -1
	}
	return n
}

func TestAdrRecordsAreIndexedAndTracked(t *testing.T) {
	names := adrRecordFiles(t)
	if len(names) == 0 {
		t.Fatal("docs/adr holds no record")
	}
	index := readText(t, filepath.Join(docsDir(), "adr.md"))
	status := readText(t, filepath.Join(docsDir(), "adr-status.md"))
	for i, name := range names {
		n := adrNumber(name)
		if want := firstNewAdr + i; n != want {
			t.Errorf("%s: number %03d, want ADR-%03d (contiguous from ADR-%03d)", name, n, want, firstNewAdr)
		}
		id := "ADR-" + strconv.Itoa(1000 + n)[1:]
		body := readText(t, filepath.Join(docsDir(), "adr", name))
		if !strings.HasPrefix(body, "## "+id+": ") {
			t.Errorf("%s: first line is not the heading %q", name, "## "+id+": <title>")
		}
		lines := strings.Split(body, "\n")
		for _, want := range adrRecordLines {
			if !hasLinePrefix(lines, want) {
				t.Errorf("%s: no line starts with %q", name, want)
			}
		}
		if !strings.Contains(index, "(adr/"+name+")") {
			t.Errorf("docs/adr.md: no link to adr/%s", name)
		}
		if !strings.Contains(status, "\n## "+id+": ") {
			t.Errorf("docs/adr-status.md: no section for %s", id)
		}
		if !strings.Contains(status, "| "+id+" | 1 ") {
			t.Errorf("docs/adr-status.md: no row for %s decision 1", id)
		}
	}
}

func TestAdrIndexLinksResolve(t *testing.T) {
	index := readText(t, filepath.Join(docsDir(), "adr.md"))
	links := regexp.MustCompile(`\((adr/[^)]+)\)`).FindAllStringSubmatch(index, -1)
	if len(links) == 0 {
		t.Fatal("docs/adr.md links to no record")
	}
	for _, m := range links {
		if _, err := os.Stat(filepath.Join(docsDir(), m[1])); err != nil {
			t.Errorf("docs/adr.md links to %s: %v", m[1], err)
		}
	}
}

func hasLinePrefix(lines []string, prefix string) bool {
	for _, l := range lines {
		if strings.HasPrefix(l, prefix) {
			return true
		}
	}
	return false
}

// fileSHA256 returns the hex SHA-256 of the file at path.
func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- a fixed test path
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestRootAdrIsUnchanged(t *testing.T) {
	got := fileSHA256(t, filepath.Join(repoRoot(), RepoMarker))
	if got != rootAdrSHA256 {
		t.Fatalf("ADR.md changed: SHA-256 %s, want %s. The root record set is read only. Add a record under vca/docs/adr that supersedes the old decision.", got, rootAdrSHA256)
	}
}

func TestRootAdrGuardSeesAChange(t *testing.T) {
	body := readText(t, filepath.Join(repoRoot(), RepoMarker))
	copyPath := filepath.Join(t.TempDir(), RepoMarker)
	if err := os.WriteFile(copyPath, []byte(body+"\n"), 0o600); err != nil {
		t.Fatalf("write copy: %v", err)
	}
	if fileSHA256(t, copyPath) == rootAdrSHA256 {
		t.Fatal("a changed copy of ADR.md has the recorded sum")
	}
}
