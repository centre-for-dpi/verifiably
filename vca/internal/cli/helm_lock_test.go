// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// chartLockMeta is the part of a Chart.lock the tests read.
type chartLockMeta struct {
	Dependencies []ChartDependency `yaml:"dependencies"`
	Digest       string            `yaml:"digest"`
	Generated    string            `yaml:"generated"`
}

// TestChartLocksMatchTheirCharts keeps each Chart.lock under the helm
// root in step with its Chart.yaml. helm dependency build refuses a lock
// whose digest differs from the digest of the dependencies. Set
// VCA_WRITE_HELM=1 to write the locks again.
func TestChartLocksMatchTheirCharts(t *testing.T) {
	root := repoRoot()
	locks, err := filepath.Glob(filepath.Join(root, HelmRoot, "*", "Chart.lock"))
	if err != nil {
		t.Fatal(err)
	}
	if len(locks) == 0 {
		t.Fatal("no Chart.lock under the helm root")
	}
	for _, path := range locks {
		chart, err := os.ReadFile(filepath.Join(filepath.Dir(path), "Chart.yaml")) // #nosec G304 -- a fixed test path
		if err != nil {
			t.Fatal(err)
		}
		want, err := ChartLock(chart)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if os.Getenv("VCA_WRITE_HELM") != "" {
			if werr := os.WriteFile(path, want, 0o600); werr != nil {
				t.Fatal(werr)
			}
		}
		got, err := os.ReadFile(path) // #nosec G304 -- a fixed test path
		if err != nil {
			t.Fatal(err)
		}
		var lock chartLockMeta
		if perr := yaml.Unmarshal(got, &lock); perr != nil {
			t.Fatalf("parse %s: %v", path, perr)
		}
		var meta struct {
			Dependencies []ChartDependency `yaml:"dependencies"`
		}
		if perr := yaml.Unmarshal(chart, &meta); perr != nil {
			t.Fatal(perr)
		}
		digest, err := LockDigest(meta.Dependencies, lock.Dependencies)
		if err != nil {
			t.Fatal(err)
		}
		if lock.Digest != digest {
			t.Errorf("%s: digest %s, the dependencies give %s; run VCA_WRITE_HELM=1 go test ./internal/cli/ -run TestChartLocks", path, lock.Digest, digest)
		}
		if names, lockNames := depNames(meta.Dependencies), depNames(lock.Dependencies); !reflect.DeepEqual(names, lockNames) {
			t.Errorf("%s: locks %v, the chart names %v", path, lockNames, names)
		}
		if lock.Generated != LockGenerated {
			t.Errorf("%s: generated %q, want the fixed %q", path, lock.Generated, LockGenerated)
		}
		if string(got) != string(want) {
			t.Errorf("%s differs from the lock of its Chart.yaml; run VCA_WRITE_HELM=1 go test ./internal/cli/ -run TestChartLocks", path)
		}
	}
}

func depNames(deps []ChartDependency) []string {
	out := make([]string, 0, len(deps))
	for _, d := range deps {
		out = append(out, d.Name+"@"+d.Version+"@"+d.Repository)
	}
	return out
}

// TestLockDigestFollowsHelm checks the digest against the way helm
// writes it: the sha256 of the compact JSON of the chart dependencies
// and the locked dependencies, with the empty fields left out.
func TestLockDigestFollowsHelm(t *testing.T) {
	req := []ChartDependency{{Name: "a", Version: "0.1.0", Repository: "file://../a", Condition: "x.enabled"}}
	lock := []ChartDependency{{Name: "a", Version: "0.1.0", Repository: "file://../a"}}
	got, err := LockDigest(req, lock)
	if err != nil {
		t.Fatal(err)
	}
	// The sha256 of
	// [[{"name":"a","version":"0.1.0","repository":"file://../a","condition":"x.enabled"}],[{"name":"a","version":"0.1.0","repository":"file://../a"}]]
	const want = "sha256:e57702a7c48ab8838aa1c2dde78bae72de2ff4e28777fe755d352d075ea3a85b"
	if got != want {
		t.Errorf("digest %s, want %s", got, want)
	}
	body, err := ChartLock([]byte("dependencies:\n  - name: a\n    version: 0.1.0\n    repository: \"file://../a\"\n    condition: x.enabled\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "digest: "+want+"\n") || !strings.HasPrefix(string(body), "dependencies:\n- name: a\n  repository: file://../a\n  version: 0.1.0\n") {
		t.Errorf("lock:\n%s", body)
	}
	if _, err := ChartLock([]byte("dependencies: [")); err == nil {
		t.Error("a Chart.yaml that does not parse gave a lock")
	}
}
