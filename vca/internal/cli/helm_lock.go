// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// LockGenerated is the time every written Chart.lock carries, so the
// same Chart.yaml gives the same lock.
const LockGenerated = "2026-09-27T00:00:00.000000000Z"

// ChartDependency is one dependency of a Chart.yaml or a Chart.lock. The
// JSON fields follow the dependency of helm in name and order, because
// the digest of a lock is the sha256 of that JSON.
type ChartDependency struct {
	Name         string   `json:"name" yaml:"name"`
	Version      string   `json:"version,omitempty" yaml:"version"`
	Repository   string   `json:"repository" yaml:"repository"`
	Condition    string   `json:"condition,omitempty" yaml:"condition"`
	Tags         []string `json:"tags,omitempty" yaml:"tags"`
	Enabled      bool     `json:"enabled,omitempty" yaml:"enabled"`
	ImportValues []any    `json:"import-values,omitempty" yaml:"import-values"`
	Alias        string   `json:"alias,omitempty" yaml:"alias"`
}

// LockDigest returns the digest helm writes in a Chart.lock: the sha256
// of the compact JSON of the chart dependencies and the locked
// dependencies. helm dependency build refuses a lock whose digest
// differs.
func LockDigest(req, lock []ChartDependency) (string, error) {
	data, err := json.Marshal([2][]ChartDependency{req, lock})
	if err != nil {
		return "", fmt.Errorf("digest of the lock: %w", err)
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// ChartLock returns the Chart.lock of a Chart.yaml whose dependencies
// are local chart directories. The lock names each dependency at the
// version the chart asks for, the way helm dependency update writes it.
func ChartLock(chartYAML []byte) ([]byte, error) {
	var meta struct {
		Dependencies []ChartDependency `yaml:"dependencies"`
	}
	if err := yaml.Unmarshal(chartYAML, &meta); err != nil {
		return nil, fmt.Errorf("parse the Chart.yaml: %w", err)
	}
	lock := make([]ChartDependency, 0, len(meta.Dependencies))
	for _, d := range meta.Dependencies {
		lock = append(lock, ChartDependency{Name: d.Name, Version: d.Version, Repository: d.Repository})
	}
	digest, err := LockDigest(meta.Dependencies, lock)
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteString("dependencies:\n")
	for _, d := range lock {
		fmt.Fprintf(&b, "- name: %s\n  repository: %s\n  version: %s\n", d.Name, d.Repository, d.Version)
	}
	fmt.Fprintf(&b, "digest: %s\ngenerated: %q\n", digest, LockGenerated)
	return []byte(b.String()), nil
}
