// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// HelmRoot is the directory of the charts, from the repository root
// (ADR-008 decision 5).
const HelmRoot = "deploy/vca/helm"

// UmbrellaChart is the name of the chart that turns roles on.
const UmbrellaChart = "vca"

// ChartVersion is the version of every committed chart. The release
// workflow packages the charts with the release version instead.
const ChartVersion = "0.1.0"

// HelmChartDir returns the directory of one chart under the root.
func HelmChartDir(root, name string) string { return filepath.Join(root, HelmRoot, name) }

// ChartCondition is the values path that turns a service chart on inside
// the umbrella chart. A role service follows its role. A DPG adapter
// follows its DPG (ADR-008 decision 5). A deployment scoped service has
// no condition: it is always on (ADR-033 decision 2).
func ChartCondition(s Service) string {
	if s.Scope == ScopeDeployment {
		return ""
	}
	if s.Dpg != configv1.Dpg_DPG_UNSPECIFIED {
		return "dpg." + ShortName(s.Dpg.String()) + ".enabled"
	}
	return "roles." + ShortName(s.Roles[0].String()) + ".enabled"
}

// HelmChartNames lists every chart directory, the service charts first
// and the umbrella chart last.
func HelmChartNames() []string {
	out := make([]string, 0, len(Catalog())+1)
	for _, s := range Catalog() {
		out = append(out, s.Name)
	}
	return append(out, UmbrellaChart)
}

// chartTime is the modification time of every file in a packaged chart,
// so the same source gives the same bytes.
var chartTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// PackageChart packages one chart directory the way helm package does:
// a gzip tar whose entries sit under the chart name. The output is
// deterministic, so the committed packages under the umbrella chart can
// be checked against the chart directories without helm.
func PackageChart(dir, name string) ([]byte, error) {
	var paths []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("package %s: %w", name, err)
	}
	sort.Strings(paths)
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, path := range paths {
		body, err := os.ReadFile(path) // #nosec G304 -- the path comes from the chart directory
		if err != nil {
			return nil, fmt.Errorf("package %s: %w", name, err)
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return nil, fmt.Errorf("package %s: %w", name, err)
		}
		hdr := &tar.Header{
			Name: name + "/" + filepath.ToSlash(rel), Mode: 0o644, Size: int64(len(body)),
			ModTime: chartTime, Typeflag: tar.TypeReg, Format: tar.FormatPAX,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, fmt.Errorf("package %s: %w", name, err)
		}
		if _, err := tw.Write(body); err != nil {
			return nil, fmt.Errorf("package %s: %w", name, err)
		}
	}
	if err := errors.Join(tw.Close(), gz.Close()); err != nil {
		return nil, fmt.Errorf("package %s: %w", name, err)
	}
	return buf.Bytes(), nil
}

// ChartFiles reads a packaged chart and returns its files by entry name.
func ChartFiles(pkg []byte) (map[string]string, error) {
	gz, err := gzip.NewReader(bytes.NewReader(pkg))
	if err != nil {
		return nil, fmt.Errorf("read the chart package: %w", err)
	}
	out := map[string]string{}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, fmt.Errorf("read the chart package: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(tr, 1<<20))
		if err != nil {
			return nil, fmt.Errorf("read the chart package: %w", err)
		}
		out[hdr.Name] = string(body)
	}
}
