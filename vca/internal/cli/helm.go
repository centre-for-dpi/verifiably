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
	"strings"
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

// UmbrellaPeersFile is the template of the umbrella chart that writes
// VCA_PEERS.
const UmbrellaPeersFile = "peers-configmap.yaml"

// UmbrellaPeersTemplate renders the peers template of the umbrella
// chart (P7-03, ADR-034). It pairs each turned on role with each turned
// on DPG, in the order of the catalogue, and names every service of the
// pair at <release>-<service> and its port, as the charts name them.
// global.publicDomain gives each pair its public address, as a base
// domain does for compose. Without it the home service stands in. The
// template uses only functions of the standard template engine, so a
// test renders it without helm.
func UmbrellaPeersTemplate() string {
	var b strings.Builder
	b.WriteString("{{- /* SPDX-License-Identifier: Apache-2.0 */ -}}\n")
	b.WriteString("{{- /*\n")
	b.WriteString("The candidate pairs of the release as VCA_PEERS (ADR-034). Every chart\n")
	b.WriteString("of a service that draws pages reads this ConfigMap. The vca CLI writes\n")
	b.WriteString("this file from its catalogue: go test ./internal/cli/ checks it, and\n")
	b.WriteString("VCA_WRITE_HELM=1 writes it again. Do not edit it by hand.\n")
	b.WriteString("*/ -}}\n")
	b.WriteString("{{- $release := .Release.Name }}\n")
	b.WriteString("{{- $domain := .Values.global.publicDomain }}\n")
	b.WriteString("{{- $peers := \"\" }}\n")
	b.WriteString("{{- $sep := \"\" }}\n")
	for _, r := range Roles() {
		for _, d := range Dpgs() {
			p := Pair{Role: r, Dpg: d}
			services := ServicesFor(p)
			entries := make([]string, 0, len(services))
			home := ""
			for _, s := range services {
				url := fmt.Sprintf("http://%%[1]s-%s:%d", s.Name, s.ExposedPort)
				entries = append(entries, s.Name+"="+url)
				if s.Name == HomeOf(r).Service {
					home = url
				}
			}
			sort.Strings(entries)
			public := strings.Replace(PairPublicURL(p, "DOMAIN"), "DOMAIN", "%s", 1)
			fmt.Fprintf(&b, "{{- if and .Values.roles.%s.enabled .Values.dpg.%s.enabled }}\n", ShortName(r.String()), ShortName(d.String()))
			fmt.Fprintf(&b, "{{- $public := printf %q $release }}\n", home)
			fmt.Fprintf(&b, "{{- if $domain }}{{- $public = printf %q $domain }}{{- end }}\n", public)
			fmt.Fprintf(&b, "{{- $peers = printf \"%%s%%s%%s|%%s|%%s\" $peers $sep %q $public (printf %q $release) }}\n",
				p.Name(), strings.Join(entries, ","))
			b.WriteString("{{- $sep = \";\" }}\n")
			b.WriteString("{{- end }}\n")
		}
	}
	b.WriteString("apiVersion: v1\n")
	b.WriteString("kind: ConfigMap\n")
	b.WriteString("metadata:\n")
	b.WriteString("  name: {{ .Release.Name }}-peers\n")
	b.WriteString("  labels:\n")
	b.WriteString("    app.kubernetes.io/instance: {{ .Release.Name }}\n")
	b.WriteString("    app.kubernetes.io/part-of: vca\n")
	b.WriteString("data:\n")
	b.WriteString("  VCA_PEERS: {{ printf \"%q\" $peers }}\n")
	return b.String()
}
