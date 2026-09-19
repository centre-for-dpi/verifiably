// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"path/filepath"

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
// follows its DPG (ADR-008 decision 5).
func ChartCondition(s Service) string {
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
