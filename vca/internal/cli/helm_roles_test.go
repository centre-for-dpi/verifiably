// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"text/template"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// The gate of the chart of a service of several roles (ADR-074).
const (
	chartGateOpen  = `{{- if include "vca.enabled" . }}`
	chartGateClose = `{{- end }}`
)

// multiRole lists the services of the catalogue that run for several
// roles of a pair.
func multiRole() []Service {
	var out []Service
	for _, s := range Catalog() {
		if s.Scope == ScopePair && len(s.Roles) > 1 {
			out = append(out, s)
		}
	}
	return out
}

func TestChartConditionHonoursEveryRole(t *testing.T) {
	issuer := Service{Name: "issuance", Roles: []commonv1.Role{commonv1.Role_ROLE_ISSUER}}
	if got := ChartCondition(issuer); got != "global.roles.issuer.enabled" {
		t.Errorf("one role: condition %q", got)
	}
	both := Service{Name: "shared", Roles: []commonv1.Role{commonv1.Role_ROLE_ISSUER, commonv1.Role_ROLE_VERIFIER}}
	if got := ChartCondition(both); got != "" {
		t.Errorf("several roles: condition %q, want none; the templates check every role", got)
	}
	if got := ChartRoles(both); !reflect.DeepEqual(got, []string{"issuer", "verifier"}) {
		t.Errorf("several roles: roles %v", got)
	}
	adapter := Service{Name: "dpg-adapter-inji", Dpg: configv1.Dpg_DPG_INJI, Roles: both.Roles}
	if got := ChartCondition(adapter); got != "dpg.inji.enabled" {
		t.Errorf("adapter: condition %q", got)
	}
	if got := ChartRoles(issuer); got != nil {
		t.Errorf("one role: roles %v, want none", got)
	}
}

// TestMultiRoleChartsHonourEveryRole: the chart of a service of several
// roles, such as a DPG adapter, names its roles in its values and
// renders each template only when one of them is on. A chart installed
// alone renders as before.
func TestMultiRoleChartsHonourEveryRole(t *testing.T) {
	root := repoRoot()
	services := multiRole()
	if len(services) == 0 {
		t.Fatal("the catalogue holds no service of several roles")
	}
	for _, s := range services {
		dir := HelmChartDir(root, s.Name)
		var values struct {
			Roles []string `yaml:"roles"`
		}
		readYaml(t, filepath.Join(dir, "values.yaml"), &values)
		if !reflect.DeepEqual(values.Roles, ChartRoles(s)) {
			t.Errorf("%s values name the roles %v, want %v", s.Name, values.Roles, ChartRoles(s))
		}
		entries, err := os.ReadDir(filepath.Join(dir, "templates"))
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if e.Name() == "_helpers.tpl" {
				continue
			}
			body := strings.TrimSpace(readText(t, filepath.Join(dir, "templates", e.Name())))
			lines := strings.Split(body, "\n")
			if len(lines) < 3 || lines[1] != chartGateOpen || lines[len(lines)-1] != chartGateClose {
				t.Errorf("%s/templates/%s is not inside the role gate", s.Name, e.Name())
			}
		}
		helpers := readText(t, filepath.Join(dir, "templates", "_helpers.tpl"))
		for name, c := range map[string]struct {
			values map[string]any
			want   bool
		}{
			"alone":             {map[string]any{"roles": values.Roles}, true},
			"no roles on":       {map[string]any{"roles": values.Roles, "global": allOff()}, false},
			"another role on":   {map[string]any{"roles": values.Roles, "global": on("admin")}, false},
			"a first role on":   {map[string]any{"roles": values.Roles, "global": on(values.Roles[0])}, true},
			"a last role on":    {map[string]any{"roles": values.Roles, "global": on(values.Roles[len(values.Roles)-1])}, true},
			"a role turned off": {map[string]any{"roles": values.Roles, "global": map[string]any{"roles": map[string]any{values.Roles[0]: map[string]any{"enabled": false}}}}, false},
		} {
			if got := renderGate(t, helpers, c.values); got != c.want {
				t.Errorf("%s %s: renders = %v, want %v", s.Name, name, got, c.want)
			}
		}
	}
}

// allOff returns the global values of the umbrella chart with every
// role off.
func allOff() map[string]any {
	roles := map[string]any{}
	for _, r := range Roles() {
		roles[ShortName(r.String())] = map[string]any{"enabled": false}
	}
	return map[string]any{"roles": roles}
}

// on returns the global values with one role turned on.
func on(role string) map[string]any {
	return map[string]any{"roles": map[string]any{role: map[string]any{"enabled": true}}}
}

// renderGate runs the vca.enabled helper with the standard template
// engine and reports whether the chart renders.
func renderGate(t *testing.T, helpers string, values map[string]any) bool {
	t.Helper()
	tmpl, err := template.New("helpers").Funcs(template.FuncMap{
		"default": func(d, v any) any {
			if v == nil {
				return d
			}
			return v
		},
		"trunc":      func(_ int, s string) string { return s },
		"trimSuffix": func(_, s string) string { return s },
		"include":    func(string, any) string { return "" },
		"quote":      func(v any) string { return "" },
		// The checksum of the peer Secrets reads the cluster; the gate
		// does not call it.
		"lookup":    func(...any) map[string]any { return nil },
		"dict":      func(...any) map[string]any { return nil },
		"get":       func(map[string]any, string) any { return nil },
		"toJson":    func(any) string { return "" },
		"sha256sum": func(string) string { return "" },
	}).Parse(helpers + `{{ template "vca.enabled" . }}`)
	if err != nil {
		t.Fatalf("parse the helpers: %v", err)
	}
	var out bytes.Buffer
	if err := tmpl.Execute(&out, map[string]any{"Values": values}); err != nil {
		t.Fatalf("render the gate: %v", err)
	}
	return strings.TrimSpace(out.String()) != ""
}

// TestUmbrellaRefusesTheOldRoleSwitch: the role switches sit under
// global, so every chart sees them. The old path stops the render with
// a message that names the new one.
func TestUmbrellaRefusesTheOldRoleSwitch(t *testing.T) {
	dir := HelmChartDir(repoRoot(), UmbrellaChart)
	guard := readText(t, filepath.Join(dir, "templates", "roles-moved.yaml"))
	for _, want := range []string{"if .Values.roles", "fail", "global.roles.<role>.enabled"} {
		if !strings.Contains(guard, want) {
			t.Errorf("templates/roles-moved.yaml holds no %q", want)
		}
	}
}
