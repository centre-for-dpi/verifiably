// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"testing"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

func TestLocalPublicURLNamesThePortalPort(t *testing.T) {
	p := Pair{Role: commonv1.Role_ROLE_ISSUER, Dpg: configv1.Dpg_DPG_WALTID}
	got := LocalPublicURL(p)
	want := ""
	for _, a := range AssignPorts(p, nil) {
		if a.Service.Name == portalService(p.Role) {
			want = fmt.Sprintf("http://localhost:%d", a.Host)
		}
	}
	if want == "" || got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestApplyLocalPublicURLFillsOnlyTheEmptyValue(t *testing.T) {
	p := Pair{Role: commonv1.Role_ROLE_ISSUER, Dpg: configv1.Dpg_DPG_WALTID}
	list := []Resolution{
		{Setting: Setting{Path: "public_url", Env: "VCA_PUBLIC_URL"}},
		{Setting: Setting{Path: "dpg_url", Env: "VCA_DPG_URL"}},
	}
	out := applyLocalPublicURL(list, p)
	if out[0].Value != LocalPublicURL(p) || out[0].Origin != OriginDefault {
		t.Errorf("empty public url: got %q origin %v", out[0].Value, out[0].Origin)
	}
	if out[1].Value != "" {
		t.Errorf("dpg url changed: %q", out[1].Value)
	}
	list[0].Value = "https://issuer.example"
	if applyLocalPublicURL(list, p)[0].Value != "https://issuer.example" {
		t.Error("a set public url was replaced")
	}
}

func TestPublicURLRuleAllowsHTTPOnLoopbackOnly(t *testing.T) {
	checks := checksFor(Setting{Validation: "An absolute https URL without a path or a trailing slash. http is allowed for localhost."})
	cases := map[string]bool{
		"http://localhost:18002":  true,
		"http://127.0.0.1:18002":  true,
		"http://app.localhost":    true,
		"https://issuer.example":  true,
		"http://issuer.example":   false,
		"http://localhost:1/path": false,
		"not a url":               false,
	}
	for value, ok := range cases {
		problem := ""
		for _, c := range checks {
			if problem == "" {
				problem = c(value)
			}
		}
		if (problem == "") != ok {
			t.Errorf("%q: problem %q, want ok=%v", value, problem, ok)
		}
	}
}
