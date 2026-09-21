// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

func TestNormalizeDomain(t *testing.T) {
	good := map[string]string{
		"labs.example":           "labs.example",
		"  Labs.Example.  ":      "labs.example",
		"*.labs.example":         "labs.example",
		"https://labs.example":   "labs.example",
		"a-b.c1.example":         "a-b.c1.example",
		"":                       "",
		"https://*.labs.example": "labs.example",
	}
	for raw, want := range good {
		got, err := NormalizeDomain(raw)
		if err != nil || got != want {
			t.Errorf("%q: got %q, %v; want %q", raw, got, err, want)
		}
	}
	for _, raw := range []string{"example", "labs.example/path", "labs.example:443", "-a.example", "a b.example", "a..example"} {
		if _, err := NormalizeDomain(raw); !errors.Is(err, ErrBadDomain) {
			t.Errorf("%q passed: %v", raw, err)
		}
	}
}

func TestPairAndKeycloakHosts(t *testing.T) {
	p := issuerPair()
	if got := PairHost(p, "labs.example"); got != "issuer-waltid.labs.example" {
		t.Errorf("PairHost = %q", got)
	}
	if got := PairPublicURL(p, "labs.example"); got != "https://issuer-waltid.labs.example" {
		t.Errorf("PairPublicURL = %q", got)
	}
	if got := KeycloakHost(configv1.Dpg_DPG_INJI, "labs.example"); got != "inji-keycloak.labs.example" {
		t.Errorf("KeycloakHost = %q", got)
	}
	if got := KeycloakPublicURL(configv1.Dpg_DPG_CREDEBL, "labs.example"); got != "https://credebl-keycloak.labs.example" {
		t.Errorf("KeycloakPublicURL = %q", got)
	}
	if KeycloakHost(configv1.Dpg_DPG_UNSPECIFIED, "labs.example") != "" ||
		KeycloakPublicURL(configv1.Dpg_DPG_UNSPECIFIED, "labs.example") != "" {
		t.Error("a DPG with no Keycloak got a host")
	}
}

func TestApplyDomainKeepsAGivenPublicURL(t *testing.T) {
	settings := Filter(Settings(), commonv1.Role_ROLE_ISSUER, configv1.Dpg_DPG_WALTID)
	p := issuerPair()
	list := resolveWithDefaults(settings, Sources{Flags: map[string]string{"VCA_PUBLIC_URL": "https://mine.example"}}, p, "labs.example")
	values := Values(list)
	if values["VCA_PUBLIC_URL"] != "https://mine.example" {
		t.Errorf("the flag lost: %q", values["VCA_PUBLIC_URL"])
	}
	if values["VCA_OIDC_PUBLIC_URL"] != "https://waltid-keycloak.labs.example" {
		t.Errorf("the Keycloak host did not follow the domain: %q", values["VCA_OIDC_PUBLIC_URL"])
	}
	list = resolveWithDefaults(settings, Sources{}, p, "")
	if got := Values(list)["VCA_PUBLIC_URL"]; got != LocalPublicURL(p) {
		t.Errorf("no domain must keep localhost: %q", got)
	}
	list = resolveWithDefaults(settings, Sources{}, p, "labs.example")
	for _, r := range list {
		if r.Setting.Path == "public_url" && (r.Origin != OriginDomain || r.Origin.String() != "domain") {
			t.Errorf("origin = %v", r.Origin)
		}
	}
}

func TestAskDomainRepeatsABadAnswer(t *testing.T) {
	var out bytes.Buffer
	p := NewPrompter(strings.NewReader("not a domain\n*.labs.example\n"), &out)
	got, err := p.AskDomain()
	if err != nil || got != "labs.example" {
		t.Fatalf("got %q, %v", got, err)
	}
	if strings.Count(out.String(), "Base domain [") != 2 || !strings.Contains(out.String(), "DNS name") {
		t.Errorf("out = %s", out.String())
	}
	p = NewPrompter(strings.NewReader(""), &out)
	if got, err := p.AskDomain(); err != nil || got != "" {
		t.Errorf("an ended input must mean no domain: %q, %v", got, err)
	}
	p = NewPrompter(strings.NewReader(strings.Repeat("bad\n", maxTries)), &out)
	if _, err := p.AskDomain(); err == nil {
		t.Error("too many bad answers passed")
	}
}

func TestResolveDomainSources(t *testing.T) {
	pairs := PairsForDpg(dpgWaltid(t))
	prompter := NewPrompter(strings.NewReader("labs.example\n"), &bytes.Buffer{})
	got, err := resolveDomain("flag.example", nil, nil, nil, pairs, true, prompter)
	if err != nil || got != "flag.example" {
		t.Errorf("flag: %q, %v", got, err)
	}
	getenv := func(name string) string {
		if name == DomainEnv {
			return "env.example"
		}
		return ""
	}
	got, err = resolveDomain("", getenv, nil, nil, pairs, true, prompter)
	if err != nil || got != "env.example" {
		t.Errorf("env: %q, %v", got, err)
	}
	if _, badErr := resolveDomain("bad", nil, nil, nil, pairs, true, prompter); badErr == nil {
		t.Error("a bad flag passed")
	}
	got, err = resolveDomain("", nil, nil, nil, pairs[:1], true, prompter)
	if err != nil || got != "" {
		t.Errorf("one pair must ask nothing: %q, %v", got, err)
	}
	got, err = resolveDomain("", nil, nil, nil, pairs, false, prompter)
	if err != nil || got != "" {
		t.Errorf("a scripted run must ask nothing: %q, %v", got, err)
	}
	public := func(name string) string {
		if name == "VCA_PUBLIC_URL" {
			return "https://one.example"
		}
		return ""
	}
	got, err = resolveDomain("", public, nil, nil, pairs, true, prompter)
	if err != nil || got != "" {
		t.Errorf("a public URL in the environment must ask nothing: %q, %v", got, err)
	}
	got, err = resolveDomain("", nil, nil, map[string]string{"VCA_PUBLIC_URL": "https://one.example"}, pairs, true, prompter)
	if err != nil || got != "" {
		t.Errorf("a public URL in the env file must ask nothing: %q, %v", got, err)
	}
	got, err = resolveDomain("", nil, nil, nil, pairs, true, prompter)
	if err != nil || got != "labs.example" {
		t.Errorf("the question: %q, %v", got, err)
	}
}
