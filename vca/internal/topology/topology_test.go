// SPDX-License-Identifier: Apache-2.0

package topology_test

import (
	"strings"
	"testing"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
)

// sample returns two peers with every field set.
func sample() []topology.Peer {
	return []topology.Peer{
		{
			Pair: "issuer-waltid", Role: commonv1.Role_ROLE_ISSUER, Dpg: configv1.Dpg_DPG_WALTID,
			PublicURL: "https://issuer-waltid.labs.example",
			Services: map[string]string{
				"schema-registry":    "http://issuer-waltid-schema-registry:8103",
				"issuer-auth":        "http://issuer-waltid-issuer-auth:8081",
				"dpg-adapter-waltid": "http://issuer-waltid-dpg-adapter-waltid:8090",
				"issuance":           "http://issuer-waltid-issuance:8080",
			},
		},
		{
			Pair: "admin-inji", Role: commonv1.Role_ROLE_ADMIN, Dpg: configv1.Dpg_DPG_INJI,
			PublicURL: "http://localhost:18900",
			Services:  map[string]string{"admin": "http://admin-inji-admin:8080"},
		},
	}
}

func TestHomePathAndSignInURL(t *testing.T) {
	for role, want := range map[commonv1.Role]string{
		commonv1.Role_ROLE_ISSUER: "/portal/", commonv1.Role_ROLE_HOLDER: "/wallet/",
		commonv1.Role_ROLE_VERIFIER: "/portal/", commonv1.Role_ROLE_ADMIN: "/admin/", commonv1.Role_ROLE_UNSPECIFIED: "",
	} {
		if got := topology.HomePath(role); got != want {
			t.Errorf("HomePath(%v) = %q, want %q", role, got, want)
		}
	}
	p := topology.Peer{Role: commonv1.Role_ROLE_HOLDER, PublicURL: "https://holder.example/"}
	if got := p.SignInURL(); got != "https://holder.example/auth/?return_to=%2Fwallet%2F" {
		t.Errorf("SignInURL = %q", got)
	}
}

func TestFormatParseRoundTrip(t *testing.T) {
	in := sample()
	text := topology.Format(in)
	if strings.ContainsAny(text, "\n ") {
		t.Fatalf("the value must fit one .env line: %q", text)
	}
	if !strings.HasPrefix(text, "issuer-waltid|https://issuer-waltid.labs.example|") {
		t.Fatalf("format = %q", text)
	}
	// The services come out in name order, so the value is stable.
	first := strings.SplitN(text, ";", 2)[0]
	if !strings.Contains(first, "dpg-adapter-waltid=http://issuer-waltid-dpg-adapter-waltid:8090,issuance=") {
		t.Fatalf("the services are not in name order: %q", first)
	}
	out, err := topology.Parse(text)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(out) != len(in) {
		t.Fatalf("parsed %d peers, want %d", len(out), len(in))
	}
	for i := range in {
		if out[i].Pair != in[i].Pair || out[i].Role != in[i].Role || out[i].Dpg != in[i].Dpg ||
			out[i].PublicURL != in[i].PublicURL {
			t.Errorf("peer %d = %+v, want %+v", i, out[i], in[i])
		}
		if len(out[i].Services) != len(in[i].Services) {
			t.Errorf("peer %d has %d services, want %d", i, len(out[i].Services), len(in[i].Services))
		}
		for name, url := range in[i].Services {
			if out[i].Services[name] != url {
				t.Errorf("peer %d service %s = %q, want %q", i, name, out[i].Services[name], url)
			}
		}
	}
	if topology.Format(out) != text {
		t.Fatal("a second Format of the parsed peers differs")
	}
	if got, err := topology.Parse(""); err != nil || len(got) != 0 {
		t.Fatalf("an empty value must parse to no peer: %v, %v", got, err)
	}
	if got, err := topology.Parse(text + ";"); err != nil || len(got) != 2 {
		t.Fatalf("a trailing separator must be harmless: %v, %v", got, err)
	}
}

func TestParseRejectsBadItem(t *testing.T) {
	cases := map[string]string{
		"two fields":       "issuer-waltid|https://a.example",
		"four fields":      "issuer-waltid|https://a.example|x=http://x:1|extra",
		"unknown role":     "clerk-waltid|https://a.example|",
		"unknown dpg":      "issuer-other|https://a.example|",
		"no dash":          "issuer|https://a.example|",
		"empty public":     "issuer-waltid||",
		"bad public":       "issuer-waltid|ftp://a.example|",
		"service no equal": "issuer-waltid|https://a.example|issuance",
		"service no name":  "issuer-waltid|https://a.example|=http://x:1",
		"service bad url":  "issuer-waltid|https://a.example|issuance=x:1",
		"duplicate pair":   "issuer-waltid|https://a.example|;issuer-waltid|https://b.example|",
	}
	for name, value := range cases {
		_, err := topology.Parse(value)
		if err == nil {
			t.Errorf("%s: %q was accepted", name, value)
			continue
		}
		if !strings.Contains(err.Error(), "VCA_PEERS") {
			t.Errorf("%s: the error must name the variable: %v", name, err)
		}
	}
}

func TestPeerNamesItsHomeAuthAndAdapter(t *testing.T) {
	peers := sample()
	issuer, admin := peers[0], peers[1]
	if issuer.Home() != "http://issuer-waltid-schema-registry:8103" {
		t.Errorf("issuer home = %q", issuer.Home())
	}
	if issuer.Auth() != "http://issuer-waltid-issuer-auth:8081" {
		t.Errorf("issuer auth = %q", issuer.Auth())
	}
	if issuer.Adapter() != "http://issuer-waltid-dpg-adapter-waltid:8090" {
		t.Errorf("issuer adapter = %q", issuer.Adapter())
	}
	if admin.Home() != "http://admin-inji-admin:8080" {
		t.Errorf("admin home = %q", admin.Home())
	}
	if admin.Auth() != "" || admin.Adapter() != "" {
		t.Errorf("the admin pair has no auth service and no adapter: %q %q", admin.Auth(), admin.Adapter())
	}
	if topology.HomeService(commonv1.Role_ROLE_HOLDER) != "wallet-portal" ||
		topology.HomeService(commonv1.Role_ROLE_VERIFIER) != "verifier-results" {
		t.Error("the home services of the holder and the verifier are wrong")
	}
	if topology.AuthService(commonv1.Role_ROLE_HOLDER) != "wallet-auth" ||
		topology.AuthService(commonv1.Role_ROLE_VERIFIER) != "verifier-auth" || topology.AuthService(commonv1.Role_ROLE_ADMIN) != "" {
		t.Error("the auth services of the holder, the verifier, and the admin are wrong")
	}
	if topology.HomeService(commonv1.Role_ROLE_UNSPECIFIED) != "" || topology.AuthService(commonv1.Role_ROLE_UNSPECIFIED) != "" {
		t.Error("an unknown role has no service")
	}
	if topology.PairName(commonv1.Role_ROLE_VERIFIER, configv1.Dpg_DPG_CREDEBL) != "verifier-credebl" {
		t.Errorf("pair name = %q", topology.PairName(commonv1.Role_ROLE_VERIFIER, configv1.Dpg_DPG_CREDEBL))
	}
}
