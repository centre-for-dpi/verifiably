// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"text/template"

	"gopkg.in/yaml.v3"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
)

// renderPeers renders the peers template of the umbrella chart with the
// standard template engine, which holds every function the template
// uses, and returns the parsed VCA_PEERS value.
func renderPeers(t *testing.T, src, release, domain string, roles, dpgs []string) []topology.Peer {
	t.Helper()
	tmpl, err := template.New("peers").Parse(src)
	if err != nil {
		t.Fatalf("parse the template: %v", err)
	}
	on := func(names []string) map[string]any {
		out := map[string]any{}
		for _, n := range names {
			out[n] = map[string]any{"enabled": true}
		}
		return out
	}
	var out bytes.Buffer
	if xerr := tmpl.Execute(&out, map[string]any{
		"Release": map[string]any{"Name": release},
		"Values":  map[string]any{"dpg": on(dpgs), "global": map[string]any{"publicDomain": domain, "roles": on(roles)}},
	}); xerr != nil {
		t.Fatalf("render the template: %v", xerr)
	}
	var doc struct {
		Metadata struct {
			Name string `yaml:"name"`
		} `yaml:"metadata"`
		Data map[string]string `yaml:"data"`
	}
	if yerr := yaml.Unmarshal(out.Bytes(), &doc); yerr != nil {
		t.Fatalf("the output is not YAML: %v\n%s", yerr, out.String())
	}
	if doc.Metadata.Name != release+"-peers" {
		t.Errorf("config map name = %q", doc.Metadata.Name)
	}
	peers, err := topology.Parse(doc.Data[topology.Env])
	if err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	return peers
}

// TestUmbrellaWritesPeers is P7-03: the umbrella chart writes VCA_PEERS
// from the release name, one pair per turned on role and DPG, each
// service at its in cluster name, as compose writes it for a pair. A
// public domain gives each pair its public address. The template file
// is generated from the catalogue, so the two never drift.
func TestUmbrellaWritesPeers(t *testing.T) {
	path := filepath.Join(HelmChartDir(repoRoot(), UmbrellaChart), "templates", UmbrellaPeersFile)
	want := UmbrellaPeersTemplate()
	if os.Getenv("VCA_WRITE_HELM") != "" {
		if err := os.WriteFile(path, []byte(want), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(path) // #nosec G304 -- a fixed test path
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(got) != want {
		t.Fatalf("%s is not current; run VCA_WRITE_HELM=1 go test ./internal/cli/ -run TestUmbrellaWritesPeers", path)
	}
	peers := renderPeers(t, string(got), "vca", "", []string{"issuer", "verifier"}, []string{"waltid"})
	if len(peers) != 2 || peers[0].Pair != "issuer-waltid" || peers[1].Pair != "verifier-waltid" {
		t.Fatalf("peers = %+v", peers)
	}
	issuer := Pair{Role: commonv1.Role_ROLE_ISSUER, Dpg: configv1.Dpg_DPG_WALTID}
	services := ServicesFor(issuer)
	if len(peers[0].Services) != len(services) {
		t.Errorf("issuer services = %v", peers[0].Services)
	}
	for _, s := range services {
		if got, want := peers[0].Services[s.Name], "http://vca-"+s.Name+":"+fmt.Sprint(s.ExposedPort); got != want {
			t.Errorf("%s = %q, want %q", s.Name, got, want)
		}
	}
	if peers[0].PublicURL != peers[0].Home() {
		t.Errorf("without a domain the public URL %q is not the home service %q", peers[0].PublicURL, peers[0].Home())
	}
	public := renderPeers(t, string(got), "prod", "labs.example", []string{"admin", "holder"}, []string{"inji", "credebl"})
	names := make([]string, 0, len(public))
	for _, p := range public {
		names = append(names, p.Pair+" "+p.PublicURL)
	}
	if strings.Join(names, ", ") != "holder-inji https://holder-inji.labs.example, holder-credebl https://holder-credebl.labs.example, "+
		"admin-inji https://admin-inji.labs.example, admin-credebl https://admin-credebl.labs.example" {
		t.Errorf("pairs = %v", names)
	}
	if public[0].Services["wallet-portal"] != "http://prod-wallet-portal:"+fmt.Sprint(serviceNamed(t, "wallet-portal").ExposedPort) {
		t.Errorf("holder services = %v", public[0].Services)
	}
	if none := renderPeers(t, string(got), "vca", "", nil, []string{"waltid"}); len(none) != 0 {
		t.Errorf("no role gave %v", none)
	}
}

// TestPeerChartsReadThePeers: every chart of a service that reads
// VCA_PEERS takes it from the ConfigMap of the umbrella chart, which a
// chart installed alone may lack. No other chart reads it.
func TestPeerChartsReadThePeers(t *testing.T) {
	ref := "name: {{ .Release.Name }}-peers\n                optional: true"
	for _, s := range Catalog() {
		reads := false
		for _, l := range s.Links {
			reads = reads || l.Kind == LinkPeers
		}
		data, err := os.ReadFile(filepath.Join(HelmChartDir(repoRoot(), s.Name), "templates", "deployment.yaml")) // #nosec G304 -- a fixed test path
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Contains(string(data), ref); got != reads {
			t.Errorf("%s: reads the peers ConfigMap = %v, want %v", s.Name, got, reads)
		}
	}
}

// serviceNamed returns one service of the catalogue.
func serviceNamed(t *testing.T, name string) Service {
	t.Helper()
	for _, s := range Catalog() {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("no service %s", name)
	return Service{}
}
