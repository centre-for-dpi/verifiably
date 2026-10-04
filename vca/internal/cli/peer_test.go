// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/peerauth"
)

// docRow is one row of the table "Connect services" of docs/deploy.md.
type docRow struct {
	name    string
	servers []string
	reach   string
}

// deployDocRows reads the Connect rows of docs/deploy.md. A server
// written as dpg-adapter-* stands for every adapter of the catalogue.
func deployDocRows(t *testing.T) []docRow {
	t.Helper()
	doc := readText(t, filepath.Join(docsDir(), "deploy.md"))
	_, section, ok := strings.Cut(doc, "\n## What the proxy publishes\n")
	if !ok {
		t.Fatal("docs/deploy.md has no section \"What the proxy publishes\"")
	}
	if end := strings.Index(section, "\n## "); end >= 0 {
		section = section[:end]
	}
	var out []docRow
	for _, line := range strings.Split(section, "\n") {
		cells := strings.Split(line, "|")
		if len(cells) < 5 || !strings.HasPrefix(strings.TrimSpace(cells[1]), "`vca.") {
			continue
		}
		row := docRow{name: strings.Trim(strings.TrimSpace(cells[1]), "`"), reach: strings.TrimSpace(cells[3])}
		for _, server := range strings.Split(cells[2], ",") {
			server = strings.Trim(strings.TrimSpace(server), "`")
			if server == "dpg-adapter-*" {
				for _, s := range Catalog() {
					if s.Dpg != configv1.Dpg_DPG_UNSPECIFIED {
						row.servers = append(row.servers, s.Name)
					}
				}
				continue
			}
			row.servers = append(row.servers, server)
		}
		out = append(out, row)
	}
	return out
}

// TestEveryInternalConnectServiceListsItsCallers is ADR-075 decision 4:
// each Connect service that stays on the compose network names the
// services that may call it, next to the routes of its server, and only
// such a service does.
func TestEveryInternalConnectServiceListsItsCallers(t *testing.T) {
	internal := map[string]bool{}
	for _, row := range deployDocRows(t) {
		if row.reach != "Compose network" {
			continue
		}
		for _, server := range row.servers {
			internal[server+" "+row.name] = true
		}
	}
	if len(internal) < 30 {
		t.Fatalf("the doc names only %d internal Connect services", len(internal))
	}
	listed := map[string]bool{}
	for _, s := range Catalog() {
		for name := range s.Callers {
			key := s.Name + " " + name
			listed[key] = true
			if !internal[key] {
				t.Errorf("%s lists callers of %s, which docs/deploy.md does not name as served on the compose network", s.Name, name)
			}
			if _, public := checkedRPC[key]; public {
				t.Errorf("%s lists callers of %s, which is public and checks the user instead", s.Name, name)
			}
		}
	}
	for key := range internal {
		if !listed[key] {
			t.Errorf("%s serves %s on the compose network but lists no callers for it", strings.Fields(key)[0], strings.Fields(key)[1])
		}
	}
}

// TestCallersNameServicesOfTheCatalogue keeps typing errors out of the
// lists: a caller is a service of the catalogue or the CLI.
func TestCallersNameServicesOfTheCatalogue(t *testing.T) {
	names := map[string]bool{CLIPeer: true}
	for _, s := range Catalog() {
		names[s.Name] = true
	}
	for _, s := range Catalog() {
		for name, callers := range s.Callers {
			for _, c := range callers {
				if !names[c] {
					t.Errorf("%s lists %q as a caller of %s, which is no service", s.Name, c, name)
				}
			}
		}
	}
}

// TestEveryServiceLinkIsAListedCaller checks the lists against the
// links: a service that holds the base URL of another service calls it,
// so the other service lists it for at least one Connect service.
func TestEveryServiceLinkIsAListedCaller(t *testing.T) {
	byName := map[string]Service{}
	for _, s := range Catalog() {
		byName[s.Name] = s
	}
	lists := func(target Service, caller string) bool {
		for _, callers := range target.Callers {
			if slices.Contains(callers, caller) {
				return true
			}
		}
		return false
	}
	checked := 0
	for _, s := range Catalog() {
		for _, l := range s.Links {
			var targets []string
			switch {
			case l.Kind == LinkURL && l.Path == "":
				targets = []string{l.Target}
			case s.Dpg != configv1.Dpg_DPG_UNSPECIFIED:
				// An adapter that names an adapter address names its own.
			case (l.Kind == LinkAdapterURL && l.Path == "") || l.Kind == LinkAdapterMap:
				for _, a := range Catalog() {
					if a.Dpg != configv1.Dpg_DPG_UNSPECIFIED {
						targets = append(targets, a.Name)
					}
				}
			}
			for _, target := range targets {
				if target == s.Name {
					// A service that names its own address, such as
					// the callback of a DPG, calls no Connect service.
					continue
				}
				checked++
				if !lists(byName[target], s.Name) {
					t.Errorf("%s links %s to %s, but %s lists %s as no caller", s.Name, l.Env, target, target, s.Name)
				}
			}
		}
	}
	if checked < 20 {
		t.Fatalf("only %d links checked", checked)
	}
	// Every page service probes the capabilities of each adapter.
	for _, s := range Catalog() {
		if !s.UI {
			continue
		}
		for _, a := range Catalog() {
			if a.Dpg != configv1.Dpg_DPG_UNSPECIFIED && !slices.Contains(a.Callers["vca.backend.v1.CapabilityService"], s.Name) {
				t.Errorf("%s probes %s but is no caller of its CapabilityService", s.Name, a.Name)
			}
		}
	}
}

// planWithAuthority runs setup for one pair with an authority.
func planWithAuthority(t *testing.T, p Pair, authority []byte) Plan {
	t.Helper()
	plan, err := BuildPlan(SetupRequest{
		Pair:          p,
		Flags:         map[string]string{"VCA_OIDC_DISCOVERY_URL": "https://login.example/realms/vca/.well-known/openid-configuration"},
		Random:        rand.Reader,
		PeerAuthority: authority,
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

// fileOf returns the file of a plan by name.
func fileOf(files []File, name string) (File, bool) {
	for _, f := range files {
		if f.Name == name {
			return f, true
		}
	}
	return File{}, false
}

// fileOrZero returns the file of a plan by name, or no file.
func fileOrZero(files []File, name string) File {
	f, _ := fileOf(files, name)
	return f
}

// loadIdentity parses one identity file and the key file beside it.
// The identity file names the key at its path in the container, so the
// test writes the key to a file of its own and points there.
func loadIdentity(t *testing.T, data, key []byte) peerauth.Settings {
	t.Helper()
	values, err := ParseDotenv(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if values[peerauth.KeyEnv] != "" {
		t.Fatalf("the identity file holds the private key in %s", peerauth.KeyEnv)
	}
	if values[peerauth.KeyFileEnv] != PeerKeyMount {
		t.Fatalf("%s = %q, want %s", peerauth.KeyFileEnv, values[peerauth.KeyFileEnv], PeerKeyMount)
	}
	path := filepath.Join(t.TempDir(), "key.jwk")
	if werr := os.WriteFile(path, key, 0o600); werr != nil {
		t.Fatal(werr)
	}
	values[peerauth.KeyFileEnv] = path
	s, err := peerauth.Load(func(k string) string { return values[k] })
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// planned loads the identity of one service from the files of a plan.
// dir is the directory of the files: empty for a pair, the service name
// for a deployment scoped service.
func planned(t *testing.T, files []File, dir, service string) peerauth.Settings {
	t.Helper()
	env, ok := fileOf(files, filepath.Join(dir, PeerFile(service)))
	key, kok := fileOf(files, filepath.Join(dir, PeerKeyFile(service)))
	if !ok || !kok {
		t.Fatalf("the plan has no identity or no key for %s", service)
	}
	if key.Mode != 0o644 || key.DirMode != 0o700 {
		t.Errorf("%s: mode %o in a directory of mode %o, want 0644 in 0700", key.Name, key.Mode, key.DirMode)
	}
	return loadIdentity(t, env.Data, key.Data)
}

// onDisk loads the identity of one service from a directory of deploy.
func onDisk(t *testing.T, dir, service string) peerauth.Settings {
	t.Helper()
	env, err := os.ReadFile(filepath.Join(dir, PeerFile(service))) // #nosec G304 -- a test path
	if err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(filepath.Join(dir, PeerKeyFile(service))) // #nosec G304 -- a test path
	if err != nil {
		t.Fatal(err)
	}
	return loadIdentity(t, env, key)
}

// TestSetupGivesEveryServiceAnIdentity is ADR-075 decisions 1 and 2.
func TestSetupGivesEveryServiceAnIdentity(t *testing.T) {
	p := Pair{Role: commonv1.Role_ROLE_ISSUER, Dpg: configv1.Dpg_DPG_WALTID}
	first := planWithAuthority(t, p, nil)
	auth, ok := fileOf(first.Shared, filepath.Join(PeerDir, PeerAuthorityFile))
	if !ok || auth.Mode != 0o600 {
		t.Fatalf("the first run writes no authority key: %+v", first.Shared)
	}
	if ignore, found := fileOf(first.Shared, filepath.Join(PeerDir, ".gitignore")); !found || string(ignore.Data) != "*\n" {
		t.Error("the authority directory has no .gitignore")
	}
	authority, err := peerauth.ParseAuthority(auth.Data)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range ServicesFor(p) {
		f, found := fileOf(first.Files, PeerFile(s.Name))
		if !found {
			t.Errorf("no identity file for %s", s.Name)
			continue
		}
		if f.Mode != 0o600 {
			t.Errorf("%s: mode %o", f.Name, f.Mode)
		}
		id := planned(t, first.Files, "", s.Name)
		if id.ID.Service != s.Name || id.ID.Pair != p.Name() {
			t.Errorf("%s: identity %+v", s.Name, id.ID)
		}
		if id.Callers.String() != peerauth.Callers(s.Callers).String() {
			t.Errorf("%s: callers %q, want %q", s.Name, id.Callers, peerauth.Callers(s.Callers))
		}
		if id.Authority.Keys[0].KeyID != peerauth.Settings(mustIssue(t, authority, "x")).Authority.Keys[0].KeyID {
			t.Errorf("%s trusts another authority", s.Name)
		}
	}
	for _, f := range []File{fileOrZero(first.Files, filepath.Join(PeerDir, ".gitignore")),
		fileOrZero(first.Shared, filepath.Join(LandingDir, PeerDir, ".gitignore"))} {
		if string(f.Data) != "*\n" {
			t.Errorf("an identity directory has no .gitignore: %+v", f)
		}
	}
	if planned(t, first.Shared, LandingDir, LandingService).ID.Service != LandingService {
		t.Fatal("the landing has no identity")
	}
	// The landing serves the whole deployment, so its statement says so.
	// A service of a pair is bound to its pair (ADR-075 consequence 3).
	if !planned(t, first.Shared, LandingDir, LandingService).ID.Deployment {
		t.Error("the identity of the landing is not deployment scoped")
	}
	if planned(t, first.Files, "", "issuance").ID.Deployment {
		t.Error("the identity of a service of a pair is deployment scoped")
	}
	// A second run keeps the authority, so every pair trusts the others.
	second := planWithAuthority(t, Pair{Role: commonv1.Role_ROLE_ADMIN, Dpg: configv1.Dpg_DPG_WALTID}, auth.Data)
	if _, ok := fileOf(second.Shared, filepath.Join(PeerDir, PeerAuthorityFile)); ok {
		t.Error("a run with an authority writes a new one")
	}
	callee := planned(t, second.Files, "", "trust-registry")
	h, err := planned(t, first.Files, "", "issuance").Header("/vca.trust.v1.TrustService/ListEntries", "admin-waltid-trust-registry:8082")
	if err != nil {
		t.Fatal(err)
	}
	if id, err := callee.Check(h, "/vca.trust.v1.TrustService/ListEntries"); err != nil || id.Service != "issuance" {
		t.Fatalf("the trust registry of another run refused issuance: %v", err)
	}
	if _, err := BuildPlan(SetupRequest{Pair: p, Random: rand.Reader, PeerAuthority: []byte("bad"),
		Flags: map[string]string{"VCA_OIDC_DISCOVERY_URL": "https://login.example/x"}}); err == nil {
		t.Error("setup took a bad authority key")
	}
}

// mustIssue issues an identity for a test.
func mustIssue(t *testing.T, a peerauth.Authority, service string) peerauth.Settings {
	t.Helper()
	s, err := a.Issue(peerauth.ID{Service: service}, rand.Reader, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestComposeGivesEachServiceItsIdentity is ADR-075 decision 2: each
// container reads its own identity file, and compose stops when it is
// missing.
func TestComposeGivesEachServiceItsIdentity(t *testing.T) {
	var doc struct {
		Services map[string]struct {
			EnvFile []struct {
				Path     string `yaml:"path"`
				Required bool   `yaml:"required"`
			} `yaml:"env_file"`
			Volumes []any `yaml:"volumes"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(RenderCompose()), &doc); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{}
	keys := map[string]string{}
	for _, p := range AllPairs() {
		for _, s := range ServicesFor(p) {
			want[composeServiceName(p, s)] = "../" + p.Name() + "/" + PeerFile(s.Name)
			keys[composeServiceName(p, s)] = "../" + p.Name() + "/" + filepath.ToSlash(PeerKeyFile(s.Name))
		}
	}
	for _, s := range DeploymentServices() {
		want[DeploymentServiceName(s)] = "../" + s.Name + "/" + PeerFile(s.Name)
		keys[DeploymentServiceName(s)] = "../" + s.Name + "/" + filepath.ToSlash(PeerKeyFile(s.Name))
	}
	for name, path := range want {
		svc, ok := doc.Services[name]
		if !ok {
			t.Errorf("compose has no %s", name)
			continue
		}
		found := false
		for _, f := range svc.EnvFile {
			found = found || (f.Path == path && f.Required)
		}
		if !found {
			t.Errorf("%s does not require %s: %+v", name, path, svc.EnvFile)
		}
		// The key file goes in read only. Compose refuses to start the
		// service when the file is missing, as it does for the identity
		// file, instead of making a directory there.
		mounted := false
		for _, v := range svc.Volumes {
			m, ok := v.(map[string]any)
			if !ok {
				continue
			}
			bind, isMap := m["bind"].(map[string]any)
			mounted = mounted || (m["type"] == "bind" && m["source"] == keys[name] && m["target"] == PeerKeyMount &&
				m["read_only"] == true && isMap && bind["create_host_path"] == false)
		}
		if !mounted {
			t.Errorf("%s does not mount its key %s at %s: %v", name, keys[name], PeerKeyMount, svc.Volumes)
		}
	}
}

// writeOldDeployment writes the .env of two pairs and of the landing,
// as a release before peer identities left them.
func writeOldDeployment(t *testing.T) (string, []Pair) {
	t.Helper()
	deploy := t.TempDir()
	pairs := []Pair{
		{Role: commonv1.Role_ROLE_ISSUER, Dpg: configv1.Dpg_DPG_WALTID},
		{Role: commonv1.Role_ROLE_ADMIN, Dpg: configv1.Dpg_DPG_WALTID},
	}
	for _, dir := range []string{pairs[0].Name(), pairs[1].Name(), LandingDir} {
		if err := os.MkdirAll(filepath.Join(deploy, dir), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(deploy, dir, EnvFileName), []byte("VCA_ROLE=x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return deploy, pairs
}

// TestUpgradeAddsPeerIdentities is ADR-075 decision 5: an existing
// deployment gets the authority and every identity file, and a second
// run changes nothing.
func TestUpgradeAddsPeerIdentities(t *testing.T) {
	deploy, pairs := writeOldDeployment(t)
	var out bytes.Buffer
	opts := PeerUpgradeOptions{Deploy: deploy, Random: rand.Reader, Out: &out}
	n, err := UpgradePeerIdentities(opts)
	if err != nil {
		t.Fatal(err)
	}
	want := 1 // the landing
	for _, p := range pairs {
		want += len(ServicesFor(p))
	}
	if n != want {
		t.Errorf("wrote %d identities, want %d:\n%s", n, want, out.String())
	}
	raw, err := os.ReadFile(filepath.Join(deploy, PeerDir, PeerAuthorityFile)) // #nosec G304 -- a test path
	if err != nil {
		t.Fatal(err)
	}
	authority, err := peerauth.ParseAuthority(raw)
	if err != nil {
		t.Fatal(err)
	}
	read := func(path string) []byte {
		data, rerr := os.ReadFile(path) // #nosec G304 -- a test path
		if rerr != nil {
			t.Fatal(rerr)
		}
		return data
	}
	issuance := filepath.Join(deploy, pairs[0].Name(), PeerFile("issuance"))
	before := read(issuance)
	if id := onDisk(t, filepath.Join(deploy, pairs[0].Name()), "issuance"); id.ID.Pair != pairs[0].Name() || id.Authority.Keys[0].KeyID != mustIssue(t, authority, "x").Authority.Keys[0].KeyID {
		t.Errorf("issuance identity %+v", id.ID)
	}
	if info, serr := os.Stat(issuance); serr != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("mode of %s: %v %v", issuance, info, serr)
	}
	// The key goes to a file that the container user reads, in a
	// directory that no other user of the host opens.
	keyPath := filepath.Join(deploy, pairs[0].Name(), PeerKeyFile("issuance"))
	if info, serr := os.Stat(keyPath); serr != nil || info.Mode().Perm() != 0o644 {
		t.Errorf("mode of %s: %v %v", keyPath, info, serr)
	}
	if info, serr := os.Stat(filepath.Dir(keyPath)); serr != nil || info.Mode().Perm() != 0o700 {
		t.Errorf("mode of %s: %v %v", filepath.Dir(keyPath), info, serr)
	}
	if onDisk(t, filepath.Join(deploy, LandingDir), LandingService).ID.Service != LandingService {
		t.Error("the landing got no identity")
	}
	if string(read(filepath.Join(deploy, pairs[0].Name(), PeerDir, ".gitignore"))) != "*\n" {
		t.Error("the identity directory of a pair has no .gitignore")
	}
	out.Reset()
	n, err = UpgradePeerIdentities(opts)
	if err != nil || n != 0 {
		t.Fatalf("a second run wrote %d: %v\n%s", n, err, out.String())
	}
	if !bytes.Equal(before, read(issuance)) {
		t.Error("a second run changed an identity")
	}
	if !strings.Contains(out.String(), "Every service already holds") {
		t.Errorf("a second run says %q", out.String())
	}
	// A landing identity of a release before the deployment scope gets
	// the scope at the next run, with the same authority.
	landingPath := filepath.Join(deploy, LandingDir, PeerFile(LandingService))
	old, _, err := peerIdentity(authority, LandingService, deploymentServiceNamed(t, LandingService), false, rand.Reader, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if werr := os.WriteFile(landingPath, old, 0o600); werr != nil {
		t.Fatal(werr)
	}
	if n, err = UpgradePeerIdentities(opts); err != nil || n != 1 || !onDisk(t, filepath.Join(deploy, LandingDir), LandingService).ID.Deployment {
		t.Fatalf("the landing without scope: wrote %d, %v", n, err)
	}
	// An identity file of the release that kept the key in the
	// environment gets the key file at the next run.
	inline := mustIssue(t, authority, "issuance")
	inlineKey, err := inline.KeyJWK()
	if err != nil {
		t.Fatal(err)
	}
	inlineEnv := inline.Env()
	inlineEnv[peerauth.KeyEnv] = base64.RawURLEncoding.EncodeToString(inlineKey)
	var text strings.Builder
	for k, v := range inlineEnv {
		text.WriteString(k + "=" + quoteValue(v) + "\n")
	}
	if werr := os.WriteFile(issuance, []byte(text.String()), 0o600); werr != nil {
		t.Fatal(werr)
	}
	if rerr := os.Remove(keyPath); rerr != nil {
		t.Fatal(rerr)
	}
	if n, err = UpgradePeerIdentities(opts); err != nil || n != 1 {
		t.Fatalf("an identity with the key in the environment: wrote %d, %v", n, err)
	}
	onDisk(t, filepath.Join(deploy, pairs[0].Name()), "issuance")
	// An identity of a lost authority gets a new one.
	if rerr := os.Remove(filepath.Join(deploy, PeerDir, PeerAuthorityFile)); rerr != nil {
		t.Fatal(rerr)
	}
	n, err = UpgradePeerIdentities(opts)
	if err != nil || n != want {
		t.Fatalf("after a new authority it wrote %d, want %d: %v", n, want, err)
	}
}

// TestHelmPeerSecrets is ADR-075 decision 6: one Secret per chart.
func TestHelmPeerSecrets(t *testing.T) {
	deploy := t.TempDir()
	var out bytes.Buffer
	if err := HelmPeerSecrets(PeerHelmOptions{Deploy: deploy, Release: "vca", Namespace: "ids", Random: rand.Reader, Out: &out}); err != nil {
		t.Fatal(err)
	}
	dec := yaml.NewDecoder(&out)
	seen := map[string]bool{}
	envs, keys := map[string]map[string]string{}, map[string]string{}
	for {
		var doc struct {
			Kind     string `yaml:"kind"`
			Metadata struct {
				Name      string `yaml:"name"`
				Namespace string `yaml:"namespace"`
			} `yaml:"metadata"`
			StringData map[string]string `yaml:"stringData"`
		}
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if doc.Kind != "Secret" || doc.Metadata.Namespace != "ids" {
			t.Errorf("document %+v", doc.Metadata)
		}
		// The key goes to a Secret of its own, which the pod mounts as a
		// file. The other Secret holds the variables.
		if key, isKey := doc.StringData[PeerKeyName]; isKey {
			keys[doc.Metadata.Name] = key
			continue
		}
		if doc.StringData[peerauth.KeyEnv] != "" || doc.StringData[peerauth.KeyFileEnv] != PeerKeyMount {
			t.Errorf("secret %s holds the key or names no key file: %v", doc.Metadata.Name, doc.StringData[peerauth.KeyFileEnv])
		}
		envs[doc.Metadata.Name] = doc.StringData
	}
	for name, values := range envs {
		key, ok := keys[name+"-key"]
		if !ok {
			t.Errorf("no key secret %s-key", name)
			continue
		}
		path := filepath.Join(t.TempDir(), PeerKeyName)
		if err := os.WriteFile(path, []byte(key), 0o600); err != nil {
			t.Fatal(err)
		}
		values[peerauth.KeyFileEnv] = path
		s, err := peerauth.Load(func(k string) string { return values[k] })
		if err != nil {
			t.Fatal(err)
		}
		if name != "vca-"+s.ID.Service+"-peer" || s.ID.Pair != "vca" {
			t.Errorf("secret %s holds %+v", name, s.ID)
		}
		if s.ID.Deployment != (s.ID.Service == LandingService) {
			t.Errorf("secret %s: deployment scope %v", name, s.ID.Deployment)
		}
		seen[s.ID.Service] = true
	}
	for _, s := range Catalog() {
		if !seen[s.Name] {
			t.Errorf("no secret for %s", s.Name)
		}
	}
	if _, err := os.Stat(filepath.Join(deploy, PeerDir, PeerAuthorityFile)); err != nil {
		t.Errorf("the authority is not kept: %v", err)
	}
	if err := HelmPeerSecrets(PeerHelmOptions{Deploy: deploy, Random: rand.Reader, Out: &out}); err == nil {
		t.Error("a run with no release worked")
	}
}

// TestServiceChartsReadTheirPeerSecret is ADR-075 decision 6 for the
// templates: each pod reads its identity, and no pod starts without it.
func TestServiceChartsReadTheirPeerSecret(t *testing.T) {
	for _, s := range Catalog() {
		dir := HelmChartDir(repoRoot(), s.Name)
		deployment := readText(t, filepath.Join(dir, "templates", "deployment.yaml"))
		if !strings.Contains(deployment, "name: {{ .Values.peer.secret | default (printf \"%s-%s-peer\" .Release.Name .Chart.Name) }}") {
			t.Errorf("%s: the deployment does not read the peer secret", s.Name)
		}
		values := readText(t, filepath.Join(dir, "values.yaml"))
		if !strings.Contains(values, "\npeer:\n  secret: \"\"\n  keySecret: \"\"\n") {
			t.Errorf("%s: values.yaml has no peer.secret and peer.keySecret", s.Name)
		}
		// The key is a file of a Secret of its own, read only. A new
		// Secret rolls the pods through a checksum, so a rotation takes
		// effect (finding 4 of the review of ADR-075).
		for _, want := range []string{
			"secretName: {{ .Values.peer.keySecret | default (printf \"%s-%s-peer-key\" .Release.Name .Chart.Name) }}",
			"mountPath: " + path.Dir(PeerKeyMount),
			"- key: " + PeerKeyName,
			"checksum/peer: {{ include \"vca.peerChecksum\" . }}",
		} {
			if !strings.Contains(deployment, want) {
				t.Errorf("%s: the deployment has no %q", s.Name, want)
			}
		}
		helpers := readText(t, filepath.Join(dir, "templates", "_helpers.tpl"))
		if !strings.Contains(helpers, `define "vca.peerChecksum"`) || !strings.Contains(helpers, `lookup "v1" "Secret"`) {
			t.Errorf("%s: _helpers.tpl has no checksum of the peer Secrets", s.Name)
		}
	}
}

// TestCLIClientSignsWithTheAuthority checks the identity of the CLI: it
// signs its calls of an adapter with an identity of the authority of
// the deployment.
func TestCLIClientSignsWithTheAuthority(t *testing.T) {
	deploy := t.TempDir()
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got = r.Header.Clone() }))
	defer srv.Close()
	// No authority: the client sends no identity.
	client, err := CLIPeerClient(deploy, srv.Client(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	post := func(c *http.Client) {
		req, rerr := http.NewRequest(http.MethodPost, srv.URL+"/vca.backend.v1.IssuerBackendService/GetIssuerIdentity", strings.NewReader("{}"))
		if rerr != nil {
			t.Fatal(rerr)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Connect-Protocol-Version", "1")
		res, rerr := c.Do(req)
		if rerr != nil {
			t.Fatal(rerr)
		}
		if cerr := res.Body.Close(); cerr != nil {
			t.Fatal(cerr)
		}
	}
	post(client)
	if got.Get(peerauth.TokenHeader) != "" {
		t.Error("a deployment with no authority signs")
	}
	if _, uerr := UpgradePeerIdentities(PeerUpgradeOptions{Deploy: deploy, Random: rand.Reader, Out: io.Discard}); uerr != nil {
		t.Fatal(uerr)
	}
	client, err = CLIPeerClient(deploy, srv.Client(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	post(client)
	raw, err := os.ReadFile(filepath.Join(deploy, PeerDir, PeerAuthorityFile)) // #nosec G304 -- a test path
	if err != nil {
		t.Fatal(err)
	}
	authority, err := peerauth.ParseAuthority(raw)
	if err != nil {
		t.Fatal(err)
	}
	callee := mustIssue(t, authority, "dpg-adapter-waltid")
	callee.Callers = peerauth.Callers{"vca.backend.v1.IssuerBackendService": {CLIPeer}}
	// The CLI calls through a port of the host, so the adapter takes its
	// token at any host: the identity is deployment scoped.
	if id, err := callee.Check(got, "/vca.backend.v1.IssuerBackendService/GetIssuerIdentity"); err != nil || id.Service != CLIPeer || !id.Deployment {
		t.Fatalf("the adapter refused the CLI: %+v, %v", id, err)
	}
}

// deploymentServiceNamed returns the deployment scoped service of the
// name.
func deploymentServiceNamed(t *testing.T, name string) Service {
	t.Helper()
	for _, s := range DeploymentServices() {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("no deployment service %s", name)
	return Service{}
}

// TestHelmPeerSecretsTwiceChangesNothing is ADR-075 decision 5 for Helm:
// a second run of vca peer secrets reuses the Secrets of the first, so
// kubectl apply changes nothing and the pods do not roll. A new release
// or a new authority gets new Secrets.
func TestHelmPeerSecretsTwiceChangesNothing(t *testing.T) {
	deploy := t.TempDir()
	run := func(release string) string {
		t.Helper()
		var out bytes.Buffer
		if err := HelmPeerSecrets(PeerHelmOptions{Deploy: deploy, Release: release, Namespace: "ids", Random: rand.Reader, Out: &out}); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}
	first, second := run("vca"), run("vca")
	if first != second {
		t.Fatalf("a second run changed the Secrets:\n%s", lineDiff(first, second))
	}
	if other := run("staging"); other == first || strings.Contains(other, "name: vca-") {
		t.Error("another release reused the Secrets of the first")
	}
	if third := run("vca"); third != first {
		t.Errorf("a run of another release changed the Secrets of the first:\n%s", lineDiff(first, third))
	}
	err := filepath.WalkDir(filepath.Join(deploy, PeerDir), func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		info, ierr := d.Info()
		if ierr == nil && info.Mode().Perm()&0o077 != 0 && d.Name() != ".gitignore" {
			t.Errorf("%s has mode %v", path, info.Mode().Perm())
		}
		return ierr
	})
	if err != nil {
		t.Fatal(err)
	}
	if rerr := os.Remove(filepath.Join(deploy, PeerDir, PeerAuthorityFile)); rerr != nil {
		t.Fatal(rerr)
	}
	if rotated := run("vca"); rotated == first {
		t.Error("a new authority kept the old Secrets")
	}
	for _, bad := range []string{"../vca", "VCA", "a/b", strings.Repeat("a", 54)} {
		if err := HelmPeerSecrets(PeerHelmOptions{Deploy: deploy, Release: bad, Random: rand.Reader, Out: io.Discard}); err == nil {
			t.Errorf("the release %q worked", bad)
		}
	}
}

// lineDiff names the lines of b that a does not hold, for a failure
// message. It keeps the field name only, so no key reaches the log.
func lineDiff(a, b string) string {
	have := map[string]bool{}
	for _, l := range strings.Split(a, "\n") {
		have[l] = true
	}
	var out []string
	for _, l := range strings.Split(b, "\n") {
		if !have[l] {
			name, _, _ := strings.Cut(l, ":")
			out = append(out, "+ "+name)
		}
	}
	return strings.Join(out, "\n")
}
