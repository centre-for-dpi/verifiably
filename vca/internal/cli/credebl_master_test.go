// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/rand"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// P6-C0d and ADR-055 decision 1: the database initialisation of the
// CREDEBL release reads the platform admin password and the other
// credentials from its committed master table. Setup writes a master
// table of its own with generated values, and the stack file mounts it
// over the committed one, so no deployment runs with a published
// credential.

// upstreamMasterTable reads the master table of the platform, as the
// fixture of the adapter keeps it.
func upstreamMasterTable(t *testing.T) map[string]any {
	t.Helper()
	path := filepath.Join(repoRoot(), "vca", "services", "dpg-adapter-credebl", "testdata", "doc", "upstream-master-table.json.txt")
	data, err := os.ReadFile(path) // #nosec G304 -- a fixed test path
	if err != nil {
		t.Fatal(err)
	}
	var table map[string]any
	if err := json.Unmarshal(data, &table); err != nil {
		t.Fatal(err)
	}
	return table
}

// field reads one string of a section of a master table.
func field(t *testing.T, table map[string]any, section, name string) string {
	t.Helper()
	if name == "" {
		if value, ok := table[section].(string); ok {
			return value
		}
		return ""
	}
	m, ok := table[section].(map[string]any)
	if !ok {
		t.Fatalf("the master table has no section %s", section)
	}
	if value, ok := m[name].(string); ok {
		return value
	}
	return ""
}

// activeAs returns the ledger rows of the release with isActive set for
// the chosen networks and for no_ledger.
func activeAs(t *testing.T, rows any, chosen string) any {
	t.Helper()
	list, ok := rows.([]any)
	if !ok {
		t.Fatalf("ledgerData is no list: %v", rows)
	}
	out := make([]any, 0, len(list))
	for _, item := range list {
		row, isMap := item.(map[string]any)
		if !isMap {
			t.Fatalf("a ledger row is no object: %v", item)
		}
		copied := map[string]any{}
		for k, v := range row {
			copied[k] = v
		}
		ns := anyval.As[string](row["indyNamespace"])
		copied["isActive"] = ns == "no_ledger" || slices.Contains(strings.Split(chosen, ","), ns)
		out = append(out, copied)
	}
	return out
}

// upstreamCredentials returns every credential the upstream sources
// commit: the four of the master table, and the platform keys of
// .env.demo of the same repository, read on 2026-09-27.
func upstreamCredentials(t *testing.T) []string {
	t.Helper()
	table := upstreamMasterTable(t)
	out := []string{
		field(t, table, "platformAdminData", "password"),
		field(t, table, "platformAdminKeycloakPassword", ""),
		field(t, table, "platformAdminData", "supabaseUserId"),
		field(t, table, "platformConfigData", "sgApiKey"),
	}
	for i, value := range out {
		if value == "" {
			t.Fatalf("credential %d of the fixture is empty", i)
		}
	}
	return append(out,
		"YourSecretPrivateKeyHere",
		"U2FsdGVkX19l6w/PpuicnGBYThBHolzF27oN0JwfWkc=",
		"000000000000000000000000Steward1",
	)
}

// TestNoUpstreamCredeblCredentialSurvives is P6-C0d: no credential of
// the upstream master table reaches a file that setup writes, the
// master table of setup holds the generated platform admin password,
// and the stack file mounts it where the initialisation reads it.
func TestNoUpstreamCredeblCredentialSurvives(t *testing.T) {
	plan, err := BuildPlan(SetupRequest{Pair: credeblPair(commonv1.Role_ROLE_ISSUER), Flags: credeblFlags(), Random: rand.Reader})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	root := t.TempDir()
	if _, werr := WritePlan(root, plan); werr != nil {
		t.Fatal(werr)
	}
	credentials := upstreamCredentials(t)
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, readErr := os.ReadFile(path) // #nosec G304 -- a file of the test directory
		if readErr != nil {
			return readErr
		}
		for _, secret := range credentials {
			if strings.Contains(string(data), secret) {
				t.Errorf("%s holds the upstream credential %q", path, secret)
			}
		}
		return nil
	})
	if walkErr != nil {
		t.Fatal(walkErr)
	}
	stack, err := ReadStackEnv(root, configv1.Dpg_DPG_CREDEBL)
	if err != nil {
		t.Fatal(err)
	}
	password := stack[PlatformAdminPasswordEnv]
	if len(password) != stackSecretLength {
		t.Fatalf("%s = %q, want %d generated characters", PlatformAdminPasswordEnv, password, stackSecretLength)
	}
	f := sharedFile(t, plan, CredeblMasterTableFile)
	if f.Mode != 0o600 {
		t.Errorf("the master table has mode %04o", f.Mode)
	}
	var table map[string]any
	if jerr := json.Unmarshal(f.Data, &table); jerr != nil {
		t.Fatalf("the master table is no JSON: %v", jerr)
	}
	// The initialisation decrypts the password with CRYPTO_PRIVATE_KEY
	// and gives the plain text to Keycloak, with no JSON quotes.
	for _, cipherText := range []string{field(t, table, "platformAdminData", "password"), field(t, table, "platformAdminKeycloakPassword", "")} {
		plain, derr := decryptCryptoJS(cipherText, stack["CRYPTO_PRIVATE_KEY"])
		if derr != nil || plain != password {
			t.Errorf("a password of the table decrypts to %q, %v; want the generated password", plain, derr)
		}
	}
	if got := field(t, table, "platformConfigData", "sgApiKey"); got != "" {
		t.Errorf("sgApiKey = %q, want empty until the operator names a mail provider", got)
	}
	if got := field(t, table, "platformConfigData", "emailFrom"); got != credeblAdmin {
		t.Errorf("emailFrom = %q, want the platform admin", got)
	}
	for _, name := range []string{"externalIp", "inboundEndpoint", "apiEndpoint"} {
		if got := field(t, table, "platformConfigData", name); got == "" || strings.Contains(got, "#") {
			t.Errorf("%s = %q, want an address of the stack", name, got)
		}
	}
	// The rows that hold no credential stay as the release has them, so
	// the initialisation makes the same roles, agent types and ledgers.
	upstream := upstreamMasterTable(t)
	for name, want := range upstream {
		got, ok := table[name]
		if !ok {
			t.Errorf("the master table has no section %s", name)
			continue
		}
		switch name {
		case "platformConfigData", "platformAdminData", "platformAdminKeycloakPassword":
			continue
		case "ledgerData":
			// The ledgers of the operator are active, and the others
			// are off (ADR-065).
			want = activeAs(t, want, credeblFlags()[CredeblLedgersSetting])
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("section %s = %v, want %v", name, got, want)
		}
	}
	if len(table) != len(upstream) {
		t.Errorf("the master table has %d sections, the release %d", len(table), len(upstream))
	}
	// The stack file mounts the table over the committed one, at the
	// path the initialisation reads from its working directory.
	doc, _ := readCredeblStack(t)
	seed := doc.Services["credebl-seed"]
	mount := "../" + CredeblMasterTableFile + ":" + CredeblMasterTableMount + ":ro"
	if !slices.Contains(seed.Volumes, mount) {
		t.Errorf("credebl-seed volumes = %v, want %s", seed.Volumes, mount)
	}
	if seed.User != "root" {
		t.Errorf("credebl-seed runs as %q; the table has mode 0600, so it needs root", seed.User)
	}
	// A later run keeps the password, so the platform admin keeps
	// signing in.
	stacks, err := ReadStackEnvs(root)
	if err != nil {
		t.Fatal(err)
	}
	again, err := BuildPlan(SetupRequest{Pair: credeblPair(commonv1.Role_ROLE_VERIFIER), Flags: credeblFlags(), Random: rand.Reader, Stacks: stacks})
	if err != nil {
		t.Fatal(err)
	}
	var later map[string]any
	if err := json.Unmarshal(sharedFile(t, again, CredeblMasterTableFile).Data, &later); err != nil {
		t.Fatal(err)
	}
	if plain, derr := decryptCryptoJS(field(t, later, "platformAdminData", "password"), stack["CRYPTO_PRIVATE_KEY"]); derr != nil || plain != password {
		t.Errorf("a later run changed the password: %q, %v", plain, derr)
	}
}

// TestCredeblPairEnvSignsInWithTheGeneratedAdmin is P6-C0d: the adapter
// of a CREDEBL pair signs in as the platform admin of setup with the
// generated password, and a flag of the operator still wins.
func TestCredeblPairEnvSignsInWithTheGeneratedAdmin(t *testing.T) {
	plan, err := BuildPlan(SetupRequest{Pair: credeblPair(commonv1.Role_ROLE_ISSUER), Flags: credeblFlags(), Random: rand.Reader})
	if err != nil {
		t.Fatal(err)
	}
	stack, err := ParseDotenv(strings.NewReader(string(sharedFile(t, plan, StackEnvFile(configv1.Dpg_DPG_CREDEBL)).Data)))
	if err != nil {
		t.Fatal(err)
	}
	env, err := ParseDotenv(strings.NewReader(planFile(t, plan, EnvFileName)))
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		CredeblAdapterEmailEnv:     credeblAdmin,
		CredeblAdapterPasswordEnv:  stack[PlatformAdminPasswordEnv],
		CredeblAdapterCryptoKeyEnv: stack["CRYPTO_PRIVATE_KEY"],
	} {
		if env[name] != want || want == "" {
			t.Errorf("%s = %q, want %q", name, env[name], want)
		}
	}
	flags := credeblFlags()
	flags[CredeblAdapterPasswordEnv] = "set-by-the-operator"
	own, err := BuildPlan(SetupRequest{Pair: credeblPair(commonv1.Role_ROLE_ISSUER), Flags: flags, Random: rand.Reader})
	if err != nil {
		t.Fatal(err)
	}
	ownEnv, err := ParseDotenv(strings.NewReader(planFile(t, own, EnvFileName)))
	if err != nil {
		t.Fatal(err)
	}
	if ownEnv[CredeblAdapterPasswordEnv] != "set-by-the-operator" {
		t.Errorf("the flag lost: %q", ownEnv[CredeblAdapterPasswordEnv])
	}
	// A pair of another DPG gets no CREDEBL account.
	waltid, err := BuildPlan(SetupRequest{Pair: waltidPair(commonv1.Role_ROLE_ISSUER), Flags: baseFlags(), Random: rand.Reader})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(planFile(t, waltid, EnvFileName), CredeblAdapterPasswordEnv) {
		t.Error("a walt.id pair carries the CREDEBL password")
	}
}

// TestCredeblAgentConfigNeedsANetwork is ADR-065 decision 4: with no
// known Indy network setup writes no agent file, because the pinned
// agent would fall back to a test network.
func TestCredeblAgentConfigNeedsANetwork(t *testing.T) {
	for _, chosen := range []string{"", " , ", "polygon:mainnet", "no_ledger"} {
		if data, ok := CredeblAgentConfig(chosen); ok {
			t.Errorf("%q wrote %s", chosen, data)
		}
	}
	files, err := StackFiles(nil, rand.Reader, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if f.Name == CredeblAgentConfigFile {
			t.Errorf("a run with no networks wrote %s", f.Name)
		}
	}
}
