// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// Plan section 3.8 and ADR-055 decision 4: the CREDEBL platform admin
// comes from a setting with no default, and setup generates the secrets
// of the CREDEBL seed.

func credeblPair(role commonv1.Role) Pair { return Pair{Role: role, Dpg: configv1.Dpg_DPG_CREDEBL} }

// credeblFlags are the base flags with the platform admin of setup.
func credeblFlags() map[string]string {
	flags := baseFlags()
	flags[PlatformAdminEmailSetting] = credeblAdmin
	return flags
}

func TestSetupWritesTheCredeblEnv(t *testing.T) {
	plan, err := BuildPlan(SetupRequest{Pair: credeblPair(commonv1.Role_ROLE_ISSUER), Flags: credeblFlags(), Random: rand.Reader})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	f := sharedFile(t, plan, StackEnvFile(configv1.Dpg_DPG_CREDEBL))
	if f.Mode != 0o600 {
		t.Errorf("the CREDEBL .env has mode %04o", f.Mode)
	}
	root := t.TempDir()
	if _, werr := WritePlan(root, plan); werr != nil {
		t.Fatal(werr)
	}
	values, err := ReadStackEnv(root, configv1.Dpg_DPG_CREDEBL)
	if err != nil {
		t.Fatal(err)
	}
	if values[PlatformAdminEmailEnv] != credeblAdmin {
		t.Errorf("%s = %q", PlatformAdminEmailEnv, values[PlatformAdminEmailEnv])
	}
	for _, name := range []string{"CRYPTO_PRIVATE_KEY", "PLATFORM_WALLET_PASSWORD", "PLATFORM_SEED"} {
		if v := values[name]; len(v) != stackSecretLength {
			t.Errorf("%s = %q, want %d generated characters", name, v, stackSecretLength)
		}
	}
	for _, tok := range mockTokens {
		if strings.Contains(string(f.Data), tok) {
			t.Errorf("the CREDEBL .env names %q", tok)
		}
	}
	// A run of another stack keeps the platform admin and the secrets.
	stacks, err := ReadStackEnvs(root)
	if err != nil {
		t.Fatal(err)
	}
	later, err := BuildPlan(SetupRequest{Pair: waltidPair(commonv1.Role_ROLE_ISSUER), Flags: baseFlags(), Random: rand.Reader, Stacks: stacks})
	if err != nil {
		t.Fatal(err)
	}
	// The walt.id pair gets the declared setting of CREDEBL from the
	// shared flags, and its .env leaves it out.
	if env := planFile(t, later, EnvFileName); strings.Contains(env, PlatformAdminEmailSetting) {
		t.Errorf("the walt.id .env carries %s:\n%s", PlatformAdminEmailSetting, env)
	}
	if got := sharedFile(t, later, StackEnvFile(configv1.Dpg_DPG_CREDEBL)); string(got.Data) != string(f.Data) {
		t.Errorf("a walt.id run changed the CREDEBL .env:\n%s\nwant\n%s", got.Data, f.Data)
	}
	// A CREDEBL pair without the platform admin stops with the name of
	// the setting. No placeholder fills it.
	without := baseFlags()
	delete(without, PlatformAdminEmailSetting)
	for _, role := range []commonv1.Role{commonv1.Role_ROLE_ISSUER, commonv1.Role_ROLE_HOLDER, commonv1.Role_ROLE_VERIFIER} {
		_, err := BuildPlan(SetupRequest{Pair: credeblPair(role), Flags: without, Random: rand.Reader})
		var missing *MissingValuesError
		if !errors.As(err, &missing) || !strings.Contains(err.Error(), PlatformAdminEmailSetting) {
			t.Errorf("%s: err = %v, want the missing platform admin", role, err)
		}
	}
	bad := credeblFlags()
	bad[PlatformAdminEmailSetting] = "not an address"
	if _, err := BuildPlan(SetupRequest{Pair: credeblPair(commonv1.Role_ROLE_ISSUER), Flags: bad, Random: rand.Reader}); err == nil {
		t.Error("a value that is no email address passed")
	}
}

// TestCredeblLedgersAreASetting is finding 6 of the CREDEBL review
// (ADR-050 decision 1): the Indy networks of the agent and of the
// platform come from a setting of the operator with no default. Setup
// writes the agent file and marks only those ledgers active in the
// master table. A value outside the real networks stops setup.
func TestCredeblLedgersAreASetting(t *testing.T) {
	flags := credeblFlags()
	flags[CredeblLedgersSetting] = "indicio:mainnet"
	plan, err := BuildPlan(SetupRequest{Pair: credeblPair(commonv1.Role_ROLE_ISSUER), Flags: flags, Random: rand.Reader})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	var agent struct {
		Ledgers []struct {
			Genesis   string `json:"genesisTransactions"`
			Namespace string `json:"indyNamespace"`
		} `json:"indyLedger"`
		Tenancy bool   `json:"tenancy"`
		Proofs  string `json:"autoAcceptProofs"`
	}
	f := sharedFile(t, plan, CredeblAgentConfigFile)
	if jerr := json.Unmarshal(f.Data, &agent); jerr != nil {
		t.Fatalf("the agent file: %v", jerr)
	}
	if len(agent.Ledgers) != 1 || agent.Ledgers[0].Namespace != "indicio:mainnet" ||
		!strings.HasPrefix(agent.Ledgers[0].Genesis, "https://raw.githubusercontent.com/Indicio-tech/") || !agent.Tenancy || agent.Proofs != "contentApproved" {
		t.Fatalf("agent file = %+v", agent)
	}
	var table struct {
		Ledgers []struct {
			Name      string `json:"name"`
			Namespace string `json:"indyNamespace"`
			Active    bool   `json:"isActive"`
		} `json:"ledgerData"`
	}
	if jerr := json.Unmarshal(sharedFile(t, plan, CredeblMasterTableFile).Data, &table); jerr != nil {
		t.Fatal(jerr)
	}
	var active []string
	for _, l := range table.Ledgers {
		if l.Active {
			active = append(active, l.Namespace)
		}
	}
	if strings.Join(active, ",") != "indicio:mainnet,no_ledger" {
		t.Errorf("active ledgers = %v", active)
	}
	if env := string(sharedFile(t, plan, StackEnvFile(configv1.Dpg_DPG_CREDEBL)).Data); !strings.Contains(env, CredeblLedgersEnv+`=`) ||
		!strings.Contains(env, "indicio:mainnet") {
		t.Errorf("the stack .env has no ledgers:\n%s", env)
	}
	without := credeblFlags()
	delete(without, CredeblLedgersSetting)
	_, err = BuildPlan(SetupRequest{Pair: credeblPair(commonv1.Role_ROLE_ISSUER), Flags: without, Random: rand.Reader})
	var missing *MissingValuesError
	if !errors.As(err, &missing) || !strings.Contains(err.Error(), CredeblLedgersSetting) {
		t.Errorf("no ledgers: err = %v", err)
	}
	for _, bad := range []string{"sovrin:mainnet", "indicio:mainnet, polygon:mainnet", " , "} {
		flags[CredeblLedgersSetting] = bad
		if _, berr := BuildPlan(SetupRequest{Pair: credeblPair(commonv1.Role_ROLE_ISSUER), Flags: flags, Random: rand.Reader}); berr == nil {
			t.Errorf("%q passed", bad)
		}
	}
	two := credeblFlags()
	two[CredeblLedgersSetting] = "bcovrin:testnet,indicio:testnet"
	plan, err = BuildPlan(SetupRequest{Pair: credeblPair(commonv1.Role_ROLE_ISSUER), Flags: two, Random: rand.Reader})
	if err != nil {
		t.Fatal(err)
	}
	if data := string(sharedFile(t, plan, CredeblAgentConfigFile).Data); !strings.Contains(data, `"bcovrin:testnet"`) || !strings.Contains(data, `"indicio:testnet"`) ||
		strings.Contains(data, "mainnet") {
		t.Errorf("two ledgers: %s", data)
	}
}

func TestCredeblStackReadsTheStackEnv(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRoot(), "deploy", "vca", "dpg", "credebl.yaml")) // #nosec G304 -- a fixed test path
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Services map[string]struct {
			EnvFile []struct {
				Path     string `yaml:"path"`
				Required bool   `yaml:"required"`
			} `yaml:"env_file"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"credebl-api-gateway", "credebl-agent-provisioning"} {
		files := doc.Services[name].EnvFile
		if len(files) != 1 || files[0].Path != "../"+StackEnvFile(configv1.Dpg_DPG_CREDEBL) || !files[0].Required {
			t.Errorf("%s reads %v, want the CREDEBL stack .env", name, files)
		}
	}
}

// upstreamCredeblServices are the services of the compose file of the
// CREDEBL platform, read on 2026-09-26 from
// https://raw.githubusercontent.com/credebl/platform/main/docker-compose.yml.
var upstreamCredeblServices = []string{
	"nats", "redis", "postgres", "seed", "schema-file-server", "api-gateway", "user", "utility",
	"connection", "issuance", "ledger", "organization", "verification", "agent-provisioning",
	"agent-service", "cloud-wallet", "geolocation", "notification", "webhook", "ecosystem",
	"oid4vc-issuance", "oid4vc-verification", "x509",
}

// credeblStack is the part of the CREDEBL stack file the tests read.
type credeblStack struct {
	Services map[string]struct {
		Image    string   `yaml:"image"`
		User     string   `yaml:"user"`
		Profiles []string `yaml:"profiles"`
		Command  []string `yaml:"command"`
		Volumes  []string `yaml:"volumes"`
		EnvFile  []struct {
			Path     string `yaml:"path"`
			Required bool   `yaml:"required"`
		} `yaml:"env_file"`
		Environment map[string]string `yaml:"environment"`
	} `yaml:"services"`
}

func readCredeblStack(t *testing.T) (credeblStack, string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot(), "deploy", "vca", "dpg", "credebl.yaml")) // #nosec G304 -- a fixed test path
	if err != nil {
		t.Fatal(err)
	}
	var doc credeblStack
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return doc, string(data)
}

// TestCredeblStackRunsEveryPlatformService is P6-C0 (ADR-045 decision
// 4): the stack file runs every service of the upstream compose file and
// the shared Credo agent. Compose starts the agent, and no container
// mounts the Docker socket (ADR-005 decision 3).
func TestCredeblStackRunsEveryPlatformService(t *testing.T) {
	doc, raw := readCredeblStack(t)
	if len(upstreamCredeblServices) != 23 {
		t.Fatalf("the upstream list holds %d names, want 23", len(upstreamCredeblServices))
	}
	for _, name := range append([]string{"agent"}, upstreamCredeblServices...) {
		if _, ok := doc.Services["credebl-"+name]; !ok {
			t.Errorf("the stack file runs no credebl-%s", name)
		}
	}
	if strings.Contains(raw, "docker.sock") {
		t.Error("a service mounts the Docker socket")
	}
	stackEnv := "../" + StackEnvFile(configv1.Dpg_DPG_CREDEBL)
	for name, svc := range doc.Services {
		if strings.Contains(strings.Join(svc.Command, " "), "docker ") {
			t.Errorf("%s calls docker: %v", name, svc.Command)
		}
		if !strings.HasPrefix(svc.Image, "ghcr.io/credebl/") || name == "credebl-agent" || name == "credebl-schema-file-server" {
			continue
		}
		// Every platform service reads the platform admin and the
		// generated platform keys from the stack .env.
		if len(svc.EnvFile) != 1 || svc.EnvFile[0].Path != stackEnv || !svc.EnvFile[0].Required {
			t.Errorf("%s reads %v, want the CREDEBL stack .env", name, svc.EnvFile)
		}
		for _, key := range []string{"DATABASE_URL", "NATS_URL", "REDIS_HOST", "SCHEMA_FILE_SERVER_URL", "AGENT_API_KEY"} {
			if svc.Environment[key] == "" {
				t.Errorf("%s has no %s", name, key)
			}
		}
	}
	// The initialisation runs once through vca dpg bootstrap credebl, so
	// docker compose up of a pair never starts it.
	if got := doc.Services["credebl-seed"].Profiles; len(got) != 1 || got[0] != PlatformInitProfile {
		t.Errorf("credebl-seed profiles = %v, want only %s", got, PlatformInitProfile)
	}
	// The shared agent takes its secrets from the stack .env and its
	// transports from the committed file.
	agent := doc.Services["credebl-agent"]
	for key, want := range map[string]string{
		"AFJ_REST_WALLET_KEY": "${" + SharedAgentWalletKeyEnv + ":?set by vca setup}",
		"AFJ_REST_API_KEY":    "${" + SharedAgentAPIKeyEnv + ":?set by vca setup}",
		"AFJ_REST_TENANCY":    "true",
	} {
		if agent.Environment[key] != want {
			t.Errorf("credebl-agent %s = %q, want %q", key, agent.Environment[key], want)
		}
	}
	// Setup writes the agent file from the ledgers of the operator
	// (finding 6 of the CREDEBL review).
	if len(agent.Volumes) != 1 || agent.Volumes[0] != "../"+CredeblAgentConfigFile+":/config/agent.json:ro" {
		t.Errorf("credebl-agent volumes = %v", agent.Volumes)
	}
	plan, err := BuildPlan(SetupRequest{Pair: credeblPair(commonv1.Role_ROLE_ISSUER), Flags: credeblFlags(), Random: rand.Reader})
	if err != nil {
		t.Fatal(err)
	}
	file := sharedFile(t, plan, CredeblAgentConfigFile).Data
	for _, secret := range []string{"walletKey", "walletPassword", "apiKey", "Password"} {
		if strings.Contains(string(file), secret) {
			t.Errorf("the agent file holds %s; secrets come from the stack .env", secret)
		}
	}
	if !strings.Contains(raw, SharedAgentHost) {
		t.Errorf("the agent has no alias %s", SharedAgentHost)
	}
}

// TestFloorCredebl is P6-C0 and open question G.11: the DPG floor of
// CREDEBL is the sum of the services of its stack file, and it passes
// the 4096 MiB target of ADR-008 decision 7 (ADR-045 consequence 2).
func TestFloorCredebl(t *testing.T) {
	doc, _ := readCredeblStack(t)
	sum := 0
	for name := range doc.Services {
		if name == "credebl-seed" {
			// The initialisation runs once and exits.
			continue
		}
		mem, ok := credeblServiceMemoryMiB[name]
		if !ok {
			t.Errorf("the floor has no figure for %s", name)
		}
		sum += mem
	}
	if len(credeblServiceMemoryMiB) != len(doc.Services)-1 {
		t.Errorf("the floor names %d services, the stack file runs %d", len(credeblServiceMemoryMiB), len(doc.Services)-1)
	}
	for _, role := range []commonv1.Role{commonv1.Role_ROLE_ISSUER, commonv1.Role_ROLE_HOLDER, commonv1.Role_ROLE_VERIFIER} {
		p := credeblPair(role)
		if got := Floor(p).DpgMemoryMiB; got != sum {
			t.Errorf("%s DPG floor = %d MiB, want %d", p.Name(), got, sum)
		}
		if MemoryFloorMiB(p) <= FloorTargetMiB || !AboveFloorTarget(p) {
			t.Errorf("%s floor %d MiB is not marked above the target", p.Name(), MemoryFloorMiB(p))
		}
		if report := FloorReport([]Pair{p}); !strings.Contains(report, "ADR-045") {
			t.Errorf("the floor report does not name ADR-045:\n%s", report)
		}
	}
	admin := credeblPair(commonv1.Role_ROLE_ADMIN)
	if AboveFloorTarget(admin) || Floor(admin).DpgMemoryMiB != keycloakMemoryMiB {
		t.Errorf("the CREDEBL admin floor = %+v", Floor(admin))
	}
	// The Inji issuer stays the ADR-049 exception.
	if report := FloorReport([]Pair{{Role: commonv1.Role_ROLE_ISSUER, Dpg: configv1.Dpg_DPG_INJI}}); !strings.Contains(report, "ADR-049") {
		t.Errorf("the Inji report lost ADR-049:\n%s", report)
	}
}

// TestCredeblStackEnvHoldsTheAgentKeys is P6-C0: setup generates the
// wallet key and the API key of the shared agent and the secret of the
// schema file server, and signs the upload token of the platform with
// that secret. A later run keeps every value.
func TestCredeblStackEnvHoldsTheAgentKeys(t *testing.T) {
	deploy := t.TempDir()
	values := writeStackEnvAt(t, deploy, configv1.Dpg_DPG_CREDEBL, secretsTime, nil)
	for _, name := range []string{SharedAgentWalletKeyEnv, SharedAgentAPIKeyEnv, SchemaFileServerSecretEnv} {
		if len(values[name]) != stackSecretLength {
			t.Errorf("%s = %q, want %d characters", name, values[name], stackSecretLength)
		}
	}
	token := values[SchemaFileServerTokenEnv]
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("the upload token %q is no JSON web token", token)
	}
	mac := hmac.New(sha256.New, []byte(values[SchemaFileServerSecretEnv]))
	anyval.DiscardWrite(mac.Write([]byte(parts[0] + "." + parts[1])))
	if base64.RawURLEncoding.EncodeToString(mac.Sum(nil)) != parts[2] {
		t.Error("the upload token does not verify with the secret of the schema file server")
	}
	claims, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !strings.Contains(string(claims), `"iss":"`+SchemaFileServerIssuer+`"`) {
		t.Errorf("claims = %s, %v", claims, err)
	}
	again := writeStackEnvAt(t, deploy, configv1.Dpg_DPG_CREDEBL, secretsTime, values)
	for _, name := range []string{SharedAgentWalletKeyEnv, SharedAgentAPIKeyEnv, SchemaFileServerSecretEnv, SchemaFileServerTokenEnv} {
		if again[name] != values[name] {
			t.Errorf("a later run changed %s", name)
		}
	}
}

// TestBootstrapCredeblCreatesOrgAndSharedAgent is P6-C0: the run binds
// the shared agent that compose starts to the platform admin
// organisation with the API key of the stack .env, and gives the
// organisation of the deployment a wallet in it. A second run changes
// nothing. The sign in sends the password in the encrypted form the
// platform reads.
func TestBootstrapCredeblCreatesOrgAndSharedAgent(t *testing.T) {
	state := &credeblState{}
	server := fakeCredebl(t, state)
	defer server.Close()
	var out bytes.Buffer
	opts := credeblOptions(t, server.URL, &out)
	stack, err := ReadStackEnv(filepath.Dir(opts.Dir), configv1.Dpg_DPG_CREDEBL)
	if err != nil {
		t.Fatal(err)
	}
	got, err := BootstrapCredebl(context.Background(), opts)
	if err != nil {
		t.Fatalf("BootstrapCredebl: %v", err)
	}
	// The password is the generated one of the stack .env.
	plain, err := decryptCryptoJS(state.signin["password"], stack["CRYPTO_PRIVATE_KEY"])
	if err != nil || plain != `"`+stack[PlatformAdminPasswordEnv]+`"` {
		t.Errorf("the sign in password decrypts to %q, %v", plain, err)
	}
	configure := state.configured[credeblPlatformOrgID]
	if configure == nil {
		t.Fatalf("the run bound no agent to the platform admin organisation: %v", state.configured)
	}
	if configure["apiKey"] != stack[SharedAgentAPIKeyEnv] || configure["agentEndpoint"] != "http://"+SharedAgentHost+":8001" {
		t.Errorf("configure = %v", configure)
	}
	if !regexp.MustCompile(`^[A-Za-z0-9]{2,25}$`).MatchString(configure["walletName"]) {
		t.Errorf("wallet name %q breaks the rule of the platform", configure["walletName"])
	}
	if len(state.configured) != 1 {
		t.Errorf("configured = %v, want the platform admin organisation only", state.configured)
	}
	wallet := state.wallets["id-vca-issuer"]
	if wallet == nil || wallet["label"] != "vca-issuer" {
		t.Errorf("wallets = %v, want one for vca-issuer", state.wallets)
	}
	steps := strings.Join(got.Steps, "\n")
	for _, want := range []string{"CREDEBL shared agent bound", "CREDEBL shared agent wallet created: vca-issuer"} {
		if !strings.Contains(steps, want) {
			t.Errorf("steps lack %q:\n%s", want, steps)
		}
	}
	again, err := BootstrapCredebl(context.Background(), opts)
	if err != nil {
		t.Fatalf("second BootstrapCredebl: %v", err)
	}
	steps = strings.Join(again.Steps, "\n")
	for _, want := range []string{"CREDEBL shared agent present", "CREDEBL shared agent wallet present: vca-issuer"} {
		if !strings.Contains(steps, want) {
			t.Errorf("second run steps lack %q:\n%s", want, steps)
		}
	}
	if state.created != 1 || len(state.wallets) != 1 {
		t.Errorf("the second run created more: %d orgs, %v", state.created, state.wallets)
	}
}

// TestBootstrapCredeblNeedsThePlatformOrganisation: without the
// organisation that the initialisation makes, the run stops and names it.
func TestBootstrapCredeblNeedsThePlatformOrganisation(t *testing.T) {
	state := &credeblState{noPlatform: true}
	server := fakeCredebl(t, state)
	defer server.Close()
	var out bytes.Buffer
	_, err := BootstrapCredebl(context.Background(), credeblOptions(t, server.URL, &out))
	if err == nil || !strings.Contains(err.Error(), PlatformOrgName) {
		t.Fatalf("err = %v, want the name of the platform admin organisation", err)
	}
	if len(state.configured) != 0 || len(state.wallets) != 0 {
		t.Errorf("the run bound an agent: %v %v", state.configured, state.wallets)
	}
}

// decryptCryptoJS reverses the CryptoJS form of the sign in password.
func decryptCryptoJS(text, passphrase string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(text)
	if err != nil || len(raw) < 32 || string(raw[:8]) != "Salted__" {
		return "", errors.New("not the CryptoJS form")
	}
	key, iv := evpKey([]byte(passphrase), raw[8:16])
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	body := raw[16:]
	if len(body)%aes.BlockSize != 0 {
		return "", errors.New("bad length")
	}
	plain := make([]byte, len(body))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, body)
	n := int(plain[len(plain)-1])
	if n == 0 || n > aes.BlockSize {
		return "", errors.New("bad padding")
	}
	return string(plain[:len(plain)-n]), nil
}
