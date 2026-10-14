// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// The Inji volumes that the release before generated secrets made with
// another layout (ADR-084). The Certify database ran as another user in
// another database, and the verify database had no init.sql.
var rebuiltVolumes = map[string]bool{"vca_inji-certify-db": true, "vca_inji-verify-db": true}

// TestRebuiltVolumesAreTheOnesWhoseLayoutChanged pins the set and the
// reasons against the stack file: each reason names a user, database or
// init file that the stack file holds today.
func TestRebuiltVolumesAreTheOnesWhoseLayoutChanged(t *testing.T) {
	t.Parallel()
	stack, err := os.ReadFile(filepath.Join("..", "..", "..", "deploy", "vca", "dpg", "inji.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range StackDpgs() {
		for _, v := range StackVolumes(d) {
			if rebuiltVolumes[v.Docker()] != (v.Rebuilt != "") {
				t.Errorf("%s: Rebuilt = %q", v.Docker(), v.Rebuilt)
			}
		}
	}
	wants := map[string][]string{
		"vca_inji-certify-db": {"POSTGRES_USER: postgres", "/inji_certify?", "certify_init.sql", "vca_claims.sql"},
		"vca_inji-verify-db":  {"verify/init.sql", "DATABASE_SCHEMA: verify"},
	}
	for _, v := range StackVolumes(configv1.Dpg_DPG_INJI) {
		for _, want := range wants[v.Docker()] {
			if !strings.Contains(string(stack), want) {
				t.Errorf("the stack file lacks %q, which the reason for %s relies on", want, v.Docker())
			}
		}
	}
	commands := RemoveVolumeCommands("vca_inji-certify-db")
	if len(commands) != 2 || !strings.Contains(commands[0], ":/from:ro") || commands[1] != "docker volume rm vca_inji-certify-db" {
		t.Errorf("commands = %q", commands)
	}
}

// rebuiltProbe answers docker volume commands for one old volume, as the
// deploy command reads them through its output runner.
func rebuiltProbe(volumes map[string]time.Time) *outputScript {
	return &outputScript{config: sampleComposeConfig, ps: noConflictPs, volumes: volumes}
}

// noConflictPs lists containers that block no Inji pair.
const noConflictPs = "inji-keycloak\tvca\nother\tsomething\n"

// TestSetupDoctorAndDeployRefuseAVolumeThisReleaseCannotServe: the
// first setup on a host with the Certify volume of the earlier release
// gives the stack a new password and names the volume with the commands
// that save and remove it. The doctor fails the stack with the same
// commands, and deploy stops before compose up (ADR-084).
func TestSetupDoctorAndDeployRefuseAVolumeThisReleaseCannotServe(t *testing.T) {
	root := t.TempDir()
	deploy := filepath.Join(root, "deploy")
	probe := healthyProbe()
	old := time.Now().UTC().AddDate(-1, 0, 0)
	probe.volumes = map[string]time.Time{"vca_inji-certify-db": old, "vca_inji-certify-keys": old}
	env := Environment{Root: root, NewProbe: func(context.Context) Probe { return probe }}
	status, out, errOut := run(t, env, "setup", "--role", "issuer", "--dpg", "inji", "--non-interactive")
	if status != 0 {
		t.Fatalf("setup = %d\n%s\n%s", status, out, errOut)
	}
	inji, err := ReadStackEnv(deploy, configv1.Dpg_DPG_INJI)
	if err != nil {
		t.Fatal(err)
	}
	if inji["INJI_DB_PASSWORD"] == "certify" || len(inji["INJI_DB_PASSWORD"]) != stackSecretLength {
		t.Errorf("the Certify database kept the old password: %q", inji["INJI_DB_PASSWORD"])
	}
	if inji["INJI_CERTIFY_KEYSTORE_PASSWORD"] != "certify" {
		t.Errorf("the key store lost its old password: %q", inji["INJI_CERTIFY_KEYSTORE_PASSWORD"])
	}
	for _, want := range []string{
		"vca_inji-certify-db comes from the release before generated secrets",
		"user certify in the database certify",
		"docker volume rm vca_inji-certify-db",
		"vca_inji-certify-db.tgz",
		"INJI_CERTIFY_KEYSTORE_PASSWORD keeps the password",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("setup does not say %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "INJI_DB_PASSWORD keeps") {
		t.Errorf("setup claims the old password serves:\n%s", out)
	}
	// The doctor fails the stack and gives the commands.
	status, out, _ = run(t, env, "doctor", "--role", "issuer", "--dpg", "inji")
	if status == 0 || !strings.Contains(out, "FAIL  stack secrets inji") || !strings.Contains(out, "docker volume rm vca_inji-certify-db") {
		t.Errorf("doctor = %d\n%s", status, out)
	}
	// Deploy stops before compose up, with the same words. The pair
	// files of a deploy root, and the stack .env of setup stamped at
	// the test time, so the volume times below read against it.
	writeStackEnvs(t, root)
	for _, role := range []commonv1.Role{commonv1.Role_ROLE_ISSUER, commonv1.Role_ROLE_HOLDER} {
		path := filepath.Join(deploy, injiPair(role).Name(), EnvFileName)
		if mkErr := os.MkdirAll(filepath.Dir(path), 0o750); mkErr != nil {
			t.Fatal(mkErr)
		}
		if writeErr := os.WriteFile(path, []byte("VCA_ROLE=x\n"), 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	delete(inji, StackSecretsSinceEnv)
	writeStackEnvAt(t, deploy, configv1.Dpg_DPG_INJI, secretsTime, inji)
	script := rebuiltProbe(map[string]time.Time{
		"vca_inji-certify-db":   secretsTime.Add(-time.Hour),
		"vca_inji-certify-keys": secretsTime.Add(-time.Hour),
	})
	rec := &recorder{}
	err = Deploy(context.Background(), DeployOptions{
		Root: root, Pairs: []Pair{injiPair(commonv1.Role_ROLE_ISSUER)}, Out: &bytes.Buffer{}, Run: rec.run, Output: script.run,
	})
	if err == nil {
		t.Fatal("deploy started on the old volume")
	}
	for _, want := range []string{"deploy issuer-inji: ", "vca_inji-certify-db", "cannot serve this release", "docker volume rm vca_inji-certify-db"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("deploy error lacks %q:\n%v", want, err)
		}
	}
	if len(rec.calls) != 0 {
		t.Errorf("compose ran %d times", len(rec.calls))
	}
	// Two pairs of one stack read the volumes once.
	lists := 0
	for _, call := range script.calls {
		if len(call) > 2 && call[1] == "volume" && call[2] == "ls" {
			lists++
		}
	}
	script.calls = nil
	err = Deploy(context.Background(), DeployOptions{
		Root: root, Pairs: []Pair{injiPair(commonv1.Role_ROLE_ISSUER), injiPair(commonv1.Role_ROLE_HOLDER)},
		Out: &bytes.Buffer{}, Run: rec.run, Output: script.run,
	})
	if err == nil {
		t.Fatal("two pairs started on the old volume")
	}
	again := 0
	for _, call := range script.calls {
		if len(call) > 2 && call[1] == "volume" && call[2] == "ls" {
			again++
		}
	}
	if lists == 0 || again != lists {
		t.Errorf("volume lists: one pair %d, two pairs %d", lists, again)
	}
	// A volume made after the secrets is this release's own and passes.
	script = rebuiltProbe(map[string]time.Time{
		"vca_inji-certify-db":   secretsTime.Add(time.Hour),
		"vca_inji-certify-keys": secretsTime.Add(-time.Hour),
	})
	rec = &recorder{}
	err = Deploy(context.Background(), DeployOptions{
		Root: root, Pairs: []Pair{injiPair(commonv1.Role_ROLE_ISSUER)}, Out: &bytes.Buffer{}, Run: rec.run, Output: script.run,
	})
	if err != nil || len(rec.calls) != 1 {
		t.Errorf("deploy on a new volume = %v, %d compose runs", err, len(rec.calls))
	}
	// Docker that cannot list volumes stops deploy too.
	script = &outputScript{config: sampleComposeConfig, psErr: errors.New("no daemon")}
	err = Deploy(context.Background(), DeployOptions{
		Root: root, Pairs: []Pair{injiPair(commonv1.Role_ROLE_ISSUER)}, Out: &bytes.Buffer{}, Run: rec.run, Output: script.run,
	})
	if err == nil || !strings.Contains(err.Error(), "cannot read the volume") {
		t.Errorf("deploy without Docker = %v", err)
	}
}

// TestDeployRefusesADefaultPasswordThatNoVolumeHolds: once the operator
// removed the old volume, a stack .env that still holds its default
// password would start the new volume on it. The doctor and deploy stop
// there and name the line to remove (ADR-084).
func TestDeployRefusesADefaultPasswordThatNoVolumeHolds(t *testing.T) {
	t.Parallel()
	root := deployRoot(t, injiPair(commonv1.Role_ROLE_VERIFIER))
	deploy := filepath.Join(root, "deploy")
	values := writeStackEnvAt(t, deploy, configv1.Dpg_DPG_INJI, secretsTime, map[string]string{"INJI_VERIFY_DB_PASSWORD": "injiverify"})
	probe := healthyProbe()
	c := stackVolumeCheck(probe, configv1.Dpg_DPG_INJI, values)
	if c.OK || !strings.Contains(c.Detail, "INJI_VERIFY_DB_PASSWORD") || !strings.Contains(c.Fix, "remove these lines from inji/.env") ||
		!strings.Contains(c.Fix, "vca setup") {
		t.Errorf("check = %+v", c)
	}
	script := &outputScript{config: sampleComposeConfig, ps: noConflictPs}
	rec := &recorder{}
	err := Deploy(context.Background(), DeployOptions{
		Root: root, Pairs: []Pair{injiPair(commonv1.Role_ROLE_VERIFIER)}, Out: &bytes.Buffer{}, Run: rec.run, Output: script.run,
	})
	if err == nil || !strings.Contains(err.Error(), "INJI_VERIFY_DB_PASSWORD") || len(rec.calls) != 0 {
		t.Errorf("deploy = %v, %d compose runs", err, len(rec.calls))
	}
	// The same password on a volume made with it is the volume's own.
	script.volumes = map[string]time.Time{"vca_inji-verify-db": secretsTime.Add(time.Hour)}
	err = Deploy(context.Background(), DeployOptions{
		Root: root, Pairs: []Pair{injiPair(commonv1.Role_ROLE_VERIFIER)}, Out: &bytes.Buffer{}, Run: rec.run, Output: script.run,
	})
	if err != nil {
		t.Errorf("deploy on the volume that holds the password = %v", err)
	}
	// A deploy without an output runner reads nothing.
	err = Deploy(context.Background(), DeployOptions{
		Root: root, Pairs: []Pair{injiPair(commonv1.Role_ROLE_VERIFIER)}, Out: &bytes.Buffer{}, Run: rec.run,
	})
	if err != nil {
		t.Errorf("deploy without an output runner = %v", err)
	}
}

// TestUpgradeSecretsLeavesAVolumeThisReleaseCannotServe: the upgrade
// names the old Certify volume and the commands, writes no password for
// it, and still carries the other old passwords over.
func TestUpgradeSecretsLeavesAVolumeThisReleaseCannotServe(t *testing.T) {
	t.Parallel()
	deploy := t.TempDir()
	before := writeStackEnvAt(t, deploy, configv1.Dpg_DPG_INJI, secretsTime, nil)
	probe := healthyProbe()
	probe.volumes = map[string]time.Time{"vca_inji-certify-db": secretsTime.Add(-time.Hour)}
	var out bytes.Buffer
	changed, err := UpgradeSecrets(UpgradeOptions{
		Deploy: deploy, Dpgs: []configv1.Dpg{configv1.Dpg_DPG_INJI}, Probe: probe, Random: rand.Reader, Out: &out,
	})
	if err != nil || changed != 0 {
		t.Fatalf("UpgradeSecrets = %d %v\n%s", changed, err, out.String())
	}
	after, err := ReadStackEnv(deploy, configv1.Dpg_DPG_INJI)
	if err != nil || after["INJI_DB_PASSWORD"] != before["INJI_DB_PASSWORD"] {
		t.Errorf("the upgrade changed the password: %v %v", after, err)
	}
	text := out.String()
	for _, want := range []string{"vca_inji-certify-db", "cannot serve", "docker volume rm vca_inji-certify-db"} {
		if !strings.Contains(text, want) {
			t.Errorf("the output lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "Nothing changed") || strings.Contains(text, rotateHint) {
		t.Errorf("the output misreads the run:\n%s", text)
	}
	// With a second old volume that this release serves, that one gets
	// its password and the hint for the other stays.
	probe.volumes["vca_inji-mimoto-db"] = secretsTime.Add(-time.Hour)
	out.Reset()
	changed, err = UpgradeSecrets(UpgradeOptions{
		Deploy: deploy, Dpgs: []configv1.Dpg{configv1.Dpg_DPG_INJI}, Probe: probe, Random: rand.Reader, Out: &out,
	})
	if err != nil || changed != 1 || !strings.Contains(out.String(), "docker volume rm vca_inji-certify-db") || !strings.Contains(out.String(), rotateHint) {
		t.Errorf("second run = %d %v\n%s", changed, err, out.String())
	}
}
