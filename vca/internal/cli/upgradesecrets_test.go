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

// secretsTime is the moment the stack secrets of a test were generated.
var secretsTime = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

// writeStackEnvAt writes the .env of one stack as setup would at the
// given time and returns its values.
func writeStackEnvAt(t *testing.T, deploy string, d configv1.Dpg, at time.Time, existing map[string]string) map[string]string {
	t.Helper()
	text, err := StackEnv(d, existing, rand.Reader, at)
	if err != nil {
		t.Fatalf("StackEnv: %v", err)
	}
	path := filepath.Join(deploy, StackEnvFile(d))
	if mkErr := os.MkdirAll(filepath.Dir(path), 0o750); mkErr != nil {
		t.Fatal(mkErr)
	}
	if writeErr := os.WriteFile(path, []byte(text), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	values, err := ReadStackEnv(deploy, d)
	if err != nil {
		t.Fatal(err)
	}
	return values
}

// TestStackEnvRecordsWhenTheSecretsBegan: the first run stamps the file
// with the time of the generated secrets, and a later run keeps the
// stamp, so a volume older than the stamp predates them.
func TestStackEnvRecordsWhenTheSecretsBegan(t *testing.T) {
	text, err := StackEnv(configv1.Dpg_DPG_INJI, nil, rand.Reader, secretsTime)
	if err != nil {
		t.Fatal(err)
	}
	values, err := ParseDotenv(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	if values[StackSecretsSinceEnv] != "2026-09-26T12:00:00Z" {
		t.Errorf("stamp = %q", values[StackSecretsSinceEnv])
	}
	again, err := StackEnv(configv1.Dpg_DPG_INJI, values, rand.Reader, secretsTime.Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(again, StackSecretsSinceEnv+"=2026-09-26T12:00:00Z") {
		t.Errorf("a later run moved the stamp:\n%s", again)
	}
}

// TestReadStackEnvTakesTheFileTimeWithoutAStamp: a file that an earlier
// release wrote has no stamp. Its modification time stands in for it.
func TestReadStackEnvTakesTheFileTimeWithoutAStamp(t *testing.T) {
	deploy := t.TempDir()
	path := filepath.Join(deploy, StackEnvFile(configv1.Dpg_DPG_WALTID))
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("WALTID_DB_PASSWORD=abcdefgh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, secretsTime, secretsTime); err != nil {
		t.Fatal(err)
	}
	values, err := ReadStackEnv(deploy, configv1.Dpg_DPG_WALTID)
	if err != nil {
		t.Fatal(err)
	}
	if values[StackSecretsSinceEnv] != "2026-09-26T12:00:00Z" {
		t.Errorf("stamp = %q", values[StackSecretsSinceEnv])
	}
}

// TestEveryStackSecretNamesItsVolume: each generated password protects
// one volume of its stack file, and the value of the release before
// generated secrets is on record for it.
func TestEveryStackSecretNamesItsVolume(t *testing.T) {
	for _, d := range StackDpgs() {
		volumes := StackVolumes(d)
		if len(volumes) != len(stackSecretNames(d)) {
			t.Errorf("%s: %d volumes for %d secrets", d, len(volumes), len(stackSecretNames(d)))
		}
		stack, err := os.ReadFile(filepath.Join("..", "..", "..", "deploy", "vca", "dpg", ShortName(d.String())+".yaml"))
		if err != nil {
			t.Fatal(err)
		}
		for i, v := range volumes {
			if v.Env != stackSecretNames(d)[i] {
				t.Errorf("%s: volume %d guards %s, want %s", d, i, v.Env, stackSecretNames(d)[i])
			}
			if v.Old == "" || !strings.HasPrefix(v.Docker(), ComposeProject+"_") {
				t.Errorf("%s: %+v", d, v)
			}
			if !strings.Contains(string(stack), "\n  "+v.Volume+":") {
				t.Errorf("%s: the stack file declares no volume %s", d, v.Volume)
			}
		}
	}
	if StackVolumes(configv1.Dpg_DPG_UNSPECIFIED) != nil {
		t.Error("an unknown DPG has volumes")
	}
}

// TestDoctorFindsAVolumeOlderThanTheSecrets: a Postgres volume that a
// release before generated secrets made keeps the old password. The
// doctor fails it until the .env holds that password, then reminds the
// operator to rotate it.
func TestDoctorFindsAVolumeOlderThanTheSecrets(t *testing.T) {
	deploy := t.TempDir()
	values := writeStackEnvAt(t, deploy, configv1.Dpg_DPG_INJI, secretsTime, nil)
	probe := healthyProbe()
	probe.volumes = map[string]time.Time{
		"vca_inji-certify-keys": secretsTime.Add(-24 * time.Hour),
		"vca_inji-mimoto-db":    secretsTime.Add(time.Hour),
	}
	stacks := map[configv1.Dpg]map[string]string{configv1.Dpg_DPG_INJI: values}
	pairs := []Pair{injiPair(commonv1.Role_ROLE_ISSUER)}
	checks := stackVolumeChecks(DoctorOptions{Pairs: pairs, Probe: probe, Stacks: stacks})
	if len(checks) != 1 {
		t.Fatalf("checks = %+v", checks)
	}
	c := checks[0]
	if c.OK || !strings.Contains(c.Detail, "vca_inji-certify-keys") || strings.Contains(c.Detail, "vca_inji-mimoto-db") ||
		!strings.Contains(c.Fix, "vca dpg upgrade-secrets --dpg inji") {
		t.Errorf("check = %+v", c)
	}
	// With the old password in place the check passes and asks for a
	// rotation.
	generated := values["INJI_CERTIFY_KEYSTORE_PASSWORD"]
	values["INJI_CERTIFY_KEYSTORE_PASSWORD"] = "certify"
	c = stackVolumeChecks(DoctorOptions{Pairs: pairs, Probe: probe, Stacks: stacks})[0]
	if !c.OK || !strings.Contains(c.Detail, "rotate") {
		t.Errorf("check with the old password = %+v", c)
	}
	// The old password with no volume left would start a new volume on
	// it (ADR-084).
	probe.volumes = nil
	c = stackVolumeChecks(DoctorOptions{Pairs: pairs, Probe: probe, Stacks: stacks})[0]
	if c.OK || !strings.Contains(c.Detail, "INJI_CERTIFY_KEYSTORE_PASSWORD") || !strings.Contains(c.Fix, "vca setup") {
		t.Errorf("check with the old password and no volume = %+v", c)
	}
	// No old volume and no old password passes quietly.
	values["INJI_CERTIFY_KEYSTORE_PASSWORD"] = generated
	c = stackVolumeChecks(DoctorOptions{Pairs: pairs, Probe: probe, Stacks: stacks})[0]
	if !c.OK || c.Name != "stack secrets inji" {
		t.Errorf("check with no volume = %+v", c)
	}
	// A volume and no .env at all: the volume predates any secret.
	probe.volumes = map[string]time.Time{"vca_waltid-db": secretsTime}
	c = stackVolumeChecks(DoctorOptions{Pairs: []Pair{issuerPair()}, Probe: probe})[0]
	if c.OK || !strings.Contains(c.Fix, "--dpg waltid") {
		t.Errorf("check with no .env = %+v", c)
	}
	// Docker that does not answer is a failed check, not a pass.
	probe.volumeErr = errors.New("no daemon")
	c = stackVolumeChecks(DoctorOptions{Pairs: pairs, Probe: probe, Stacks: stacks})[0]
	if c.OK || !strings.Contains(c.Detail, "cannot read") {
		t.Errorf("check with no daemon = %+v", c)
	}
	// Two roles of one stack give one check.
	probe.volumeErr = nil
	both := append(pairs, injiPair(commonv1.Role_ROLE_HOLDER))
	if got := stackVolumeChecks(DoctorOptions{Pairs: both, Probe: probe, Stacks: stacks}); len(got) != 1 {
		t.Errorf("two inji roles gave %d checks", len(got))
	}
	// A bad stamp is a failed check that names the file.
	values[StackSecretsSinceEnv] = "yesterday"
	c = stackVolumeChecks(DoctorOptions{Pairs: pairs, Probe: probe, Stacks: stacks})[0]
	if c.OK || !strings.Contains(c.Detail, StackSecretsSinceEnv) {
		t.Errorf("check with a bad stamp = %+v", c)
	}
}

// TestUpgradeSecretsWritesTheOldPasswords: the upgrade writes the old
// password of each volume that predates the secrets, keeps every other
// value, and tells the operator to rotate. A second run changes nothing.
func TestUpgradeSecretsWritesTheOldPasswords(t *testing.T) {
	deploy := t.TempDir()
	before := writeStackEnvAt(t, deploy, configv1.Dpg_DPG_INJI, secretsTime, nil)
	probe := healthyProbe()
	probe.volumes = map[string]time.Time{
		"vca_inji-esignet-db":   secretsTime.Add(-time.Hour),
		"vca_inji-certify-keys": secretsTime.Add(-time.Hour),
		"vca_inji-mimoto-db":    secretsTime.Add(time.Hour),
	}
	var out bytes.Buffer
	changed, err := UpgradeSecrets(UpgradeOptions{
		Deploy: deploy, Dpgs: []configv1.Dpg{configv1.Dpg_DPG_INJI}, Probe: probe,
		Random: rand.Reader, Now: func() time.Time { return secretsTime.Add(72 * time.Hour) }, Out: &out,
	})
	if err != nil {
		t.Fatalf("UpgradeSecrets: %v", err)
	}
	if changed != 2 {
		t.Errorf("changed = %d, want 2\n%s", changed, out.String())
	}
	after, err := ReadStackEnv(deploy, configv1.Dpg_DPG_INJI)
	if err != nil {
		t.Fatal(err)
	}
	if after["INJI_ESIGNET_DB_PASSWORD"] != "esignet" || after["INJI_CERTIFY_KEYSTORE_PASSWORD"] != "certify" {
		t.Errorf("old passwords = %q %q", after["INJI_ESIGNET_DB_PASSWORD"], after["INJI_CERTIFY_KEYSTORE_PASSWORD"])
	}
	for _, name := range []string{"INJI_DB_PASSWORD", "INJI_VERIFY_DB_PASSWORD", "INJI_MIMOTO_DB_PASSWORD", StackSecretsSinceEnv} {
		if after[name] != before[name] {
			t.Errorf("%s changed from %q to %q", name, before[name], after[name])
		}
	}
	info, err := os.Stat(filepath.Join(deploy, StackEnvFile(configv1.Dpg_DPG_INJI)))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v %v", info, err)
	}
	text := out.String()
	for _, want := range []string{"INJI_ESIGNET_DB_PASSWORD", "vca_inji-esignet-db", "Rotate", "docs/deploy.md"} {
		if !strings.Contains(text, want) {
			t.Errorf("the output lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "certify\n") || strings.Contains(text, before["INJI_ESIGNET_DB_PASSWORD"]) {
		t.Errorf("the output shows a password:\n%s", text)
	}
	out.Reset()
	changed, err = UpgradeSecrets(UpgradeOptions{
		Deploy: deploy, Dpgs: []configv1.Dpg{configv1.Dpg_DPG_INJI}, Probe: probe, Random: rand.Reader, Out: &out,
	})
	if err != nil || changed != 0 || !strings.Contains(out.String(), "Nothing changed") {
		t.Errorf("second run = %d %v\n%s", changed, err, out.String())
	}
}

// TestUpgradeSecretsWithoutAnEnvFile: a deployment that never ran the
// new setup has volumes and no stack .env. The upgrade writes the file
// with the old password of each volume and generates the rest.
func TestUpgradeSecretsWithoutAnEnvFile(t *testing.T) {
	deploy := t.TempDir()
	probe := healthyProbe()
	probe.volumes = map[string]time.Time{"vca_credebl-db": secretsTime}
	var out bytes.Buffer
	changed, err := UpgradeSecrets(UpgradeOptions{
		Deploy: deploy, Probe: probe, Random: rand.Reader,
		Now: func() time.Time { return secretsTime.Add(time.Hour) }, Out: &out,
	})
	if err != nil || changed != 1 {
		t.Fatalf("UpgradeSecrets = %d %v\n%s", changed, err, out.String())
	}
	values, err := ReadStackEnv(deploy, configv1.Dpg_DPG_CREDEBL)
	if err != nil || values["CREDEBL_DB_PASSWORD"] != "credebl" {
		t.Errorf("credebl = %v %v", values, err)
	}
	if values[StackSecretsSinceEnv] != "2026-09-26T13:00:00Z" {
		t.Errorf("the new file has no stamp: %v", values)
	}
	// A stack with no old volume gets no file here. Setup writes it.
	if _, err := os.Stat(filepath.Join(deploy, StackEnvFile(configv1.Dpg_DPG_WALTID))); err == nil {
		t.Error("the upgrade wrote the walt.id file")
	}
	if _, err := os.Stat(filepath.Join(deploy, "credebl", ".gitignore")); err != nil {
		t.Errorf("no .gitignore: %v", err)
	}
	// A daemon that does not answer stops the run before any write.
	probe.volumeErr = errors.New("no daemon")
	if _, err := UpgradeSecrets(UpgradeOptions{Deploy: t.TempDir(), Probe: probe, Random: rand.Reader, Out: &out}); err == nil {
		t.Error("the upgrade ran without Docker")
	}
	// A broken .env stops the run too.
	broken := t.TempDir()
	if err := os.MkdirAll(filepath.Join(broken, "waltid"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(broken, StackEnvFile(configv1.Dpg_DPG_WALTID)), []byte("not a line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	probe.volumeErr = nil
	if _, err := UpgradeSecrets(UpgradeOptions{Deploy: broken, Probe: probe, Random: rand.Reader, Out: &out}); err == nil {
		t.Error("the upgrade read a broken file")
	}
}

// TestDpgUpgradeSecretsCommand: vca dpg upgrade-secrets runs the upgrade
// for the named stack, and vca doctor then passes the stack check.
func TestDpgUpgradeSecretsCommand(t *testing.T) {
	root := t.TempDir()
	deploy := filepath.Join(root, "deploy")
	writeStackEnvAt(t, deploy, configv1.Dpg_DPG_WALTID, secretsTime, nil)
	probe := healthyProbe()
	probe.volumes = map[string]time.Time{"vca_waltid-db": secretsTime.Add(-time.Hour)}
	env := Environment{Root: root, NewProbe: func(context.Context) Probe { return probe }}
	status, out, errOut := run(t, env, "doctor", "--role", "issuer", "--dpg", "waltid")
	if status == 0 || !strings.Contains(out, "upgrade-secrets") {
		t.Errorf("doctor before the upgrade = %d\n%s\n%s", status, out, errOut)
	}
	status, out, errOut = run(t, env, "dpg", "upgrade-secrets", "--dpg", "waltid")
	if status != 0 || !strings.Contains(out, "WALTID_DB_PASSWORD") {
		t.Fatalf("upgrade = %d\n%s\n%s", status, out, errOut)
	}
	values, err := ReadStackEnv(deploy, configv1.Dpg_DPG_WALTID)
	if err != nil || values["WALTID_DB_PASSWORD"] != "waltid" {
		t.Errorf("values = %v %v", values, err)
	}
	status, out, _ = run(t, env, "doctor", "--role", "issuer", "--dpg", "waltid")
	if !strings.Contains(out, "pass  stack secrets waltid") {
		t.Errorf("doctor after the upgrade = %d\n%s", status, out)
	}
	if status, _, errOut := run(t, env, "dpg", "upgrade-secrets", "--dpg", "nothing"); status == 0 {
		t.Errorf("an unknown DPG passed: %s", errOut)
	}
}

// TestSystemProbeReadsTheVolumeTime: the probe lists the volume by its
// exact name, then reads its creation time.
func TestSystemProbeReadsTheVolumeTime(t *testing.T) {
	var calls []string
	answers := map[string]string{
		"volume ls --quiet --filter name=vca_waltid-db":             "vca_waltid-db-old\nvca_waltid-db\n",
		"volume inspect --format {{.CreatedAt}} vca_waltid-db":      "2026-09-01T08:00:00Z\n",
		"volume ls --quiet --filter name=vca_credebl-db":            "vca_credebl-db-copy\n",
		"volume ls --quiet --filter name=vca_inji-verify-db":        "vca_inji-verify-db\n",
		"volume inspect --format {{.CreatedAt}} vca_inji-verify-db": "last week\n",
	}
	probe := &SystemProbe{Ctx: context.Background(), Output: func(_ context.Context, name string, args []string) (string, error) {
		key := strings.Join(args, " ")
		calls = append(calls, name+" "+key)
		if out, ok := answers[key]; ok {
			return out, nil
		}
		return "", errors.New("no daemon")
	}}
	at, ok, err := probe.VolumeCreated("vca_waltid-db")
	if err != nil || !ok || !at.Equal(time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)) {
		t.Errorf("waltid = %v %v %v", at, ok, err)
	}
	if _, ok, err := probe.VolumeCreated("vca_credebl-db"); ok || err != nil {
		t.Errorf("a longer name matched: %v %v", ok, err)
	}
	if _, _, err := probe.VolumeCreated("vca_inji-verify-db"); err == nil {
		t.Error("a bad time passed")
	}
	if _, _, err := probe.VolumeCreated("vca_inji-certify-db"); err == nil {
		t.Error("a failed list passed")
	}
	answers["volume ls --quiet --filter name=vca_inji-certify-db"] = "vca_inji-certify-db\n"
	if _, _, err := probe.VolumeCreated("vca_inji-certify-db"); err == nil {
		t.Error("a failed inspect passed")
	}
	if len(calls) == 0 || !strings.HasPrefix(calls[0], "docker volume ls") {
		t.Errorf("calls = %v", calls)
	}
}

// TestSetupKeepsTheOldPasswordsOfExistingVolumes: the first setup run
// on a host whose stack volumes predate generated secrets finds no stack
// .env. It writes the old passwords of the volumes it finds into the new
// .env, names each one, and asks the operator to rotate them. A stack
// without volumes gets new passwords, and a host without Docker keeps
// the run going with a warning.
func TestSetupKeepsTheOldPasswordsOfExistingVolumes(t *testing.T) {
	root := t.TempDir()
	deploy := filepath.Join(root, "deploy")
	probe := healthyProbe()
	// The volumes are a year older than the run.
	old := time.Now().UTC().AddDate(-1, 0, 0)
	probe.volumes = map[string]time.Time{"vca_inji-esignet-db": old, "vca_inji-mimoto-keys": old}
	env := Environment{Root: root, NewProbe: func(context.Context) Probe { return probe }}
	status, out, errOut := run(t, env, "setup", "--role", "issuer", "--dpg", "inji", "--non-interactive")
	if status != 0 {
		t.Fatalf("setup = %d\n%s\n%s", status, out, errOut)
	}
	inji, err := ReadStackEnv(deploy, configv1.Dpg_DPG_INJI)
	if err != nil {
		t.Fatal(err)
	}
	if inji["INJI_ESIGNET_DB_PASSWORD"] != "esignet" || inji["INJI_MIMOTO_KEYSTORE_PASSWORD"] != "mimoto" {
		t.Fatalf("the old passwords are lost: %v", inji)
	}
	if inji["INJI_VERIFY_DB_PASSWORD"] == "injiverify" || len(inji["INJI_VERIFY_DB_PASSWORD"]) != stackSecretLength {
		t.Fatalf("a stack secret without a volume is not new: %q", inji["INJI_VERIFY_DB_PASSWORD"])
	}
	waltid, err := ReadStackEnv(deploy, configv1.Dpg_DPG_WALTID)
	if err != nil || waltid["WALTID_DB_PASSWORD"] == "waltid" {
		t.Fatalf("waltid = %v %v", waltid, err)
	}
	for _, want := range []string{"INJI_ESIGNET_DB_PASSWORD", "vca_inji-esignet-db", "INJI_MIMOTO_KEYSTORE_PASSWORD", rotateHint} {
		if !strings.Contains(out, want) {
			t.Errorf("the run does not say %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "=esignet") || strings.Contains(out, "=mimoto") {
		t.Error("the run printed a password")
	}
	// The doctor then passes the stack and asks for a rotation.
	status, out, _ = run(t, env, "doctor", "--role", "issuer", "--dpg", "inji")
	if !strings.Contains(out, "pass  stack secrets inji") || !strings.Contains(out, "rotate") {
		t.Errorf("doctor = %d\n%s", status, out)
	}
	// A later run keeps the values and reads no volume.
	probe.volumeErr = errors.New("docker is gone")
	status, _, errOut = run(t, env, "setup", "--role", "issuer", "--dpg", "inji", "--non-interactive")
	if status != 0 {
		t.Fatalf("second setup = %d\n%s", status, errOut)
	}
	again, err := ReadStackEnv(deploy, configv1.Dpg_DPG_INJI)
	if err != nil || again["INJI_ESIGNET_DB_PASSWORD"] != "esignet" {
		t.Fatalf("again = %v %v", again, err)
	}
	// A first run without Docker writes new secrets and says so.
	other := t.TempDir()
	env = Environment{Root: other, NewProbe: func(context.Context) Probe { return probe }}
	status, out, errOut = run(t, env, "setup", "--role", "issuer", "--dpg", "inji", "--non-interactive")
	if status != 0 {
		t.Fatalf("setup without Docker = %d\n%s", status, errOut)
	}
	if !strings.Contains(out+errOut, "vca dpg upgrade-secrets") {
		t.Errorf("the run does not name the upgrade:\n%s\n%s", out, errOut)
	}
}
