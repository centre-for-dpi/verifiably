// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// The upgrade of a deployment from before generated stack secrets
// (ADR-055 decision 1). A release before it ran every stack on the
// default passwords of the stack files. A Postgres volume keeps the
// password of its first start, and a key store volume keeps the password
// it was made with. So a volume from that time needs its old password in
// the stack .env until the operator rotates it.

// StackVolume is one volume of a stack file that a stack secret guards.
type StackVolume struct {
	// Volume is the name of the volume in the stack file.
	Volume string
	// Env is the stack secret that guards it.
	Env string
	// Old is the default password of the stack file before generated
	// secrets. A volume of that time still holds it.
	Old string
}

// Docker returns the name that compose gives the volume.
func (v StackVolume) Docker() string { return ComposeProject + "_" + v.Volume }

// StackVolumes returns the volumes of the stack file of one DPG, in the
// order of stackSecretNames.
func StackVolumes(d configv1.Dpg) []StackVolume {
	switch d {
	case configv1.Dpg_DPG_WALTID:
		return []StackVolume{{Volume: "waltid-db", Env: "WALTID_DB_PASSWORD", Old: "waltid"}}
	case configv1.Dpg_DPG_INJI:
		return []StackVolume{
			{Volume: "inji-certify-db", Env: "INJI_DB_PASSWORD", Old: "certify"},
			{Volume: "inji-certify-keys", Env: "INJI_CERTIFY_KEYSTORE_PASSWORD", Old: "certify"},
			{Volume: "inji-esignet-db", Env: "INJI_ESIGNET_DB_PASSWORD", Old: "esignet"},
			{Volume: "inji-mimoto-db", Env: "INJI_MIMOTO_DB_PASSWORD", Old: "mimoto"},
			{Volume: "inji-mimoto-keys", Env: "INJI_MIMOTO_KEYSTORE_PASSWORD", Old: "mimoto"},
			{Volume: "inji-verify-db", Env: "INJI_VERIFY_DB_PASSWORD", Old: "injiverify"},
		}
	case configv1.Dpg_DPG_CREDEBL:
		return []StackVolume{{Volume: "credebl-db", Env: "CREDEBL_DB_PASSWORD", Old: "credebl"}}
	}
	return nil
}

// rotateHint is the line that asks the operator to rotate an old
// password.
const rotateHint = "Rotate these passwords later. See docs/deploy.md, section Upgrade from shared passwords."

// olderVolume is a volume that predates the secrets of its stack.
type olderVolume struct {
	StackVolume
	// Current reports whether the stack .env already holds the old
	// password.
	Current bool
}

// olderVolumes returns the volumes of one stack that predate the
// secrets of its .env. values holds the .env; an empty map means no
// file, so every volume predates it.
func olderVolumes(probe Probe, d configv1.Dpg, values map[string]string) ([]olderVolume, error) {
	var since time.Time
	if stamp := values[StackSecretsSinceEnv]; stamp != "" {
		parsed, err := time.Parse(time.RFC3339, stamp)
		if err != nil {
			return nil, fmt.Errorf("%s of %s is not an RFC 3339 time: %q", StackSecretsSinceEnv, StackEnvFile(d), stamp)
		}
		since = parsed
	}
	var out []olderVolume
	for _, v := range StackVolumes(d) {
		created, exists, err := probe.VolumeCreated(v.Docker())
		if err != nil {
			return nil, fmt.Errorf("cannot read the volume %s: %w", v.Docker(), err)
		}
		if !exists || (!since.IsZero() && !created.Before(since)) {
			continue
		}
		out = append(out, olderVolume{StackVolume: v, Current: values[v.Env] == v.Old})
	}
	return out, nil
}

// stackVolumeChecks returns one doctor check per stack of the selected
// pairs. It fails a volume that predates the generated secrets while the
// stack .env holds a new password for it.
func stackVolumeChecks(opts DoctorOptions) []Check {
	seen := map[configv1.Dpg]bool{}
	var out []Check
	for _, p := range opts.Pairs {
		if seen[p.Dpg] || StackVolumes(p.Dpg) == nil {
			continue
		}
		seen[p.Dpg] = true
		out = append(out, stackVolumeCheck(opts.Probe, p.Dpg, opts.Stacks[p.Dpg]))
	}
	return out
}

// stackVolumeCheck checks the volumes of one stack.
func stackVolumeCheck(probe Probe, d configv1.Dpg, values map[string]string) Check {
	short := ShortName(d.String())
	name := "stack secrets " + short
	fix := "run vca dpg upgrade-secrets --dpg " + short
	older, err := olderVolumes(probe, d, values)
	if err != nil {
		return Check{Name: name, Detail: err.Error(), Fix: "start Docker, check " + StackEnvFile(d) + ", and run vca doctor again"}
	}
	var stale, kept []string
	for _, v := range older {
		if v.Current {
			kept = append(kept, v.Docker())
			continue
		}
		stale = append(stale, v.Docker())
	}
	if len(stale) > 0 {
		return Check{
			Name:   name,
			Detail: "volumes older than the generated secrets hold another password: " + strings.Join(stale, ", "),
			Fix:    fix + " to write their old passwords into " + StackEnvFile(d),
		}
	}
	if len(kept) > 0 {
		return Check{Name: name, OK: true,
			Detail: "old passwords in use for " + strings.Join(kept, ", ") + "; rotate them later"}
	}
	return Check{Name: name, OK: true, Detail: "no volume predates the generated secrets"}
}

// UpgradeOptions holds everything one upgrade run needs.
type UpgradeOptions struct {
	// Deploy is the deploy directory under the repository root.
	Deploy string
	// Dpgs lists the stacks to upgrade. Empty means every stack.
	Dpgs []configv1.Dpg
	// Probe reads the volumes of Docker.
	Probe Probe
	// Random is the source of a secret that the .env still lacks.
	Random io.Reader
	// Now reads the clock for the stamp of a new file. Nil reads the
	// real clock.
	Now func() time.Time
	// Out receives the report. It never shows a password.
	Out io.Writer
}

// UpgradeSecrets writes the old password of each volume that predates
// the generated secrets into the .env of its stack. It keeps every other
// value and returns the number of values it changed. It reads every
// stack before it writes one, so a failure writes nothing.
func UpgradeSecrets(opts UpgradeOptions) (int, error) {
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	dpgs := opts.Dpgs
	if len(dpgs) == 0 {
		dpgs = StackDpgs()
	}
	type plan struct {
		d      configv1.Dpg
		values map[string]string
		older  []olderVolume
	}
	var plans []plan
	for _, d := range dpgs {
		values, err := ReadStackEnv(opts.Deploy, d)
		if err != nil {
			return 0, err
		}
		older, err := olderVolumes(opts.Probe, d, values)
		if err != nil {
			return 0, err
		}
		plans = append(plans, plan{d: d, values: values, older: older})
	}
	changed := 0
	for _, pl := range plans {
		var lines []string
		for _, v := range pl.older {
			if v.Current {
				continue
			}
			pl.values[v.Env] = v.Old
			lines = append(lines, fmt.Sprintf("%s: %s now holds the password of %s from before generated secrets.",
				ShortName(pl.d.String()), v.Env, v.Docker()))
		}
		if len(lines) == 0 {
			continue
		}
		if err := writeStackEnv(opts, pl.d, pl.values, now()); err != nil {
			return changed, err
		}
		sort.Strings(lines)
		for _, line := range lines {
			anyval.DiscardWrite(fmt.Fprintln(opts.Out, line))
		}
		changed += len(lines)
	}
	if changed == 0 {
		anyval.DiscardWrite(fmt.Fprintln(opts.Out, "No stack volume predates the generated secrets. Nothing changed."))
		return 0, nil
	}
	anyval.DiscardWrite(fmt.Fprintln(opts.Out, rotateHint))
	return changed, nil
}

// writeStackEnv writes the .env of one stack and its .gitignore, as
// setup does.
func writeStackEnv(opts UpgradeOptions, d configv1.Dpg, values map[string]string, now time.Time) error {
	text, err := StackEnv(d, values, opts.Random, now)
	if err != nil {
		return err
	}
	dir := filepath.Join(opts.Deploy, StackDir(d))
	if err := makeReadableDir(dir); err != nil {
		return err
	}
	for name, data := range map[string]string{EnvFileName: text, ".gitignore": "*\n"} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return fmt.Errorf("set the mode of %s: %w", path, err)
		}
	}
	return nil
}

// VolumeCreated asks Docker when a volume was made. A volume that does
// not exist gives false and no error.
func (p *SystemProbe) VolumeCreated(name string) (time.Time, bool, error) {
	list, err := p.Output(p.Ctx, "docker", []string{"volume", "ls", "--quiet", "--filter", "name=" + name})
	if err != nil {
		return time.Time{}, false, err
	}
	found := false
	for _, line := range strings.Fields(list) {
		if line == name {
			found = true
		}
	}
	if !found {
		return time.Time{}, false, nil
	}
	out, err := p.Output(p.Ctx, "docker", []string{"volume", "inspect", "--format", "{{.CreatedAt}}", name})
	if err != nil {
		return time.Time{}, false, err
	}
	created, err := time.Parse(time.RFC3339, strings.TrimSpace(out))
	if err != nil {
		return time.Time{}, false, fmt.Errorf("volume %s: cannot read the time %q", name, strings.TrimSpace(out))
	}
	return created, true, nil
}
