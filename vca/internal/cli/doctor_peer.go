// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// upgradeSecretsFix is the command that writes the authority and every
// missing or stale identity file (ADR-075 decision 5).
const upgradeSecretsFix = "vca dpg upgrade-secrets" // #nosec G101 -- the name of a command, not a credential

// peerTarget is one service whose identity the doctor checks.
type peerTarget struct {
	owner      string
	dir        string
	s          Service
	deployment bool
	hosts      []string
}

// peerTargets lists the services of each pair that setup wrote, and the
// landing once its .env exists. A pair with no .env has nothing to check
// yet. A .env that does not parse gives the default host ports.
func peerTargets(deploy string, pairs []Pair) []peerTarget {
	var out []peerTarget
	for _, p := range pairs {
		dir := OutputDir(deploy, p)
		raw, err := os.ReadFile(filepath.Join(dir, EnvFileName)) // #nosec G304 -- the path comes from the deploy root
		if err != nil {
			continue
		}
		values, perr := ParseDotenv(bytes.NewReader(raw))
		if perr != nil {
			values = nil
		}
		for _, s := range ServicesFor(p) {
			out = append(out, peerTarget{owner: p.Name(), dir: dir, s: s, hosts: PublishedHosts(p, values, s.Name)})
		}
	}
	if len(out) == 0 {
		return nil
	}
	for _, s := range DeploymentServices() {
		dir := filepath.Join(deploy, s.Name)
		if _, err := os.Stat(filepath.Join(dir, EnvFileName)); err == nil {
			out = append(out, peerTarget{owner: s.Name, dir: dir, s: s, deployment: true})
		}
	}
	return out
}

// PeerChecks checks the peer identities of the pairs that setup wrote
// under deploy (ADR-075): the authority, an identity file and a key file
// per service, an identity that the authority signed with the callers,
// the scope, and the published hosts of the catalogue, and a key file
// that the container user can read. Each finding is one check with the
// command that fixes it. A deployment with no finding gives one passing
// check, and a host before setup gives none.
func PeerChecks(deploy string, pairs []Pair) []Check {
	targets := peerTargets(deploy, pairs)
	if len(targets) == 0 {
		return nil
	}
	var out []Check
	existing, err := ReadPeerAuthority(deploy)
	trusted := ""
	switch {
	case err != nil:
		out = append(out, Check{Name: "peer authority", Detail: err.Error(), Fix: upgradeSecretsFix})
	case existing == nil:
		out = append(out, Check{Name: "peer authority", Detail: filepath.Join(deploy, PeerDir, PeerAuthorityFile) + " is missing", Fix: upgradeSecretsFix})
	default:
		authority, _, perr := peerAuthority(existing, nil)
		if perr != nil {
			out = append(out, Check{Name: "peer authority", Detail: perr.Error(), Fix: upgradeSecretsFix})
		} else {
			trusted = authority.PublicSet()
		}
	}
	for _, tg := range targets {
		name := "peer identity " + tg.owner + "/" + tg.s.Name
		identity := filepath.Join(tg.dir, PeerFile(tg.s.Name))
		key := filepath.Join(tg.dir, PeerKeyFile(tg.s.Name))
		if _, serr := os.Stat(identity); serr != nil {
			out = append(out, Check{Name: name, Detail: identity + " is missing", Fix: upgradeSecretsFix})
			continue
		}
		info, kerr := os.Stat(key)
		if kerr != nil {
			out = append(out, Check{Name: name, Detail: "the key file " + key + " is missing", Fix: upgradeSecretsFix})
			continue
		}
		if trusted != "" && !current(tg.dir, trusted, tg.s, tg.deployment, tg.hosts) {
			out = append(out, Check{Name: name, Detail: identity + " is stale: another authority, other callers, or other host ports",
				Fix: upgradeSecretsFix})
			continue
		}
		// The container user has another user id than the operator, so
		// the key needs the read bit of other users (ADR-075, amendment
		// of 2026-10-04 item 7).
		if info.Mode().Perm()&0o004 == 0 {
			out = append(out, Check{Name: name, Detail: fmt.Sprintf("the container user cannot read %s, mode %04o", key, info.Mode().Perm()),
				Fix: "chmod 0644 " + key})
		}
	}
	if len(out) == 0 {
		return []Check{{Name: "peer identities", OK: true, Detail: strconv.Itoa(len(targets)) + " services hold a current identity"}}
	}
	return out
}
