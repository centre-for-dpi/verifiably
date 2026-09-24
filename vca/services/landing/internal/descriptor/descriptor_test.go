// SPDX-License-Identifier: Apache-2.0

package descriptor

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
)

func TestBuildListsPresentPairsAndTheirStacks(t *testing.T) {
	first, second := configv1.Dpg(1), configv1.Dpg(2)
	info := &backendv1.DpgInfo{DisplayName: "Alpha Stack", Version: "1.0", Components: []*backendv1.Component{
		{Name: "api", Version: "1.0", RepositoryUrl: "https://example.org/r", DocsUrl: "https://example.org/d", License: "Apache-2.0"},
	}}
	snap := topology.Snapshot{Taken: time.Date(2026, 9, 24, 9, 0, 0, 0, time.FixedZone("x", 3600)), Peers: []topology.Status{
		// A starting pair comes first: the stack gets its id until a live pair names it.
		{Peer: topology.Peer{Pair: topology.PairName(commonv1.Role_ROLE_HOLDER, first), Role: commonv1.Role_ROLE_HOLDER, Dpg: first, PublicURL: "https://h"}, State: topology.Starting},
		{Peer: topology.Peer{Pair: topology.PairName(commonv1.Role_ROLE_ISSUER, first), Role: commonv1.Role_ROLE_ISSUER, Dpg: first, PublicURL: "https://i"}, State: topology.Live,
			Capabilities: &backendv1.GetCapabilitiesResponse{DpgInfo: info}},
		{Peer: topology.Peer{Pair: topology.PairName(commonv1.Role_ROLE_ADMIN, second), Role: commonv1.Role_ROLE_ADMIN, Dpg: second, PublicURL: "https://a"}, State: topology.Live},
		{Peer: topology.Peer{Pair: topology.PairName(commonv1.Role_ROLE_VERIFIER, second), Role: commonv1.Role_ROLE_VERIFIER, Dpg: second}, State: topology.Absent},
	}}
	d := Build("1.2.3", "https://vca.example/", snap)
	if d.Version != "1.2.3" || d.PublicURL != "https://vca.example/" || d.Taken.Location() != time.UTC || d.Taken.Hour() != 8 {
		t.Errorf("head = %+v", d)
	}
	if len(d.Stacks) != 2 || d.Stacks[0].ID != DpgID(first) || d.Stacks[0].Name != "Alpha Stack" || d.Stacks[0].Version != "1.0" {
		t.Errorf("stacks = %+v", d.Stacks)
	}
	if len(d.Stacks[0].Components) != 1 || d.Stacks[0].Components[0].License != "Apache-2.0" || d.Stacks[0].Components[0].RepositoryURL != "https://example.org/r" {
		t.Errorf("components = %+v", d.Stacks[0].Components)
	}
	// The admin pair has no adapter, so its stack keeps the id as its name.
	if d.Stacks[1].Name != d.Stacks[1].ID || d.Stacks[1].Version != "" || len(d.Stacks[1].Components) != 0 {
		t.Errorf("admin only stack = %+v", d.Stacks[1])
	}
	if len(d.Pairs) != 3 || d.Pairs[0].State != "starting" || d.Pairs[0].Role != "holder" || d.Pairs[1].State != "live" || d.Pairs[2].Role != "admin" {
		t.Errorf("pairs = %+v", d.Pairs)
	}
	data, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"public_url":"https://vca.example/"`, `"taken":"2026-09-24T08:00:00Z"`, `"components":[]`, `"repository_url"`} {
		if !strings.Contains(string(data), want) {
			t.Errorf("json missing %q:\n%s", want, data)
		}
	}
	if strings.Contains(string(data), "absent") || strings.Contains(string(data), "null") {
		t.Errorf("json:\n%s", data)
	}
}

func TestEmptySnapshotGivesEmptyLists(t *testing.T) {
	data, err := json.Marshal(Build("", "", topology.Snapshot{}))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"stacks":[]`) || !strings.Contains(string(data), `"pairs":[]`) || strings.Contains(string(data), "public_url") {
		t.Errorf("json:\n%s", data)
	}
}

func TestIDsComeFromTheEnums(t *testing.T) {
	for number, name := range configv1.Dpg_name {
		if number == 0 {
			continue
		}
		want := strings.ToLower(strings.TrimPrefix(name, "DPG_"))
		if got := DpgID(configv1.Dpg(number)); got != want {
			t.Errorf("DpgID(%d) = %q, want %q", number, got, want)
		}
	}
	if RoleID(commonv1.Role_ROLE_VERIFIER) != "verifier" || RoleID(commonv1.Role_ROLE_UNSPECIFIED) != "unspecified" {
		t.Error("RoleID")
	}
}
