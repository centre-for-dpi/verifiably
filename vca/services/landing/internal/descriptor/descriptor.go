// SPDX-License-Identifier: Apache-2.0

// Package descriptor builds the machine readable summary of a deployment
// that the landing serves at /.well-known/vca.json (ADR-033 decision 1).
// It names the version, the stacks that run with their components, and
// the state of every pair that is present. An absent pair stays out, as
// it does on the page.
package descriptor

import (
	"strings"
	"time"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
)

// Descriptor is the document.
type Descriptor struct {
	// Version is the image version of the deployment.
	Version string `json:"version"`
	// PublicURL is the address of the landing, when it is known.
	PublicURL string `json:"public_url,omitempty"`
	// Taken is the time of the probe behind the states.
	Taken time.Time `json:"taken"`
	// Stacks lists every stack with at least one present pair.
	Stacks []Stack `json:"stacks"`
	// Pairs lists every present pair with its state.
	Pairs []Pair `json:"pairs"`
}

// Stack is one DPG stack of the deployment.
type Stack struct {
	// ID is the short name of the stack, from the DPG enum.
	ID string `json:"id"`
	// Name is the display name the adapter reports, or the ID until a
	// pair of the stack is live.
	Name string `json:"name"`
	// Version is the release the adapter reports.
	Version string `json:"version,omitempty"`
	// Components lists the parts of the stack with their versions and
	// links, from the adapter.
	Components []Component `json:"components"`
}

// Component is one part of a stack.
type Component struct {
	Name          string `json:"name"`
	Version       string `json:"version,omitempty"`
	RepositoryURL string `json:"repository_url,omitempty"`
	DocsURL       string `json:"docs_url,omitempty"`
	License       string `json:"license,omitempty"`
}

// Pair is one present role and DPG pair.
type Pair struct {
	Pair      string `json:"pair"`
	Role      string `json:"role"`
	Stack     string `json:"stack"`
	State     string `json:"state"`
	PublicURL string `json:"public_url"`
}

// Build makes the descriptor of one snapshot.
func Build(version, publicURL string, snap topology.Snapshot) Descriptor {
	out := Descriptor{Version: version, PublicURL: publicURL, Taken: snap.Taken.UTC(), Stacks: []Stack{}, Pairs: []Pair{}}
	index := map[configv1.Dpg]int{}
	for _, st := range snap.Peers {
		if st.State == topology.Absent {
			continue
		}
		id := DpgID(st.Peer.Dpg)
		i, ok := index[st.Peer.Dpg]
		if !ok {
			index[st.Peer.Dpg] = len(out.Stacks)
			i = len(out.Stacks)
			out.Stacks = append(out.Stacks, Stack{ID: id, Name: id, Components: []Component{}})
		}
		if info := st.Capabilities.GetDpgInfo(); info != nil && out.Stacks[i].Version == "" {
			out.Stacks[i].Name = info.GetDisplayName()
			out.Stacks[i].Version = info.GetVersion()
			out.Stacks[i].Components = components(info.GetComponents())
		}
		out.Pairs = append(out.Pairs, Pair{
			Pair: st.Peer.Pair, Role: RoleID(st.Peer.Role), Stack: id, State: st.State.String(), PublicURL: st.Peer.PublicURL,
		})
	}
	return out
}

// components converts the adapter answer.
func components(list []*backendv1.Component) []Component {
	out := make([]Component, 0, len(list))
	for _, c := range list {
		out = append(out, Component{
			Name: c.GetName(), Version: c.GetVersion(), RepositoryURL: c.GetRepositoryUrl(), DocsURL: c.GetDocsUrl(), License: c.GetLicense(),
		})
	}
	return out
}

// DpgID returns the short lower case name of a DPG from the enum, the
// same name the pair names and the compose profiles use.
func DpgID(d configv1.Dpg) string { return shortName(d.String()) }

// RoleID returns the short lower case name of a role from the enum.
func RoleID(r commonv1.Role) string { return shortName(r.String()) }

// shortName turns an enum name such as ROLE_ISSUER into issuer.
func shortName(name string) string {
	if i := strings.Index(name, "_"); i >= 0 {
		name = name[i+1:]
	}
	return strings.ToLower(name)
}
