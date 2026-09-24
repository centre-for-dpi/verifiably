// SPDX-License-Identifier: Apache-2.0

package pages

import (
	"sort"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/landing/internal/descriptor"
)

// roleOrder is the order the pages list the roles in: the three roles
// of the triangle, then the admin.
var roleOrder = []commonv1.Role{
	commonv1.Role_ROLE_ISSUER, commonv1.Role_ROLE_HOLDER, commonv1.Role_ROLE_VERIFIER, commonv1.Role_ROLE_ADMIN,
}

// dpgOrder lists every DPG of the enum in number order. The enum is the
// one place a DPG is named (ADR-001 decision 4).
func dpgOrder() []configv1.Dpg {
	var out []configv1.Dpg
	for number := range configv1.Dpg_name {
		if number != 0 {
			out = append(out, configv1.Dpg(number))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Overview is what the pages know about a deployment, from one snapshot:
// the stacks with at least one present pair and the roles with at least
// one present pair, each in a fixed order.
type Overview struct {
	Stacks []Stack
	Roles  []Role
}

// Stack is one DPG stack with at least one present pair.
type Stack struct {
	// Dpg is the DPG of the stack.
	Dpg configv1.Dpg
	// ID is the short name of the DPG, from the enum.
	ID string
	// Info is the DPG information of the first live adapter of the
	// stack, or nil while no pair of the stack is live.
	Info *backendv1.DpgInfo
	// Pairs lists the present pairs of the stack in role order.
	Pairs []topology.Status
}

// Name returns the display name of the stack: the name the adapter
// reports, or the ID until an adapter answers.
func (s Stack) Name() string {
	if name := s.Info.GetDisplayName(); name != "" {
		return name
	}
	return s.ID
}

// Live reports whether one pair of the stack is live.
func (s Stack) Live() bool {
	for _, p := range s.Pairs {
		if p.State == topology.Live {
			return true
		}
	}
	return false
}

// Role is one role with at least one present pair.
type Role struct {
	// Role is the role.
	Role commonv1.Role
	// ID is the short name of the role, from the enum.
	ID string
	// Pairs lists the present pairs of the role in stack order.
	Pairs []topology.Status
}

// Label returns the label of the role from the catalogue.
func (r Role) Label() string { return roleLabel(r.Role) }

// Live returns the live pairs of the role, in stack order.
func (r Role) Live() []topology.Status {
	var out []topology.Status
	for _, p := range r.Pairs {
		if p.State == topology.Live {
			out = append(out, p)
		}
	}
	return out
}

// roleLabel returns the label of a role from the catalogue.
func roleLabel(r commonv1.Role) string { return msg.T("role." + descriptor.RoleID(r) + ".label") }

// NewOverview reads one snapshot.
func NewOverview(snap topology.Snapshot) Overview {
	byDpg := map[configv1.Dpg]*Stack{}
	byRole := map[commonv1.Role]*Role{}
	for _, role := range roleOrder {
		for _, d := range dpgOrder() {
			st, ok := find(snap, role, d)
			if !ok || st.State == topology.Absent {
				continue
			}
			stack := byDpg[d]
			if stack == nil {
				stack = &Stack{Dpg: d, ID: descriptor.DpgID(d)}
				byDpg[d] = stack
			}
			if stack.Info == nil {
				stack.Info = st.Capabilities.GetDpgInfo()
			}
			stack.Pairs = append(stack.Pairs, st)
			r := byRole[role]
			if r == nil {
				r = &Role{Role: role, ID: descriptor.RoleID(role)}
				byRole[role] = r
			}
			r.Pairs = append(r.Pairs, st)
		}
	}
	var out Overview
	for _, d := range dpgOrder() {
		if s := byDpg[d]; s != nil {
			out.Stacks = append(out.Stacks, *s)
		}
	}
	for _, role := range roleOrder {
		if r := byRole[role]; r != nil {
			out.Roles = append(out.Roles, *r)
		}
	}
	return out
}

// find returns the status of one pair of the snapshot.
func find(snap topology.Snapshot, role commonv1.Role, d configv1.Dpg) (topology.Status, bool) {
	for _, st := range snap.Peers {
		if st.Peer.Role == role && st.Peer.Dpg == d {
			return st, true
		}
	}
	return topology.Status{}, false
}

// LiveRoles returns the roles with at least one live pair.
func (o Overview) LiveRoles() []Role {
	var out []Role
	for _, r := range o.Roles {
		if len(r.Live()) > 0 {
			out = append(out, r)
		}
	}
	return out
}

// allLive returns every live pair of the deployment, in role order.
func (o Overview) allLive() []topology.Status {
	var out []topology.Status
	for _, r := range o.Roles {
		out = append(out, r.Live()...)
	}
	return out
}

// StackName returns the display name of the stack of one pair.
func (o Overview) StackName(d configv1.Dpg) string {
	for _, s := range o.Stacks {
		if s.Dpg == d {
			return s.Name()
		}
	}
	return descriptor.DpgID(d)
}

// StackNames returns the display names of the stacks of the pairs, in
// stack order and once each.
func (o Overview) StackNames(pairs []topology.Status) []string {
	seen := map[configv1.Dpg]bool{}
	var out []string
	for _, s := range o.Stacks {
		for _, p := range pairs {
			if p.Peer.Dpg == s.Dpg && !seen[s.Dpg] {
				seen[s.Dpg] = true
				out = append(out, s.Name())
			}
		}
	}
	return out
}
