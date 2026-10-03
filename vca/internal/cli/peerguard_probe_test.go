// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// guardProbe holds Go sources that mount Connect handlers in every
// spelling the guard must see. Each file whose name starts with bad_
// mounts a handler without the check. Each file whose name starts with
// good_ mounts one with it, or is a public service of the allowlist.
var guardProbe = map[string]string{
	"services/probe/bad_alias.go": `package probe
import bc "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
func mount(mux Mux, svc bc.IssuerBackendServiceHandler) { mux.Handle(bc.NewIssuerBackendServiceHandler(svc)) }`,
	"services/probe/bad_value.go": `package probe
import "github.com/centre-for-dpi/vc-adapters/gen/vca/issuance/v1/issuancev1connect"
func mount(mux Mux, svc S) { mk := issuancev1connect.NewIssuanceServiceHandler; mux.Handle(mk(svc)) }`,
	"services/probe/bad_unary.go": `package probe
import "connectrpc.com/connect"
func mount(mux Mux) { mux.Handle("/vca.trust.v1.TrustService/GetEntry", connect.NewUnaryHandler("/vca.trust.v1.TrustService/GetEntry", get)) }`,
	"services/probe/bad_procedure.go": `package probe
import (
	rpc "connectrpc.com/connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1/trustv1connect"
)
func mount(mux Mux) { mux.Handle(trustv1connect.TrustServiceGetEntryProcedure, rpc.NewUnaryHandler(trustv1connect.TrustServiceGetEntryProcedure, get)) }`,
	"services/internal/wrap/wrap.go": `package wrap
import (
	"net/http"
	"connectrpc.com/connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1/trustv1connect"
)
func Mount(svc trustv1connect.TrustServiceHandler, opts ...connect.HandlerOption) (string, http.Handler) {
	return trustv1connect.NewTrustServiceHandler(svc, opts...)
}
func Outer(svc trustv1connect.TrustServiceHandler, more ...connect.HandlerOption) (string, http.Handler) {
	return Mount(svc, more...)
}`,
	"services/probe/bad_wrapper.go": `package probe
import "github.com/centre-for-dpi/vc-adapters/services/internal/wrap"
func mount(mux Mux, svc S) { mux.Handle(wrap.Mount(svc)) }`,
	"services/probe/bad_outer.go": `package probe
import w "github.com/centre-for-dpi/vc-adapters/services/internal/wrap"
func mount(mux Mux, svc S) { mux.Handle(w.Outer(svc)) }`,
	"services/probe/good_wrapper.go": `package probe
import (
	"github.com/centre-for-dpi/vc-adapters/internal/peerauth"
	"github.com/centre-for-dpi/vc-adapters/services/internal/wrap"
)
func mount(mux Mux, svc S, p peerauth.Settings) { mux.Handle(wrap.Outer(svc, peerauth.Require(p))) }`,
	"internal/probe/bad_outside.go": `package probe
import "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1/trustv1connect"
func mount(mux Mux, svc S) { mux.Handle(trustv1connect.NewTrustServiceHandler(svc)) }`,
	"cmd/probe/good_alias.go": `package main
import (
	pa "github.com/centre-for-dpi/vc-adapters/internal/peerauth"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1/trustv1connect"
)
func mount(mux Mux, svc S, p pa.Settings) { mux.Handle(trustv1connect.NewTrustServiceHandler(svc, pa.Require(p))) }`,
	"services/probe/bad_fakeguard.go": `package probe
import (
	peerauth "example.org/fake/peerauth"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1/trustv1connect"
)
func mount(mux Mux, svc S, p peerauth.Settings) { mux.Handle(trustv1connect.NewTrustServiceHandler(svc, peerauth.Require(p))) }`,
	"services/probe/bad_slice.go": `package probe
import (
	"connectrpc.com/connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1/trustv1connect"
)
func mount(mux Mux, svc S, opts ...connect.HandlerOption) {
	other := []connect.HandlerOption{}
	mux.Handle(trustv1connect.NewTrustServiceHandler(svc, other...))
}`,
	"services/probe/bad_dot.go": `package probe
import . "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1/trustv1connect"
func mount(mux Mux, svc S) { mux.Handle(NewTrustServiceHandler(svc)) }`,
	"services/admin/good_public.go": `package admin
import "github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1/adminv1connect"
func mount(mux Mux, svc S) { mux.Handle(adminv1connect.NewAdminServiceHandler(svc)) }`,
}

// probeFiles parses the probe sources.
func probeFiles(t *testing.T) []guardFile {
	t.Helper()
	fset := token.NewFileSet()
	var out []guardFile
	for rel, src := range guardProbe {
		f, err := parser.ParseFile(fset, rel, src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
		out = append(out, guardFile{rel: rel, file: f})
	}
	return out
}

// TestTheGuardSeesEverySpelling is ADR-075 decision 7: the guard finds a
// handler mount by the import path of its constructor, not by the name
// of a package identifier. It sees an aliased import, a constructor
// taken as a value, connect.NewUnaryHandler, a wrapper and a wrapper of
// a wrapper called with no options, and a mount outside services. An
// imitation of peerauth.Require or a forwarded slice that is not the
// options of the caller does not count as the check.
func TestTheGuardSeesEverySpelling(t *testing.T) {
	_, problems := scanPeerGuard(probeFiles(t))
	joined := strings.Join(problems, "\n")
	for rel := range guardProbe {
		base := rel[strings.LastIndex(rel, "/")+1:]
		flagged := strings.Contains(joined, rel+" ")
		switch {
		case strings.HasPrefix(base, "bad_") && !flagged:
			t.Errorf("the guard missed %s", rel)
		case !strings.HasPrefix(base, "bad_") && flagged:
			t.Errorf("the guard flagged %s:\n%s", rel, joined)
		}
	}
}
