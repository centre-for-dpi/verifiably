// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// handlerFunc matches the constructor of a generated Connect handler.
var handlerFunc = regexp.MustCompile(`^New(\w+Service)Handler$`)

// connectHandlerOf returns the full name of the Connect service whose
// handler a call builds, or "" when the call builds none. It knows the
// generated constructors and the two shared wrappers.
func connectHandlerOf(call *ast.CallExpr) string {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return ""
	}
	switch {
	case pkg.Name == "oidcflow" && sel.Sel.Name == "NewAdminHandler":
		return rpcAdmin
	case pkg.Name == "auditlog" && sel.Sel.Name == "NewHandler":
		return rpcAudit
	case strings.HasSuffix(pkg.Name, "v1connect"):
		m := handlerFunc.FindStringSubmatch(sel.Sel.Name)
		if m == nil {
			return ""
		}
		return "vca." + strings.TrimSuffix(pkg.Name, "v1connect") + ".v1." + m[1]
	}
	return ""
}

// requiresPeer reports whether one argument of call is
// peerauth.Require(...).
func requiresPeer(call *ast.CallExpr) bool {
	for _, arg := range call.Args {
		inner, ok := arg.(*ast.CallExpr)
		if !ok {
			continue
		}
		sel, ok := inner.Fun.(*ast.SelectorExpr)
		if !ok {
			continue
		}
		if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "peerauth" && sel.Sel.Name == "Require" {
			return true
		}
	}
	return false
}

// TestEveryConnectHandlerChecksItsCaller is ADR-075 decision 3: a
// service that mounts a Connect handler passes peerauth.Require to it,
// unless the proxy publishes that service and it checks the user
// instead (ADR-047). A shared wrapper in services/internal forwards the
// options of its caller.
func TestEveryConnectHandlerChecksItsCaller(t *testing.T) {
	root := filepath.Join("..", "..", "services")
	found := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel := filepath.ToSlash(strings.TrimPrefix(path, root+string(filepath.Separator)))
		owner, _, _ := strings.Cut(rel, "/")
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := connectHandlerOf(call)
			if name == "" {
				return true
			}
			found++
			if owner == "internal" {
				if call.Ellipsis == token.NoPos {
					t.Errorf("%s builds the handler of %s but does not forward the options of its caller", rel, name)
				}
				return true
			}
			if _, public := checkedRPC[owner+" "+name]; public {
				return true
			}
			if !requiresPeer(call) {
				t.Errorf("%s mounts %s without peerauth.Require (ADR-075)", rel, name)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found < 40 {
		t.Fatalf("found only %d Connect handlers under %s", found, root)
	}
}
