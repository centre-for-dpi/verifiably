// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The guard of ADR-075 decision 7 reads every Go file of vca/ that is
// not a test, and resolves each call by the import path of its callee,
// so an alias, a wrapper or a file outside services/ does not hide a
// mount. A handler builder is:
//
//   - a generated constructor New<Name>Handler of a package under
//     gen/vca/<pkg>/v1/<pkg>v1connect,
//   - connect.NewUnaryHandler and the three stream handlers of
//     connectrpc.com/connect,
//   - a wrapper: a function anywhere in vca/ that calls a builder and
//     forwards its own variadic options. The guard finds the wrappers
//     itself, wrappers of wrappers too, and checks their callers.
//
// Every builder call must take peerauth.Require of
// internal/peerauth as a direct argument, unless it forwards the options
// of the function around it (then that function is a wrapper), or the
// proxy publishes the service and the service checks the user
// (checkedRPC, ADR-047). A builder taken as a value, or any name of a
// dot import, is a finding too, because the guard cannot follow it.

// modulePath is the import path of the vca module.
const modulePath = "github.com/centre-for-dpi/vc-adapters"

// peerauthPath is the import path of the package of the check.
const peerauthPath = modulePath + "/internal/peerauth"

// connectPath is the import path of connect-go.
const connectPath = "connectrpc.com/connect"

// generatedConnect matches the import path of a generated Connect
// package and captures the proto package.
var generatedConnect = regexp.MustCompile(`^` + regexp.QuoteMeta(modulePath) + `/gen/vca/(\w+)/v1/\w+v1connect$`)

// handlerFunc matches the constructor of a generated Connect handler.
var handlerFunc = regexp.MustCompile(`^New(\w+Service)Handler$`)

// procedureConst matches a generated procedure constant.
var procedureConst = regexp.MustCompile(`^(\w+?Service)\w*Procedure$`)

// connectHandlers are the handler constructors of connect-go.
var connectHandlers = map[string]bool{
	"NewUnaryHandler": true, "NewServerStreamHandler": true, "NewClientStreamHandler": true, "NewBidiStreamHandler": true,
}

// guardFile is one parsed Go file and its slash path under vca/.
type guardFile struct {
	rel  string
	file *ast.File
}

// pkgPath is the import path of the package of the file.
func (g guardFile) pkgPath() string { return modulePath + "/" + path.Dir(g.rel) }

// owner is the service directory of the file under services/, or the
// directory of a file elsewhere.
func (g guardFile) owner() string {
	if rest, ok := strings.CutPrefix(g.rel, "services/"); ok {
		owner, _, _ := strings.Cut(rest, "/")
		return owner
	}
	return path.Dir(g.rel)
}

// funcRef names one function by the import path of its package.
type funcRef struct{ pkg, name string }

// guardScope resolves the names of one file.
type guardScope struct {
	file    guardFile
	imports map[string]string
	dots    []string
}

// newScope reads the imports of a file. A dot import goes to dots.
func newScope(g guardFile) guardScope {
	s := guardScope{file: g, imports: map[string]string{}}
	for _, imp := range g.file.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		name := path.Base(p)
		if imp.Name != nil {
			name = imp.Name.Name
		}
		switch name {
		case "_":
		case ".":
			s.dots = append(s.dots, p)
		default:
			s.imports[name] = p
		}
	}
	return s
}

// resolve names the function an expression refers to: pkg.Name through
// an import, or Name of the package of the file.
func (s guardScope) resolve(e ast.Expr) (funcRef, bool) {
	switch x := e.(type) {
	case *ast.SelectorExpr:
		id, ok := x.X.(*ast.Ident)
		if !ok {
			return funcRef{}, false
		}
		p, ok := s.imports[id.Name]
		if !ok {
			return funcRef{}, false
		}
		return funcRef{pkg: p, name: x.Sel.Name}, true
	case *ast.Ident:
		return funcRef{pkg: s.file.pkgPath(), name: x.Name}, true
	case *ast.ParenExpr:
		return s.resolve(x.X)
	}
	return funcRef{}, false
}

// builders knows the handler builders and the service each one builds.
type builders map[funcRef]string

// of returns the service a call to fn builds, or "".
func (b builders) of(s guardScope, call *ast.CallExpr, fn funcRef) string {
	if name, ok := b[fn]; ok {
		return name
	}
	if m := generatedConnect.FindStringSubmatch(fn.pkg); m != nil {
		if h := handlerFunc.FindStringSubmatch(fn.name); h != nil {
			return "vca." + m[1] + ".v1." + h[1]
		}
	}
	if fn.pkg == connectPath && connectHandlers[fn.name] {
		return procedureService(s, call)
	}
	return ""
}

// procedureService reads the Connect service of the procedure that a
// connect-go handler takes as its first argument.
func procedureService(s guardScope, call *ast.CallExpr) string {
	const unknown = "a Connect service the guard cannot name"
	if len(call.Args) == 0 {
		return unknown
	}
	switch a := call.Args[0].(type) {
	case *ast.BasicLit:
		if p, err := strconv.Unquote(a.Value); err == nil {
			name, _, _ := strings.Cut(strings.TrimPrefix(p, "/"), "/")
			return name
		}
	case *ast.SelectorExpr:
		if ref, ok := s.resolve(a); ok {
			m, c := generatedConnect.FindStringSubmatch(ref.pkg), procedureConst.FindStringSubmatch(ref.name)
			if m != nil && c != nil {
				return "vca." + m[1] + ".v1." + c[1]
			}
		}
	}
	return unknown
}

// variadicOf returns the name of the variadic parameter of fn, or "".
func variadicOf(fn *ast.FuncDecl) string {
	params := fn.Type.Params.List
	if len(params) == 0 {
		return ""
	}
	last := params[len(params)-1]
	if _, ok := last.Type.(*ast.Ellipsis); !ok || len(last.Names) != 1 {
		return ""
	}
	return last.Names[0].Name
}

// forwards reports whether call passes the variadic parameter v of the
// function around it on: v... as an argument, or as the argument of
// connect.WithHandlerOptions.
func forwards(s guardScope, call *ast.CallExpr, v string) bool {
	if v == "" {
		return false
	}
	if call.Ellipsis != token.NoPos {
		if id, ok := call.Args[len(call.Args)-1].(*ast.Ident); ok && id.Name == v {
			return true
		}
	}
	for _, arg := range call.Args {
		inner, ok := arg.(*ast.CallExpr)
		if !ok || inner.Ellipsis == token.NoPos {
			continue
		}
		ref, ok := s.resolve(inner.Fun)
		if !ok || ref.pkg != connectPath || ref.name != "WithHandlerOptions" {
			continue
		}
		if id, ok := inner.Args[len(inner.Args)-1].(*ast.Ident); ok && id.Name == v {
			return true
		}
	}
	return false
}

// requiresPeer reports whether one argument of call is
// peerauth.Require(...) of internal/peerauth, under any import name.
func requiresPeer(s guardScope, call *ast.CallExpr) bool {
	for _, arg := range call.Args {
		inner, ok := arg.(*ast.CallExpr)
		if !ok {
			continue
		}
		if sel, ok := inner.Fun.(*ast.SelectorExpr); ok {
			if ref, ok := s.resolve(sel); ok && ref.pkg == peerauthPath && ref.name == "Require" {
				return true
			}
		}
	}
	return false
}

// findWrappers adds every function that calls a builder and forwards
// its own options, until no new one turns up.
func findWrappers(scopes []guardScope) builders {
	b := builders{}
	for changed := true; changed; {
		changed = false
		for _, s := range scopes {
			for _, decl := range s.file.file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil || fn.Recv != nil {
					continue
				}
				self := funcRef{pkg: s.file.pkgPath(), name: fn.Name.Name}
				if _, known := b[self]; known {
					continue
				}
				v := variadicOf(fn)
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					ref, ok := s.resolve(call.Fun)
					if !ok {
						return true
					}
					if name := b.of(s, call, ref); name != "" && forwards(s, call, v) {
						b[self] = name
						changed = true
						return false
					}
					return true
				})
			}
		}
	}
	return b
}

// scanPeerGuard returns the number of handler builds in the files and
// one line per build without the check.
func scanPeerGuard(files []guardFile) (int, []string) {
	scopes := make([]guardScope, 0, len(files))
	for _, g := range files {
		scopes = append(scopes, newScope(g))
	}
	b := findWrappers(scopes)
	found := 0
	var problems []string
	report := func(s guardScope, format string, args ...any) {
		problems = append(problems, s.file.rel+" "+fmt.Sprintf(format, args...))
	}
	for _, s := range scopes {
		for _, p := range s.dots {
			if generatedConnect.MatchString(p) || p == connectPath || p == peerauthPath || strings.HasPrefix(p, modulePath+"/services/internal/") {
				report(s, "dot imports %s, which hides the handlers it builds from the guard", p)
			}
		}
		for _, decl := range s.file.file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			v := ""
			var body ast.Node = decl
			if ok {
				v = variadicOf(fn)
				if fn.Body == nil {
					continue
				}
				body = fn.Body
			}
			called := map[ast.Expr]bool{}
			ast.Inspect(body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CallExpr:
					called[x.Fun] = true
					ref, resolved := s.resolve(x.Fun)
					if !resolved {
						return true
					}
					name := b.of(s, x, ref)
					if name == "" {
						return true
					}
					found++
					switch {
					case fn != nil && fn.Recv == nil && forwards(s, x, v):
						// A wrapper: the guard checks its callers.
					case requiresPeer(s, x):
					default:
						if _, public := checkedRPC[s.file.owner()+" "+name]; !public {
							report(s, "mounts %s without peerauth.Require (ADR-075)", name)
						}
					}
				case *ast.SelectorExpr:
					called[x.Sel] = true
					if !called[x] {
						if ref, ok := s.resolve(x); ok && b.of(s, &ast.CallExpr{}, ref) != "" {
							report(s, "takes the handler builder %s.%s as a value; call it with peerauth.Require", path.Base(ref.pkg), ref.name)
						}
					}
				case *ast.Ident:
					if !called[x] {
						if ref, ok := s.resolve(x); ok {
							if _, wrapper := b[ref]; wrapper && (fn == nil || fn.Name != x) {
								report(s, "takes the handler builder %s as a value; call it with peerauth.Require", ref.name)
							}
						}
					}
				}
				return true
			})
		}
	}
	sort.Strings(problems)
	return found, problems
}

// readGuardFiles parses every Go file of root that is not a test. It
// skips gen/, whose generated constructors the guard knows by name, and
// every testdata directory.
func readGuardFiles(t *testing.T, root string) []guardFile {
	t.Helper()
	fset := token.NewFileSet()
	var out []guardFile
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel := filepath.ToSlash(strings.TrimPrefix(p, root+string(filepath.Separator)))
		if d.IsDir() {
			if rel == "gen" || d.Name() == "testdata" || (strings.HasPrefix(d.Name(), ".") && p != root) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		out = append(out, guardFile{rel: rel, file: f})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestEveryConnectHandlerChecksItsCaller is ADR-075 decision 7: every
// Go file of vca/ that builds a Connect handler passes peerauth.Require
// to it, unless the proxy publishes that service and it checks the user
// instead (ADR-047). A wrapper forwards the options of its caller, and
// the guard checks each call of the wrapper.
func TestEveryConnectHandlerChecksItsCaller(t *testing.T) {
	root := filepath.Join("..", "..")
	found, problems := scanPeerGuard(readGuardFiles(t, root))
	for _, p := range problems {
		t.Error(p)
	}
	t.Logf("%d Connect handler builds checked", found)
	if found < 40 {
		t.Fatalf("found only %d Connect handler builds under %s", found, root)
	}
}
