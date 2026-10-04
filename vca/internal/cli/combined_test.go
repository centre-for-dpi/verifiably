// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	combinedv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/combined/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/combined/v1/combinedv1connect"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/peerauth"
)

// combinedStore stands in for the verifier-combined service: it keeps
// the templates it gets.
type combinedStore struct {
	combinedv1connect.UnimplementedCombinedServiceHandler
	mu        sync.Mutex
	templates []*combinedv1.CombinedTemplate
}

func (c *combinedStore) Create(_ context.Context, req *connect.Request[combinedv1.CreateRequest]) (*connect.Response[combinedv1.CreateResponse], error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := req.Msg.GetTemplate()
	if len(t.GetMembers()) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("a template names its members"))
	}
	if t.GetId() == "" {
		t.Id = "guardian-check"
	}
	c.templates = append(c.templates, t)
	return connect.NewResponse(&combinedv1.CreateResponse{Template: t}), nil
}

func (c *combinedStore) List(context.Context, *connect.Request[combinedv1.ListRequest]) (*connect.Response[combinedv1.ListResponse], error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return connect.NewResponse(&combinedv1.ListResponse{Templates: append([]*combinedv1.CombinedTemplate(nil), c.templates...)}), nil
}

func (c *combinedStore) Delete(_ context.Context, req *connect.Request[combinedv1.DeleteRequest]) (*connect.Response[combinedv1.DeleteResponse], error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, t := range c.templates {
		if t.GetId() == req.Msg.GetId() {
			c.templates = append(c.templates[:i], c.templates[i+1:]...)
			return connect.NewResponse(&combinedv1.DeleteResponse{}), nil
		}
	}
	return nil, connect.NewError(connect.CodeNotFound, errors.New("no such template"))
}

// verifierCombinedCallers returns the callers that the catalogue lists
// for the combined service.
func verifierCombinedCallers(t *testing.T) peerauth.Callers {
	t.Helper()
	for _, s := range Catalog() {
		if s.Name == "verifier-combined" {
			return s.Callers
		}
	}
	t.Fatal("the catalogue has no verifier-combined")
	return nil
}

// TestCombinedCommandsManageTheTemplatesOfThePair is ADR-078: the vca
// command is the caller of the combined service of a verifier pair. It
// signs with its identity of the deployment and reaches the service on
// its host port. The service takes the call because the catalogue lists
// the caller cli for it.
func TestCombinedCommandsManageTheTemplatesOfThePair(t *testing.T) {
	root := t.TempDir()
	deploy := filepath.Join(root, "deploy")
	if _, err := UpgradePeerIdentities(PeerUpgradeOptions{Deploy: deploy, Random: rand.Reader, Out: io.Discard}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(deploy, PeerDir, PeerAuthorityFile)) // #nosec G304 -- a test path
	if err != nil {
		t.Fatal(err)
	}
	authority, err := peerauth.ParseAuthority(raw)
	if err != nil {
		t.Fatal(err)
	}
	pair := Pair{Role: commonv1.Role_ROLE_VERIFIER, Dpg: configv1.Dpg_DPG_WALTID}
	callee, err := authority.Issue(peerauth.ID{Service: "verifier-combined", Pair: pair.Name()}, rand.Reader, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	callee.Callers = verifierCombinedCallers(t)
	store := &combinedStore{}
	mux := http.NewServeMux()
	srv := httptest.NewUnstartedServer(mux)
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	opts := CombinedOptions{
		Root: root, Pair: pair, Client: srv.Client(), Out: &out,
		Values: map[string]string{"VCA_HOST_PORT_VERIFIER_COMBINED": port},
	}
	// The combined service takes the token of the vca command at the
	// names of its host port, as setup writes them.
	callee.Hosts = PublishedHosts(pair, opts.Values, "verifier-combined")
	mux.Handle(combinedv1connect.NewCombinedServiceHandler(store, peerauth.Require(callee)))
	srv.Start()
	defer srv.Close()
	opts.Client = srv.Client()
	file := filepath.Join(root, "guardian.json")
	template := `{"displayName":"Guardian check","members":[{"templateId":"identity"},{"templateId":"delegation"}],` +
		`"rules":[{"kind":"CROSS_RULE_DELEGATION_LINK","params":{"subject":"identity","delegation":"delegation"}}]}`
	if err := os.WriteFile(file, []byte(template), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := CombinedCreate(ctx, opts, file); err != nil {
		t.Fatalf("CombinedCreate: %v", err)
	}
	if err := CombinedList(ctx, opts); err != nil {
		t.Fatalf("CombinedList: %v", err)
	}
	if err := CombinedDelete(ctx, opts, "guardian-check"); err != nil {
		t.Fatalf("CombinedDelete: %v", err)
	}
	if err := CombinedList(ctx, opts); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Stored the combined template guardian-check.", "guardian-check  Guardian check  2 members  1 rules",
		"Removed the combined template guardian-check.", "The pair verifier-waltid holds no combined template."} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the output has no %q:\n%s", want, out.String())
		}
	}
	// The command line reads the host port from the .env of the pair.
	if err := os.MkdirAll(OutputDir(deploy, pair), 0o750); err != nil {
		t.Fatal(err)
	}
	writeText(t, OutputDir(deploy, pair), EnvFileName, "VCA_HOST_PORT_VERIFIER_COMBINED="+port+"\n")
	env := Environment{Root: root, HTTP: srv.Client()}
	for _, args := range [][]string{
		{"combined", "create", "--dpg", "waltid", file},
		{"combined", "list", "--dpg", "waltid"},
		{"combined", "delete", "--dpg", "waltid", "guardian-check"},
	} {
		if text, err := runCLI(t, env, args...); err != nil {
			t.Fatalf("vca %s: %v\n%s", strings.Join(args, " "), err, text)
		}
	}
	for _, args := range [][]string{
		{"combined", "list", "--dpg", "nope"},
		{"combined", "create", "--dpg", "inji", file},
		{"combined", "delete", "--dpg", "credebl", "x"},
	} {
		if _, err := runCLI(t, env, args...); err == nil {
			t.Errorf("vca %s: no error", strings.Join(args, " "))
		}
	}
	if err := CombinedDelete(ctx, opts, ""); err == nil {
		t.Error("a delete with no id: no error")
	}
	// The refusals name what went wrong.
	for name, run := range map[string]func() error{
		"missing file":  func() error { return CombinedCreate(ctx, opts, filepath.Join(root, "none.json")) },
		"not JSON":      func() error { return CombinedCreate(ctx, opts, writeText(t, root, "bad.json", "{")) },
		"refused":       func() error { return CombinedCreate(ctx, opts, writeText(t, root, "empty.json", "{}")) },
		"unknown id":    func() error { return CombinedDelete(ctx, opts, "nothing") },
		"an issuer":     func() error { o := opts; o.Pair.Role = commonv1.Role_ROLE_ISSUER; return CombinedList(ctx, o) },
		"no deployment": func() error { o := opts; o.Root = t.TempDir(); return CombinedList(ctx, o) },
	} {
		if err := run(); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

// writeText writes one file under dir and returns its path.
func writeText(t *testing.T, dir, name, text string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
