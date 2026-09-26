// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
)

// issuerDisplay reads the display of the one issuer of a holder plan.
func issuerDisplay(t *testing.T, plan Plan) mimotoDisplay {
	t.Helper()
	var doc struct {
		Issuers []mimotoIssuer `json:"issuers"`
	}
	if err := json.Unmarshal(sharedFile(t, plan, filepath.Join(MimotoDir, MimotoIssuersFile)).Data, &doc); err != nil || len(doc.Issuers) != 1 {
		t.Fatalf("issuers = %v %v", doc, err)
	}
	if len(doc.Issuers[0].Display) != 1 {
		t.Fatalf("display = %v", doc.Issuers[0].Display)
	}
	return doc.Issuers[0].Display[0]
}

// TestMimotoIssuerListNamesTheIssuerIdentity is plan N8: Inji Web shows
// the issuer as the issuer described itself in its identity. Before the
// issuer sets one, the display names the host of the issuer pair.
func TestMimotoIssuerListNamesTheIssuerIdentity(t *testing.T) {
	holder := injiPair(commonv1.Role_ROLE_HOLDER)
	before := issuerDisplay(t, planOf(t, SetupRequest{Pair: holder, Domain: "labs.example"}))
	if before.Name != "Issuer of issuer-inji.labs.example" || !strings.Contains(before.Description, before.Name) {
		t.Errorf("the display before an identity = %+v", before)
	}
	named := issuerDisplay(t, planOf(t, SetupRequest{Pair: holder, Domain: "labs.example",
		InjiIssuer: InjiIssuerIdentity{DisplayName: "[ISSUER NAME]"}}))
	if named.Name != "[ISSUER NAME]" || named.Title != "[ISSUER NAME]" || named.Language != "en" ||
		!strings.Contains(named.Description, "[ISSUER NAME]") || named.Logo.AltText != "The logo of [ISSUER NAME]" {
		t.Errorf("the display with an identity = %+v", named)
	}
	if strings.Contains(strings.ToLower(named.Name+named.Title+named.Description), "inji") ||
		strings.Contains(before.Name+before.Description, "Certify") {
		t.Errorf("the display names the stack, not the issuer: %+v %+v", before, named)
	}
}

// TestMimotoIssuerListLogoIsServedByVca is plan N8: the logo of the
// issuer is the logo route of the issuer pair when the theme has a
// logo, else an inline image of the wordmark. No remote demo asset.
func TestMimotoIssuerListLogoIsServedByVca(t *testing.T) {
	holder := injiPair(commonv1.Role_ROLE_HOLDER)
	themed := issuerDisplay(t, planOf(t, SetupRequest{Pair: holder, Domain: "labs.example",
		Brand: InjiBrand{LogoFile: "logo.svg", Wordmark: "VCA"}}))
	if themed.Logo.URL != "https://issuer-inji.labs.example/static/logo.svg" {
		t.Errorf("the themed logo = %q", themed.Logo.URL)
	}
	plain := issuerDisplay(t, planOf(t, SetupRequest{Pair: holder, Domain: "labs.example"}))
	data, ok := strings.CutPrefix(plain.Logo.URL, "data:image/svg+xml;base64,")
	if !ok {
		t.Fatalf("the default logo = %q, want an inline SVG", plain.Logo.URL)
	}
	svg, err := base64.StdEncoding.DecodeString(data)
	if err != nil || !strings.Contains(string(svg), ">VCA</text>") {
		t.Fatalf("the default logo = %s %v", svg, err)
	}
	word := issuerDisplay(t, planOf(t, SetupRequest{Pair: holder, Brand: InjiBrand{Wordmark: `A<b>&"`}}))
	svg = anyval.OrZero(base64.StdEncoding.DecodeString(strings.TrimPrefix(word.Logo.URL, "data:image/svg+xml;base64,")))
	if strings.Contains(string(svg), "<b>") {
		t.Errorf("the wordmark reaches the SVG unescaped: %s", svg)
	}
	for _, f := range planOf(t, SetupRequest{Pair: holder}).Shared {
		if strings.Contains(string(f.Data), "github.io") {
			t.Errorf("%s names github.io", f.Name)
		}
	}
	template, err := os.ReadFile(filepath.Join(repoRoot(), "deploy", "vca", "dpg", "inji", "mimoto", "credential-template.html"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(template), "https://") || !strings.Contains(string(template), "data:image/svg+xml") {
		t.Error("the credential template loads a remote icon")
	}
}

// identityAdapter answers GetIssuerIdentity as the Inji adapter does.
type identityAdapter struct {
	backendv1connect.UnimplementedIssuerBackendServiceHandler
	identity *backendv1.IssuerIdentity
	err      error
}

func (a identityAdapter) GetIssuerIdentity(context.Context, *connect.Request[backendv1.GetIssuerIdentityRequest]) (*connect.Response[backendv1.GetIssuerIdentityResponse], error) {
	if a.err != nil {
		return nil, a.err
	}
	return connect.NewResponse(&backendv1.GetIssuerIdentityResponse{Identity: a.identity}), nil
}

// TestApplyInjiRewritesAndRestartsHolderContainers is plan N8: vca dpg
// apply inji reads the issuer identity from the adapter of the issuer
// pair, keeps it beside the pair, rewrites the display of the Mimoto
// issuer list, and restarts Mimoto and Inji Web.
func TestApplyInjiRewritesAndRestartsHolderContainers(t *testing.T) {
	repo := t.TempDir()
	deploy := filepath.Join(repo, "deploy")
	holder := injiPair(commonv1.Role_ROLE_HOLDER)
	plan := planOf(t, SetupRequest{Pair: holder, Domain: "labs.example"})
	for _, f := range append(plan.Shared, plan.Files...) {
		dir := deploy
		if f.Name == EnvFileName {
			dir = OutputDir(deploy, holder)
		}
		path := filepath.Join(dir, f.Name)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, f.Data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mux := http.NewServeMux()
	adapter := &identityAdapter{identity: &backendv1.IssuerIdentity{
		Identifiers: []string{"did:web:issuer-inji.labs.example"},
		Metadata:    &backendv1.IssuerIdentity_Metadata{DisplayName: "[ISSUER NAME]", LegalIdentifier: "[REGISTRATION NUMBER]"},
	}}
	mux.Handle(backendv1connect.NewIssuerBackendServiceHandler(adapter))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	rec := &recorder{}
	var out strings.Builder
	opts := ApplyOptions{Root: repo, Values: map[string]string{EnvBootstrapAdapterURL: srv.URL}, Client: srv.Client(), Out: &out, Run: rec.run,
		Brand: InjiBrand{LogoFile: "logo.png"}}
	if err := DpgApplyInji(context.Background(), opts); err != nil {
		t.Fatalf("apply: %v\n%s", err, out.String())
	}
	var kept InjiIssuerIdentity
	raw, err := os.ReadFile(filepath.Join(OutputDir(deploy, injiIssuer), InjiIdentityFile)) // #nosec G304 -- a test path
	if err != nil || json.Unmarshal(raw, &kept) != nil || kept.DisplayName != "[ISSUER NAME]" {
		t.Fatalf("identity file = %s %v", raw, err)
	}
	issuers, err := os.ReadFile(filepath.Join(deploy, MimotoDir, MimotoIssuersFile)) // #nosec G304 -- a test path
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Issuers []mimotoIssuer `json:"issuers"`
	}
	if err := json.Unmarshal(issuers, &doc); err != nil || len(doc.Issuers) != 1 {
		t.Fatalf("issuers = %s %v", issuers, err)
	}
	got := doc.Issuers[0]
	if got.Display[0].Name != "[ISSUER NAME]" || got.Display[0].Logo.URL != "https://issuer-inji.labs.example/static/logo.png" ||
		got.RedirectURI != "https://inji-web.labs.example/redirect" {
		t.Errorf("the rewritten issuer = %+v", got)
	}
	if len(rec.calls) != 1 {
		t.Fatalf("runs = %v", rec.calls)
	}
	call := strings.Join(rec.calls[0], " ")
	if !strings.Contains(call, "--profile holder-inji restart inji-mimoto inji-web") {
		t.Errorf("the restart = %q", call)
	}

	// Without a holder pair the run keeps the identity and restarts
	// nothing. An adapter that fails stops the run.
	if err := os.RemoveAll(OutputDir(deploy, holder)); err != nil {
		t.Fatal(err)
	}
	rec.calls = nil
	if err := DpgApplyInji(context.Background(), opts); err != nil || len(rec.calls) != 0 {
		t.Fatalf("without a holder: %v %v", err, rec.calls)
	}
	adapter.err = connect.NewError(connect.CodeUnavailable, errors.New("down"))
	if err := DpgApplyInji(context.Background(), opts); err == nil {
		t.Fatal("a failed adapter passed")
	}
}
