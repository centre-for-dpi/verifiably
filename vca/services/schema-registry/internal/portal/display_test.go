// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
)

// cardSVG is the SVG template of the test stack.
const cardSVG = `<svg xmlns="http://www.w3.org/2000/svg" width="340" height="214"><rect width="340" height="214"/></svg>`

// fakeCatalog answers GetIssuerMetadata as the adapter of the pair.
type fakeCatalog struct {
	configs []*backendv1.CredentialConfiguration
	err     error
	calls   int
}

func (f *fakeCatalog) GetIssuerMetadata(context.Context, *connect.Request[backendv1.GetIssuerMetadataRequest]) (
	*connect.Response[backendv1.GetIssuerMetadataResponse], error,
) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return connect.NewResponse(&backendv1.GetIssuerMetadataResponse{Configurations: f.configs}), nil
}

// catalogServer wires the portal with a catalog over one live stack.
func catalogServer(t *testing.T, catalog Catalog) http.Handler {
	t.Helper()
	svc, id := registry(t)
	if _, err := svc.Publish(context.Background(), connect.NewRequest(&schemav1.PublishRequest{Id: id})); err != nil {
		t.Fatal(err)
	}
	p, err := New(Options{Client: svc, Catalog: catalog, Shell: shellOf(stack{dpg: configv1.Dpg_DPG_INJI, name: secondStack,
		state: topology.Live, features: configAPI, formats: []commonv1.Format{commonv1.Format_FORMAT_DC_SD_JWT}})})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	p.Register(mux)
	sess := staffsession.Session{Subject: "kc|wanjiru", Name: "Wanjiru Kamau", CSRF: "tok"}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(w, r.WithContext(staffsession.With(r.Context(), sess)))
	})
}

// TestSvgTemplateShown shows the display entries of a version, and the
// SVG card template of the stack when its adapter returns one for the
// type. The template goes in as an image, so no script of the stack runs
// in the page.
func TestSvgTemplateShown(t *testing.T) {
	catalog := &fakeCatalog{configs: []*backendv1.CredentialConfiguration{
		{Id: "Other", Type: "Other", RenderTemplates: []*backendv1.RenderTemplate{{Url: "https://stack.example/other", Content: cardSVG}}},
		{Id: "UniversityDegree_dc+sd-jwt", Type: "UniversityDegree", RenderTemplates: []*backendv1.RenderTemplate{{
			Url: "https://stack.example/v1/certify/rendering-template/degree-card", MediaType: "image/svg+xml", Content: cardSVG, Name: "Degree",
		}}},
	}}
	doc := get(t, catalogServer(t, catalog), "/portal/schemas/degree-a")
	src := "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(cardSVG))
	for _, want := range []string{
		msg.T("issuer.schemas.display.title.label"), "Degree", `src="` + src + `"`,
		`href="https://stack.example/v1/certify/rendering-template/degree-card"`,
		msg.T("issuer.schemas.display.render.alt", "Degree", secondStack),
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("the detail lacks %q", want)
		}
	}
	if strings.Contains(doc, "https://stack.example/other") || strings.Contains(doc, "<rect") {
		t.Error("the page shows the template of another type, or inlines the SVG")
	}

	none := &fakeCatalog{configs: []*backendv1.CredentialConfiguration{{Id: "UniversityDegree_dc+sd-jwt", Type: "UniversityDegree"}}}
	doc = get(t, catalogServer(t, none), "/portal/schemas/degree-a")
	if strings.Contains(doc, "data:image/svg+xml") || !strings.Contains(doc, msg.T("issuer.schemas.display.title.label")) {
		t.Error("a stack without a template shows one, or the display block is gone")
	}
	down := &fakeCatalog{err: errors.New("down")}
	if doc = get(t, catalogServer(t, down), "/portal/schemas/degree-a"); strings.Contains(doc, "data:image/svg+xml") {
		t.Error("a failed catalogue shows a template")
	}
	if doc = get(t, catalogServer(t, nil), "/portal/schemas/degree-a"); strings.Contains(doc, "data:image/svg+xml") {
		t.Error("a portal without a catalogue shows a template")
	}
}

// TestSvgTemplateOnlyForAPublishedVersion leaves a draft without the
// stack call: the stack holds no configuration of a draft.
func TestSvgTemplateOnlyForAPublishedVersion(t *testing.T) {
	svc, id := registry(t)
	catalog := &fakeCatalog{}
	p, err := New(Options{Client: svc, Catalog: catalog})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	p.Register(mux)
	doc := get(t, mux, "/portal/schemas/"+id)
	if catalog.calls != 0 || !strings.Contains(doc, msg.T("issuer.schemas.display.title.label")) {
		t.Fatalf("calls %d", catalog.calls)
	}
}
