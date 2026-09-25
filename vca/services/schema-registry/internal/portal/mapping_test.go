// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"connectrpc.com/connect"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/schema-registry/internal/record"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// postMapping posts the mapping form of one schema.
func postMapping(t *testing.T, h http.Handler, id string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/portal/schemas/"+id+"/mapping", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestMappingPageSaves checks the mapping page: it lists every claim of
// the version, refuses a context or a term that is not an absolute IRI
// with the reason next to the field, and saves a good mapping as the
// next draft version.
func TestMappingPageSaves(t *testing.T) {
	svc, id := registry(t)
	h := staffServer(t, svc, deployment(), nil)
	body := get(t, h, "/portal/schemas/"+id+"/mapping")
	for _, want := range []string{
		"https://www.w3.org/ns/credentials/v2", `name="contexts"`, `name="claim.0.name" value="name"`, `name="claim.1.name" value="age"`,
		`name="claim.0.iri"`, `name="claim.0.label.en"`, `value="Full name"`, `name="csrf_token" value="tok"`,
		msg.T("issuer.mapping.lead"),
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the mapping page lacks %q", want)
		}
	}
	// A bad context and a bad term stay on the page with the reasons.
	bad := url.Values{"version": {"1"}, "contexts": {"schema.org"}, "claim.0.name": {"name"}, "claim.0.iri": {"given name"}, "claim.0.label.en": {"Name"}}
	rec := postMapping(t, h, id, bad)
	if rec.Code != http.StatusOK {
		t.Fatalf("bad mapping: %d", rec.Code)
	}
	a11ytest.AssertPage(t, rec.Body.String())
	for _, want := range []string{msg.T("issuer.mapping.error.context", "schema.org"), `aria-invalid="true"`, msg.T("issuer.mapping.error.iri", "name"), `value="given name"`} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("the refused page lacks %q", want)
		}
	}
	if versions, verr := svc.ListVersions(context.Background(), connect.NewRequest(&schemav1.ListVersionsRequest{Id: id})); verr != nil || len(versions.Msg.GetSchemas()) != 1 {
		t.Fatalf("a refused mapping made a version: %v", verr)
	}
	good := url.Values{
		"version":      {"1"},
		"contexts":     {"https://w3id.org/citizenship/v1\r\n\r\nhttps://schema.org/\n"},
		"claim.0.name": {"name"}, "claim.0.iri": {"https://schema.org/name"}, "claim.0.label.en": {"Name"}, "claim.0.description.en": {"The name on the card"},
		"claim.1.name": {"age"}, "claim.1.iri": {""}, "claim.1.label.en": {""},
	}
	rec = postMapping(t, h, id, good)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/portal/schemas/"+id+"?version=2&notice=mapped" {
		t.Fatalf("save: %d %q %s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	got, err := svc.Get(context.Background(), connect.NewRequest(&schemav1.GetRequest{Id: id, Version: 2}))
	if err != nil {
		t.Fatal(err)
	}
	m := got.Msg.GetSchema()
	if len(m.GetContexts()) != 2 || m.GetContexts()[1] != "https://schema.org/" || len(m.GetClaimMappings()) != 1 ||
		m.GetClaimMappings()[0].GetIri() != "https://schema.org/name" || m.GetClaimMappings()[0].GetLabels()[0].GetDescription() != "The name on the card" {
		t.Fatalf("saved %v", m)
	}
	if m.GetType() != "UniversityDegree" || len(m.GetSdClaims()) != 1 || m.GetState() != schemav1.State_STATE_DRAFT {
		t.Fatalf("the new version lost a field: %v", m)
	}
	// The next visit shows the saved mapping, and the detail says so.
	body = get(t, h, "/portal/schemas/"+id+"/mapping?version=2")
	if !strings.Contains(body, "https://w3id.org/citizenship/v1\nhttps://schema.org/") || !strings.Contains(body, `value="https://schema.org/name"`) {
		t.Fatal("the mapping page does not show the saved mapping")
	}
	detail := get(t, h, rec.Header().Get("Location"))
	if !strings.Contains(detail, msg.T("issuer.mapping.saved")) || !strings.Contains(detail, `href="/portal/schemas/`+id+`/mapping?version=2"`) {
		t.Fatal("the detail has no notice or no mapping link")
	}
	// The row of the schema links to the mapping page.
	if !strings.Contains(row(t, get(t, h, "/portal/"), id), msg.T("issuer.schemas.action.mapping.label")) {
		t.Fatal("the row has no mapping action")
	}
	if rec := httptest.NewRecorder(); true {
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/portal/schemas/ghost/mapping", nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("missing schema: %d", rec.Code)
		}
	}
}

// updateFails wraps the service and fails Update with err.
type updateFails struct {
	broken
	err error
}

func (u updateFails) Update(context.Context, *connect.Request[schemav1.UpdateRequest]) (*connect.Response[schemav1.UpdateResponse], error) {
	return nil, u.err
}

// TestMappingPageAnswers checks the answers of the mapping form when the
// request or the registry fails, and the page of a version with two
// display locales and a mapping for one of them.
func TestMappingPageAnswers(t *testing.T) {
	svc, id := registry(t)
	good := url.Values{"version": {"1"}, "claim.0.name": {"name"}, "claim.0.label.en": {"Name"}}
	if rec := postMapping(t, staffServer(t, svc, nil, nil), id, url.Values{"version": {"x"}}); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad version: %d", rec.Code)
	}
	if rec := postMapping(t, staffServer(t, svc, nil, nil), "ghost", good); rec.Code != http.StatusNotFound {
		t.Fatalf("missing schema: %d", rec.Code)
	}
	refused := connect.NewError(connect.CodeInvalidArgument, errors.New("the registry refused it"))
	rec := postMapping(t, clientServer(t, Options{Client: updateFails{broken: broken{Service: svc}, err: refused}}), id, good)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "the registry refused it") {
		t.Fatalf("refused: %d", rec.Code)
	}
	down := connect.NewError(connect.CodeUnavailable, errors.New("down"))
	if rec := postMapping(t, clientServer(t, Options{Client: updateFails{broken: broken{Service: svc}, err: down}}), id, good); rec.Code != http.StatusInternalServerError {
		t.Fatalf("down: %d", rec.Code)
	}
	// Two locales: the mapping fills one, the title fills the other.
	up, err := svc.Update(context.Background(), connect.NewRequest(&schemav1.UpdateRequest{Schema: &schemav1.Schema{
		Id: id, Type: "UniversityDegree", JsonSchema: doc, Formats: []commonv1.Format{commonv1.Format_FORMAT_LDP_VC},
		Display:       []*schemav1.Display{{Name: "Degree", Locale: "en"}, {Name: "Shahada", Locale: "sw"}, {Name: "Again", Locale: "en"}},
		ClaimMappings: []*schemav1.ClaimMapping{{Claim: "name", Labels: []*schemav1.ClaimLabel{{Locale: "sw", Label: "Jina"}}}},
	}}))
	if err != nil {
		t.Fatal(err)
	}
	body := get(t, staffServer(t, svc, nil, nil), "/portal/schemas/"+id+"/mapping?version="+strconv.Itoa(int(up.Msg.GetSchema().GetVersion())))
	for _, want := range []string{`name="claim.0.label.sw" value="Jina"`, `name="claim.0.label.en" value=""`, `name="claim.1.label.sw" value="age"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	if strings.Count(body, `name="claim.0.label.en"`) != 1 {
		t.Fatal("a locale shows twice")
	}
	if claimType(record.Record{JSONSchema: doc}, "ghost") != "" {
		t.Fatal("the type of a missing claim")
	}
}
