// SPDX-License-Identifier: Apache-2.0

package inji

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// answerWith serves one body with a status for every call.
func answerWith(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		mustWrite(t, w, []byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestConfigurationCallsReadTheErrorBody(t *testing.T) {
	ctx := context.Background()
	notFound := `{"errors":[{"errorCode":"config_not_found_by_id","errorMessage":"no"}]}`
	c := NewCertify(newHTTP(answerWith(t, 200, notFound)), "")
	if _, err := c.GetConfiguration(ctx, "x"); !errors.Is(err, ErrConfigNotFound) {
		t.Fatalf("an errors body with the not found code: %v", err)
	}
	c = NewCertify(newHTTP(answerWith(t, 404, "")), "")
	if _, err := c.GetConfiguration(ctx, "x"); !errors.Is(err, ErrConfigNotFound) {
		t.Fatalf("a 404: %v", err)
	}
	c = NewCertify(newHTTP(answerWith(t, 200, `{"errors":[{"errorCode":"config_not_active","errorMessage":"off"}]}`)), "")
	if _, err := c.GetConfiguration(ctx, "x"); !IsAPIError(err, "config_not_active") || !strings.Contains(err.Error(), "off") {
		t.Fatalf("another code: %v", err)
	}
	c = NewCertify(newHTTP(answerWith(t, 500, "")), "")
	if _, err := c.GetConfiguration(ctx, "x"); err == nil || IsAPIError(err, "") {
		t.Fatalf("a server error: %v", err)
	}
	c = NewCertify(newHTTP(answerWith(t, 200, "[")), "")
	if _, err := c.GetConfiguration(ctx, "x"); err == nil {
		t.Fatal("a broken body passed")
	}
	if _, err := c.CreateConfiguration(ctx, ConfigurationDTO{}); err == nil {
		t.Fatal("a broken write answer passed")
	}
	c = NewCertify(newHTTP(answerWith(t, 200, `{"errors":[{"errorCode":"config_not_found_for_update","errorMessage":"no"}]}`)), "")
	if _, err := c.UpdateConfiguration(ctx, "x", ConfigurationDTO{}); !errors.Is(err, ErrConfigNotFound) {
		t.Fatalf("an update of an unknown id: %v", err)
	}
	c = NewCertify(newHTTP(answerWith(t, 200, `{"errors":[{"errorCode":"unsupported_format","errorMessage":"no"}]}`)), "")
	if _, err := c.CreateConfiguration(ctx, ConfigurationDTO{}); !IsAPIError(err, "unsupported_format") {
		t.Fatalf("a refused create: %v", err)
	}
	c = NewCertify(newHTTP(answerWith(t, 500, "")), "")
	if _, err := c.CreateConfiguration(ctx, ConfigurationDTO{}); err == nil {
		t.Fatal("a server error passed")
	}
	c = NewCertify(newHTTP(answerWith(t, 201, `{"status":"active"}`)), "")
	out, err := c.CreateConfiguration(ctx, ConfigurationDTO{CredentialConfigKeyID: "kept"})
	if err != nil || out.ID != "kept" {
		t.Fatalf("an answer without an id keeps the sent id: %+v %v", out, err)
	}
	var none *Certify
	if _, err := none.GetConfiguration(ctx, "x"); !errors.Is(err, ErrNoCertify) {
		t.Fatal(err)
	}
	if _, err := none.CreateConfiguration(ctx, ConfigurationDTO{}); !errors.Is(err, ErrNoCertify) {
		t.Fatal(err)
	}
}

func TestBuildConfigurationChecksItsInput(t *testing.T) {
	schema := `{"type":"object","properties":{"name":{"type":"string"}}}`
	cases := []ConfigInput{
		{ID: "x", Format: "jwt_vc_json", Type: "X", JSONSchema: schema},
		{ID: "x", Format: "ldp_vc", Type: "X", JSONSchema: `{"type":"object"}`},
		{ID: "x", Format: "ldp_vc", Type: "X", JSONSchema: "nope"},
	}
	for _, in := range cases {
		if _, err := BuildConfiguration(in, DefaultProfiles()); err == nil {
			t.Errorf("%+v passed", in)
		}
	}
	dto, err := BuildConfiguration(ConfigInput{ID: "x", Format: "ldp_vc", Type: "X", JSONSchema: schema,
		Display:  `[{"name":"A","locale":"en","logo":{"url":"https://l"}},{"name":"B","locale":"fr"},{"name":"C","locale":"en"}]`,
		Contexts: []string{" ", VCDMContext, "https://c"}}, Profiles{DidURL: "did:web:x", Ldp: SigningProfile{CryptoSuite: "DataIntegrityProof"}})
	if err != nil {
		t.Fatal(err)
	}
	if dto.DidURL != "did:web:x" || len(dto.ContextURLs) != 2 || dto.MetaDataDisplay[0].Logo.URL != "https://l" {
		t.Fatalf("%+v", dto)
	}
	if got := dto.CredentialSubjectDefinition["name"].Display; len(got) != 2 {
		t.Fatalf("one label per locale: %+v", got)
	}
	dto, err = BuildConfiguration(ConfigInput{ID: "x", Format: "ldp_vc", Type: "X", JSONSchema: schema, Display: "[broken"}, DefaultProfiles())
	if err != nil || dto.MetaDataDisplay[0].Name != "X" || dto.MetaDataDisplay[0].Locale != "en" {
		t.Fatalf("a broken display falls back to the type: %+v %v", dto.MetaDataDisplay, err)
	}
	if _, err := DecodeTemplate("%%%"); err == nil {
		t.Fatal("a broken template decoded")
	}
}

func TestJwsSuitesCarryTheirContext(t *testing.T) {
	schema := `{"type":"object","properties":{"name":{"type":"string"}}}`
	for suite, want := range map[string]string{
		"Ed25519Signature2018": "https://w3id.org/security/suites/ed25519-2018/v1",
		"RsaSignature2018":     "https://w3id.org/security/v2",
		"DataIntegrityProof":   "",
	} {
		p := DefaultProfiles()
		p.Ldp.CryptoSuite = suite
		dto, err := BuildConfiguration(ConfigInput{ID: "x", Format: "ldp_vc", Type: "X", JSONSchema: schema}, p)
		if err != nil {
			t.Fatal(err)
		}
		last := dto.ContextURLs[len(dto.ContextURLs)-1]
		if (want == "" && last != VCDMContext) || (want != "" && last != want) {
			t.Errorf("%s: contexts %v", suite, dto.ContextURLs)
		}
	}
}

func TestMdocNamespaceAndTemplate(t *testing.T) {
	if MdocNamespace("org.iso.18013.5.1.mDL") != "org.iso.18013.5.1" || MdocNamespace("org.example.degree") != "org.example.degree" ||
		MdocNamespace(".mDL") != ".mDL" {
		t.Fatal("namespace")
	}
	dto, err := BuildConfiguration(ConfigInput{ID: "x", Format: "mso_mdoc", Type: "org.example.degree",
		JSONSchema: `{"type":"object","properties":{"name":{"type":"string"},"age":{"type":"integer"}}}`}, DefaultProfiles())
	if err != nil {
		t.Fatal(err)
	}
	tmpl, err := DecodeTemplate(dto.VcTemplate)
	if err != nil || !strings.Contains(tmpl, `"elementValue": ${age}`) || !strings.Contains(tmpl, `"digestId": 1`) {
		t.Fatalf("template %s %v", tmpl, err)
	}
}

func TestRenderingTemplateReadsAnSvg(t *testing.T) {
	ctx := context.Background()
	if got := RenderRefs(`"id": "https://c.example/v1/certify/rendering-template/card-1"}, {"id": "https://c.example/v1/certify/rendering-template/card-1"`); len(got) != 1 || got[0] != "card-1" {
		t.Fatalf("refs %v", got)
	}
	if RenderingTemplateURL("https://c.example/", "a b") != "https://c.example/v1/certify/rendering-template/a%20b" {
		t.Fatal(RenderingTemplateURL("https://c.example/", "a b"))
	}
	c := NewCertify(newHTTP(answerWith(t, 200, `<svg xmlns="http://www.w3.org/2000/svg"/>`)), "")
	if svg, err := c.RenderingTemplate(ctx, "card"); err != nil || !strings.HasPrefix(svg, "<svg") {
		t.Fatalf("%q %v", svg, err)
	}
	c = NewCertify(newHTTP(answerWith(t, 200, `{"not":"svg"}`)), "")
	if _, err := c.RenderingTemplate(ctx, "card"); err == nil {
		t.Fatal("a JSON answer passed as an SVG")
	}
	c = NewCertify(newHTTP(answerWith(t, 200, "<svg>"+strings.Repeat("x", MaxRenderBytes)+"</svg>")), "")
	if _, err := c.RenderingTemplate(ctx, "card"); !errors.Is(err, ErrRenderTooLarge) {
		t.Fatalf("a large template: %v", err)
	}
	c = NewCertify(newHTTP(answerWith(t, 404, "")), "")
	if _, err := c.RenderingTemplate(ctx, "card"); err == nil {
		t.Fatal("a 404 passed")
	}
	var none *Certify
	if _, err := none.RenderingTemplate(ctx, "card"); !errors.Is(err, ErrNoCertify) {
		t.Fatal(err)
	}
}
