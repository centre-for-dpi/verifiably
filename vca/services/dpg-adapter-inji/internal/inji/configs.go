// SPDX-License-Identifier: Apache-2.0

package inji

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/centre-for-dpi/vc-adapters/core/jsonschema"
	"github.com/centre-for-dpi/vc-adapters/services/internal/dpgclient"
)

// The credential configuration API of Inji Certify 0.14.0.
//
//   - POST /v1/certify/credential-configurations creates one entry.
//   - GET /v1/certify/credential-configurations/{id} reads one entry.
//   - PUT /v1/certify/credential-configurations/{id} replaces one entry.
//
// Certify builds its OID4VCI issuer metadata from these entries, so a
// wallet sees a new entry at once.
const configurationsPath = "/v1/certify/credential-configurations"

// The Certify error codes the adapter tells apart.
const (
	// CodeConfigNotFound reports a read of an unknown entry.
	CodeConfigNotFound = "config_not_found_by_id"
	// CodeConfigNotFoundForUpdate reports an update of an unknown entry.
	CodeConfigNotFoundForUpdate = "config_not_found_for_update"
)

// ErrConfigNotFound reports that Certify holds no entry with the id.
var ErrConfigNotFound = errors.New("inji: Certify holds no credential configuration with this id")

// APIError is an error that an internal controller of Certify returned.
// Those controllers answer with the status 200 and an errors array.
type APIError struct {
	// Code is the Certify error code, such as ldp_vc_config_exists.
	Code string
	// Message is the Certify error text.
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("inji: Certify answered %s: %s", e.Code, e.Message)
}

// IsAPIError reports whether err is an APIError with the code.
func IsAPIError(err error, code string) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Code == code
}

// apiErrors is the error body of an internal controller.
type apiErrors struct {
	Errors []struct {
		ErrorCode    string `json:"errorCode"`
		ErrorMessage string `json:"errorMessage"`
	} `json:"errors"`
}

// errorOf returns the first error of an internal controller answer, or
// nil when the body carries none.
func errorOf(body []byte) error {
	var out apiErrors
	// A body that is not an error object, such as an array, is an answer.
	if json.Unmarshal(body, &out) == nil && len(out.Errors) > 0 {
		return &APIError{Code: out.Errors[0].ErrorCode, Message: out.Errors[0].ErrorMessage}
	}
	return nil
}

// Display is one entry of metaDataDisplay.
type Display struct {
	Name            string       `json:"name,omitempty"`
	Locale          string       `json:"locale,omitempty"`
	Logo            *DisplayLogo `json:"logo,omitempty"`
	BackgroundColor string       `json:"background_color,omitempty"`
	TextColor       string       `json:"text_color,omitempty"`
	BackgroundImage *DisplayURI  `json:"background_image,omitempty"`
}

// DisplayLogo is the logo of a display entry.
type DisplayLogo struct {
	URL     string `json:"url,omitempty"`
	AltText string `json:"alt_text,omitempty"`
}

// DisplayURI is an image of a display entry.
type DisplayURI struct {
	URI string `json:"uri,omitempty"`
}

// ClaimDisplay names one claim for a wallet.
type ClaimDisplay struct {
	Display []ClaimLabel `json:"display"`
}

// ClaimLabel is the name of a claim in one locale.
type ClaimLabel struct {
	Name   string `json:"name"`
	Locale string `json:"locale,omitempty"`
}

// ConfigurationDTO is the body of the credential configuration API.
type ConfigurationDTO struct {
	VcTemplate                  string                             `json:"vcTemplate,omitempty"`
	CredentialConfigKeyID       string                             `json:"credentialConfigKeyId,omitempty"`
	ContextURLs                 []string                           `json:"contextURLs,omitempty"`
	CredentialTypes             []string                           `json:"credentialTypes,omitempty"`
	CredentialFormat            string                             `json:"credentialFormat"`
	DidURL                      string                             `json:"didUrl,omitempty"`
	KeyManagerAppID             string                             `json:"keyManagerAppId,omitempty"`
	KeyManagerRefID             string                             `json:"keyManagerRefId,omitempty"`
	SignatureAlgo               string                             `json:"signatureAlgo,omitempty"`
	SignatureCryptoSuite        string                             `json:"signatureCryptoSuite,omitempty"`
	SdClaim                     string                             `json:"sdClaim,omitempty"`
	MetaDataDisplay             []Display                          `json:"metaDataDisplay"`
	DisplayOrder                []string                           `json:"displayOrder,omitempty"`
	Scope                       string                             `json:"scope"`
	CredentialSubjectDefinition map[string]ClaimDisplay            `json:"credentialSubjectDefinition,omitempty"`
	MsoMdocClaims               map[string]map[string]ClaimDisplay `json:"msoMdocClaims,omitempty"`
	SdJwtClaims                 map[string]ClaimDisplay            `json:"sdJwtClaims,omitempty"`
	DocType                     string                             `json:"doctype,omitempty"`
	SdJwtVct                    string                             `json:"sdJwtVct,omitempty"`
	CredentialStatusPurposes    []string                           `json:"credentialStatusPurposes,omitempty"`
}

// ConfigResponse is the answer of a create or an update.
type ConfigResponse struct {
	// ID is the credential configuration id.
	ID string `json:"id"`
	// Status is the state of the entry, such as active.
	Status string `json:"status"`
}

// GetConfiguration reads one entry. It returns ErrConfigNotFound when
// Certify holds no entry with the id.
func (c *Certify) GetConfiguration(ctx context.Context, id string) (ConfigurationDTO, error) {
	if c == nil {
		return ConfigurationDTO{}, ErrNoCertify
	}
	resp, err := c.client.Do(ctx, dpgclient.Request{
		Method: http.MethodGet, Path: configurationsPath + "/" + url.PathEscape(id), Accept: "application/json",
	})
	if dpgclient.IsStatus(err, http.StatusNotFound) {
		return ConfigurationDTO{}, ErrConfigNotFound
	}
	if err != nil {
		return ConfigurationDTO{}, err
	}
	if aerr := errorOf(resp.Body); aerr != nil {
		if IsAPIError(aerr, CodeConfigNotFound) {
			return ConfigurationDTO{}, ErrConfigNotFound
		}
		return ConfigurationDTO{}, aerr
	}
	var out ConfigurationDTO
	if err := json.Unmarshal(resp.Body, &out); err != nil {
		return ConfigurationDTO{}, fmt.Errorf("inji: read the credential configuration: %w", err)
	}
	return out, nil
}

// CreateConfiguration adds one entry.
func (c *Certify) CreateConfiguration(ctx context.Context, dto ConfigurationDTO) (ConfigResponse, error) {
	return c.writeConfiguration(ctx, http.MethodPost, configurationsPath, dto)
}

// UpdateConfiguration replaces the entry with the id.
func (c *Certify) UpdateConfiguration(ctx context.Context, id string, dto ConfigurationDTO) (ConfigResponse, error) {
	return c.writeConfiguration(ctx, http.MethodPut, configurationsPath+"/"+url.PathEscape(id), dto)
}

// writeConfiguration sends a create or an update.
func (c *Certify) writeConfiguration(ctx context.Context, method, path string, dto ConfigurationDTO) (ConfigResponse, error) {
	if c == nil {
		return ConfigResponse{}, ErrNoCertify
	}
	raw, err := json.Marshal(dto)
	if err != nil {
		return ConfigResponse{}, fmt.Errorf("inji: encode the credential configuration: %w", err)
	}
	resp, err := c.client.Do(ctx, dpgclient.Request{
		Method: method, Path: path, Body: raw, ContentType: "application/json", Accept: "application/json",
	})
	if err != nil {
		return ConfigResponse{}, err
	}
	if aerr := errorOf(resp.Body); aerr != nil {
		if IsAPIError(aerr, CodeConfigNotFoundForUpdate) {
			return ConfigResponse{}, ErrConfigNotFound
		}
		return ConfigResponse{}, aerr
	}
	var out ConfigResponse
	if err := json.Unmarshal(resp.Body, &out); err != nil {
		return ConfigResponse{}, fmt.Errorf("inji: read the configuration answer: %w", err)
	}
	if out.ID == "" {
		out.ID = dto.CredentialConfigKeyID
	}
	return out, nil
}

// SigningProfile names the Certify key and the proof of one format. The
// stack keeps the key; the profile only names it (ADR-001 decision 3).
type SigningProfile struct {
	// AppID is the key manager application id.
	AppID string
	// RefID is the key manager reference id.
	RefID string
	// Algorithm is the JOSE signature algorithm, such as EdDSA.
	Algorithm string
	// CryptoSuite is the proof type of a JSON-LD credential or the
	// suite of an mDoc, such as Ed25519Signature2020.
	CryptoSuite string
}

// Profiles hold the signing profile of each format and the DID URL of
// the issuer.
type Profiles struct {
	// DidURL is the issuer DID URL. Empty uses the default of Certify.
	DidURL string
	// Ldp signs ldp_vc credentials.
	Ldp SigningProfile
	// SdJwt signs vc+sd-jwt credentials.
	SdJwt SigningProfile
	// Mdoc signs mso_mdoc credentials.
	Mdoc SigningProfile
}

// DefaultProfiles are the keys of the stack defaults: the key alias
// mapper of the Certify configuration of the stack.
func DefaultProfiles() Profiles {
	return Profiles{
		Ldp: SigningProfile{AppID: "CERTIFY_VC_SIGN_ED25519", RefID: "ED25519_SIGN",
			Algorithm: "EdDSA", CryptoSuite: "Ed25519Signature2020"},
		SdJwt: SigningProfile{AppID: "CERTIFY_VC_SIGN_EC_R1", RefID: "EC_SECP256R1_SIGN", Algorithm: "ES256"},
		Mdoc: SigningProfile{AppID: "CERTIFY_VC_SIGN_EC_R1", RefID: "EC_SECP256R1_SIGN",
			Algorithm: "ES256", CryptoSuite: "ES256"},
	}
}

// ConfigInput is one configuration as VCA describes it.
type ConfigInput struct {
	// ID is the credential configuration id.
	ID string
	// Format is the OID4VCI format, such as ldp_vc.
	Format string
	// Type is the credential type name or the SD-JWT VC vct.
	Type string
	// JSONSchema is the JSON Schema document of the claims.
	JSONSchema string
	// Display is the OID4VCI display array as JSON.
	Display string
	// SDClaims lists the selectively disclosable claims.
	SDClaims []string
	// Contexts lists the JSON-LD context extensions.
	Contexts []string
	// RenderURL is the address of the SVG template of the stack. An
	// ldp_vc template then names it as its render method. Empty names
	// none.
	RenderURL string
	// RenderName is the name of the render method.
	RenderName string
}

// ErrUnsupportedFormat reports a format the configuration API refuses.
var ErrUnsupportedFormat = errors.New("inji: Certify 0.14.0 registers ldp_vc, vc+sd-jwt, and mso_mdoc configurations")

// VCDMContext is the base context of the W3C data model 2.0.
const VCDMContext = "https://www.w3.org/ns/credentials/v2"

// Ed25519Context defines the terms of an Ed25519Signature2020 proof.
const Ed25519Context = "https://w3id.org/security/suites/ed25519-2020/v1"

// suiteContexts maps each Linked Data proof suite of Certify 0.14.0 onto
// the context that defines its terms. The 2018 and 2019 suites carry a
// detached JWS. A data integrity proof needs no context beyond the data
// model 2.0 context.
var suiteContexts = map[string]string{
	"Ed25519Signature2020":        Ed25519Context,
	"Ed25519Signature2018":        "https://w3id.org/security/suites/ed25519-2018/v1",
	"RsaSignature2018":            "https://w3id.org/security/v2",
	"EcdsaSecp256k1Signature2019": "https://w3id.org/security/suites/secp256k1-2019/v1",
	"EcdsaKoblitzSignature2016":   "https://w3id.org/security/v2",
}

// MdocNamespace returns the namespace of the claims of an mDoc type: the
// ISO 18013-5 namespace for an mDL, and the type itself otherwise.
func MdocNamespace(doctype string) string {
	if ns, ok := strings.CutSuffix(doctype, ".mDL"); ok && ns != "" {
		return ns
	}
	return doctype
}

// templateName is a claim name that a Velocity template can read.
var templateName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`)

// markers are the template variables the adapter stages beside the
// claims. A configuration the adapter registers declares them, so the
// staging call passes the claim check of Certify.
var markers = []string{StatusIndexClaim, StatusURIClaim, ValidFromClaim, ValidUntilClaim}

// BuildConfiguration returns the Certify entry of one configuration. The
// entry carries a Velocity template that places the claims and the
// status entry of VCA, when the staging call passes one.
func BuildConfiguration(in ConfigInput, p Profiles) (ConfigurationDTO, error) {
	claims, err := schemaClaims(in.JSONSchema)
	if err != nil {
		return ConfigurationDTO{}, err
	}
	display := displays(in)
	locales := localesOf(display)
	dto := ConfigurationDTO{
		CredentialConfigKeyID: in.ID,
		CredentialFormat:      in.Format,
		DidURL:                p.DidURL,
		MetaDataDisplay:       display,
		DisplayOrder:          names(claims),
		Scope:                 in.ID,
	}
	switch in.Format {
	case "ldp_vc":
		dto.ContextURLs = ldpContexts(in.Contexts, p.Ldp)
		dto.CredentialTypes = []string{"VerifiableCredential", in.Type}
		dto.KeyManagerAppID, dto.KeyManagerRefID = p.Ldp.AppID, p.Ldp.RefID
		dto.SignatureAlgo, dto.SignatureCryptoSuite = p.Ldp.Algorithm, p.Ldp.CryptoSuite
		dto.CredentialSubjectDefinition = claimDisplays(claims, locales, markers)
		dto.VcTemplate = encodeTemplate(ldpTemplate(dto.ContextURLs, in, claims))
	case "vc+sd-jwt":
		dto.SdJwtVct = in.Type
		dto.KeyManagerAppID, dto.KeyManagerRefID = p.SdJwt.AppID, p.SdJwt.RefID
		dto.SignatureAlgo = p.SdJwt.Algorithm
		dto.SdClaim = strings.Join(in.SDClaims, ",")
		dto.SdJwtClaims = claimDisplays(claims, locales, []string{StatusIndexClaim, StatusURIClaim})
		dto.VcTemplate = encodeTemplate(sdJwtTemplate(claims))
	case "mso_mdoc":
		ns := MdocNamespace(in.Type)
		dto.DocType = in.Type
		dto.KeyManagerAppID, dto.KeyManagerRefID = p.Mdoc.AppID, p.Mdoc.RefID
		dto.SignatureAlgo, dto.SignatureCryptoSuite = p.Mdoc.Algorithm, p.Mdoc.CryptoSuite
		dto.MsoMdocClaims = map[string]map[string]ClaimDisplay{ns: claimDisplays(claims, locales, nil)}
		dto.VcTemplate = encodeTemplate(mdocTemplate(in.Type, ns, claims))
	default:
		return ConfigurationDTO{}, fmt.Errorf("%w, not %q", ErrUnsupportedFormat, in.Format)
	}
	return dto, nil
}

// claim is one top level property of the schema.
type claim struct {
	name  string
	title string
	// quoted is true for a string claim. A number, a boolean, an
	// object, or an array goes into the template as JSON.
	quoted bool
}

// schemaClaims reads the top level properties of the schema in order.
func schemaClaims(doc string) ([]claim, error) {
	parsed, err := jsonschema.Parse([]byte(doc))
	if err != nil {
		return nil, fmt.Errorf("inji: the JSON Schema does not parse: %w", err)
	}
	var out []claim
	for _, name := range parsed.Properties() {
		if !templateName.MatchString(name) {
			return nil, fmt.Errorf("inji: the claim name %q is not a template variable name", name)
		}
		c := claim{name: name, title: name, quoted: true}
		if sub, ok := parsed.Property(name); ok {
			if t, ok := sub["title"].(string); ok && t != "" {
				c.title = t
			}
			switch sub["type"] {
			case "integer", "number", "boolean", "object", "array":
				c.quoted = false
			}
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("inji: the JSON Schema has no property, so the credential would carry no claim")
	}
	return out, nil
}

// names returns the claim names in order.
func names(claims []claim) []string {
	out := make([]string, 0, len(claims))
	for _, c := range claims {
		out = append(out, c.name)
	}
	return out
}

// displays maps the OID4VCI display array onto metaDataDisplay. Certify
// needs at least one entry, so the type name fills an empty list.
func displays(in ConfigInput) []Display {
	var list []struct {
		Name            string `json:"name"`
		Locale          string `json:"locale"`
		BackgroundColor string `json:"background_color"`
		TextColor       string `json:"text_color"`
		Logo            *struct {
			URI     string `json:"uri"`
			URL     string `json:"url"`
			AltText string `json:"alt_text"`
		} `json:"logo"`
	}
	if strings.TrimSpace(in.Display) != "" && json.Unmarshal([]byte(in.Display), &list) != nil {
		list = nil
	}
	out := make([]Display, 0, len(list))
	for _, d := range list {
		e := Display{Name: d.Name, Locale: d.Locale, BackgroundColor: d.BackgroundColor, TextColor: d.TextColor}
		if d.Logo != nil {
			logo := d.Logo.URI
			if logo == "" {
				logo = d.Logo.URL
			}
			if logo != "" {
				e.Logo = &DisplayLogo{URL: logo, AltText: d.Logo.AltText}
			}
		}
		out = append(out, e)
	}
	if len(out) == 0 {
		out = append(out, Display{Name: in.Type, Locale: "en"})
	}
	return out
}

// localesOf returns the locales of the display entries, or en.
func localesOf(list []Display) []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range list {
		if d.Locale != "" && !seen[d.Locale] {
			seen[d.Locale] = true
			out = append(out, d.Locale)
		}
	}
	if len(out) == 0 {
		out = []string{"en"}
	}
	return out
}

// claimDisplays names each claim and each marker in every locale.
func claimDisplays(claims []claim, locales, extra []string) map[string]ClaimDisplay {
	out := make(map[string]ClaimDisplay, len(claims)+len(extra))
	label := func(name string) ClaimDisplay {
		d := ClaimDisplay{}
		for _, l := range locales {
			d.Display = append(d.Display, ClaimLabel{Name: name, Locale: l})
		}
		return d
	}
	for _, c := range claims {
		out[c.name] = label(c.title)
	}
	for _, m := range extra {
		if _, taken := out[m]; !taken {
			out[m] = label(m)
		}
	}
	return out
}

// ldpContexts puts the data model context first, then the extensions,
// then the context of the proof suite when it has one.
func ldpContexts(extensions []string, p SigningProfile) []string {
	out := []string{VCDMContext}
	for _, c := range extensions {
		if c = strings.TrimSpace(c); c != "" && c != VCDMContext {
			out = append(out, c)
		}
	}
	if suite, ok := suiteContexts[p.CryptoSuite]; ok {
		out = append(out, suite)
	}
	return out
}

// quote returns s as a JSON string.
func quote(s string) string {
	raw, err := json.Marshal(s)
	if err != nil {
		return `""`
	}
	return string(raw)
}

// placeholder returns the template value of one claim.
func placeholder(c claim) string {
	if c.quoted {
		return `"${` + c.name + `}"`
	}
	return "${" + c.name + "}"
}

// statusGuard opens the part of a template that only a staged status
// address fills.
const statusGuard = `#if($` + StatusURIClaim + ` && $` + StatusURIClaim + ` != "")`

// ldpTemplate returns the Velocity template of a JSON-LD credential. It
// follows the sample template of the Certify stack, with the data model
// 2.0 context and the bitstring status list entry of VCA (ADR-018).
func ldpTemplate(contexts []string, in ConfigInput, claims []claim) string {
	var b strings.Builder
	b.WriteString("{\n  \"@context\": [")
	for i, c := range contexts {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(quote(c))
	}
	b.WriteString("],\n")
	b.WriteString("  \"type\": [\"VerifiableCredential\", " + quote(in.Type) + "],\n")
	b.WriteString("  \"issuer\": \"${_issuer}\",\n")
	b.WriteString("  \"validFrom\": \"${" + ValidFromClaim + "}\",\n")
	b.WriteString("  \"validUntil\": \"${" + ValidUntilClaim + "}\",\n")
	b.WriteString(statusGuard + "\n")
	b.WriteString("  \"credentialStatus\": {\n")
	b.WriteString("    \"id\": \"${" + StatusURIClaim + "}#${" + StatusIndexClaim + "}\",\n")
	b.WriteString("    \"type\": \"BitstringStatusListEntry\",\n")
	b.WriteString("    \"statusPurpose\": \"revocation\",\n")
	b.WriteString("    \"statusListIndex\": \"${" + StatusIndexClaim + "}\",\n")
	b.WriteString("    \"statusListCredential\": \"${" + StatusURIClaim + "}\"\n")
	b.WriteString("  },\n#end\n")
	if in.RenderURL != "" {
		b.WriteString("  \"renderMethod\": [{\"id\": " + quote(in.RenderURL) +
			", \"type\": \"SvgRenderingTemplate\", \"name\": " + quote(in.RenderName) + "}],\n")
	}
	b.WriteString("  \"credentialSubject\": {\n    \"id\": \"${_holderId}\"")
	for _, c := range claims {
		b.WriteString(",\n    " + quote(c.name) + ": " + placeholder(c))
	}
	b.WriteString("\n  }\n}\n")
	return b.String()
}

// sdJwtTemplate returns the Velocity template of an SD-JWT VC. Certify
// adds iss, vct, cnf, and the times. The status claim points at the
// token status list of VCA (ADR-019).
func sdJwtTemplate(claims []claim) string {
	var b strings.Builder
	b.WriteString("{\n")
	b.WriteString(statusGuard + "\n")
	b.WriteString("  \"status\": {\"status_list\": {\"idx\": ${" + StatusIndexClaim +
		"}, \"uri\": \"${" + StatusURIClaim + "}\"}},\n#end\n")
	for i, c := range claims {
		if i > 0 {
			b.WriteString(",\n")
		}
		b.WriteString("  " + quote(c.name) + ": " + placeholder(c))
	}
	b.WriteString("\n}\n")
	return b.String()
}

// mdocTemplate returns the template of an mDoc. Certify reads docType,
// validityInfo, and one list of elements per namespace, and it fills
// _validFrom and _validUntil itself.
func mdocTemplate(doctype, ns string, claims []claim) string {
	var b strings.Builder
	b.WriteString("{\n  \"docType\": " + quote(doctype) + ",\n")
	b.WriteString("  \"validityInfo\": {\"validFrom\": \"${_validFrom}\", \"validUntil\": \"${_validUntil}\"},\n")
	b.WriteString("  \"namespaces\": {\n    " + quote(ns) + ": [")
	for i, c := range claims {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString("\n      {\"digestId\": " + strconv.Itoa(i) + ", \"elementIdentifier\": " + quote(c.name) +
			", \"elementValue\": " + placeholder(c) + "}")
	}
	b.WriteString("\n    ]\n  }\n}\n")
	return b.String()
}

// encodeTemplate returns the base64 form Certify stores.
func encodeTemplate(t string) string { return base64.StdEncoding.EncodeToString([]byte(t)) }

// DecodeTemplate returns the text of a stored template.
func DecodeTemplate(encoded string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("inji: the template is not base64: %w", err)
	}
	return string(raw), nil
}
