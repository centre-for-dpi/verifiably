// SPDX-License-Identifier: Apache-2.0

// Package present reads an OpenID for Verifiable Presentations 1.0
// request and prepares the consent screen (ADR-021 decision 5).
//
// The flow has four steps:
//
//  1. Parse reads an openid4vp URI. The URI carries the request or the
//     address of the request.
//  2. Fetch reads a request object from an allowlisted host. The host
//     allowlist stops a request URI that points at a private address.
//  3. Consent lists every claim the verifier asks for, with the value
//     the wallet would send. The citizen reads it before submit.
//  4. Submit posts the vp_token to the response URI with direct_post.
//
// The parsing and the consent building are pure. The fetch and the post
// come in as function values, so a test needs no network.
package present

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/centre-for-dpi/vc-adapters/core/dcql"
	"github.com/centre-for-dpi/vc-adapters/core/fetchguard"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/sdjwt"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	walletportalv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/cards"
)

// ResponseModeDirectPost is the only response mode the wallet supports.
const ResponseModeDirectPost = "direct_post"

// Errors the package returns.
var (
	// ErrNotSupported reports a request the wallet cannot answer.
	ErrNotSupported = errors.New("present: the wallet cannot answer this request")
	// ErrHostNotAllowed reports a request URI on a host the operator did
	// not allow.
	ErrHostNotAllowed = errors.New("present: the request host is not on the allowlist")
	// ErrBadRequest reports a request object the wallet cannot read.
	ErrBadRequest = errors.New("present: the request does not parse")
)

// Request is the part of an OID4VP request the wallet needs.
type Request struct {
	// RequestURI is the address of the request object, when the URI
	// carried one.
	RequestURI string
	// ClientID is the verifier identifier. The key binding audience
	// takes this value.
	ClientID string
	// Nonce is the value the wallet binds the presentation to.
	Nonce string
	// ResponseURI is the address the wallet posts the answer to.
	ResponseURI string
	// ResponseMode is the response mode of the request.
	ResponseMode string
	// State is the value the verifier gave, when any.
	State string
	// Purpose is the text the verifier shows the citizen, when any.
	Purpose string
	// Query is the DCQL query of the request (OID4VP 1.0 section 6).
	Query dcql.Query
	// DefinitionID is the Presentation Exchange definition id, when the
	// verifier sent a definition instead of a query.
	DefinitionID string
}

// Parse reads an openid4vp URI. A URI with a request_uri returns a
// Request that carries only that address. Fetch reads the rest.
func Parse(raw string) (Request, error) {
	text := strings.TrimSpace(raw)
	if text == "" {
		return Request{}, fmt.Errorf("%w: the request is empty", ErrBadRequest)
	}
	if !strings.Contains(text, "?") && !strings.HasPrefix(text, "{") {
		return Request{RequestURI: text}, nil
	}
	if strings.HasPrefix(text, "{") {
		return fromObject([]byte(text))
	}
	u, err := url.Parse(text)
	if err != nil {
		return Request{}, fmt.Errorf("%w: %w", ErrBadRequest, err)
	}
	q := u.Query()
	if uri := strings.TrimSpace(q.Get("request_uri")); uri != "" {
		return Request{RequestURI: uri, ClientID: q.Get("client_id")}, nil
	}
	doc := map[string]any{
		"client_id":     q.Get("client_id"),
		"nonce":         q.Get("nonce"),
		"response_uri":  q.Get("response_uri"),
		"response_mode": q.Get("response_mode"),
		"state":         q.Get("state"),
	}
	for _, name := range []string{"dcql_query", "presentation_definition"} {
		if value := q.Get(name); value != "" {
			var nested any
			if serr := json.Unmarshal([]byte(value), &nested); serr != nil {
				return Request{}, fmt.Errorf("%w: the %s does not parse", ErrBadRequest, name)
			}
			doc[name] = nested
		}
	}
	raw2, err := json.Marshal(doc)
	if err != nil {
		return Request{}, fmt.Errorf("%w: %w", ErrBadRequest, err)
	}
	return fromObject(raw2)
}

// AllowHost reports whether the host of uri is on the allowlist. An
// empty allowlist blocks every request URI. It uses the shared guard of
// core/fetchguard (ADR-002 decision 7). The host allowlist is the
// control here, so the guard allows a private address of an allowed
// host, and it allows plain http.
func AllowHost(ctx context.Context, uri string, hosts []string) error {
	if _, err := url.Parse(strings.TrimSpace(uri)); err != nil {
		return fmt.Errorf("%w: %w", ErrBadRequest, err)
	}
	if len(hosts) == 0 {
		return fmt.Errorf("%w: no host is allowed", ErrHostNotAllowed)
	}
	guard := fetchguard.Guard{
		AllowedHosts:        hosts,
		AllowPlainHTTP:      true,
		AllowPrivateNetwork: true,
	}
	if _, err := guard.Check(ctx, uri); err != nil {
		return fmt.Errorf("%w: %w", ErrHostNotAllowed, err)
	}
	return nil
}

// Fetcher reads one request object.
type Fetcher func(ctx context.Context, url string) ([]byte, error)

// Fetch reads the request object of r.RequestURI and returns the full
// request. The host must be on the allowlist.
func Fetch(ctx context.Context, r Request, hosts []string, fetch Fetcher) (Request, error) {
	if r.RequestURI == "" {
		return r, nil
	}
	if err := AllowHost(ctx, r.RequestURI, hosts); err != nil {
		return Request{}, err
	}
	if fetch == nil {
		return Request{}, fmt.Errorf("%w: the service has no fetcher", ErrNotSupported)
	}
	raw, err := fetch(ctx, r.RequestURI)
	if err != nil {
		return Request{}, fmt.Errorf("present: read the request object: %w", err)
	}
	got, err := ParseObject(raw)
	if err != nil {
		return Request{}, err
	}
	got.RequestURI = r.RequestURI
	if got.ClientID == "" {
		got.ClientID = r.ClientID
	}
	return got, nil
}

// ParseObject reads a request object. The object is a JSON document or
// a signed request object (JAR), whose payload the wallet reads.
func ParseObject(raw []byte) (Request, error) {
	text := strings.TrimSpace(string(raw))
	if strings.HasPrefix(text, "{") {
		return fromObject([]byte(text))
	}
	payload, err := jose.PeekPayload(text)
	if err != nil {
		return Request{}, fmt.Errorf("%w: the request object is neither JSON nor a JWT", ErrBadRequest)
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return Request{}, fmt.Errorf("%w: %w", ErrBadRequest, err)
	}
	return fromObject(encoded)
}

// requestObject is the shape of an OID4VP request object.
type requestObject struct {
	ClientID               string          `json:"client_id"`
	Nonce                  string          `json:"nonce"`
	ResponseURI            string          `json:"response_uri"`
	ResponseMode           string          `json:"response_mode"`
	State                  string          `json:"state"`
	DCQL                   json.RawMessage `json:"dcql_query"`
	PresentationDefinition json.RawMessage `json:"presentation_definition"`
}

// fromObject reads a request object document.
func fromObject(raw []byte) (Request, error) {
	var doc requestObject
	if err := json.Unmarshal(raw, &doc); err != nil {
		return Request{}, fmt.Errorf("%w: %w", ErrBadRequest, err)
	}
	out := Request{
		ClientID: doc.ClientID, Nonce: doc.Nonce, ResponseURI: doc.ResponseURI,
		ResponseMode: doc.ResponseMode, State: doc.State,
	}
	if out.ResponseMode == "" {
		out.ResponseMode = ResponseModeDirectPost
	}
	switch {
	case len(doc.DCQL) > 0:
		query, err := dcql.Parse(doc.DCQL)
		if err != nil {
			return Request{}, fmt.Errorf("%w: the DCQL query does not parse", ErrBadRequest)
		}
		out.Query = query
	case len(doc.PresentationDefinition) > 0:
		query, id, purpose, err := fromDefinition(doc.PresentationDefinition)
		if err != nil {
			return Request{}, err
		}
		out.Query, out.DefinitionID, out.Purpose = query, id, purpose
	default:
		return Request{}, fmt.Errorf("%w: the request asks for no credential", ErrBadRequest)
	}
	if out.ResponseURI == "" || out.Nonce == "" {
		return Request{}, fmt.Errorf("%w: the request has no nonce or no response address", ErrBadRequest)
	}
	if out.ResponseMode != ResponseModeDirectPost {
		return Request{}, fmt.Errorf("%w: the response mode %q is not direct_post",
			ErrNotSupported, out.ResponseMode)
	}
	return out, nil
}

// definition is the part of a Presentation Exchange definition the
// wallet reads. Some DPG verifiers still send one (ADR-022 decision 3).
type definition struct {
	ID               string `json:"id"`
	Purpose          string `json:"purpose"`
	InputDescriptors []struct {
		ID          string                     `json:"id"`
		Name        string                     `json:"name"`
		Purpose     string                     `json:"purpose"`
		Format      map[string]json.RawMessage `json:"format"`
		Constraints struct {
			Fields []struct {
				Path     []string `json:"path"`
				Optional bool     `json:"optional"`
				Filter   struct {
					Pattern string `json:"pattern"`
					Const   string `json:"const"`
				} `json:"filter"`
			} `json:"fields"`
		} `json:"constraints"`
	} `json:"input_descriptors"`
}

// fromDefinition maps a Presentation Exchange definition to a DCQL
// query, so the rest of the package handles one shape only.
func fromDefinition(raw []byte) (dcql.Query, string, string, error) {
	var def definition
	if err := json.Unmarshal(raw, &def); err != nil {
		return dcql.Query{}, "", "", fmt.Errorf("%w: the definition does not parse", ErrBadRequest)
	}
	var query dcql.Query
	for _, d := range def.InputDescriptors {
		cq := dcql.CredentialQuery{ID: dcql.CleanID(d.ID), Format: formatOf(d.Format)}
		var all, required []string
		for _, f := range d.Constraints.Fields {
			name := claimName(f.Path)
			switch name {
			case "":
				continue
			case "vct", "type":
				if pattern := firstNonEmpty(f.Filter.Const, f.Filter.Pattern); pattern != "" {
					cq.Meta = &dcql.Meta{VctValues: []string{strings.Trim(pattern, "^$")}}
				}
			default:
				path, err := dcql.ParsePath(name)
				if err != nil {
					continue
				}
				id := "c" + strconv.Itoa(len(cq.Claims)+1)
				cq.Claims = append(cq.Claims, dcql.ClaimQuery{ID: id, Path: path})
				all = append(all, id)
				if !f.Optional {
					required = append(required, id)
				}
			}
		}
		// An optional field becomes a claim that the smaller claim set
		// leaves out, so the consent screen offers it off by default.
		if len(required) < len(all) {
			cq.ClaimSets = [][]string{all, required}
		}
		query.Credentials = append(query.Credentials, cq)
	}
	if len(query.Credentials) == 0 {
		return dcql.Query{}, "", "", fmt.Errorf("%w: the definition asks for no credential", ErrBadRequest)
	}
	return query, def.ID, def.Purpose, nil
}

// formatOf returns the first format key of a descriptor.
func formatOf(formats map[string]json.RawMessage) string {
	for name := range formats {
		return name
	}
	return dcql.FormatSDJWT
}

// claimName returns the claim name of a JSONPath list, for example
// "$.credentialSubject.given_name" gives "given_name".
func claimName(paths []string) string {
	for _, p := range paths {
		p = strings.TrimPrefix(strings.TrimSpace(p), "$.")
		p = strings.TrimPrefix(p, "credentialSubject.")
		if i := strings.LastIndex(p, "."); i >= 0 {
			p = p[i+1:]
		}
		if p != "" {
			return p
		}
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// Consent builds the consent screen of a request. It lists one entry
// per requested credential, with the matching cards and the value of
// each requested claim (ADR-021 decision 5).
func Consent(r Request, held []*walletportalv1.Card) []*walletportalv1.PresentStartResponse_RequestedCredential {
	out := make([]*walletportalv1.PresentStartResponse_RequestedCredential, 0, len(r.Query.Credentials))
	for _, cq := range r.Query.Credentials {
		entry := &walletportalv1.PresentStartResponse_RequestedCredential{
			QueryId: cq.ID,
			Type:    cq.Type(),
			Format:  FormatOf(cq.Format),
		}
		entry.Matches = Matches(cq, held)
		var first *walletportalv1.Card
		if len(entry.GetMatches()) > 0 {
			first = entry.GetMatches()[0]
		}
		for _, claim := range cq.Claims {
			path := claim.Path.String()
			entry.Claims = append(entry.Claims, &walletportalv1.PresentStartResponse_RequestedCredential_Claim{
				Path:      path,
				Value:     valueOf(first, path),
				Mandatory: mandatory(cq, claim.ID),
			})
		}
		out = append(out, entry)
	}
	return out
}

// mandatory reports whether every claim set of a credential query holds
// the claim. A query with no claim set needs every claim (OID4VP 1.0
// section 6.4).
func mandatory(cq dcql.CredentialQuery, id string) bool {
	for _, set := range cq.ClaimSets {
		if !slices.Contains(set, id) {
			return false
		}
	}
	return true
}

// RequestObjectText returns a request object as JSON text when text is
// one: a JSON document or a signed request object that names a nonce, a
// response address, and a query. Parse reads the JSON text. Any other
// text gives false.
func RequestObjectText(text string) (string, bool) {
	text = strings.TrimSpace(text)
	if text == "" || (!strings.HasPrefix(text, "{") && strings.Contains(text, "://")) {
		return "", false
	}
	req, err := ParseObject([]byte(text))
	if err != nil || req.Nonce == "" {
		return "", false
	}
	if strings.HasPrefix(text, "{") {
		return text, true
	}
	payload, err := jose.PeekPayload(text)
	if err != nil {
		return "", false
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", false
	}
	return string(raw), true
}

// Matches returns the cards that answer one credential query.
func Matches(cq dcql.CredentialQuery, held []*walletportalv1.Card) []*walletportalv1.Card {
	want := strings.TrimSpace(cq.Type())
	format := FormatOf(cq.Format)
	var out []*walletportalv1.Card
	for _, card := range held {
		if want != "" && !strings.EqualFold(want, card.GetType()) {
			continue
		}
		if format != commonv1.Format_FORMAT_UNSPECIFIED && card.GetFormat() != commonv1.Format_FORMAT_UNSPECIFIED &&
			format != card.GetFormat() {
			continue
		}
		out = append(out, card)
	}
	return out
}

// valueOf returns the value of one claim path on a card.
func valueOf(card *walletportalv1.Card, path string) string {
	if card == nil {
		return ""
	}
	name := path
	if i := strings.LastIndex(name, "."); i >= 0 {
		name = name[i+1:]
	}
	if value, ok := card.GetClaims()[path]; ok {
		return value
	}
	return card.GetClaims()[name]
}

// FormatOf maps a DCQL format name to the proto format.
func FormatOf(name string) commonv1.Format {
	switch name {
	case dcql.FormatSDJWT:
		return commonv1.Format_FORMAT_DC_SD_JWT
	case dcql.FormatSDJWTLegacy:
		return commonv1.Format_FORMAT_VC_SD_JWT
	case dcql.FormatJWTVCJSON:
		return commonv1.Format_FORMAT_JWT_VC_JSON
	case dcql.FormatLDPVC:
		return commonv1.Format_FORMAT_LDP_VC
	case dcql.FormatMdoc:
		return commonv1.Format_FORMAT_MSO_MDOC
	}
	return commonv1.Format_FORMAT_UNSPECIFIED
}

// FormatName maps a proto format to the OID4VCI format identifier.
func FormatName(f commonv1.Format) string {
	switch f {
	case commonv1.Format_FORMAT_DC_SD_JWT:
		return dcql.FormatSDJWT
	case commonv1.Format_FORMAT_VC_SD_JWT:
		return dcql.FormatSDJWTLegacy
	case commonv1.Format_FORMAT_JWT_VC_JSON:
		return dcql.FormatJWTVCJSON
	case commonv1.Format_FORMAT_LDP_VC:
		return dcql.FormatLDPVC
	case commonv1.Format_FORMAT_MSO_MDOC:
		return dcql.FormatMdoc
	}
	return ""
}

// Disclosed returns an SD-JWT presentation that carries only the
// disclosures the citizen agreed to send. Every other disclosure stays
// out of the token, so the verifier learns nothing more.
func Disclosed(credential string, paths []string) (string, error) {
	parsed, err := sdjwt.Parse(credential)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrBadRequest, err)
	}
	keep := map[string]bool{}
	for _, p := range paths {
		name := p
		if i := strings.LastIndex(name, "."); i >= 0 {
			name = name[i+1:]
		}
		keep[name] = true
	}
	kept := make([]sdjwt.Disclosure, 0, len(parsed.Disclosures))
	for _, d := range parsed.Disclosures {
		if d.Name == "" || keep[d.Name] {
			kept = append(kept, d)
		}
	}
	parsed.Disclosures = kept
	return sdjwt.Serialize(parsed), nil
}

// ClaimNames returns the claim names of one requested credential.
func ClaimNames(entry *walletportalv1.PresentStartResponse_RequestedCredential) []string {
	out := make([]string, 0, len(entry.GetClaims()))
	for _, c := range entry.GetClaims() {
		out = append(out, c.GetPath())
	}
	return out
}

// Poster sends the response of the wallet. It returns the response body.
type Poster func(ctx context.Context, url string, form url.Values) ([]byte, error)

// Result is the answer of the verifier.
type Result struct {
	// Accepted is true when the verifier took the presentation.
	Accepted bool
	// RedirectURI is the address the verifier returned, when any.
	RedirectURI string
	// Message is the outcome in plain language.
	Message string
}

// Submit posts the vp_token to the response URI with direct_post
// (OID4VP 1.0 section 8.2).
func Submit(ctx context.Context, r Request, vpToken string, post Poster) (Result, error) {
	if post == nil {
		return Result{}, fmt.Errorf("%w: the service cannot post the answer", ErrNotSupported)
	}
	if strings.TrimSpace(vpToken) == "" {
		return Result{}, fmt.Errorf("%w: the wallet built no token", ErrBadRequest)
	}
	form := url.Values{}
	form.Set("vp_token", vpToken)
	if r.State != "" {
		form.Set("state", r.State)
	}
	body, err := post(ctx, r.ResponseURI, form)
	if err != nil {
		return Result{Message: "The verifier did not take the credential. Try again later."}, err
	}
	return Result{
		Accepted:    true,
		RedirectURI: redirectOf(body),
		Message:     "You sent the credential. The verifier has your answer.",
	}, nil
}

// redirectOf reads the redirect_uri of a direct_post answer.
func redirectOf(body []byte) string {
	var doc struct {
		RedirectURI string `json:"redirect_uri"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return ""
	}
	return doc.RedirectURI
}

// Summary returns one sentence that says what the verifier asks for.
func Summary(entries []*walletportalv1.PresentStartResponse_RequestedCredential) string {
	if len(entries) == 0 {
		return "The verifier asks for no credential."
	}
	claims := 0
	for _, e := range entries {
		claims += len(e.GetClaims())
	}
	if len(entries) == 1 {
		return fmt.Sprintf("The verifier asks for one credential and %d fields.", claims)
	}
	return fmt.Sprintf("The verifier asks for %d credentials and %d fields.", len(entries), claims)
}

// TrustOf returns the trust outcome of the verifier. The lookup is the
// same trust registry call the cards use (ADR-011 decision 7).
func TrustOf(ctx context.Context, lookup cards.TrustLookup, clientID string) cards.Trust {
	if lookup == nil || clientID == "" {
		return cards.Trust{}
	}
	got, err := lookup(ctx, clientID, "")
	if err != nil {
		return cards.Trust{}
	}
	return got
}
