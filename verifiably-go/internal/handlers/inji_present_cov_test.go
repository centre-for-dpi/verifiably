package handlers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// Coverage tests for inji_present.go — the branches the F21/F23/F24 tests do
// not reach: error paths of the helpers, the multi-credential preview, and the
// four HTTP handlers driven through real templates.

// injiPresentBogusKey is an ecdsa key on an unknown curve — x509 refuses to
// marshal it.
func injiPresentBogusKey() *ecdsa.PrivateKey {
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: &elliptic.CurveParams{Name: "bogus", N: big.NewInt(7), P: big.NewInt(7), B: big.NewInt(1), Gx: big.NewInt(1), Gy: big.NewInt(1), BitSize: 8},
			X:     big.NewInt(1), Y: big.NewInt(1),
		},
		D: big.NewInt(1),
	}
}

// injiPresentZeroKey is a P-256 key with scalar 0 — ecdsa.Sign rejects it, so
// signES256 (and everything above it) returns an error.
func injiPresentZeroKey() *ecdsa.PrivateKey {
	return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(1), Y: big.NewInt(1)}, D: big.NewInt(0)}
}

// injiPresentVerifier is a fake OID4VP verifier: serves a JAR at /jar and
// records every direct_post form at /submit.
type injiPresentVerifier struct {
	srv        *httptest.Server
	jar        string
	submitCode int
	mu         sync.Mutex
	posts      []url.Values
}

func injiPresentNewVerifier(t *testing.T, descriptors []any) *injiPresentVerifier {
	t.Helper()
	v := &injiPresentVerifier{submitCode: http.StatusOK}
	v.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jar":
			_, _ = w.Write([]byte(v.jar))
		case "/submit":
			_ = r.ParseForm()
			v.mu.Lock()
			v.posts = append(v.posts, r.PostForm)
			v.mu.Unlock()
			w.WriteHeader(v.submitCode)
			_, _ = w.Write([]byte("nope"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(v.srv.Close)
	v.jar = makeJAR(map[string]any{
		"nonce":        "n-1",
		"client_id":    "did:web:verifier.example",
		"response_uri": v.srv.URL + "/submit",
		"state":        "st-1",
		"presentation_definition": map[string]any{
			"id":                "pd-1",
			"input_descriptors": descriptors,
		},
	})
	return v
}

// requestURI is the openid4vp:// envelope pointing at this verifier's JAR.
func (v *injiPresentVerifier) requestURI() string {
	return "openid4vp://authorize?client_id=x&request_uri=" + url.QueryEscape(v.srv.URL+"/jar")
}

func (v *injiPresentVerifier) lastPost() url.Values {
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.posts) == 0 {
		return nil
	}
	return v.posts[len(v.posts)-1]
}

// injiPresentDescriptor is a PD input_descriptor literal in the JAR shape.
func injiPresentDescriptor(id, name, format string, fields ...string) map[string]any {
	fs := []any{}
	for _, f := range fields {
		fs = append(fs, map[string]any{"path": []string{"$." + f}})
	}
	return map[string]any{
		"id": id, "name": name,
		"format":      map[string]any{format: map[string]any{}},
		"constraints": map[string]any{"fields": fs},
	}
}

// injiPresentH builds an H with real holder_inji_present templates.
func injiPresentH(t *testing.T) *H {
	t.Helper()
	return &H{Sessions: NewStore(), Templates: loadPageTemplates(t, "holder_inji_present")}
}

func injiPresentToast(t *testing.T, rr *httptest.ResponseRecorder, want string) {
	t.Helper()
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (HTMX toast)", rr.Code)
	}
	trig := rr.Header().Get("HX-Trigger")
	if !strings.Contains(trig, want) {
		t.Fatalf("HX-Trigger = %q, want it to contain %q", trig, want)
	}
	if rr.Body.Len() != 0 {
		t.Errorf("toast body must be empty, got %q", rr.Body.String())
	}
}

// ─── helpers: error branches ───────────────────────────────────────────────────

func TestInjiPresentCov_MarshalECKeyPEMError(t *testing.T) {
	if s, err := marshalECKeyPEM(injiPresentBogusKey()); err == nil || s != "" {
		t.Fatalf("marshal of unknown curve: pem=%q err=%v, want error + empty", s, err)
	}
}

func TestInjiPresentCov_SDJWTVctUndecodablePayload(t *testing.T) {
	if got := injiSDJWTVct("aGVhZGVy.!!!not-base64!!!.c2ln~"); got != "" {
		t.Fatalf("vct of undecodable payload = %q, want empty", got)
	}
}

func TestInjiPresentCov_BuildVPTokenSignError(t *testing.T) {
	_, err := injiBuildVPToken(sampleSDJWT(t), injiPresentZeroKey(), "n", "aud")
	if err == nil || !strings.Contains(err.Error(), "ecdsa") {
		t.Fatalf("err = %v, want an ecdsa signing error", err)
	}
}

func TestInjiPresentCov_PrimaryPrefersDescriptors(t *testing.T) {
	jar := injiJAR{DescID: "scalar", Descriptors: []injiDescriptor{{ID: "d0", Name: "First"}, {ID: "d1"}}}
	if p := jar.primary(); p.ID != "d0" || p.Name != "First" {
		t.Fatalf("primary = %+v, want Descriptors[0]", p)
	}
}

func TestInjiPresentCov_FetchInjiVPRequestErrorBranches(t *testing.T) {
	h := &H{}
	ctx := context.Background()

	if _, err := h.fetchInjiVPRequest(ctx, "http://[::1]:namedport"); err == nil || !strings.Contains(err.Error(), "parse request uri") {
		t.Errorf("unparseable URI: err = %v", err)
	}
	unreachable := "openid4vp://authorize?request_uri=" + url.QueryEscape("http://127.0.0.1:1/jar")
	if _, err := h.fetchInjiVPRequest(ctx, unreachable); err == nil || !strings.Contains(err.Error(), "connect") {
		t.Errorf("unreachable request_uri: err = %v, want connection error", err)
	}

	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
	defer srv.Close()
	uri := "openid4vp://authorize?request_uri=" + url.QueryEscape(srv.URL)

	body = "not-a-jwt"
	if _, err := h.fetchInjiVPRequest(ctx, uri); err == nil || !strings.Contains(err.Error(), "not a JWT (9 bytes)") {
		t.Errorf("non-JWT body: err = %v", err)
	}
	body = "aGVhZGVy.!!!.c2ln"
	if _, err := h.fetchInjiVPRequest(ctx, uri); err == nil || !strings.Contains(err.Error(), "decode request object") {
		t.Errorf("bad base64 payload: err = %v", err)
	}
	body = "aGVhZGVy." + base64.RawURLEncoding.EncodeToString([]byte("{not json")) + ".c2ln"
	if _, err := h.fetchInjiVPRequest(ctx, uri); err == nil || !strings.Contains(err.Error(), "parse request object") {
		t.Errorf("non-JSON payload: err = %v", err)
	}
}

func TestInjiPresentCov_DirectPostMulti(t *testing.T) {
	v := injiPresentNewVerifier(t, nil)
	jar := injiJAR{PDID: "pd-1", State: "st-1", ResponseURI: v.srv.URL + "/submit"}
	legs := []injiMatch{{Desc: injiDescriptor{ID: "id-desc"}}, {Desc: injiDescriptor{ID: "del-desc"}}}
	if err := (&H{}).injiDirectPostMulti(context.Background(), jar, `{"vp":1}`, legs); err != nil {
		t.Fatal(err)
	}
	form := v.lastPost()
	if form.Get("vp_token") != `{"vp":1}` || form.Get("state") != "st-1" {
		t.Fatalf("form = %v", form)
	}
	var sub struct {
		DefinitionID  string `json:"definition_id"`
		DescriptorMap []struct {
			ID, Format, Path string
			PathNested       struct{ Format, Path string } `json:"path_nested"`
		} `json:"descriptor_map"`
	}
	if err := json.Unmarshal([]byte(form.Get("presentation_submission")), &sub); err != nil {
		t.Fatal(err)
	}
	if sub.DefinitionID != "pd-1" || len(sub.DescriptorMap) != 2 {
		t.Fatalf("submission = %+v", sub)
	}
	for i, want := range []string{"id-desc", "del-desc"} {
		d := sub.DescriptorMap[i]
		if d.ID != want || d.Format != "ldp_vp" || d.Path != "$" || d.PathNested.Format != "ldp_vc" ||
			d.PathNested.Path != "$.verifiableCredential["+string(rune('0'+i))+"]" {
			t.Errorf("descriptor_map[%d] = %+v", i, d)
		}
	}

	// Transport failure surfaces as the error (postVPResponse Do branch).
	down := injiJAR{ResponseURI: "http://127.0.0.1:1/submit"}
	if err := (&H{}).injiDirectPostMulti(context.Background(), down, "x", legs); err == nil || !strings.Contains(err.Error(), "connect") {
		t.Fatalf("unreachable response_uri: err = %v", err)
	}
}

func TestInjiPresentCov_W3CHelperBranches(t *testing.T) {
	if got := injiW3CTitle(`{"type":"PersonCredential"}`); got != "PersonCredential" {
		t.Errorf("string type: %q", got)
	}
	if got := injiW3CTitle(`{"type":"VerifiableCredential"}`); got != "In-app Inji credential" {
		t.Errorf("bare VerifiableCredential string type: %q", got)
	}
	if got := injiW3CFields("{not json"); got != nil {
		t.Errorf("fields of invalid JSON = %v, want nil", got)
	}
	if got := injiHeldFieldValue(`{"credentialSubject":{"id":"did:x"}}`, "name"); got != "" {
		t.Errorf("missing W3C field = %q", got)
	}
	if got := injiHeldFieldValue("{not json", "name"); got != "" {
		t.Errorf("invalid W3C JSON = %q", got)
	}
	sd := "h.p.s~" + "!!!bad-disclosure!!!" + "~" + discl("name", "Ada") + "~"
	if got := injiHeldFieldValue(sd, "name"); got != "Ada" {
		t.Errorf("undecodable disclosure must be skipped, got %q", got)
	}
	desc := injiDescriptor{Format: "ldp_vp", RequestedFields: []string{"name"}}
	if injiDescriptorFits(desc, "{not json") {
		t.Error("unparseable W3C credential must not fit a descriptor with requested fields")
	}
	if got := injiCredTitle(tSDJWT); got != "vct" {
		t.Errorf("SD-JWT title = %q", got)
	}
	// vct without a path segment after the last slash falls back to the whole vct.
	pl := base64.RawURLEncoding.EncodeToString([]byte(`{"vct":"PersonCredential"}`))
	if got := injiCredTitle("h." + pl + ".s~"); got != "PersonCredential" {
		t.Errorf("slash-less vct title = %q", got)
	}
}

func TestInjiPresentCov_HeldPresentableBadKeyPEM(t *testing.T) {
	sd := sampleSDJWT(t)
	sess := &Session{
		InjiClaimedVCs: []string{sd},
		InjiHolderKeys: map[string]string{vcID(sd): "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n"},
	}
	if _, _, ok := injiHeldPresentable(sess, vcID(sd)); ok {
		t.Fatal("a held SD-JWT whose retained key does not parse must not be presentable")
	}
}

func TestInjiPresentCov_AutoMatchSkipsUnpresentable(t *testing.T) {
	// The SD-JWT has no retained key, so it is skipped even though it is first.
	sess := &Session{InjiClaimedVCs: []string{tSDJWT, tIdentityVC}}
	sd := injiDescriptor{ID: "sd", Format: "vc+sd-jwt"}
	got := (&H{}).injiAutoMatch(sess, injiJAR{Descriptors: []injiDescriptor{sd, dIdentity}})
	if len(got) != 2 || got[0].Found || !got[1].Found || got[1].CredID != vcID(tIdentityVC) {
		t.Fatalf("matches = %+v", got)
	}
}

func TestInjiPresentCov_MultiPreview(t *testing.T) {
	h := &H{}
	sess := &Session{InjiClaimedVCs: []string{tIdentityVC}}
	unnamed := injiDescriptor{ID: "x", Format: "ldp_vp", RequestedFields: []string{"licence"}}
	jar := injiJAR{Aud: "did:web:verifier.example", Descriptors: []injiDescriptor{dIdentity, unnamed}}

	previews, ids, all := h.injiMultiPreview(sess, jar)
	if all {
		t.Error("allMatched must be false when a descriptor has no held credential")
	}
	if len(previews) != 2 || len(ids) != 1 || ids[0] != vcID(tIdentityVC) {
		t.Fatalf("previews=%d ids=%v", len(previews), ids)
	}
	if p := previews[0]; !p.Compatible || p.CredentialTitle != "Identity" || p.VerifierClientID != jar.Aud || len(p.Fields) != 2 || p.Fields[1].Value != "Abdullahi" {
		t.Errorf("matched preview = %+v", p)
	}
	if p := previews[1]; p.Compatible || p.CredentialTitle != "requested credential" || p.RequestedFormat != "ldp_vp" ||
		len(p.Fields) != 1 || p.Fields[0].Name != "licence" || p.Fields[0].Value != "" ||
		!strings.Contains(p.IncompatibleReason, "don't hold a credential") || p.CredentialID != "" {
		t.Errorf("unmatched preview = %+v", p)
	}

	sess.InjiClaimedVCs = []string{tIdentityVC, tDelegationVC}
	previews, ids, all = h.injiMultiPreview(sess, injiJAR{Descriptors: []injiDescriptor{dIdentity, dDelegation}})
	if !all || len(previews) != 2 || len(ids) != 2 || ids[1] != vcID(tDelegationVC) {
		t.Fatalf("pair: all=%v previews=%d ids=%v", all, len(previews), ids)
	}
}

func TestInjiPresentCov_PickerAndBuildVPTokenFor(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pemStr, _ := marshalECKeyPEM(key)
	sd := sampleSDJWT(t)
	sess := &Session{
		InjiClaimedVCs: []string{sd, tIdentityVC, tSDJWT}, // tSDJWT has no key -> hidden
		InjiHolderKeys: map[string]string{vcID(sd): pemStr},
	}
	rows := (&H{}).injiPresentableCredsForPicker(sess)
	if len(rows) != 2 {
		t.Fatalf("picker rows = %v", rows)
	}
	if rows[0]["ID"] != vcID(sd) || rows[0]["Format"] != "vc+sd-jwt" || rows[0]["Title"] != "custom-abc" {
		t.Errorf("SD-JWT row = %v", rows[0])
	}
	if rows[1]["ID"] != vcID(tIdentityVC) || rows[1]["Format"] != "ldp_vp" || rows[1]["Title"] != "IdentityCred" {
		t.Errorf("W3C row = %v", rows[1])
	}

	jar := injiJAR{Nonce: "n-1", Aud: "did:web:verifier.example"}
	tok, format, err := injiBuildVPTokenFor(tIdentityVC, nil, jar)
	if err != nil || format != "ldp_vp" || !strings.Contains(tok, `"VerifiablePresentation"`) {
		t.Errorf("W3C: tok=%q format=%q err=%v", tok, format, err)
	}
	tok, format, err = injiBuildVPTokenFor(sd, key, jar)
	if err != nil || format != "vc+sd-jwt" || !strings.HasPrefix(tok, strings.Split(sd, "~")[0]+"~") || strings.Count(tok, "~") != 3 {
		t.Errorf("SD-JWT: tok=%q format=%q err=%v", tok, format, err)
	}
	kb := tok[strings.LastIndex(tok, "~")+1:]
	if strings.Count(kb, ".") != 2 {
		t.Errorf("SD-JWT vp_token must end in a KB-JWT, got %q", kb)
	}
}

// ─── handlers ──────────────────────────────────────────────────────────────────

func TestInjiPresentCov_ShowInjiPresentRequest(t *testing.T) {
	h := injiPresentH(t)
	cookies := seedSession(t, h, func(s *Session) { s.InjiClaimedVCs = []string{tIdentityVC, tDelegationVC} })

	req := htmxMainRequest(http.MethodGet, "/holder/wallet/inji/present?credential="+vcID(tDelegationVC))
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	h.ShowInjiPresentRequest(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, "IdentityCred · ldp_vp") || !strings.Contains(body, `value="`+vcID(tDelegationVC)+`" data-format="ldp_vp" selected`) {
		t.Fatalf("picker markup missing/preselect wrong:\n%s", body)
	}
	if !strings.Contains(body, "Present a request") {
		t.Error("content template not rendered")
	}
}

func TestInjiPresentCov_ConfirmInjiPresentRequest(t *testing.T) {
	h := injiPresentH(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pemStr, _ := marshalECKeyPEM(key)
	sd := sampleSDJWT(t)
	cookies := seedSession(t, h, func(s *Session) {
		s.InjiClaimedVCs = []string{sd, tIdentityVC, tDelegationVC, tSDJWT}
		s.InjiHolderKeys = map[string]string{vcID(sd): pemStr}
	})
	do := func(v url.Values) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		h.ConfirmInjiPresentRequest(rr, formPost("/holder/wallet/inji/present/confirm", v, cookies...))
		return rr
	}

	injiPresentToast(t, do(url.Values{}), "Paste the verifier's request URI")
	injiPresentToast(t, do(url.Values{"request_uri": {"openid4vp://authorize?client_id=x"}}), "Couldn't read the verifier's request: no request_uri")

	single := injiPresentNewVerifier(t, []any{injiPresentDescriptor("d1", "Identity card", "ldp_vp", "last_name")})
	injiPresentToast(t, do(url.Values{"request_uri": {single.requestURI()}}), "Pick a credential to present")
	injiPresentToast(t, do(url.Values{"request_uri": {single.requestURI()}, "credential_id": {vcID(tSDJWT)}}), "can't be presented over OID4VP")

	rr := do(url.Values{"request_uri": {single.requestURI()}, "credential_id": {vcID(tIdentityVC)}})
	body := rr.Body.String()
	if rr.Code != 200 || !strings.Contains(body, "Identity card") || !strings.Contains(body, "did:web:verifier.example") ||
		!strings.Contains(body, "Abdullahi") || !strings.Contains(body, "Disclose →") ||
		!strings.Contains(body, `name="credential_id" value="`+vcID(tIdentityVC)+`"`) || strings.Contains(body, "incompatible") {
		t.Fatalf("single consent card:\n%s", body)
	}
	// Incompatible single pick (SD-JWT requested, W3C held): card renders the reason, no Disclose.
	sdOnly := injiPresentNewVerifier(t, []any{injiPresentDescriptor("d1", "Card", "vc+sd-jwt")})
	body = do(url.Values{"request_uri": {sdOnly.requestURI()}, "credential_id": {vcID(tIdentityVC)}}).Body.String()
	if !strings.Contains(body, "present-consent incompatible") || !strings.Contains(body, "but this one is W3C") || strings.Contains(body, "Disclose →") {
		t.Fatalf("incompatible consent card:\n%s", body)
	}

	pair := injiPresentNewVerifier(t, []any{
		injiPresentDescriptor("id-desc", "Identity", "ldp_vp", "testa_id", "last_name"),
		injiPresentDescriptor("del-desc", "Delegation", "ldp_vp", "onBehalfOf"),
	})
	body = do(url.Values{"request_uri": {pair.requestURI()}}).Body.String()
	if !strings.Contains(body, "2 credentials") || !strings.Contains(body, "Delegation") || !strings.Contains(body, "<dt>onBehalfOf</dt>") ||
		strings.Count(body, `name="credential_id"`) != 2 || !strings.Contains(body, "Disclose →") {
		t.Fatalf("multi consent card:\n%s", body)
	}
}

func TestInjiPresentCov_SubmitInjiPresentRequest(t *testing.T) {
	h := injiPresentH(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pemStr, _ := marshalECKeyPEM(key)
	sd := sampleSDJWT(t)
	badW3C := `{"type":["VerifiableCredential","Broken"` // starts with "{" but is not JSON
	cookies := seedSession(t, h, func(s *Session) {
		s.InjiClaimedVCs = []string{sd, tIdentityVC, tSDJWT, badW3C}
		s.InjiHolderKeys = map[string]string{vcID(sd): pemStr}
	})
	do := func(v url.Values) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		h.SubmitInjiPresentRequest(rr, formPost("/holder/wallet/inji/present/submit", v, cookies...))
		return rr
	}

	injiPresentToast(t, do(url.Values{}), "Paste the verifier's request URI")
	injiPresentToast(t, do(url.Values{"request_uri": {"openid4vp://authorize?client_id=x"}}), "Couldn't read the verifier's request")

	v := injiPresentNewVerifier(t, []any{injiPresentDescriptor("d1", "", "vc+sd-jwt", "last_name")})
	with := func(id string) url.Values { return url.Values{"request_uri": {v.requestURI()}, "credential_id": {id}} }
	injiPresentToast(t, do(url.Values{"request_uri": {v.requestURI()}}), "Pick a credential to present")
	injiPresentToast(t, do(with(vcID(tSDJWT))), "can't be presented over OID4VP")
	injiPresentToast(t, do(with(vcID(tIdentityVC))), "requesting an SD-JWT credential, but this one is W3C")

	// Happy path: SD-JWT + KB-JWT posted; DescName empty -> title from vct.
	rr := do(with(vcID(sd)))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "Presentation shared") || !strings.Contains(rr.Body.String(), "custom-abc") ||
		!strings.Contains(rr.Body.String(), "did:web:verifier.example") {
		t.Fatalf("shared fragment:\n%s", rr.Body.String())
	}
	form := v.lastPost()
	if form == nil || !strings.HasPrefix(form.Get("vp_token"), strings.Split(sd, "~")[0]+"~") || form.Get("state") != "st-1" ||
		!strings.Contains(form.Get("presentation_submission"), `"format":"vc+sd-jwt"`) {
		t.Fatalf("direct_post form = %v", form)
	}

	// Verifier rejects the post.
	v.submitCode = http.StatusBadRequest
	injiPresentToast(t, do(with(vcID(sd))), "Submit presentation: direct-post 400: nope")

	// Build failure: a "{"-prefixed held credential that is not JSON.
	anyFmt := injiPresentNewVerifier(t, []any{injiPresentDescriptor("d1", "Any", "")})
	injiPresentToast(t, do(url.Values{"request_uri": {anyFmt.requestURI()}, "credential_id": {vcID(badW3C)}}), "Build presentation: inji present: W3C credential is not JSON")

	// Named descriptor -> its name is the shared title (W3C ldp_vp path).
	w3c := injiPresentNewVerifier(t, []any{injiPresentDescriptor("d1", "Identity card", "ldp_vp", "last_name")})
	rr = do(url.Values{"request_uri": {w3c.requestURI()}, "credential_id": {vcID(tIdentityVC)}})
	if !strings.Contains(rr.Body.String(), "Identity card") {
		t.Fatalf("W3C shared fragment:\n%s", rr.Body.String())
	}
	if f := w3c.lastPost(); !strings.Contains(f.Get("vp_token"), `"verifiableCredential"`) || !strings.Contains(f.Get("presentation_submission"), `"format":"ldp_vp"`) {
		t.Fatalf("W3C direct_post form = %v", f)
	}
}

func TestInjiPresentCov_SubmitInjiMulti(t *testing.T) {
	h := injiPresentH(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pemStr, _ := marshalECKeyPEM(key)
	sd := sampleSDJWT(t)
	badW3C := `{"type":["VerifiableCredential","Broken"`
	cookies := seedSession(t, h, func(s *Session) {
		s.InjiClaimedVCs = []string{tIdentityVC, sd, badW3C}
		s.InjiHolderKeys = map[string]string{vcID(sd): pemStr}
	})
	do := func(v *injiPresentVerifier) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		h.SubmitInjiPresentRequest(rr, formPost("/holder/wallet/inji/present/submit", url.Values{"request_uri": {v.requestURI()}}, cookies...))
		return rr
	}
	identity := injiPresentDescriptor("id-desc", "Identity", "ldp_vp", "testa_id", "last_name")

	// One leg unmatched.
	injiPresentToast(t, do(injiPresentNewVerifier(t, []any{identity, injiPresentDescriptor("x", "Licence", "ldp_vp", "licence")})),
		"You don't hold all the credentials this request needs.")
	// One leg is an SD-JWT.
	injiPresentToast(t, do(injiPresentNewVerifier(t, []any{identity, injiPresentDescriptor("sd", "Card", "vc+sd-jwt")})),
		"Multi-credential presentation is currently supported for W3C credentials only.")
	// A "{"-prefixed non-JSON leg fits a field-less descriptor but cannot be wrapped.
	injiPresentToast(t, do(injiPresentNewVerifier(t, []any{identity, injiPresentDescriptor("any", "Any", "ldp_vp")})),
		"Build presentation: inji present: W3C credential is not JSON")

	// Two W3C legs: posted as one VP with two path_nested entries.
	h.Sessions.(*Store).Get(formPost("/", nil, cookies...)).InjiClaimedVCs = []string{tIdentityVC, tDelegationVC}
	v := injiPresentNewVerifier(t, []any{identity, injiPresentDescriptor("del-desc", "Delegation", "ldp_vp", "onBehalfOf")})
	v.submitCode = http.StatusInternalServerError
	injiPresentToast(t, do(v), "Submit presentation: direct-post 500: nope")
	v.submitCode = http.StatusOK
	rr := do(v)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "IdentityCred &#43; DelegationCred") || !strings.Contains(rr.Body.String(), "Presentation shared") {
		t.Fatalf("multi shared fragment:\n%s", rr.Body.String())
	}
	form := v.lastPost()
	var vp struct {
		Holder string `json:"holder"`
		VCs    []any  `json:"verifiableCredential"`
	}
	if err := json.Unmarshal([]byte(form.Get("vp_token")), &vp); err != nil || vp.Holder != "did:holder:1" || len(vp.VCs) != 2 {
		t.Fatalf("vp_token = %s (err=%v)", form.Get("vp_token"), err)
	}
	if ps := form.Get("presentation_submission"); strings.Count(ps, `"path_nested"`) != 2 || !strings.Contains(ps, `$.verifiableCredential[1]`) {
		t.Fatalf("presentation_submission = %s", ps)
	}
}

func TestInjiPresentCov_DeclineInjiPresent(t *testing.T) {
	h := injiPresentH(t)
	rr := httptest.NewRecorder()
	h.DeclineInjiPresent(rr, formPost("/holder/wallet/inji/present/decline", nil))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "Presentation declined") || !strings.Contains(rr.Body.String(), "Nothing was sent to the verifier") {
		t.Fatalf("declined fragment:\n%s", rr.Body.String())
	}
}
