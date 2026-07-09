package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// makeJAR builds a JWS-shaped signed request object (header.payload.sig) whose
// payload is the given claims.
func makeJAR(claims map[string]any) string {
	pl, _ := json.Marshal(claims)
	return "aGVhZGVy." + base64.RawURLEncoding.EncodeToString(pl) + ".c2ln"
}

func TestFetchInjiVPRequest(t *testing.T) {
	jar := makeJAR(map[string]any{
		"nonce":        "nonce-xyz",
		"client_id":    "did:web:verifier",
		"response_uri": "https://verifier.example/submit",
		"state":        "req_123",
		"presentation_definition": map[string]any{
			"id":                "pd-abc",
			"input_descriptors": []any{map[string]any{"id": "vc-1"}},
		},
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
		_, _ = w.Write([]byte(jar))
	}))
	defer srv.Close()

	reqURI := "openid4vp://authorize?client_id=x&request_uri=" + url.QueryEscape(srv.URL+"/jar")
	got, err := (&H{}).fetchInjiVPRequest(context.Background(), reqURI)
	if err != nil {
		t.Fatal(err)
	}
	if got.Nonce != "nonce-xyz" || got.Aud != "did:web:verifier" ||
		got.ResponseURI != "https://verifier.example/submit" || got.State != "req_123" ||
		got.PDID != "pd-abc" || got.DescID != "vc-1" {
		t.Fatalf("parsed JAR = %+v", got)
	}
}

func TestFetchInjiVPRequestErrors(t *testing.T) {
	h := &H{}
	// no request_uri param
	if _, err := h.fetchInjiVPRequest(context.Background(), "openid4vp://authorize?client_id=x"); err == nil {
		t.Error("expected error when request_uri missing")
	}
	// request object missing nonce/response_uri
	bad := makeJAR(map[string]any{"client_id": "did:web:v"})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(bad))
	}))
	defer srv.Close()
	if _, err := h.fetchInjiVPRequest(context.Background(), "openid4vp://authorize?request_uri="+url.QueryEscape(srv.URL)); err == nil {
		t.Error("expected error when nonce/response_uri absent")
	}
}

func TestInjiDirectPost(t *testing.T) {
	var gotForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotForm = r.PostForm
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{}"))
	}))
	defer srv.Close()

	jar := injiJAR{ResponseURI: srv.URL, State: "req_9", PDID: "pd-9", DescID: "vc-1"}
	if err := (&H{}).injiDirectPost(context.Background(), jar, "issuer~disc~kb"); err != nil {
		t.Fatal(err)
	}
	if gotForm.Get("vp_token") != "issuer~disc~kb" {
		t.Errorf("vp_token = %q", gotForm.Get("vp_token"))
	}
	if gotForm.Get("state") != "req_9" {
		t.Errorf("state = %q", gotForm.Get("state"))
	}
	var sub map[string]any
	if err := json.Unmarshal([]byte(gotForm.Get("presentation_submission")), &sub); err != nil {
		t.Fatalf("presentation_submission not JSON: %v", err)
	}
	if sub["definition_id"] != "pd-9" {
		t.Errorf("definition_id = %v", sub["definition_id"])
	}
	dm, _ := sub["descriptor_map"].([]any)
	if len(dm) != 1 {
		t.Fatalf("descriptor_map = %v", sub["descriptor_map"])
	}
	d0, _ := dm[0].(map[string]any)
	if d0["id"] != "vc-1" || d0["format"] != "vc+sd-jwt" || d0["path"] != "$" {
		t.Errorf("descriptor = %v", d0)
	}
}

func TestInjiDirectPostError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("nope"))
	}))
	defer srv.Close()
	err := (&H{}).injiDirectPost(context.Background(), injiJAR{ResponseURI: srv.URL}, "vp")
	if err == nil || !strings.Contains(err.Error(), "direct-post 400") {
		t.Fatalf("expected direct-post 400 error, got %v", err)
	}
}
