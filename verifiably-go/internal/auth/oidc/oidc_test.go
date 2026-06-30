package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUserInfo_ExtractsClaims(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 base,
			"authorization_endpoint": base + "/authorize",
			"token_endpoint":         base + "/token",
			"userinfo_endpoint":      base + "/userinfo",
		})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sub":            "user-123",
			"email":          "ana@example.gt",
			"name":           "Ana Pérez",
			"given_name":     "Ana",
			"family_name":    "Pérez",
			"birthdate":      "1990-05-01",
			"cedula":         "0801-1990-12345",
			"nationality":    "GT",
			"email_verified": true, // non-string: must be skipped, not crash
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p, err := New(Config{ID: "test", IssuerURL: srv.URL, ClientID: "client"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ui, err := p.UserInfo(context.Background(), "access-token")
	if err != nil {
		t.Fatalf("UserInfo: %v", err)
	}

	if ui.Subject != "user-123" {
		t.Errorf("Subject = %q, want user-123", ui.Subject)
	}
	if ui.Email != "ana@example.gt" {
		t.Errorf("Email = %q, want ana@example.gt", ui.Email)
	}
	if ui.GivenName != "Ana" {
		t.Errorf("GivenName = %q, want Ana", ui.GivenName)
	}
	if ui.FamilyName != "Pérez" {
		t.Errorf("FamilyName = %q, want Pérez", ui.FamilyName)
	}
	if ui.Birthdate != "1990-05-01" {
		t.Errorf("Birthdate = %q, want 1990-05-01", ui.Birthdate)
	}
	if ui.Claims["cedula"] != "0801-1990-12345" {
		t.Errorf("Claims[cedula] = %q, want 0801-1990-12345", ui.Claims["cedula"])
	}
	if ui.Claims["nationality"] != "GT" {
		t.Errorf("Claims[nationality] = %q, want GT", ui.Claims["nationality"])
	}
	if _, ok := ui.Claims["email_verified"]; ok {
		t.Errorf("Claims[email_verified] present, want skipped (non-string claim)")
	}
}

func TestSwapAuthority(t *testing.T) {
	tests := []struct {
		name, endpoint, authority, want string
	}{
		{
			name:      "localhost→container",
			endpoint:  "https://localhost:9443/oauth2/token",
			authority: "https://wso2is:9443",
			want:      "https://wso2is:9443/oauth2/token",
		},
		{
			name:      "container→public",
			endpoint:  "https://wso2is:9443/oauth2/authorize?foo=1",
			authority: "https://172.24.0.1:9443",
			want:      "https://172.24.0.1:9443/oauth2/authorize?foo=1",
		},
		{
			name:      "preserves path, query, scheme change",
			endpoint:  "http://keycloak:8180/realms/x/protocol/openid-connect/token",
			authority: "https://auth.example.com",
			want:      "https://auth.example.com/realms/x/protocol/openid-connect/token",
		},
		{
			name:      "empty endpoint is passthrough",
			endpoint:  "",
			authority: "https://x:1",
			want:      "",
		},
		{
			name:      "empty authority is passthrough",
			endpoint:  "https://localhost:9443/oauth2/token",
			authority: "",
			want:      "https://localhost:9443/oauth2/token",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := swapAuthority(tt.endpoint, tt.authority)
			if got != tt.want {
				t.Errorf("swapAuthority(%q, %q) = %q, want %q", tt.endpoint, tt.authority, got, tt.want)
			}
		})
	}
}

func TestInsecureSkipVerify_ProductionBlocked(t *testing.T) {
	t.Setenv("VERIFIABLY_ENV", "production")
	_, err := New(Config{
		ID:                 "test-idp",
		IssuerURL:          "https://idp.example.com",
		ClientID:           "client",
		InsecureSkipVerify: true,
	})
	if err == nil {
		t.Fatal("expected error when InsecureSkipVerify=true in production, got nil")
	}
	if !strings.Contains(err.Error(), "not allowed") {
		t.Errorf("error %q should mention 'not allowed'", err.Error())
	}
}

func TestInsecureSkipVerify_AllowedOutsideProduction(t *testing.T) {
	t.Setenv("VERIFIABLY_ENV", "development")
	p, err := New(Config{
		ID:                 "test-idp",
		IssuerURL:          "https://idp.example.com",
		ClientID:           "client",
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("expected no error outside production, got: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil provider")
	}
}

func TestInsecureSkipVerify_FalseAlwaysAllowed(t *testing.T) {
	t.Setenv("VERIFIABLY_ENV", "production")
	_, err := New(Config{
		ID:                 "test-idp",
		IssuerURL:          "https://idp.example.com",
		ClientID:           "client",
		InsecureSkipVerify: false,
	})
	if err != nil {
		t.Fatalf("InsecureSkipVerify=false should always succeed, got: %v", err)
	}
}

func TestURLAuthority(t *testing.T) {
	tests := map[string]string{
		"https://wso2is:9443/oauth2/token": "https://wso2is:9443",
		"https://172.24.0.1:9443":          "https://172.24.0.1:9443",
		"http://keycloak:8180/realms/x":    "http://keycloak:8180",
		"":                                  "",
	}
	for in, want := range tests {
		if got := urlAuthority(in); got != want {
			t.Errorf("urlAuthority(%q) = %q, want %q", in, got, want)
		}
	}
}
