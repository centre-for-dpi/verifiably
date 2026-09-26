// SPDX-License-Identifier: Apache-2.0

//go:build contract_inji

package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// formAction reads the action of the login form of Keycloak 25.
var formAction = regexp.MustCompile(`<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"`)

// holderIDToken returns the ID token of a holder that the Mimoto token
// login trusts. VCA_INJI_CONTRACT_ID_TOKEN wins. Else the nightly job
// signs a test holder in at the holder realm of the stack Keycloak with
// VCA_INJI_CONTRACT_HOLDER_USER and _PASSWORD, through the
// authorization code flow with PKCE of the client vca-holder. The
// requests name the host of the issuer that Mimoto expects
// (inji-keycloak:8080 by default) and reach the host port of the stack,
// because Keycloak names the issuer after the host of the request.
func holderIDToken(t *testing.T) string {
	t.Helper()
	if token := os.Getenv("VCA_INJI_CONTRACT_ID_TOKEN"); token != "" {
		return token
	}
	user, password := os.Getenv("VCA_INJI_CONTRACT_HOLDER_USER"), os.Getenv("VCA_INJI_CONTRACT_HOLDER_PASSWORD")
	redirect := os.Getenv("VCA_INJI_CONTRACT_HOLDER_REDIRECT_URI")
	if user == "" || password == "" || redirect == "" {
		return ""
	}
	token, err := keycloakLogin(context.Background(), keycloakLoginRequest{
		Dial:     envOr("VCA_INJI_CONTRACT_KEYCLOAK_ADDRESS", "127.0.0.1:17080"),
		Issuer:   envOr("VCA_INJI_CONTRACT_HOLDER_ISSUER", "http://inji-keycloak:8080/realms/vca-holder-realm"),
		ClientID: envOr("VCA_INJI_CONTRACT_HOLDER_CLIENT_ID", "vca-holder"),
		Redirect: redirect, User: user, Password: password,
	})
	if err != nil {
		t.Fatalf("sign the test holder in: %v", err)
	}
	return token
}

type keycloakLoginRequest struct {
	Dial, Issuer, ClientID, Redirect, User, Password string
}

// keycloakLogin runs the authorization code flow through the login form
// and returns the ID token.
func keycloakLogin(ctx context.Context, req keycloakLoginRequest) (string, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return "", err
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	client := &http.Client{
		Jar:     jar,
		Timeout: 30 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, req.Dial)
		}},
		CheckRedirect: func(r *http.Request, _ []*http.Request) error {
			if strings.HasPrefix(r.URL.String(), req.Redirect) {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	verifier := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(verifier))
	auth := req.Issuer + "/protocol/openid-connect/auth?" + url.Values{
		"client_id": {req.ClientID}, "response_type": {"code"}, "scope": {"openid email profile"},
		"redirect_uri": {req.Redirect}, "state": {verifier[:16]},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
	}.Encode()
	page, err := get(ctx, client, auth)
	if err != nil {
		return "", err
	}
	m := formAction.FindStringSubmatch(page)
	if m == nil {
		return "", errors.New("the login page holds no login form")
	}
	form := url.Values{"username": {req.User}, "password": {req.Password}, "credentialId": {""}}
	post, err := http.NewRequestWithContext(ctx, http.MethodPost, html.UnescapeString(m[1]), strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(post)
	if err != nil {
		return "", err
	}
	_ = resp.Body.Close()
	location, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || location.Query().Get("code") == "" {
		return "", fmt.Errorf("the login answered %d without a code; check the user and the redirect URI", resp.StatusCode)
	}
	grant := url.Values{
		"grant_type": {"authorization_code"}, "code": {location.Query().Get("code")},
		"redirect_uri": {req.Redirect}, "client_id": {req.ClientID}, "code_verifier": {verifier},
	}
	tokenReq, err := http.NewRequestWithContext(ctx, http.MethodPost, req.Issuer+"/protocol/openid-connect/token", strings.NewReader(grant.Encode()))
	if err != nil {
		return "", err
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenResp, err := client.Do(tokenReq)
	if err != nil {
		return "", err
	}
	defer func() { _ = tokenResp.Body.Close() }()
	var tokens struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokens); err != nil || tokens.IDToken == "" {
		return "", fmt.Errorf("the token endpoint answered %d without an ID token", tokenResp.StatusCode)
	}
	return tokens.IDToken, nil
}

func get(ctx context.Context, client *http.Client, target string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return string(body), err
}
