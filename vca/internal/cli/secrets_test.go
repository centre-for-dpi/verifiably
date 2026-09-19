// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
)

// shortReader gives fewer bytes than the caller asks for.
type shortReader struct{ n int }

func (r *shortReader) Read(p []byte) (int, error) {
	if r.n <= 0 {
		return 0, errors.New("no more bytes")
	}
	read := min(r.n, len(p))
	for i := 0; i < read; i++ {
		p[i] = 7
	}
	r.n -= read
	return read, nil
}

func TestRandomSecret(t *testing.T) {
	got, err := RandomSecret(bytes.NewReader(bytes.Repeat([]byte{1}, 32)))
	if err != nil {
		t.Fatalf("RandomSecret: %v", err)
	}
	if len(got) < 40 {
		t.Errorf("secret is too short: %q", got)
	}
	if strings.ContainsAny(got, "+/=") {
		t.Errorf("secret is not base64 without padding: %q", got)
	}
	if _, err := RandomSecret(&shortReader{n: 3}); err == nil {
		t.Fatal("a short reader passed")
	}
}

func TestSigningKeyPEM(t *testing.T) {
	got, err := SigningKeyPEM(rand.Reader)
	if err != nil {
		t.Fatalf("SigningKeyPEM: %v", err)
	}
	block, _ := pem.Decode(got)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("not a private key PEM: %q", got)
	}
	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		t.Fatalf("ParsePKCS8PrivateKey: %v", err)
	}
	if _, err := SigningKeyPEM(&shortReader{n: 1}); err == nil {
		t.Fatal("a short reader passed")
	}
}

func TestFillSecretsGeneratesAndKeeps(t *testing.T) {
	list := []Resolution{
		{Setting: Setting{Path: "secrets.signing_key", Env: "VCA_SECRETS_SIGNING_KEY", Secret: true, Required: true, Kind: KindSecretRef}},
		{Setting: Setting{Path: "secrets.session_key", Env: "VCA_SECRETS_SESSION_KEY", Secret: true, Required: true, Kind: KindSecretRef}},
		{Setting: Setting{Path: "secrets.dpg_api_key", Env: "VCA_SECRETS_DPG_API_KEY", Secret: true, Kind: KindSecretRef}},
		{Setting: Setting{Path: "database_url", Env: "VCA_DATABASE_URL", Secret: true, Required: true}},
		{Setting: Setting{Path: "public_url", Env: "VCA_PUBLIC_URL", Required: true}, Value: "https://x.example"},
	}
	out, files, err := FillSecrets(list, rand.Reader)
	if err != nil {
		t.Fatalf("FillSecrets: %v", err)
	}
	if out[0].Value != "file:"+SigningKeyFile {
		t.Errorf("signing key value = %q", out[0].Value)
	}
	if len(files) != 1 || files[0].Name != SigningKeyFile || files[0].Mode != 0o600 {
		t.Fatalf("files = %+v", files)
	}
	if out[1].Value == "" {
		t.Error("the session key was not generated")
	}
	if out[2].Value != "" {
		t.Error("an optional secret was generated")
	}
	if out[3].Value != "" {
		t.Error("a connection URL was generated")
	}
	if out[4].Value != "https://x.example" {
		t.Error("a plain value changed")
	}
	if list[1].Value != "" {
		t.Error("FillSecrets changed its input")
	}
}

func TestFillSecretsIsRerunnable(t *testing.T) {
	list := []Resolution{
		{Setting: Setting{Path: "secrets.session_key", Env: "VCA_SECRETS_SESSION_KEY", Secret: true, Required: true, Kind: KindSecretRef}, Value: "kept", Origin: OriginExisting},
		{Setting: Setting{Path: "secrets.signing_key", Env: "VCA_SECRETS_SIGNING_KEY", Secret: true, Required: true, Kind: KindSecretRef}, Value: "file:" + SigningKeyFile, Origin: OriginExisting},
	}
	out, files, err := FillSecrets(list, rand.Reader)
	if err != nil {
		t.Fatalf("FillSecrets: %v", err)
	}
	if out[0].Value != "kept" {
		t.Errorf("an existing secret changed to %q", out[0].Value)
	}
	if len(files) != 0 {
		t.Errorf("a second run rewrote %d files", len(files))
	}
}

func TestFillSecretsReportsRandomFailure(t *testing.T) {
	signing := []Resolution{{Setting: Setting{Path: "secrets.signing_key", Secret: true, Required: true, Kind: KindSecretRef}}}
	if _, _, err := FillSecrets(signing, &shortReader{n: 1}); err == nil {
		t.Error("a failing reader passed for the signing key")
	}
	session := []Resolution{{Setting: Setting{Path: "secrets.session_key", Secret: true, Required: true, Kind: KindSecretRef}}}
	if _, _, err := FillSecrets(session, &shortReader{n: 2}); err == nil {
		t.Error("a failing reader passed for the session key")
	}
}

func TestMask(t *testing.T) {
	if Mask("") != "" {
		t.Error("an empty value got a mask")
	}
	if got := Mask("top secret"); got != "********" || strings.Contains(got, "secret") {
		t.Errorf("Mask leaked the value: %q", got)
	}
}
