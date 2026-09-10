package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

// loadTrustSigningKey produces the key that signs the trust registry JWT — the
// artefact every federation verifier anchors on. Its failure modes need to be
// loud and specific, because a deployment that silently falls back to an
// ephemeral key issues a registry nobody else can verify across a restart.

func TestLoadTrustSigningKey_EphemeralWhenUnset(t *testing.T) {
	t.Setenv("VERIFIABLY_TRUST_SIGNING_KEY", "")

	key, err := loadTrustSigningKey()
	if err != nil {
		t.Fatalf("unset key must fall back to an ephemeral one: %v", err)
	}
	if key == nil || key.Curve != elliptic.P256() {
		t.Errorf("ephemeral key = %v, want a P-256 key", key)
	}
}

func TestLoadTrustSigningKey_SECG(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("VERIFIABLY_TRUST_SIGNING_KEY",
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})))

	got, err := loadTrustSigningKey()
	if err != nil {
		t.Fatalf("loadTrustSigningKey: %v", err)
	}
	if !got.Equal(k) {
		t.Error("loaded key does not match the configured one")
	}
}

// openssl genpkey emits PKCS#8, which is what an operator following most
// tutorials will paste in. Both encodings must work.
func TestLoadTrustSigningKey_PKCS8(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("VERIFIABLY_TRUST_SIGNING_KEY",
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})))

	got, err := loadTrustSigningKey()
	if err != nil {
		t.Fatalf("PKCS#8 key rejected: %v", err)
	}
	if !got.Equal(k) {
		t.Error("loaded key does not match the configured one")
	}
}

func TestLoadTrustSigningKey_Errors(t *testing.T) {
	t.Run("not PEM", func(t *testing.T) {
		t.Setenv("VERIFIABLY_TRUST_SIGNING_KEY", "clearly not a PEM block")
		if _, err := loadTrustSigningKey(); err == nil {
			t.Fatal("expected an error")
		} else if !strings.Contains(err.Error(), "not valid PEM") {
			t.Errorf("error should say the value is not PEM, got: %v", err)
		}
	})

	// Garbage inside a well-formed PEM envelope: neither the SECG nor the
	// PKCS#8 parse can succeed, and the message must name both attempts so the
	// operator knows it was not a format mismatch.
	t.Run("PEM envelope with garbage DER", func(t *testing.T) {
		t.Setenv("VERIFIABLY_TRUST_SIGNING_KEY",
			string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("not der")})))
		_, err := loadTrustSigningKey()
		if err == nil {
			t.Fatal("expected an error")
		}
		msg := err.Error()
		if !strings.Contains(msg, "EC:") || !strings.Contains(msg, "PKCS8:") {
			t.Errorf("error must report both parse attempts, got: %v", err)
		}
	})

	// A valid PKCS#8 key of the wrong algorithm parses but cannot sign ES256.
	t.Run("RSA key in PKCS#8", func(t *testing.T) {
		der, err := x509.MarshalPKCS8PrivateKey(mustRSAKey(t))
		if err != nil {
			t.Fatal(err)
		}
		t.Setenv("VERIFIABLY_TRUST_SIGNING_KEY",
			string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})))
		_, err = loadTrustSigningKey()
		if err == nil {
			t.Fatal("expected an error for a non-EC key")
		}
		if !strings.Contains(err.Error(), "not an EC key") {
			t.Errorf("error should say the key is not EC, got: %v", err)
		}
	})
}

func mustRSAKey(t *testing.T) any {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}
