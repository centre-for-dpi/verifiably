// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
)

// SigningKeyFile is the name of the generated signing key inside the
// output directory of a role and DPG pair.
const SigningKeyFile = "signing-key.pem"

// secretBytes is the length of a generated random secret.
const secretBytes = 32

// File is one file the CLI writes into the output directory.
type File struct {
	// Name is the path inside the output directory.
	Name string
	// Data is the content.
	Data []byte
	// Mode is the file mode. A secret gets 0600 (ADR-007 decision 5).
	Mode fs.FileMode
}

// RandomSecret returns 32 random bytes as base64 without padding.
func RandomSecret(random io.Reader) (string, error) {
	buf := make([]byte, secretBytes)
	if _, err := io.ReadFull(random, buf); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// SigningKeyPEM returns a new ES256 private key in PKCS#8 PEM form.
func SigningKeyPEM(random io.Reader) ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), random)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("encode signing key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// FillSecrets gives every required secret setting a value when no source
// supplied one. It returns the updated resolutions and the files to write.
// The signing key goes into its own file. Every other secret is inline.
// A run that already has a value changes nothing, so setup is re-runnable
// (ADR-007 decision 5).
func FillSecrets(list []Resolution, random io.Reader) ([]Resolution, []File, error) {
	out := make([]Resolution, len(list))
	copy(out, list)
	var files []File
	for i, r := range out {
		if r.Value != "" || !r.Setting.Secret || !r.Setting.Required {
			continue
		}
		if r.Setting.Kind != KindSecretRef {
			// A connection URL is a secret, but only an operator knows it.
			continue
		}
		if r.Setting.Path == "secrets.signing_key" {
			pemBytes, err := SigningKeyPEM(random)
			if err != nil {
				return nil, nil, err
			}
			files = append(files, File{Name: SigningKeyFile, Data: pemBytes, Mode: 0o600})
			out[i].Value = SigningKeyRef(pemBytes)
			out[i].Origin = OriginExisting
			continue
		}
		value, err := RandomSecret(random)
		if err != nil {
			return nil, nil, err
		}
		out[i].Value = value
		out[i].Origin = OriginExisting
	}
	return out, files, nil
}

// SigningKeyRefPrefix marks a signing key reference that carries the
// PEM itself as base64. The services read this form, the PEM text, and
// a file path.
const SigningKeyRefPrefix = "base64:"

// SigningKeyRef returns the value of VCA_SECRETS_SIGNING_KEY for one
// PEM. The key travels in the .env file, which has mode 0600 like the
// PEM file, because a file on the host belongs to the operator and the
// container user 65532 cannot read it (ADR-005 decision 2).
func SigningKeyRef(pemBytes []byte) string {
	return SigningKeyRefPrefix + base64.StdEncoding.EncodeToString(pemBytes)
}

// Mask hides a secret value in a summary or a log.
func Mask(value string) string {
	if value == "" {
		return ""
	}
	return "********"
}
