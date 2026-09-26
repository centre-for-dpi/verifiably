// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// Mimoto 0.21.0 is the backend of Inji Web 0.16.0. It claims a
// credential through the authorization code flow of eSignet with its
// own client, and signs the client assertion of the token call with the
// key of the client_alias of its issuer list. It reads that key from
// certs/oidckeystore.p12 with the password of oidc_p12_password
// (mosip.oidc.p12.* of its properties). The stack file names the VCA
// client of eSignet in the issuer list, so the holder bootstrap writes
// the key of that client into the key store.
const (
	// MimotoDir is the directory of the key store beside the pair
	// directories. The stack file mounts it read only at
	// /home/mosip/certs. It holds a .gitignore that ignores everything.
	MimotoDir = "mimoto-inji"
	// MimotoKeystoreFile is the key store that Mimoto reads.
	MimotoKeystoreFile = "oidckeystore.p12"
	// MimotoKeystorePasswordEnv is the variable of the key store
	// password in the .env of MimotoDir, which the stack file reads.
	MimotoKeystorePasswordEnv = "oidc_p12_password" //nolint:gosec // G101: this is a variable name, not a credential.
	// DefaultInjiWebURL is the address of Inji Web on the host port of
	// the stack file. VCA_INJI_WEB_URL changes it.
	DefaultInjiWebURL = "http://localhost:17085"
	// MimotoWalletJWKFile is the public key of the key store, as a JWK.
	// The setup run of the Inji issuer pair registers it as the key of
	// the client of Inji Web at the holder authorization server of its
	// adapter (ADR-052 decision 5).
	MimotoWalletJWKFile = "vca-inji.jwk.json"
)

// ReadWalletJWK reads the public key of the client of Inji Web that the
// holder bootstrap wrote under the deploy root. A missing file gives an
// empty key and no error.
func ReadWalletJWK(root string) (string, error) {
	path := filepath.Join(root, MimotoDir, MimotoWalletJWKFile)
	raw, err := os.ReadFile(path) // #nosec G304 -- the path comes from the deploy root
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	if _, err := jose.ParseJWK(raw); err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	return strings.TrimSpace(string(raw)), nil
}

// isInjiHolder reports the holder pair of the Inji stack, which runs
// Mimoto and Inji Web.
func isInjiHolder(p Pair) bool {
	return p.Dpg == configv1.Dpg_DPG_INJI && p.Role == commonv1.Role_ROLE_HOLDER
}

// injiWebURL returns the address of Inji Web that a browser opens.
func injiWebURL(values map[string]string) string {
	if v := strings.TrimRight(strings.TrimSpace(values["VCA_INJI_WEB_URL"]), "/"); v != "" {
		return v
	}
	return DefaultInjiWebURL
}

// mimotoSharedFiles are the files of the Inji holder pair that live
// beside the pair directories: the ignore file of the key store
// directory, the issuer list, and the trusted verifiers (P6-I7h). setup
// writes them, so the directory belongs to the operator before compose
// mounts it.
func mimotoSharedFiles(p Pair, values map[string]string, domain string, peers PeerOverrides) ([]File, error) {
	if !isInjiHolder(p) {
		return nil, nil
	}
	files, err := mimotoFiles(values, domain, peers)
	if err != nil {
		return nil, err
	}
	return append([]File{{Name: filepath.Join(MimotoDir, ".gitignore"), Data: []byte("*\n"), Mode: 0o600}}, files...), nil
}

// writeMimotoKeystore writes the key of the VCA client of eSignet into
// the key store of Mimoto under the client id as its alias. The
// password comes from the .env of the directory, or a new one goes
// there. Both files keep mode 0600.
func writeMimotoKeystore(opts BootstrapOptions, key *rsa.PrivateKey, result *BootstrapResult) error {
	dir := filepath.Join(filepath.Dir(opts.Dir), MimotoDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("make the Mimoto key store directory: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte("*\n"), 0o600); err != nil {
		return fmt.Errorf("write the Mimoto key store directory: %w", err)
	}
	envPath := filepath.Join(dir, EnvFileName)
	password, err := mimotoPassword(envPath)
	if err != nil {
		return err
	}
	store, err := EncodePKCS12(key, EsignetClientID, password, rand.Reader)
	if err != nil {
		return err
	}
	storePath := filepath.Join(dir, MimotoKeystoreFile)
	if werr := os.WriteFile(storePath, store, 0o600); werr != nil {
		return fmt.Errorf("write the Mimoto key store: %w", werr)
	}
	// The public half goes beside it, for the holder authorization server
	// of the issuer pair. It holds no secret.
	pub, err := jose.PublicJWK(key, "")
	if err != nil {
		return fmt.Errorf("the public key of the Mimoto key store: %w", err)
	}
	raw, err := json.Marshal(pub)
	if err != nil {
		return fmt.Errorf("the public key of the Mimoto key store: %w", err)
	}
	jwkPath := filepath.Join(dir, MimotoWalletJWKFile)
	if err := os.WriteFile(jwkPath, append(raw, '\n'), 0o644); err != nil { //nolint:gosec // G306: a public key
		return fmt.Errorf("write the public key of the Mimoto key store: %w", err)
	}
	result.step(opts.Out, "The public key of Inji Web written to %s. Run vca setup and vca deploy for the Inji issuer pair, "+
		"so its holder authorization server accepts Inji Web", jwkPath)
	result.step(opts.Out, "Mimoto key store written to %s with the key of %s. Run vca deploy again so Mimoto reads it",
		storePath, EsignetClientID)
	return nil
}

// mimotoPassword reads the key store password of the .env, or writes a
// new one.
func mimotoPassword(path string) (string, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- the path comes from the deploy root
	if err == nil {
		values, perr := ParseDotenv(bytes.NewReader(raw))
		if perr != nil {
			return "", fmt.Errorf("read %s: %w", path, perr)
		}
		if v := values[MimotoKeystorePasswordEnv]; v != "" {
			return v, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	password, err := RandomSecret(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate the Mimoto key store password: %w", err)
	}
	var b strings.Builder
	b.WriteString("# The key store of Mimoto in the Inji stack. vca dpg bootstrap wrote this file.\n")
	b.WriteString("# The stack file reads it. A later run keeps the password.\n")
	b.WriteString(MimotoKeystorePasswordEnv + "=" + quoteValue(password) + "\n")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		return "", fmt.Errorf("write %s: %w", path, err)
	}
	return password, nil
}
