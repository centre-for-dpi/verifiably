// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// eSignet 1.5.1 runs in the Inji stack only with a real authenticator
// (ADR-053). The operator names the authenticator at setup. The image
// mosipid/esignet-with-plugins:1.5.1 bundles the MOSIP IDA and the
// Sunbird RC plugins. A custom plugin comes from the operator. Only
// these three are options.
const (
	// EsignetAuthenticatorEnv is the setting that names the
	// authenticator. vca deploy reads it from the .env of the pair.
	EsignetAuthenticatorEnv = "VCA_ESIGNET_AUTHENTICATOR"
	// EsignetPluginFileEnv is the setting with the jar of a custom
	// authenticator on the host.
	EsignetPluginFileEnv = "VCA_ESIGNET_PLUGIN_FILE"
	// EsignetPropertiesEnv is the setting with the properties of the
	// plugin on the host.
	EsignetPropertiesEnv = "VCA_ESIGNET_PROPERTIES_FILE"
	// EsignetPluginEnv is the compose variable of the plugin jar that
	// eSignet loads. Every Inji pair sets it, empty without eSignet, so
	// compose can read the stack file for any pair.
	EsignetPluginEnv = "INJI_ESIGNET_PLUGIN"
	// EsignetURLEnv tells the Inji adapter that the pair runs eSignet.
	// The feature answer lists eSignet only then (ADR-053 decision 5).
	EsignetURLEnv = "VCA_INJI_ESIGNET_URL"
	// EsignetInternalURL is eSignet on the compose network.
	EsignetInternalURL = "http://inji-esignet:8088"
	// EsignetProfile is the compose profile of eSignet, its login page,
	// its database, and its Redis.
	EsignetProfile = "esignet-inji"
	// EsignetPropertiesFile is the copy of the plugin properties under
	// the eSignet directory. eSignet reads it as the profile integration.
	EsignetPropertiesFile = "esignet-integration.properties"
	// EsignetCustomPluginDir holds a custom plugin jar under the eSignet
	// directory. The stack file mounts it under the plugins of the image.
	EsignetCustomPluginDir = "vca"
	// EsignetHolderClientEnv and EsignetHolderKeyEnv name eSignet as the
	// holder provider of the holder authorization server of the Inji
	// issuer pair (ADR-053 decision 4): the client id of VCA at eSignet,
	// and the private key of its client assertion as the base64 text of
	// the DER bytes on one line.
	EsignetHolderClientEnv = "VCA_INJI_HOLDER_ESIGNET_CLIENT_ID"
	EsignetHolderKeyEnv    = "VCA_INJI_HOLDER_ESIGNET_CLIENT_KEY" //nolint:gosec // G101: this is a variable name, not a credential.
	// EsignetNone is the authenticator that runs no eSignet.
	EsignetNone = "none"
	// maxEsignetFile caps a file that setup copies.
	maxEsignetFile = 64 << 20
)

// esignetBundledPlugins maps an authenticator to the jar of the image.
var esignetBundledPlugins = map[string]string{
	"mosip-ida":  "mosip-identity-plugin.jar",
	"sunbird-rc": "sunbird-rc-plugin.jar",
}

// esignetAuthenticator returns the authenticator the values name, with
// none for an empty value.
func esignetAuthenticator(values map[string]string) string {
	a := strings.TrimSpace(values[EsignetAuthenticatorEnv])
	if a == "" {
		return EsignetNone
	}
	return a
}

// esignetOn reports whether the values name a real authenticator.
func esignetOn(values map[string]string) bool {
	return esignetAuthenticator(values) != EsignetNone
}

// runsEsignet reports an Inji pair that can run eSignet and its login
// page: the issuer and the holder pairs. The setting decides whether it
// does.
func runsEsignet(p Pair) bool {
	return p.Dpg == configv1.Dpg_DPG_INJI && (p.Role == commonv1.Role_ROLE_ISSUER || p.Role == commonv1.Role_ROLE_HOLDER)
}

// EsignetValues returns the compose variables and the adapter setting
// of eSignet for one pair, and the files setup copies under the eSignet
// directory of the deploy root. read reads a file of the operator. A
// missing or wrong file is an error that names the path.
func EsignetValues(p Pair, values map[string]string, read func(string) ([]byte, error)) (map[string]string, []File, error) {
	if p.Dpg != configv1.Dpg_DPG_INJI {
		return nil, nil, nil
	}
	out := map[string]string{EsignetPluginEnv: ""}
	if !runsEsignet(p) || !esignetOn(values) {
		return out, nil, nil
	}
	authenticator := esignetAuthenticator(values)
	propsPath := strings.TrimSpace(values[EsignetPropertiesEnv])
	if propsPath == "" {
		return nil, nil, fmt.Errorf("the authenticator %s needs its properties file: set %s", authenticator, EsignetPropertiesEnv)
	}
	props, err := readOperatorFile(read, propsPath)
	if err != nil {
		return nil, nil, err
	}
	// The directory holds the secrets of the plugin and the client key,
	// so git ignores all of it.
	files := []File{
		{Name: filepath.Join(EsignetDir, ".gitignore"), Data: []byte("*\n"), Mode: 0o600},
		{Name: filepath.Join(EsignetDir, EsignetPropertiesFile), Data: props, Mode: 0o600},
	}
	plugin, bundled := esignetBundledPlugins[authenticator]
	if !bundled {
		jarPath := strings.TrimSpace(values[EsignetPluginFileEnv])
		if jarPath == "" || !strings.HasSuffix(strings.ToLower(jarPath), ".jar") {
			return nil, nil, fmt.Errorf("the custom authenticator needs its plugin jar: set %s to a .jar file", EsignetPluginFileEnv)
		}
		jar, err := readOperatorFile(read, jarPath)
		if err != nil {
			return nil, nil, err
		}
		name := filepath.Base(jarPath)
		files = append(files, File{Name: filepath.Join(EsignetDir, EsignetCustomPluginDir, name), Data: jar, Mode: 0o600})
		plugin = EsignetCustomPluginDir + "/" + name
	}
	out[EsignetPluginEnv] = plugin
	out[EsignetURLEnv] = EsignetInternalURL
	return out, files, nil
}

// readOperatorFile reads one file of the operator for a copy.
func readOperatorFile(read func(string) ([]byte, error), path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("the eSignet file %s is not an absolute path", path)
	}
	if read == nil {
		read = os.ReadFile
	}
	data, err := read(path)
	if err != nil {
		return nil, fmt.Errorf("read the eSignet file %s: %w", path, err)
	}
	if len(data) == 0 || len(data) > maxEsignetFile {
		return nil, fmt.Errorf("the eSignet file %s is empty or larger than %d MiB", path, maxEsignetFile>>20)
	}
	return data, nil
}

// esignetProfileOf reads the .env of a pair and reports whether its
// compose run adds the eSignet profile. A pair without a .env runs no
// eSignet.
func esignetProfileOf(root string, p Pair) bool {
	if !runsEsignet(p) {
		return false
	}
	f, err := os.Open(EnvPath(root, p)) // #nosec G304 -- the path comes from the deploy root
	if err != nil {
		return false
	}
	defer func() { ignored := f.Close(); _ = ignored }()
	values, err := ParseDotenv(f)
	if err != nil {
		return false
	}
	return esignetOn(values)
}

// ReadEsignetClientKey reads the key of the VCA client of eSignet under
// the deploy root, the file that setup and bootstrap share. A missing
// file gives nil and no error.
func ReadEsignetClientKey(root string) ([]byte, error) {
	path := filepath.Join(root, EsignetDir, EsignetKeyFile)
	raw, err := os.ReadFile(path) // #nosec G304 -- the path comes from the deploy root
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return raw, nil
}

// EsignetHolderValues names eSignet as the holder provider of the holder
// authorization server of the Inji issuer pair when the pair runs eSignet
// (ADR-053 decision 4). The adapter signs its client assertion with the
// key of the VCA client, which bootstrap registers at eSignet. existing is
// the key file of an earlier run, from ReadEsignetClientKey. Without one,
// the run makes a key from random and writes the file with mode 0600.
func EsignetHolderValues(p Pair, values map[string]string, existing []byte, random io.Reader) (map[string]string, []File, error) {
	if p != injiIssuer || !esignetOn(values) {
		return nil, nil, nil
	}
	var files []File
	var key *rsa.PrivateKey
	if len(existing) > 0 {
		block, _ := pem.Decode(existing)
		if block == nil {
			return nil, nil, fmt.Errorf("the eSignet client key %s holds no PEM block", filepath.Join(EsignetDir, EsignetKeyFile))
		}
		parsed, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("the eSignet client key %s: %w", filepath.Join(EsignetDir, EsignetKeyFile), err)
		}
		key = parsed
	} else {
		made, err := rsa.GenerateKey(random, esignetKeyBits)
		if err != nil {
			return nil, nil, fmt.Errorf("make the eSignet client key: %w", err)
		}
		key = made
		files = append(files, File{
			Name: filepath.Join(EsignetDir, EsignetKeyFile),
			Data: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
			Mode: 0o600,
		})
	}
	return map[string]string{
		EsignetHolderClientEnv: EsignetClientID,
		EsignetHolderKeyEnv:    base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PrivateKey(key)),
	}, files, nil
}
