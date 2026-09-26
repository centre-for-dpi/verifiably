// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// eSignet 1.5.1 runs in the Inji stack only with a real authenticator
// (ADR-053). The operator names the authenticator at setup. The image
// mosipid/esignet-with-plugins:1.5.1 bundles the MOSIP IDA and the
// Sunbird RC plugins. A custom plugin comes from the operator. The mock
// plugin of the image is not an option.
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
	files := []File{{Name: filepath.Join(EsignetDir, EsignetPropertiesFile), Data: props, Mode: 0o600}}
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
