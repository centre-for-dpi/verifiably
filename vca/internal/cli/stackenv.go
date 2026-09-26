// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// The secrets of a stack file (ADR-055 decision 1). Each stack has a
// directory beside the pair directories under deploy, named after the
// DPG. Its .env holds the database and key store passwords that setup
// generates. The main compose file reads it as the env_file of the
// include of the stack file, and the stack file requires every value
// with ${NAME:?...}, so no stack starts on a default password.

// stackSecretLength is the length of a generated stack secret. The
// letters and digits of the value need no quoting in a database URL, a
// properties file, or a command line.
const stackSecretLength = 32

// stackSecretAlphabet holds the characters of a generated stack secret.
const stackSecretAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// StackSecretsSinceEnv names the time, in RFC 3339, when the secrets of
// a stack .env began. Compose reads it as a variable that no service
// uses.
const StackSecretsSinceEnv = "VCA_STACK_SECRETS_SINCE"

// StackDpgs returns every DPG that has a stack file, in the order of the
// includes of the main compose file.
func StackDpgs() []configv1.Dpg { return Dpgs() }

// stackSecretNames returns the variables of the stack file of one DPG
// that setup generates, in the order of the .env file.
func stackSecretNames(d configv1.Dpg) []string {
	switch d {
	case configv1.Dpg_DPG_WALTID:
		return []string{"WALTID_DB_PASSWORD"}
	case configv1.Dpg_DPG_INJI:
		return []string{
			"INJI_DB_PASSWORD", "INJI_CERTIFY_KEYSTORE_PASSWORD", "INJI_ESIGNET_DB_PASSWORD",
			"INJI_MIMOTO_DB_PASSWORD", "INJI_MIMOTO_KEYSTORE_PASSWORD", "INJI_VERIFY_DB_PASSWORD",
		}
	case configv1.Dpg_DPG_CREDEBL:
		return []string{"CREDEBL_DB_PASSWORD"}
	}
	return nil
}

// stackKey is one generated key of a stack .env that a configuration
// file of the stack holds. No volume keeps it, so a new value costs the
// sessions of the stack and nothing else.
type stackKey struct {
	name   string
	length int
}

// stackKeys returns the keys of the configuration files that setup
// writes for the stack of one DPG, in the order of the .env file. The
// walt.id wallet API reads its keys and the hash pepper from the files
// of ADR-054 decision 3. An AES-128 key and an HMAC key of the legacy
// login take 16 characters.
//
// The database initialisation of CREDEBL encrypts with
// CRYPTO_PRIVATE_KEY and makes the platform wallet with
// PLATFORM_WALLET_PASSWORD and PLATFORM_SEED, which an Indy wallet
// takes as 32 characters (plan section 3.8).
func stackKeys(d configv1.Dpg) []stackKey {
	switch d {
	case configv1.Dpg_DPG_WALTID:
		return []stackKey{
			{WaltidWalletEncryptionKeyEnv, 16},
			{WaltidWalletSignKeyEnv, 16},
			{WaltidWalletTokenKeyEnv, 48},
			{WaltidWalletPepperEnv, stackSecretLength},
		}
	case configv1.Dpg_DPG_CREDEBL:
		// The shared Credo agent of the stack file encrypts its wallet
		// with a key and guards its admin port with an API key of 16
		// characters or more. The schema file server signs the upload
		// tokens of the platform with a secret (P6-C0).
		return []stackKey{
			{"CRYPTO_PRIVATE_KEY", stackSecretLength},
			{"PLATFORM_WALLET_PASSWORD", stackSecretLength},
			{"PLATFORM_SEED", stackSecretLength},
			{SharedAgentWalletKeyEnv, stackSecretLength},
			{SharedAgentAPIKeyEnv, stackSecretLength},
			{SchemaFileServerSecretEnv, stackSecretLength},
		}
	}
	return nil
}

// stackSettingNames returns the values of the operator that the .env of
// a stack carries for its containers, such as the platform admin of
// CREDEBL. A setup run of a pair of the stack writes them. A run of any
// other pair keeps them.
func stackSettingNames(d configv1.Dpg) []string {
	if d == configv1.Dpg_DPG_CREDEBL {
		return []string{PlatformAdminEmailEnv}
	}
	return nil
}

// StackSettings returns the values of the operator that one pair puts in
// the .env of its stack, keyed by DPG. A value the run left empty is
// left out, so an earlier value stays.
func StackSettings(p Pair, values map[string]string) map[configv1.Dpg]map[string]string {
	if p.Dpg != configv1.Dpg_DPG_CREDEBL {
		return nil
	}
	email := strings.TrimSpace(values[PlatformAdminEmailSetting])
	if email == "" {
		return nil
	}
	return map[configv1.Dpg]map[string]string{p.Dpg: {PlatformAdminEmailEnv: email}}
}

// StackDir returns the directory of the secrets of one stack under the
// deploy root, for example inji. A DPG with no stack file gives "".
func StackDir(d configv1.Dpg) string {
	if stackSecretNames(d) == nil {
		return ""
	}
	return ShortName(d.String())
}

// StackEnvFile returns the path of the .env of one stack under the
// deploy root, for example inji/.env. A DPG with no stack file gives "".
func StackEnvFile(d configv1.Dpg) string {
	dir := StackDir(d)
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, EnvFileName)
}

// StackEnv renders the .env of one stack. A value of existing stays, so
// a later run of any role keeps the passwords that the containers and
// their volumes already hold. A missing value comes from random.
//
// The file records when its secrets began in StackSecretsSinceEnv. The
// first run writes now, and a later run keeps the value. A volume older
// than that time holds a password of a release before generated secrets
// (see UpgradeSecrets).
func StackEnv(d configv1.Dpg, existing map[string]string, random io.Reader, now time.Time) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "# The secrets of the %s stack. Every role of the stack shares them.\n", ShortName(d.String()))
	b.WriteString("# The vca setup command wrote this file. A later run keeps every value.\n")
	b.WriteString("# The main compose file reads it for the stack file. Keep it with mode 0600.\n")
	for _, name := range stackSecretNames(d) {
		value := existing[name]
		if value == "" {
			generated, err := randomAlphanumeric(random, stackSecretLength)
			if err != nil {
				return "", fmt.Errorf("generate %s: %w", name, err)
			}
			value = generated
		}
		b.WriteString(name + "=" + quoteValue(value) + "\n")
	}
	keys := map[string]string{}
	if list := stackKeys(d); len(list) > 0 {
		b.WriteString("# The keys of the configuration files that setup writes for the stack.\n")
		for _, k := range list {
			value := existing[k.name]
			if value == "" {
				generated, err := randomAlphanumeric(random, k.length)
				if err != nil {
					return "", fmt.Errorf("generate %s: %w", k.name, err)
				}
				value = generated
			}
			keys[k.name] = value
			b.WriteString(k.name + "=" + quoteValue(value) + "\n")
		}
	}
	if d == configv1.Dpg_DPG_CREDEBL {
		// The upload token of the platform, signed with the secret of the
		// schema file server. A later run keeps it.
		token := existing[SchemaFileServerTokenEnv]
		if token == "" {
			token = schemaFileServerToken(keys[SchemaFileServerSecretEnv], now)
		}
		b.WriteString(SchemaFileServerTokenEnv + "=" + quoteValue(token) + "\n")
	}
	var settings []string
	for _, name := range stackSettingNames(d) {
		if value := existing[name]; value != "" {
			settings = append(settings, name+"="+quoteValue(value)+"\n")
		}
	}
	if len(settings) > 0 {
		b.WriteString("# The settings of the operator for the containers of the stack.\n")
		b.WriteString(strings.Join(settings, ""))
	}
	since := existing[StackSecretsSinceEnv]
	if since == "" {
		since = now.UTC().Format(time.RFC3339)
	}
	b.WriteString("# When these secrets began. A volume older than this holds an older password.\n")
	b.WriteString(StackSecretsSinceEnv + "=" + quoteValue(since) + "\n")
	return b.String(), nil
}

// StackFiles renders the .env of every stack and a .gitignore beside
// each, with paths relative to the deploy root. Every setup run writes
// all of them: the main compose file includes every stack file, and
// compose checks the required variables of each one, whatever profile
// runs. existing holds the values of an earlier run by DPG.
func StackFiles(existing map[configv1.Dpg]map[string]string, random io.Reader, now time.Time) ([]File, error) {
	var out []File
	for _, d := range StackDpgs() {
		env, err := StackEnv(d, existing[d], random, now)
		if err != nil {
			return nil, err
		}
		out = append(out,
			File{Name: StackEnvFile(d), Data: []byte(env), Mode: 0o600},
			File{Name: filepath.Join(StackDir(d), ".gitignore"), Data: []byte("*\n"), Mode: 0o600},
		)
	}
	return out, nil
}

// randomAlphanumeric returns n characters of stackSecretAlphabet. It
// drops a random byte above the last whole multiple of the alphabet
// size, so every character is equally likely.
func randomAlphanumeric(random io.Reader, n int) (string, error) {
	size := len(stackSecretAlphabet)
	limit := 256 - 256%size
	out := make([]byte, 0, n)
	buf := make([]byte, n)
	for len(out) < n {
		if _, err := io.ReadFull(random, buf); err != nil {
			return "", fmt.Errorf("read random bytes: %w", err)
		}
		for _, c := range buf {
			if int(c) >= limit {
				continue
			}
			out = append(out, stackSecretAlphabet[int(c)%size])
			if len(out) == n {
				break
			}
		}
	}
	return string(out), nil
}

// ReadStackEnv reads the .env of one stack under the deploy root. A
// missing file is not an error, so the first run works.
func ReadStackEnv(root string, d configv1.Dpg) (map[string]string, error) {
	name := StackEnvFile(d)
	if name == "" {
		return map[string]string{}, nil
	}
	path := filepath.Join(root, name)
	f, err := os.Open(path) // #nosec G304 -- the path comes from the DPG name
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return map[string]string{}, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	defer func() { anyval.Discard(f.Close()) }()
	values, err := ParseDotenv(f)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	// A file of an earlier release has no stamp. Its last write is the
	// latest moment its secrets can have begun.
	if values[StackSecretsSinceEnv] == "" {
		info, statErr := f.Stat()
		if statErr != nil {
			return nil, fmt.Errorf("read %s: %w", path, statErr)
		}
		values[StackSecretsSinceEnv] = info.ModTime().UTC().Format(time.RFC3339)
	}
	return values, nil
}

// ReadStackEnvs reads the .env of every stack under the deploy root,
// keyed by DPG.
func ReadStackEnvs(root string) (map[configv1.Dpg]map[string]string, error) {
	out := make(map[configv1.Dpg]map[string]string, len(StackDpgs()))
	for _, d := range StackDpgs() {
		values, err := ReadStackEnv(root, d)
		if err != nil {
			return nil, err
		}
		out[d] = values
	}
	return out, nil
}

// The subject of a key manager certificate (ADR-055 decision 3). The
// key managers of Inji Certify and Mimoto read these variables, and the
// stack file passes them from the .env of the pair.
const (
	// KeyCertCNEnv holds the common name: the public host of the pair.
	KeyCertCNEnv = "INJI_KEY_CERT_CN"
	// KeyCertOEnv holds the organisation that setup collected.
	KeyCertOEnv = "INJI_KEY_CERT_O"
	// KeyCertOUEnv holds the organisational unit that setup collected.
	KeyCertOUEnv = "INJI_KEY_CERT_OU"
)

// hasKeyManager reports whether the stack of a pair runs a key manager
// that makes certificates: the Certify of an Inji issuer and the Mimoto
// of an Inji holder.
func hasKeyManager(p Pair) bool {
	if p.Dpg != configv1.Dpg_DPG_INJI {
		return false
	}
	return p.Role == commonv1.Role_ROLE_ISSUER || p.Role == commonv1.Role_ROLE_HOLDER
}

// KeyCertValues returns the subject of the key certificates of a pair
// from its values: the public host, the organisation and the unit. A
// pair with no key manager gets nothing.
func KeyCertValues(p Pair, values map[string]string) map[string]string {
	if !hasKeyManager(p) {
		return nil
	}
	return map[string]string{
		KeyCertCNEnv: hostOf(values["VCA_PUBLIC_URL"]),
		KeyCertOEnv:  values["VCA_ORGANISATION_NAME"],
		KeyCertOUEnv: values["VCA_ORGANISATION_UNIT"],
	}
}

// roleTitle returns the role name with a capital, for example Issuer.
// It is the default organisational unit of a key certificate.
func roleTitle(role commonv1.Role) string {
	name := ShortName(role.String())
	if name == "" {
		return ""
	}
	return strings.ToUpper(name[:1]) + name[1:]
}

// missingStackEnv reports whether a stack has no .env yet.
func missingStackEnv(stacks map[configv1.Dpg]map[string]string) bool {
	for _, d := range StackDpgs() {
		if len(stacks[d]) == 0 {
			return true
		}
	}
	return false
}

// CompleteStacks returns the values of every stack .env after a setup
// run: the values of existing, the settings of the pair from
// StackSettings, and a generated value for each missing secret and key.
// The files of a pair that hold a stack value, such as the walt.id
// wallet files, read them from here, so they always match the .env that
// the same run writes.
func CompleteStacks(existing, settings map[configv1.Dpg]map[string]string, random io.Reader, now time.Time) (map[configv1.Dpg]map[string]string, error) {
	out := make(map[configv1.Dpg]map[string]string, len(StackDpgs()))
	for _, d := range StackDpgs() {
		merged := make(map[string]string, len(existing[d])+len(settings[d]))
		for name, value := range existing[d] {
			merged[name] = value
		}
		for name, value := range settings[d] {
			merged[name] = value
		}
		text, err := StackEnv(d, merged, random, now)
		if err != nil {
			return nil, err
		}
		values, err := ParseDotenv(strings.NewReader(text))
		if err != nil {
			return nil, fmt.Errorf("read the %s stack .env: %w", filepath.Base(StackDir(d)), err)
		}
		out[d] = values
	}
	return out, nil
}
