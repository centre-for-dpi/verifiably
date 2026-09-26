// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// The configuration of the walt.id stack that setup writes (ADR-054).
// walt.id 0.18.2 reads every file of the config directory of its working
// directory, and code defaults fill the rest. Without a file the issuer
// API advertises the example catalogue of the release, and the wallet API
// runs on the defaults of the release. So setup writes the catalogue in
// the directory of the issuer pair and the wallet files in the directory
// of the holder pair. The stack file mounts both read only.

// WaltidConfigDir is the directory of the walt.id files inside the
// directory of a pair.
const WaltidConfigDir = "config"

// WaltidIssuerCatalogueFile is the catalogue of the issuer API, relative
// to the directory of the issuer pair.
const WaltidIssuerCatalogueFile = WaltidConfigDir + "/credential-issuer-metadata.conf"

// WaltidCataloguePrefix starts the id of every catalogue entry that
// setup writes. The walt.id adapter signs through these entries only.
const WaltidCataloguePrefix = "vca_"

// The keys of the wallet API in the .env of the walt.id stack. Setup
// generates each one once and a later run keeps it (ADR-054 decision 3).
const (
	// WaltidWalletEncryptionKeyEnv encrypts the session cookie.
	WaltidWalletEncryptionKeyEnv = "WALTID_WALLET_ENCRYPTION_KEY" //nolint:gosec // G101: a variable name, not a credential
	// WaltidWalletSignKeyEnv signs the session cookie.
	WaltidWalletSignKeyEnv = "WALTID_WALLET_SIGN_KEY" //nolint:gosec // G101: a variable name, not a credential
	// WaltidWalletTokenKeyEnv signs the login token with HS256.
	WaltidWalletTokenKeyEnv = "WALTID_WALLET_TOKEN_KEY" //nolint:gosec // G101: a variable name, not a credential
	// WaltidWalletPepperEnv salts the password hashes.
	WaltidWalletPepperEnv = "WALTID_WALLET_PEPPER"
)

// waltidWalletAddress is the address of the wallet API on the compose
// network. The walt.id adapter of the holder pair calls it, so the login
// token names it as its issuer and audience.
const waltidWalletAddress = "http://waltid-wallet-api:7001"

// waltidEntry is one entry of the catalogue: one wire format.
type waltidEntry struct {
	id     string
	format string
	body   []string
}

// waltidCatalogue lists one entry per wire format that VCA issues. The
// binding methods and the algorithms are the ones the release uses for
// a type list entry. No entry has display text: the portal shows the
// schema of the issuer, not the catalogue.
func waltidCatalogue() []waltidEntry {
	w3c := []string{
		`cryptographic_binding_methods_supported = ["did"]`,
		`credential_signing_alg_values_supported = ["EdDSA", "ES256", "ES256K", "RSA"]`,
		`credential_definition = {`,
		`    type = ["VerifiableCredential"]`,
		`}`,
	}
	sdJwt := []string{
		`cryptographic_binding_methods_supported = ["jwk"]`,
		`credential_signing_alg_values_supported = ["EdDSA", "ES256"]`,
	}
	return []waltidEntry{
		{"vca_jwt_vc_json", "jwt_vc_json", w3c},
		{"vca_ldp_vc", "ldp_vc", w3c},
		{"vca_vc_sd_jwt", `"vc+sd-jwt"`, sdJwt},
		{"vca_dc_sd_jwt", `"dc+sd-jwt"`, sdJwt},
		{"vca_mso_mdoc", "mso_mdoc", []string{
			`cryptographic_binding_methods_supported = ["cose_key"]`,
			`credential_signing_alg_values_supported = ["ES256"]`,
			`doctype = "vca.mdoc"`,
			`proof_types_supported = {`,
			`    cwt = { proof_signing_alg_values_supported = ["ES256"] }`,
			`}`,
		}},
	}
}

// WaltidCatalogueIDs returns the id of every catalogue entry.
func WaltidCatalogueIDs() []string {
	entries := waltidCatalogue()
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.id)
	}
	return out
}

// WaltidIssuerCatalogue renders credential-issuer-metadata.conf. It
// replaces the default list of the release, so the issuer API
// advertises the entries of VCA and nothing else (ADR-054 decision 1).
func WaltidIssuerCatalogue() string {
	var b strings.Builder
	b.WriteString("# The catalogue of the walt.id issuer API. The vca setup command wrote it.\n")
	b.WriteString("# One entry per wire format. The walt.id adapter signs each schema through\n")
	b.WriteString("# the entry of its format. The credential carries the type of the schema.\n")
	b.WriteString("supportedCredentialTypes = {\n")
	for _, e := range waltidCatalogue() {
		fmt.Fprintf(&b, "    %s = {\n", e.id)
		fmt.Fprintf(&b, "        format = %s\n", e.format)
		for _, line := range e.body {
			b.WriteString("        " + line + "\n")
		}
		b.WriteString("    }\n")
	}
	b.WriteString("}\n")
	return b.String()
}

// WaltidWalletFile returns the path of one wallet API file, relative to
// the directory of the holder pair.
func WaltidWalletFile(name string) string { return WaltidConfigDir + "/" + name }

// waltidWalletFiles renders the five wallet API files from the values
// of the walt.id stack .env. A missing value is an error: the files
// never fall back to a key of the release.
func waltidWalletFiles(stack map[string]string) ([]File, error) {
	need := []string{"WALTID_DB_PASSWORD", WaltidWalletEncryptionKeyEnv, WaltidWalletSignKeyEnv,
		WaltidWalletTokenKeyEnv, WaltidWalletPepperEnv}
	for _, name := range need {
		if stack[name] == "" {
			return nil, fmt.Errorf("walt.id wallet: the stack .env has no %s", name)
		}
	}
	auth := "# The legacy login of the walt.id wallet API. The vca setup command wrote it.\n" +
		"# The keys come from the .env of the walt.id stack. A later run keeps them.\n" +
		hoconString("encryptionKey", stack[WaltidWalletEncryptionKeyEnv]) +
		hoconString("signKey", stack[WaltidWalletSignKeyEnv]) +
		"# A key that is not a JWK signs the login token with HS256.\n" +
		hoconString("tokenKey", stack[WaltidWalletTokenKeyEnv]) +
		hoconString("issTokenClaim", waltidWalletAddress) +
		hoconString("audTokenClaim", waltidWalletAddress) +
		"# The lifetime of a login token in days.\n" +
		hoconString("tokenLifetime", "1")
	authnz := "# The newer login of the walt.id wallet API. _features.conf leaves it off.\n" +
		"# The vca setup command wrote this file with a pepper of the deployment.\n" +
		"requireHttps = false\n" +
		hoconString("pepper", stack[WaltidWalletPepperEnv]) +
		"hashAlgorithm = ARGON2\n" +
		"authFlow = {\n    method: email\n    expiration: \"1d\"\n    ok: true\n}\n" +
		"cookieDomain = null\n" +
		"tokenType = STORE_IN_MEMORY\n"
	defaults := "# The key and the DID that the wallet API makes for a new wallet.\n" +
		"# The vca setup command wrote this file. No issuer is registered by default.\n" +
		"defaultKeyConfig: {\n    backend: jwk\n    keyType: secp256r1\n}\n" +
		"defaultDidConfig: {\n    method: jwk\n}\n"
	db := "# The database of the walt.id wallet API. The vca setup command wrote it.\n" +
		"# The password is the one of the .env of the walt.id stack.\n" +
		"dataSource {\n" +
		"    " + hoconString("jdbcUrl", "jdbc:postgresql://waltid-postgres:5432/waltid") +
		"    " + hoconString("driverClassName", "org.postgresql.Driver") +
		"    " + hoconString("username", "waltid") +
		"    " + hoconString("password", stack["WALTID_DB_PASSWORD"]) +
		"    transactionIsolation = \"TRANSACTION_SERIALIZABLE\"\n" +
		"    maximumPoolSize = 16\n    minimumIdle = 4\n    maxLifetime = 60000\n    autoCommit = false\n" +
		"}\n" +
		"recreateDatabaseOnStart = false\n"
	features := "# The features of the walt.id wallet API. The vca setup command wrote it.\n" +
		"# The legacy login stays on by default. The developer mode stays off.\n" +
		"enabledFeatures = [\n]\n" +
		"disabledFeatures = [\n    dev-mode\n]\n"
	return []File{
		{Name: WaltidWalletFile("auth.conf"), Data: []byte(auth), Mode: 0o600},
		{Name: WaltidWalletFile("ktor-authnz.conf"), Data: []byte(authnz), Mode: 0o600},
		{Name: WaltidWalletFile("registration-defaults.conf"), Data: []byte(defaults), Mode: 0o644},
		{Name: WaltidWalletFile("db.conf"), Data: []byte(db), Mode: 0o600},
		{Name: WaltidWalletFile("_features.conf"), Data: []byte(features), Mode: 0o644},
	}, nil
}

// hoconString renders one line key = "value". The generated values hold
// letters and digits only, and the fixed ones hold no quote.
func hoconString(key, value string) string {
	return key + " = \"" + value + "\"\n"
}

// WaltidFiles renders the walt.id files of a pair from the values of the
// walt.id stack .env: the catalogue for the issuer pair and the wallet
// files for the holder pair. Every other pair gets nothing.
func WaltidFiles(p Pair, stack map[string]string) ([]File, error) {
	if p.Dpg != configv1.Dpg_DPG_WALTID {
		return nil, nil
	}
	switch p.Role {
	case commonv1.Role_ROLE_ISSUER:
		return []File{{Name: WaltidIssuerCatalogueFile, Data: []byte(WaltidIssuerCatalogue()), Mode: 0o644}}, nil
	case commonv1.Role_ROLE_HOLDER:
		return waltidWalletFiles(stack)
	}
	return nil, nil
}

// CompleteStacks returns the values of every stack .env after a setup
// run: the values of existing, and a generated value for each missing
// secret and key. The files of a pair that hold a stack value, such as
// the walt.id wallet files, read them from here, so they always match
// the .env that the same run writes.
func CompleteStacks(existing map[configv1.Dpg]map[string]string, random io.Reader, now time.Time) (map[configv1.Dpg]map[string]string, error) {
	out := make(map[configv1.Dpg]map[string]string, len(StackDpgs()))
	for _, d := range StackDpgs() {
		text, err := StackEnv(d, existing[d], random, now)
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
