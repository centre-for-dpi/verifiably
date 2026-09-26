// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/themefile"
)

// InjiIdentityFile keeps the identity of the Inji issuer in the
// directory of the issuer pair. vca dpg apply inji writes it from the
// adapter, and a holder setup reads it for the issuer list of Mimoto.
const InjiIdentityFile = "identity.json"

// InjiIssuerIdentity is what Inji Web shows of the issuer: the metadata
// of its identity (ADR-046).
type InjiIssuerIdentity struct {
	// DisplayName is the name of the organisation.
	DisplayName string `json:"display_name,omitempty"`
	// LegalIdentifier is its registration number or LEI.
	LegalIdentifier string `json:"legal_identifier,omitempty"`
	// Identifier is the DID or the certificate subject it signs with.
	Identifier string `json:"identifier,omitempty"`
}

// InjiBrand is the part of the theme the issuer list reads: the logo
// file the pair serves under /static, and the wordmark.
type InjiBrand struct {
	// LogoFile is logo.svg, logo.png, or logo.webp, or empty without a
	// logo in the theme.
	LogoFile string
	// Wordmark is the name in the header. Empty means VCA.
	Wordmark string
}

// ReadInjiIssuerIdentity reads the identity file of the Inji issuer
// pair under the deploy root. A missing file gives an empty identity.
func ReadInjiIssuerIdentity(deploy string) (InjiIssuerIdentity, error) {
	path := filepath.Join(OutputDir(deploy, injiIssuer), InjiIdentityFile)
	raw, err := os.ReadFile(path) // #nosec G304 -- the path comes from the deploy root
	if errors.Is(err, os.ErrNotExist) {
		return InjiIssuerIdentity{}, nil
	}
	if err != nil {
		return InjiIssuerIdentity{}, fmt.Errorf("read %s: %w", path, err)
	}
	var id InjiIssuerIdentity
	if err := json.Unmarshal(raw, &id); err != nil {
		return InjiIssuerIdentity{}, fmt.Errorf("read %s: %w", path, err)
	}
	return id, nil
}

// ReadInjiBrand reads the logo and the wordmark of a theme file. A theme
// that does not load gives the default brand, because the theme check
// reports it on its own.
func ReadInjiBrand(path string) InjiBrand {
	f, err := themefile.Load(path)
	if err != nil {
		return InjiBrand{}
	}
	b := f.Config().Brand
	logo := anyval.OrZero(b.Logo.File())
	return InjiBrand{LogoFile: logo.Name, Wordmark: b.Wordmark}
}

// injiIssuerDisplay builds the display of the issuer in Inji Web from
// its identity, the origin of the issuer pair, and the brand. Before the
// issuer names itself, the display names the host of the pair. The
// logo is the logo route of the pair, or an inline image of the
// wordmark. It names no remote asset.
func injiIssuerDisplay(id InjiIssuerIdentity, origin string, brand InjiBrand) mimotoDisplay {
	name := strings.TrimSpace(id.DisplayName)
	if name == "" {
		host := hostOf(origin)
		if host == "" {
			host = "this deployment"
		}
		name = "Issuer of " + host
	}
	d := mimotoDisplay{Name: name, Language: "en", Title: name, Description: "Claim a credential of " + name + "."}
	d.Logo.AltText = "The logo of " + name
	switch {
	case brand.LogoFile != "" && origin != "":
		d.Logo.URL = strings.TrimRight(origin, "/") + "/static/" + brand.LogoFile
	default:
		d.Logo.URL = wordmarkLogo(brand.Wordmark)
	}
	return d
}

// wordmarkLogo returns an inline SVG of the wordmark as a data URI.
func wordmarkLogo(wordmark string) string {
	wordmark = strings.TrimSpace(wordmark)
	if wordmark == "" {
		wordmark = "VCA"
	}
	svg := `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 160 48" role="img">` +
		`<rect width="160" height="48" rx="8" fill="#ffffff" stroke="#1f2a24"/>` +
		`<text x="80" y="31" font-family="sans-serif" font-size="20" font-weight="600" text-anchor="middle" fill="#1f2a24">` +
		html.EscapeString(wordmark) + `</text></svg>`
	return "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(svg))
}

// ApplyOptions holds one run of vca dpg apply inji.
type ApplyOptions struct {
	// Root is the repository root that holds the deploy directory.
	Root string
	// Values are the settings of the Inji issuer pair, from its .env.
	Values map[string]string
	// Client calls the adapter. Nil means http.DefaultClient.
	Client *http.Client
	// Out receives the steps.
	Out io.Writer
	// Run runs docker compose.
	Run Runner
	// Brand is the logo and the wordmark of the theme.
	Brand InjiBrand
}

// DpgApplyInji reads the issuer identity from the adapter of the Inji
// issuer pair, keeps it in the pair directory, rewrites the display of
// the issuer list of Mimoto, and restarts Mimoto and Inji Web, so Inji
// Web shows the issuer as it described itself (plan N8).
func DpgApplyInji(ctx context.Context, opts ApplyOptions) error {
	deploy := filepath.Join(opts.Root, "deploy")
	boot := BootstrapOptions{Pair: injiIssuer, Values: opts.Values, Client: opts.Client, Out: opts.Out}
	base, err := boot.adapterURL()
	if err != nil {
		return err
	}
	res, err := backendv1connect.NewIssuerBackendServiceClient(boot.client(), base).
		GetIssuerIdentity(ctx, connect.NewRequest(&backendv1.GetIssuerIdentityRequest{}))
	if err != nil {
		return fmt.Errorf("dpg apply inji: read the issuer identity at %s: %w", base, err)
	}
	identity := InjiIssuerIdentity{
		DisplayName:     res.Msg.GetIdentity().GetMetadata().GetDisplayName(),
		LegalIdentifier: res.Msg.GetIdentity().GetMetadata().GetLegalIdentifier(),
	}
	if ids := res.Msg.GetIdentity().GetIdentifiers(); len(ids) > 0 {
		identity.Identifier = ids[0]
	}
	raw, err := json.MarshalIndent(identity, "", "  ")
	if err != nil {
		return err
	}
	idPath := filepath.Join(OutputDir(deploy, injiIssuer), InjiIdentityFile)
	if err := os.MkdirAll(filepath.Dir(idPath), 0o750); err != nil {
		return fmt.Errorf("dpg apply inji: %w", err)
	}
	// The file holds public metadata only.
	if err := os.WriteFile(idPath, append(raw, '\n'), 0o644); err != nil { //nolint:gosec // public metadata that a holder setup reads
		return fmt.Errorf("dpg apply inji: write %s: %w", idPath, err)
	}
	var r BootstrapResult
	r.step(opts.Out, "The issuer identity went to %s.", idPath)
	holder := Pair{Role: commonv1.Role_ROLE_HOLDER, Dpg: configv1.Dpg_DPG_INJI}
	if !fileExists(EnvPath(opts.Root, holder)) {
		r.step(opts.Out, "No Inji holder pair runs here, so no issuer list changes. A holder setup reads the identity file.")
		return nil
	}
	if err := rewriteIssuerDisplay(deploy, opts.Root, holder, identity, opts.Brand); err != nil {
		return err
	}
	r.step(opts.Out, "The issuer list of Mimoto names %s.", identityName(identity))
	if opts.Run == nil {
		return errors.New("dpg apply inji: no command runner")
	}
	args := ComposeArgs(opts.Root, holder, []string{"restart", "inji-mimoto", "inji-web"})
	anyval.DiscardWrite(fmt.Fprintf(opts.Out, "docker %s\n", strings.Join(args, " ")))
	if err := opts.Run(ctx, "docker", args); err != nil {
		return fmt.Errorf("dpg apply inji: restart Mimoto and Inji Web: %w", err)
	}
	return nil
}

// fileExists reports whether path names a file that the run can stat.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// identityName is the name the display shows, for a step line.
func identityName(id InjiIssuerIdentity) string {
	if id.DisplayName != "" {
		return id.DisplayName
	}
	return "the host of the issuer pair"
}

// rewriteIssuerDisplay replaces the display of every issuer in the
// issuer list of Mimoto and keeps the rest of the file.
func rewriteIssuerDisplay(deploy, root string, holder Pair, id InjiIssuerIdentity, brand InjiBrand) error {
	path := filepath.Join(deploy, MimotoDir, MimotoIssuersFile)
	raw, err := os.ReadFile(path) // #nosec G304 -- the path comes from the deploy root
	if err != nil {
		return fmt.Errorf("dpg apply inji: read %s: %w; run vca setup --role holder --dpg inji first", path, err)
	}
	var doc map[string][]mimotoIssuer
	if uerr := json.Unmarshal(raw, &doc); uerr != nil {
		return fmt.Errorf("dpg apply inji: read %s: %w", path, uerr)
	}
	f, err := os.Open(EnvPath(root, holder)) // #nosec G304 -- the path comes from the deploy root
	if err != nil {
		return fmt.Errorf("dpg apply inji: %w", err)
	}
	values, err := ParseDotenv(f)
	anyval.Discard(f.Close())
	if err != nil {
		return fmt.Errorf("dpg apply inji: read the holder .env: %w", err)
	}
	display := injiIssuerDisplay(id, originOf(values[injiAuthzIssuerHolderEnv]), brand)
	for i := range doc["issuers"] {
		doc["issuers"][i].Display = []mimotoDisplay{display}
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	// Mimoto and the nginx of Inji Web read the file, and it holds no
	// secret.
	if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil { //nolint:gosec // the containers read the file
		return fmt.Errorf("dpg apply inji: write %s: %w", path, err)
	}
	return nil
}
