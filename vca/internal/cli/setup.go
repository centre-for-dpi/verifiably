// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
)

// EnvFileName is the name of the file that setup writes in the output
// directory of a pair.
const EnvFileName = ".env"

// SetupRequest holds everything one setup run needs. The caller supplies
// the sources, so the run does no input or output of its own except the
// prompts and the final write.
type SetupRequest struct {
	// Pair is the role and DPG the run configures.
	Pair Pair
	// Flags holds --set values, keyed by variable name.
	Flags map[string]string
	// Env reads the process environment.
	Env func(string) string
	// File holds the values of the --env-file file.
	File map[string]string
	// Existing holds the values the last run wrote.
	Existing map[string]string
	// Interactive turns the questions on.
	Interactive bool
	// Prompter asks the questions when Interactive is true.
	Prompter Prompter
	// Offers pre-fills one question, keyed by variable name. A --all run
	// passes the answer of the last pair (ADR-007 decision 2).
	Offers map[string]string
	// Random is the source of generated secrets.
	Random io.Reader
	// Domain is the base domain of the deployment. It gives every pair
	// its own host name and puts the Keycloak of the stack behind the
	// reverse proxy of the host. Empty means none.
	Domain string
	// Peers holds the .env values of every pair directory present, from
	// ReadPeerOverrides. The peer list of the pages honours their port
	// overrides and public URLs (ADR-034 decision 1).
	Peers PeerOverrides
}

// Plan is the result of a setup run before anything reaches the disk.
// A plan is data, so a test checks it without a file system.
type Plan struct {
	// Pair is the role and DPG of the plan.
	Pair Pair
	// Resolutions holds every setting with its value and its origin.
	Resolutions []Resolution
	// Ports is the port plan of the services of the pair.
	Ports []PortAssignment
	// Files lists every file the plan writes, including the .env file.
	Files []File
}

// MissingValuesError reports every required value that no source filled.
// The non interactive run fails with it (ADR-007 decision 3).
type MissingValuesError struct {
	// Pair is the role and DPG of the failed run.
	Pair string
	// Settings lists the settings with no value.
	Settings []Setting
}

func (e *MissingValuesError) Error() string {
	lines := make([]string, 0, len(e.Settings)+1)
	lines = append(lines, fmt.Sprintf("setup %s needs %d more values:", e.Pair, len(e.Settings)))
	for _, s := range e.Settings {
		lines = append(lines, fmt.Sprintf("  %s  %s", s.Env, s.Description))
	}
	return strings.Join(lines, "\n")
}

// InvalidValuesError reports every value that breaks a rule.
type InvalidValuesError struct {
	// Pair is the role and DPG of the failed run.
	Pair string
	// Problems lists one error per bad value.
	Problems []error
}

func (e *InvalidValuesError) Error() string {
	lines := make([]string, 0, len(e.Problems)+1)
	lines = append(lines, fmt.Sprintf("setup %s found %d bad values:", e.Pair, len(e.Problems)))
	for _, p := range e.Problems {
		lines = append(lines, "  "+p.Error())
	}
	return strings.Join(lines, "\n")
}

// BuildPlan resolves every setting of the pair, asks the questions the
// higher sources left open, generates the secrets, and renders every file.
// It writes nothing.
func BuildPlan(req SetupRequest) (Plan, error) {
	settings := Filter(Settings(), req.Pair.Role, req.Pair.Dpg)
	src := Sources{
		Flags:    req.Flags,
		Env:      req.Env,
		File:     req.File,
		Existing: req.Existing,
	}
	list := resolveWithDefaults(settings, src, req.Pair, req.Domain)
	if req.Interactive {
		answers, err := req.Prompter.AskAll(list, req.Offers)
		if err != nil {
			return Plan{}, err
		}
		src.Answers = answers
		list = resolveWithDefaults(settings, src, req.Pair, req.Domain)
	}
	list, secretFiles, err := FillSecrets(list, req.Random)
	if err != nil {
		return Plan{}, err
	}
	if missing := Missing(list); len(missing) > 0 {
		return Plan{}, &MissingValuesError{Pair: req.Pair.Name(), Settings: missing}
	}
	values := Values(list)
	if problems := ValidateAll(settings, values); len(problems) > 0 {
		return Plan{}, &InvalidValuesError{Pair: req.Pair.Name(), Problems: problems}
	}
	plan := AssignPorts(req.Pair, values)
	extra := PortValues(plan)
	// The base domain reaches the peer list through the values, and
	// only there: the .env file never records it as a setting.
	linkValues := make(map[string]string, len(values)+1)
	for name, value := range values {
		linkValues[name] = value
	}
	if req.Domain != "" {
		linkValues[DomainEnv] = req.Domain
	}
	for name, value := range LinkValuesWith(req.Pair, linkValues, req.Peers) {
		extra[name] = value
	}
	for name, value := range Passthrough(settings, req.Flags, req.File) {
		extra[name] = value
	}
	if bind, ok := BindAddress(values); ok {
		extra[BindEnv] = bind
	}
	files := []File{{
		Name: EnvFileName,
		Data: []byte(RenderDotenv(req.Pair.Name()+" deployment", list, extra)),
		Mode: 0o600,
	}}
	files = append(files, secretFiles...)
	dpgFiles, err := DpgConfigFiles(req.Pair, values, plan)
	if err != nil {
		return Plan{}, err
	}
	files = append(files, dpgFiles...)
	return Plan{Pair: req.Pair, Resolutions: list, Ports: plan, Files: files}, nil
}

// BindEnv is the variable that holds the address the host ports bind
// to. The compose file reads it, so a public host publishes no service
// port on every interface.
const BindEnv = "VCA_BIND"

// LoopbackAddress is the bind address of a public host. The reverse
// proxy of the host reaches the ports there, and nothing else does.
const LoopbackAddress = "127.0.0.1"

// BindAddress returns the bind address of the host ports of a pair. A
// public host name gets the loopback address. A local public URL gets
// nothing, so compose keeps its default and a laptop reaches the ports
// from any interface.
func BindAddress(values map[string]string) (string, bool) {
	host := hostOf(values["VCA_PUBLIC_URL"])
	if host == "" || isLocalHost(host) {
		return "", false
	}
	return LoopbackAddress, true
}

// PassthroughPrefix marks a variable that setup writes as given. A
// service setting that the proto does not declare, for example the
// CREDEBL operator account of the CREDEBL adapter, reaches the .env
// file this way from a --set flag or an env file.
const PassthroughPrefix = "VCA_"

// Passthrough returns every flag and env file value whose name starts
// with VCA_ and that no setting declares. A flag wins over the file.
func Passthrough(settings []Setting, flags, file map[string]string) map[string]string {
	known := make(map[string]bool, len(settings))
	for _, s := range settings {
		known[s.Env] = true
	}
	out := map[string]string{}
	for _, src := range []map[string]string{file, flags} {
		for name, value := range src {
			if !strings.HasPrefix(name, PassthroughPrefix) || known[name] || strings.TrimSpace(value) == "" {
				continue
			}
			out[name] = value
		}
	}
	return out
}

// resolveWithDefaults resolves every setting and fills every value that
// follows from the pair. The result holds a question only where no
// source and no default supplied a value.
func resolveWithDefaults(settings []Setting, src Sources, p Pair, domain string) []Resolution {
	list := ResolveAll(settings, src)
	list = applyRoleAndDpg(list, p)
	list = applyDomain(list, p, domain)
	list = applyLocalPublicURL(list, p)
	return applyDerivedDefaults(list, p, domain)
}

// applyLocalPublicURL fills an empty public URL with the localhost address
// of the home service of the pair. A laptop deployment then needs no
// public host (ADR-007 decision 4, ADR-008 decision 7).
func applyLocalPublicURL(list []Resolution, p Pair) []Resolution {
	out := make([]Resolution, len(list))
	copy(out, list)
	for i := range out {
		if out[i].Setting.Path != "public_url" || out[i].Value != "" {
			continue
		}
		out[i].Value, out[i].Origin = LocalPublicURL(p), OriginDefault
	}
	return out
}

// LocalPublicURL returns http://localhost with the host port of the
// home service of the pair, so the address opens the home page.
func LocalPublicURL(p Pair) string {
	for _, a := range AssignPorts(p, nil) {
		if a.Service.Name == HomeOf(p.Role).Service {
			return fmt.Sprintf("http://localhost:%d", a.Host)
		}
	}
	return "http://localhost"
}

// applyRoleAndDpg fills the role and the DPG from the flags of the run.
// Those two values never come from a question (ADR-007 decision 2).
func applyRoleAndDpg(list []Resolution, p Pair) []Resolution {
	out := make([]Resolution, len(list))
	copy(out, list)
	for i := range out {
		switch out[i].Setting.Path {
		case "role":
			out[i].Value, out[i].Origin = ShortName(p.Role.String()), OriginFlag
		case "dpg":
			out[i].Value, out[i].Origin = ShortName(p.Dpg.String()), OriginFlag
		}
	}
	return out
}

// applyDerivedDefaults fills every value that follows from the pair or
// from another value. The DPG URL follows from the role and the DPG.
// The internal URL, the OIDC redirect URI, and the OIDC public URL
// follow from the public URL. A base domain puts the Keycloak of the
// stack on its own host name behind the reverse proxy of the host
// (ADR-007 decision 2).
func applyDerivedDefaults(list []Resolution, p Pair, domain string) []Resolution {
	out := make([]Resolution, len(list))
	copy(out, list)
	public := ""
	for _, r := range out {
		if r.Setting.Path == "public_url" {
			public = strings.TrimRight(r.Value, "/")
		}
	}
	pairDefaults := map[string]string{
		"dpg_url":            DefaultDpgURL(p),
		"oidc.discovery_url": DefaultDiscoveryURL(p),
		"oidc.public_url":    OidcPublicURLFor(p, public),
		"oidc.client_id":     DefaultClientID(p.Role),
	}
	oidcOrigin := OriginDefault
	if domain != "" {
		pairDefaults["oidc.public_url"] = KeycloakPublicURL(p.Dpg, domain)
		oidcOrigin = OriginDomain
	}
	for i := range out {
		if out[i].Value != "" {
			continue
		}
		if value := pairDefaults[out[i].Setting.Path]; value != "" {
			out[i].Value, out[i].Origin = value, OriginDefault
			if out[i].Setting.Path == "oidc.public_url" {
				out[i].Origin = oidcOrigin
			}
		}
	}
	if public == "" {
		return out
	}
	for i := range out {
		if out[i].Value != "" {
			continue
		}
		switch out[i].Setting.Path {
		case "internal_url":
			out[i].Value, out[i].Origin = public, OriginDefault
		case "oidc.redirect_uri":
			out[i].Value, out[i].Origin = public+"/auth/callback", OriginDefault
		}
	}
	return out
}

// CarryOffers returns the values that pre-fill the questions of the next
// pair of a --all run. A public host carries over, so the operator
// presses enter to repeat it. A localhost value does not, because each
// pair has its own host port (ADR-007 decision 2).
func CarryOffers(p Plan) map[string]string {
	out := make(map[string]string)
	for _, r := range p.Resolutions {
		if !r.Setting.Prompt || r.Value == "" {
			continue
		}
		if r.Setting.Path == "public_url" && r.Value == LocalPublicURL(p.Pair) {
			continue
		}
		out[r.Setting.Env] = r.Value
	}
	return out
}

// Summary renders the table the CLI shows before it writes anything
// (ADR-007 decision 2). A secret value never appears.
func (p Plan) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Setup plan for %s\n\n", p.Pair.Name())
	b.WriteString("Variable  Value  Source\n")
	for _, r := range p.Resolutions {
		if r.Value == "" {
			continue
		}
		value := r.Value
		if r.Setting.Secret {
			value = Mask(value)
		}
		fmt.Fprintf(&b, "  %s = %s  (%s)\n", r.Setting.Env, value, r.Origin)
	}
	b.WriteString("\nServices and ports\n")
	for _, a := range p.Ports {
		fmt.Fprintf(&b, "  %s  listens on %d, host port %d\n", a.Service.Name, a.Listen, a.Host)
	}
	b.WriteString("\nFiles\n")
	for _, f := range p.Files {
		fmt.Fprintf(&b, "  %s  mode %04o\n", f.Name, f.Mode)
	}
	return b.String()
}

// readableDirMode is the mode of a subdirectory that a container with
// another user id reads, such as the realm directory of Keycloak.
const readableDirMode = 0o755

// makeReadableDir creates a directory with readableDirMode. MkdirAll
// keeps the mode of a directory that already exists, so the function
// sets it as well.
func makeReadableDir(dir string) error {
	if err := os.MkdirAll(dir, readableDirMode); err != nil { //nolint:gosec // another user reads the directory
		return fmt.Errorf("make %s: %w", dir, err)
	}
	if err := os.Chmod(dir, readableDirMode); err != nil { //nolint:gosec // another user reads the directory
		return fmt.Errorf("set the mode of %s: %w", dir, err)
	}
	return nil
}

// OutputDir returns the directory of a pair under the deploy root.
func OutputDir(root string, p Pair) string { return filepath.Join(root, p.Name()) }

// ReadExisting reads the .env file an earlier run wrote. A missing file
// is not an error, so the first run works (ADR-007 decision 5).
func ReadExisting(root string, p Pair) (map[string]string, error) {
	path := filepath.Join(OutputDir(root, p), EnvFileName)
	f, err := os.Open(path) // #nosec G304 -- the path comes from the pair name
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
	if err := upgradeSigningKeyRef(OutputDir(root, p), values); err != nil {
		return nil, err
	}
	return values, nil
}

// ReadPeerOverrides reads the .env file of every pair directory under
// the deploy root, keyed by pair name. A pair with no directory is left
// out. The peer list of a setup run honours the values found here.
func ReadPeerOverrides(root string) (PeerOverrides, error) {
	out := PeerOverrides{}
	for _, p := range AllPairs() {
		path := filepath.Join(OutputDir(root, p), EnvFileName)
		f, err := os.Open(path) // #nosec G304 -- the path comes from the pair name
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		values, perr := ParseDotenv(f)
		anyval.Discard(f.Close())
		if perr != nil {
			return nil, fmt.Errorf("read %s: %w", path, perr)
		}
		out[p.Name()] = values
	}
	return out, nil
}

// legacySigningKeyRef is the value an earlier setup wrote. It named the
// PEM file by a relative path that no container could open.
const legacySigningKeyRef = "file:" + SigningKeyFile

// upgradeSigningKeyRef replaces the legacy file reference with the PEM
// of that file, so a second run of setup repairs an existing pair and
// keeps its key.
func upgradeSigningKeyRef(dir string, values map[string]string) error {
	if values["VCA_SECRETS_SIGNING_KEY"] != legacySigningKeyRef {
		return nil
	}
	path := filepath.Join(dir, SigningKeyFile)
	pemBytes, err := os.ReadFile(path) // #nosec G304 -- the path comes from the pair name
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	values["VCA_SECRETS_SIGNING_KEY"] = SigningKeyRef(pemBytes)
	return nil
}

// WritePlan writes every file of the plan under the deploy root, and the
// default theme file when the root has none yet.
// A secret file gets mode 0600 (ADR-007 decision 5). A file in a
// subdirectory gets that directory with mode 0755, so a container that
// runs as another user, such as Keycloak, reads it.
func WritePlan(root string, p Plan) ([]string, error) {
	dir := OutputDir(root, p.Pair)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("make %s: %w", dir, err)
	}
	written := make([]string, 0, len(p.Files))
	files := make([]File, len(p.Files))
	copy(files, p.Files)
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	for _, f := range files {
		path := filepath.Join(dir, f.Name)
		if sub := filepath.Dir(path); sub != dir {
			if err := makeReadableDir(sub); err != nil {
				return nil, err
			}
		}
		if err := os.WriteFile(path, f.Data, f.Mode); err != nil {
			return nil, fmt.Errorf("write %s: %w", path, err)
		}
		// WriteFile keeps the mode of a file that already exists, so set it.
		if err := os.Chmod(path, f.Mode); err != nil {
			return nil, fmt.Errorf("set the mode of %s: %w", path, err)
		}
		written = append(written, path)
	}
	// The theme file of every page lives next to the compose file. The
	// first setup writes the default; an edited file stays (ADR-032).
	theme := filepath.Join(root, "vca", "theme.yaml")
	wrote, err := WriteDefaultTheme(theme)
	if err != nil {
		return nil, err
	}
	if wrote {
		written = append(written, theme)
	}
	return written, nil
}
