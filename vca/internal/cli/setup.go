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
	// Random is the source of generated secrets.
	Random io.Reader
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
	if req.Interactive {
		answers, err := req.Prompter.AskAll(settings, src)
		if err != nil {
			return Plan{}, err
		}
		src.Answers = answers
	}
	list := ResolveAll(settings, src)
	list = applyRoleAndDpg(list, req.Pair)
	list = applyDerivedDefaults(list)
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
	for name, value := range LinkValues(req.Pair, values) {
		extra[name] = value
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

// applyDerivedDefaults fills the values the Config message says follow
// from another value: the internal URL and the OIDC redirect URI.
func applyDerivedDefaults(list []Resolution) []Resolution {
	out := make([]Resolution, len(list))
	copy(out, list)
	public := ""
	for _, r := range out {
		if r.Setting.Path == "public_url" {
			public = strings.TrimRight(r.Value, "/")
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
	defer func() { _ = f.Close() }()
	values, err := ParseDotenv(f)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return values, nil
}

// WritePlan writes every file of the plan under the deploy root.
// A secret file gets mode 0600 (ADR-007 decision 5).
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
		if err := os.WriteFile(path, f.Data, f.Mode); err != nil {
			return nil, fmt.Errorf("write %s: %w", path, err)
		}
		// WriteFile keeps the mode of a file that already exists, so set it.
		if err := os.Chmod(path, f.Mode); err != nil {
			return nil, fmt.Errorf("set the mode of %s: %w", path, err)
		}
		written = append(written, path)
	}
	return written, nil
}
