// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	"github.com/centre-for-dpi/vc-adapters/internal/themefile"
)

// Version is the version the CLI prints. The release build sets it with
// the linker flag -X (ADR-006 decision 3).
var Version = "dev"

// Environment holds every input and output of one CLI run. The command
// tree touches nothing outside it, so a test drives the whole CLI
// (ADR-004).
type Environment struct {
	// Root is the repository root that holds the deploy directory.
	Root string
	// Args are the command line arguments after the program name.
	Args []string
	// In is the answer source of the setup questions.
	In io.Reader
	// Out receives the normal output.
	Out io.Writer
	// ErrOut receives the errors.
	ErrOut io.Writer
	// Getenv reads the process environment.
	Getenv func(string) string
	// Random is the source of secrets and PKCE values.
	Random io.Reader
	// Run runs docker compose.
	Run Runner
	// Output runs docker and returns its output. The deploy command
	// reads the compose configuration and the container list with it.
	// Nil runs the real docker when Run is nil as well; a test that gives
	// only Run gets no container name check.
	Output OutputRunner
	// HTTP makes the DPG and admin calls.
	HTTP *http.Client
	// StateDir holds the saved admin token.
	StateDir string
	// OpenDB opens the legacy database of vca migrate export. Nil opens
	// it with database/sql.
	OpenDB OpenDB
	// Getwd reads the working directory. The CLI walks up from it to
	// find the repository root. Nil reads it with os.Getwd.
	Getwd func() (string, error)
	// NewProbe reads the host for the doctor command and for the memory
	// hint of the setup command. Nil reads the real host.
	NewProbe func(context.Context) Probe
	// IsTTY reports whether a person watches the input. The CLI asks the
	// role and the DPG only then (ADR-007 decision 2). Nil reads the real
	// standard input, unless the caller supplied In.
	IsTTY func() bool
}

// withDefaults fills the fields a caller left empty.
func (e Environment) withDefaults() Environment {
	inGiven := e.In != nil
	if e.Root == "" {
		e.Root = "."
	}
	if e.In == nil {
		e.In = os.Stdin
	}
	if e.IsTTY == nil {
		e.IsTTY = func() bool { return !inGiven && stdinIsTerminal() }
	}
	if e.Out == nil {
		e.Out = os.Stdout
	}
	if e.ErrOut == nil {
		e.ErrOut = os.Stderr
	}
	if e.Getenv == nil {
		e.Getenv = os.Getenv
	}
	if e.Random == nil {
		e.Random = rand.Reader
	}
	if e.Getwd == nil {
		e.Getwd = os.Getwd
	}
	if e.NewProbe == nil {
		e.NewProbe = func(ctx context.Context) Probe { return NewSystemProbe(ctx) }
	}
	if e.Run == nil {
		e.Run = ExecRunner(e.Out, e.ErrOut)
		if e.Output == nil {
			e.Output = commandOutput
		}
	}
	if e.StateDir == "" {
		e.StateDir = filepath.Join(e.Root, "deploy", ".vca")
	}
	return e
}

// stdinIsTerminal reports whether the standard input is a character
// device. A pipe and a file are not, so a script asks nothing.
func stdinIsTerminal() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// Execute runs the CLI and returns the process exit status.
func Execute(env Environment) int {
	errOut := env.ErrOut
	if errOut == nil {
		errOut = os.Stderr
	}
	root := NewRootCommand(env)
	root.SetArgs(env.Args)
	if err := root.Execute(); err != nil {
		anyval.DiscardWrite(fmt.Fprintf(errOut, "vca: %s\n", err))
		return 1
	}
	return 0
}

// AllChoice is the menu line that stands for every role or every DPG.
const AllChoice = "all"

// RoleQuestion and DpgQuestion head the two selection menus.
const (
	RoleQuestion = "Which role?"
	DpgQuestion  = "Which DPG?"
)

// selection holds the --role, --dpg, --all, and --non-interactive flags
// of one command.
type selection struct {
	role string
	dpg  string
	all  bool
	// nonInteractive stops every question. The run then fails on a
	// missing name (ADR-007 decision 3).
	nonInteractive bool
	// allowAll says the command takes --all, so the menus offer "all".
	allowAll bool
	// everyDpg says the operator chose one role with every DPG.
	everyDpg bool
}

// roleChoices lists the role menu in proto order. No DPG and no role is
// a default or a first choice (ADR-001 decision 2, ADR-002 decision 2).
func (s selection) roleChoices() []string {
	return withAll(RoleNames(), s.allowAll)
}

// dpgChoices lists the DPG menu in proto order.
func (s selection) dpgChoices() []string {
	return withAll(DpgNames(), s.allowAll)
}

// withAll appends the "all" line when the command takes --all.
func withAll(names []string, allowAll bool) []string {
	if !allowAll {
		return names
	}
	return append(names, AllChoice)
}

// ask fills a missing --role or --dpg from a numbered menu. It asks
// nothing when the run is not interactive, so that run keeps the error
// of a missing name (ADR-007 decision 2).
func (s *selection) ask(p Prompter, interactive bool) error {
	if !interactive || s.all {
		return nil
	}
	if s.role == "" {
		choice, err := p.Choose(RoleQuestion, s.roleChoices())
		if err != nil {
			return err
		}
		if choice == AllChoice {
			s.all = true
		} else {
			s.role = choice
		}
	}
	if s.dpg != "" {
		return nil
	}
	choice, err := p.Choose(DpgQuestion, s.dpgChoices())
	if err != nil {
		return err
	}
	if choice == AllChoice {
		s.everyDpg = true
		return nil
	}
	s.dpg = choice
	return nil
}

// pairs turns the flags into the list of role and DPG pairs to act on.
func (s selection) pairs() ([]Pair, error) {
	if s.all {
		if s.dpg == "" {
			return AllPairs(), nil
		}
		d, err := ParseDpg(s.dpg)
		if err != nil {
			return nil, err
		}
		return PairsForDpg(d), nil
	}
	if s.role != "" && s.everyDpg {
		r, err := ParseRole(s.role)
		if err != nil {
			return nil, err
		}
		return PairsForRole(r), nil
	}
	if s.role == "" || s.dpg == "" {
		return nil, errors.New("name --role and --dpg, or use --all")
	}
	r, err := ParseRole(s.role)
	if err != nil {
		return nil, err
	}
	d, err := ParseDpg(s.dpg)
	if err != nil {
		return nil, err
	}
	return []Pair{{Role: r, Dpg: d}}, nil
}

// resolve asks the menus when a name is missing, then builds the pairs.
// The caller passes the one Prompter of the run, so no answer is lost in
// a second buffer.
func (s *selection) resolve(p Prompter, env *Environment) ([]Pair, error) {
	if s.role == "" || s.dpg == "" {
		if err := s.ask(p, !s.nonInteractive && env.IsTTY()); err != nil {
			return nil, err
		}
	}
	return s.pairs()
}

// addSelectionFlags adds --role, --dpg, --all, and --non-interactive to
// a command.
func addSelectionFlags(cmd *cobra.Command, s *selection) {
	s.allowAll = true
	cmd.Flags().StringVar(&s.role, "role", "",
		"The deployment role: "+strings.Join(RoleNames(), ", ")+
			". A terminal run asks for it when the flag is absent.")
	cmd.Flags().StringVar(&s.dpg, "dpg", "",
		"The digital public good: "+strings.Join(DpgNames(), ", ")+
			". The three are equal. A terminal run asks for it when the flag is absent.")
	cmd.Flags().BoolVar(&s.all, "all", false,
		"Act on every role of every DPG. Add --dpg to limit it to one stack.")
	cmd.Flags().BoolVar(&s.nonInteractive, "non-interactive", false,
		"Ask nothing. The run fails and names every missing value.")
}

// NewRootCommand builds the whole command tree.
func NewRootCommand(env Environment) *cobra.Command {
	rootGiven := env.Root != ""
	stateGiven := env.StateDir != ""
	env = env.withDefaults()
	shared := &env
	var repoFlag string
	root := &cobra.Command{
		Use:   "vca",
		Short: "Set up and deploy the Verifiable Credentials Adapters.",
		Long: "The vca tool sets up one deployment per role and DPG, deploys it, " +
			"configures the DPG, and administers the running system.\n\n" +
			"Every setup question comes from the Config message of the proto API, " +
			"so the CLI, the documentation, and the services never drift.",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       Version,
	}
	root.SetOut(env.Out)
	root.SetErr(env.ErrOut)
	root.SetIn(env.In)
	root.PersistentFlags().StringVar(&repoFlag, "repo", "",
		"The repository root that holds "+RepoMarker+". The default is "+
			RepoEnv+", or the first parent directory that holds "+RepoMarker+".")
	root.PersistentPreRunE = func(_ *cobra.Command, _ []string) error {
		return applyRepoRoot(shared, repoFlag, rootGiven, stateGiven)
	}
	root.AddCommand(
		newSetupCommand(shared),
		newDeployCommand(shared),
		newImagesCommand(shared),
		newStatusCommand(shared),
		newDownCommand(shared),
		newDoctorCommand(shared),
		newPortsCommand(shared),
		newProxyCommand(shared),
		newDpgCommand(shared),
		newAdminCommand(shared),
		newMigrateCommand(shared),
		newThemeCommand(shared),
		newManCommand(shared),
	)
	return root
}

// applyRepoRoot sets the repository root of one run. It runs before
// every command, so each command reads one root (ADR-008 decision 1).
func applyRepoRoot(env *Environment, flag string, rootGiven, stateGiven bool) error {
	if flag == "" && rootGiven {
		return nil
	}
	wd, err := env.Getwd()
	if err != nil {
		return fmt.Errorf("read the working directory: %w", err)
	}
	root, err := ResolveRepoRoot(flag, env.Getenv, wd)
	if err != nil {
		return err
	}
	env.Root = root
	if !stateGiven {
		env.StateDir = filepath.Join(root, "deploy", ".vca")
	}
	return nil
}

// newSetupCommand builds vca setup (ADR-007).
func newSetupCommand(env *Environment) *cobra.Command {
	var (
		sel     selection
		envFile string
		sets    []string
		outRoot string
		yes     bool
		domain  string
	)
	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Ask the setup questions of one role and DPG and write the files.",
		Long: "setup asks only the questions the role and the DPG need. " +
			"It shows the values and their sources, then writes one .env file " +
			"and the generated DPG configuration under deploy/<role>-<dpg>/.\n\n" +
			"The order of the sources is, highest first: a --set flag, the " +
			"process environment, the --env-file file, the answer you type, " +
			"and the default in the proto.\n\n" +
			"Secrets are generated and written with mode 0600. A second run " +
			"keeps them.",
		Example: "  vca setup\n" +
			"  vca setup --role <role> --dpg <dpg>\n" +
			"  vca setup --all --domain labs.example\n" +
			"  vca setup --all --dpg <dpg> --env-file base.env --non-interactive",
		RunE: func(cmd *cobra.Command, _ []string) error {
			prompter := NewPrompter(cmd.InOrStdin(), cmd.OutOrStdout())
			pairs, err := sel.resolve(prompter, env)
			if err != nil {
				return err
			}
			flags, err := parseSets(sets)
			if err != nil {
				return err
			}
			file := map[string]string{}
			if envFile != "" {
				file, err = readEnvFile(envFile)
				if err != nil {
					return err
				}
			}
			root := outRoot
			if root == "" {
				root = filepath.Join(env.Root, "deploy")
			}
			if hint := memoryHintOf(env.NewProbe(cmd.Context()), pairs); hint != "" {
				anyval.DiscardWrite(fmt.Fprintf(cmd.OutOrStdout(),
					"This host has less free memory than this selection needs (%d MiB).\n%s\n\n",
					SelectionFloorMiB(pairs), hint))
			}
			base, err := resolveDomain(domain, env.Getenv, flags, file, pairs, !sel.nonInteractive, prompter)
			if err != nil {
				return err
			}
			// The answer of one pair pre-fills the question of the next
			// pair of a --all run (ADR-007 decision 2).
			offers := map[string]string{}
			for _, p := range pairs {
				existing, existingErr := ReadExisting(root, p)
				if existingErr != nil {
					return existingErr
				}
				// The pairs written so far in this run count as well, so
				// every peer list of a --all run agrees.
				peers, peersErr := ReadPeerOverrides(root)
				if peersErr != nil {
					return peersErr
				}
				// The Keycloak of the stack keeps its password across
				// the roles and the runs (ADR-035 decision 7).
				keycloak, keycloakErr := ReadKeycloakEnv(root, p.Dpg)
				if keycloakErr != nil {
					return keycloakErr
				}
				plan, err := BuildPlan(SetupRequest{
					Pair:        p,
					Flags:       flags,
					Env:         env.Getenv,
					File:        file,
					Existing:    existing,
					Interactive: !sel.nonInteractive,
					Prompter:    prompter,
					Offers:      offers,
					Random:      env.Random,
					Domain:      base,
					Peers:       peers,
					Keycloak:    keycloak,
				})
				if err != nil {
					return err
				}
				offers = CarryOffers(plan)
				anyval.DiscardWrite(fmt.Fprint(cmd.OutOrStdout(), plan.Summary()))
				if !sel.nonInteractive && !yes {
					ok, confirmErr := prompter.Confirm("Write these files?", true)
					if confirmErr != nil {
						return confirmErr
					}
					if !ok {
						anyval.DiscardWrite(fmt.Fprintf(cmd.OutOrStdout(), "setup %s: nothing written\n", p.Name()))
						continue
					}
				}
				written, err := WritePlan(root, plan)
				if err != nil {
					return err
				}
				for _, path := range written {
					anyval.DiscardWrite(fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", path))
				}
			}
			return nil
		},
	}
	addSelectionFlags(cmd, &sel)
	cmd.Flags().StringVar(&envFile, "env-file", "", "A dotenv file that prefills the answers.")
	cmd.Flags().StringArrayVar(&sets, "set", nil, "One value as NAME=value. Repeat the flag for more.")
	cmd.Flags().StringVar(&outRoot, "out", "", "The directory that holds one folder per pair.")
	cmd.Flags().BoolVar(&yes, "yes", false, "Write the files without the last question.")
	cmd.Flags().StringVar(&domain, "domain", "",
		"The base domain. Every pair gets https://<role>-<dpg>.<domain>. Also "+DomainEnv+".")
	return cmd
}

// resolveDomain reads the base domain of a setup run: the --domain flag,
// then VCA_DOMAIN, then one question when the run sets up more than one
// pair and no source named a public URL. A single pair keeps its own
// public URL question (ADR-007 decision 2).
func resolveDomain(flag string, getenv func(string) string, flags, file map[string]string,
	pairs []Pair, interactive bool, prompter Prompter) (string, error) {
	raw := flag
	if raw == "" && getenv != nil {
		raw = getenv(DomainEnv)
	}
	if raw != "" {
		return NormalizeDomain(raw)
	}
	if !interactive || len(pairs) < 2 {
		return "", nil
	}
	if _, ok := flags["VCA_PUBLIC_URL"]; ok {
		return "", nil
	}
	if _, ok := file["VCA_PUBLIC_URL"]; ok {
		return "", nil
	}
	if getenv != nil && strings.TrimSpace(getenv("VCA_PUBLIC_URL")) != "" {
		return "", nil
	}
	return prompter.AskDomain()
}

// parseSets turns --set NAME=value flags into a map.
func parseSets(sets []string) (map[string]string, error) {
	out := make(map[string]string, len(sets))
	for _, item := range sets {
		name, value, found := strings.Cut(item, "=")
		if !found || strings.TrimSpace(name) == "" {
			return nil, fmt.Errorf("--set %q: expected NAME=value", item)
		}
		out[strings.TrimSpace(name)] = value
	}
	return out, nil
}

// readEnvFile reads a dotenv file from the disk.
func readEnvFile(path string) (map[string]string, error) {
	f, err := os.Open(path) // #nosec G304 -- the operator names the file
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	defer func() { anyval.Discard(f.Close()) }()
	values, err := ParseDotenv(f)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return values, nil
}

// newDeployCommand builds vca deploy (ADR-008 decisions 1, 2, and 6).
func newDeployCommand(env *Environment) *cobra.Command {
	var (
		sel    selection
		dryRun bool
		build  bool
	)
	cmd := &cobra.Command{
		Use:   "deploy",
		Short: "Start one role and DPG with docker compose.",
		Long: "deploy runs docker compose with the profile of the role and the " +
			"DPG against the committed compose file. Add --all to start every " +
			"role of every DPG, or --all --dpg to start every role of one DPG. " +
			"Add --dry-run to print the rendered compose file " +
			"and the commands without starting anything.",
		Example: "  vca deploy --build\n" +
			"  vca deploy --role <role> --dpg <dpg>\n" +
			"  vca deploy --all --dpg <dpg> --dry-run\n" +
			"  vca deploy --all --build",
		RunE: func(cmd *cobra.Command, _ []string) error {
			prompter := NewPrompter(cmd.InOrStdin(), cmd.OutOrStdout())
			pairs, err := sel.resolve(prompter, env)
			if err != nil {
				return err
			}
			return Deploy(cmd.Context(), DeployOptions{
				Root: env.Root, Pairs: pairs, DryRun: dryRun, Build: build,
				Out: cmd.OutOrStdout(), Run: env.Run, Output: env.Output,
			})
		},
	}
	addSelectionFlags(cmd, &sel)
	cmd.Flags().BoolVar(&dryRun, "dry-run", false,
		"Print the rendered compose file and the commands only.")
	cmd.Flags().BoolVar(&build, "build", false,
		"Build every image from the source in this repository first.")
	return cmd
}

// newImagesCommand builds vca images build (ADR-008 decision 1).
func newImagesCommand(env *Environment) *cobra.Command {
	images := &cobra.Command{
		Use:   "images",
		Short: "Work with the service images.",
		Long: "The images commands build the service images from the source " +
			"in this repository. Use them before the first tagged release, " +
			"when the registry holds no image yet.",
	}
	var (
		sel    selection
		dryRun bool
	)
	build := &cobra.Command{
		Use:   "build",
		Short: "Build one image per service with the tag local.",
		Long: "build runs docker build for every service of the selection. " +
			"Each image gets the tag " + LocalTag + ". The command then sets " +
			VersionEnv + "=" + LocalTag + " in the .env file of each pair, so " +
			"vca deploy starts the local images.",
		Example: "  vca images build --role <role> --dpg <dpg>\n" +
			"  vca images build --all --dpg <dpg> --dry-run",
		RunE: func(cmd *cobra.Command, _ []string) error {
			prompter := NewPrompter(cmd.InOrStdin(), cmd.OutOrStdout())
			pairs, err := sel.resolve(prompter, env)
			if err != nil {
				return err
			}
			return BuildImages(cmd.Context(), ImageOptions{
				Root: env.Root, Pairs: pairs, DryRun: dryRun,
				Out: cmd.OutOrStdout(), Run: env.Run,
			})
		},
	}
	addSelectionFlags(build, &sel)
	build.Flags().BoolVar(&dryRun, "dry-run", false, "Print the commands only.")
	images.AddCommand(build)
	return images
}

// newDoctorCommand builds vca doctor (ADR-007 decision 1).
func newDoctorCommand(env *Environment) *cobra.Command {
	var (
		sel        selection
		fromSource bool
		suggest    bool
	)
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check that this host meets every prerequisite.",
		Long: "doctor prints one line per prerequisite with a pass or a fail " +
			"and the fix. It checks Docker, the compose plugin, the free " +
			"memory, every host port of the selection, and the public URL. " +
			"It then prints the memory floor of every selected pair.\n\n" +
			"The command exits with status 1 when one check fails. Add " +
			"--from-source when you build the tool with Go. Add --suggest to " +
			"print the largest selection that fits the free memory.",
		Example: "  vca doctor --from-source\n" +
			"  vca doctor --role <role> --dpg <dpg>\n" +
			"  vca doctor --all --dpg <dpg> --from-source\n" +
			"  vca doctor --suggest",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if suggest {
				return Suggest(DoctorOptions{
					Probe: env.NewProbe(cmd.Context()), Out: cmd.OutOrStdout(),
				})
			}
			prompter := NewPrompter(cmd.InOrStdin(), cmd.OutOrStdout())
			pairs, err := sel.resolve(prompter, env)
			if err != nil {
				return err
			}
			public, err := PublicURLOf(env.Root, pairs, env.Getenv)
			if err != nil {
				return err
			}
			deployRoot := filepath.Join(env.Root, "deploy")
			return Doctor(DoctorOptions{
				Pairs:      pairs,
				FromSource: fromSource,
				PublicURL:  public,
				Values: func(p Pair) map[string]string {
					values, readErr := ReadExisting(deployRoot, p)
					if readErr != nil {
						return nil
					}
					return values
				},
				Landing: landingValuesOrNil(env.Root),
				Probe:   env.NewProbe(cmd.Context()),
				Out:     cmd.OutOrStdout(),
			})
		},
	}
	addSelectionFlags(cmd, &sel)
	cmd.Flags().BoolVar(&fromSource, "from-source", false,
		"Check the Go version too. Only a source build needs Go.")
	cmd.Flags().BoolVar(&suggest, "suggest", false,
		"Print the largest selection that fits the free memory.")
	return cmd
}

// landingValuesOrNil reads the landing .env for the doctor. A read error
// falls back to the defaults, as the pair values do.
func landingValuesOrNil(root string) map[string]string {
	values, err := ReadLandingEnv(root)
	if err != nil {
		return nil
	}
	return values
}

// newPortsCommand builds vca ports (ADR-008 decision 1).
func newPortsCommand(env *Environment) *cobra.Command {
	var sel selection
	cmd := &cobra.Command{
		Use:   "ports",
		Short: "Print the host ports of one role and DPG.",
		Long: "ports prints one line per service with the port inside the " +
			"container and the port on the machine that runs compose. On a " +
			"server the host ports bind to 127.0.0.1 (VCA_BIND in the .env " +
			"file), so only the reverse proxy of the machine reaches them.",
		Example: "  vca ports --role <role> --dpg <dpg>",
		RunE: func(cmd *cobra.Command, _ []string) error {
			prompter := NewPrompter(cmd.InOrStdin(), cmd.OutOrStdout())
			pairs, err := sel.resolve(prompter, env)
			if err != nil {
				return err
			}
			deployRoot := filepath.Join(env.Root, "deploy")
			for _, p := range pairs {
				values, readErr := ReadExisting(deployRoot, p)
				if readErr != nil {
					return readErr
				}
				anyval.DiscardWrite(fmt.Fprintf(cmd.OutOrStdout(), "%s\n", p.Name()))
				for _, a := range HostPorts(p, values) {
					anyval.DiscardWrite(fmt.Fprintf(cmd.OutOrStdout(),
						"  %-22s host %d  container %d\n", a.Service.Name, a.Host, a.Listen))
				}
				for _, d := range DpgHostPorts(p) {
					anyval.DiscardWrite(fmt.Fprintf(cmd.OutOrStdout(),
						"  %-22s host %d  container 8080\n", d.Container, d.Host))
				}
			}
			return nil
		},
	}
	addSelectionFlags(cmd, &sel)
	return cmd
}

// newProxyCommand builds vca proxy (ADR-007 decision 5).
func newProxyCommand(env *Environment) *cobra.Command {
	var sel selection
	cmd := &cobra.Command{
		Use:   "proxy",
		Short: "Print the reverse proxy snippet of one or more pairs.",
		Long: "proxy prints the Caddyfile of every selected pair as one snippet. " +
			"The reverse proxy of the host imports it, so VCA shares the host " +
			"with other projects and binds no port 80 or 443 itself. Each site " +
			"sends its requests to 127.0.0.1 and the host port of a service.",
		Example: "  vca proxy --all | sudo tee /etc/caddy/vca.caddy >/dev/null\n" +
			"  echo 'import /etc/caddy/vca.caddy' | sudo tee -a /etc/caddy/Caddyfile\n" +
			"  sudo systemctl reload caddy",
		RunE: func(cmd *cobra.Command, _ []string) error {
			prompter := NewPrompter(cmd.InOrStdin(), cmd.ErrOrStderr())
			pairs, err := sel.resolve(prompter, env)
			if err != nil {
				return err
			}
			snippet, skipped, err := ProxySnippet(env.Root, pairs)
			if err != nil {
				return err
			}
			for _, name := range skipped {
				anyval.DiscardWrite(fmt.Fprintf(cmd.ErrOrStderr(),
					"proxy: %s has no Caddyfile; run vca setup for it first\n", name))
			}
			anyval.DiscardWrite(io.WriteString(cmd.OutOrStdout(), snippet))
			return nil
		},
	}
	addSelectionFlags(cmd, &sel)
	return cmd
}

// newStatusCommand builds vca status (ADR-008 decision 6).
func newStatusCommand(env *Environment) *cobra.Command {
	var sel selection
	cmd := &cobra.Command{
		Use:     "status",
		Short:   "Show the containers of one role and DPG.",
		Long:    "status runs docker compose ps with the profile of the role and the DPG.",
		Example: "  vca status --role <role> --dpg <dpg>",
		RunE: func(cmd *cobra.Command, _ []string) error {
			prompter := NewPrompter(cmd.InOrStdin(), cmd.OutOrStdout())
			pairs, err := sel.resolve(prompter, env)
			if err != nil {
				return err
			}
			return Status(cmd.Context(), DeployOptions{
				Root: env.Root, Pairs: pairs, Out: cmd.OutOrStdout(), Run: env.Run,
			})
		},
	}
	addSelectionFlags(cmd, &sel)
	return cmd
}

// newDownCommand builds vca down (ADR-008 decision 6).
func newDownCommand(env *Environment) *cobra.Command {
	var sel selection
	cmd := &cobra.Command{
		Use:   "down",
		Short: "Stop one role and DPG.",
		Long: "down runs docker compose down with the profile of the role and " +
			"the DPG. The volumes stay, so no data is lost.",
		Example: "  vca down --role <role> --dpg <dpg>",
		RunE: func(cmd *cobra.Command, _ []string) error {
			prompter := NewPrompter(cmd.InOrStdin(), cmd.OutOrStdout())
			pairs, err := sel.resolve(prompter, env)
			if err != nil {
				return err
			}
			return Down(cmd.Context(), DeployOptions{
				Root: env.Root, Pairs: pairs, Out: cmd.OutOrStdout(), Run: env.Run,
			})
		},
	}
	addSelectionFlags(cmd, &sel)
	return cmd
}

// newDpgCommand builds vca dpg bootstrap (ADR-008 decision 4) and vca
// dpg realm (ADR-035 decision 6).
func newDpgCommand(env *Environment) *cobra.Command {
	dpg := &cobra.Command{
		Use:   "dpg",
		Short: "Configure a digital public good after it boots.",
		Long: "The dpg commands call the HTTP API of the digital public good. " +
			"Nothing writes into a DPG database and nothing restarts a container.",
	}
	var nonInteractive bool
	bootstrap := &cobra.Command{
		Use:   "bootstrap [<dpg>]",
		Short: "Apply the post boot configuration of one DPG.",
		Long: "bootstrap applies the post boot steps of the chosen DPG. It " +
			"asks the DPG adapter for the did:web issuer, imports the generated " +
			"Keycloak realm, or creates the organisation, as that DPG needs. " +
			"Each run checks first, so a second run changes nothing.\n\n" +
			"<dpg> is one of " + strings.Join(DpgNames(), ", ") +
			". A terminal run asks for the DPG and the role when they are absent.",
		Example: "  vca dpg bootstrap <dpg> --role issuer",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p := NewPrompter(cmd.InOrStdin(), cmd.OutOrStdout())
			interactive := !nonInteractive && env.IsTTY()
			name, err := bootstrapName(p, args, interactive)
			if err != nil {
				return err
			}
			d, err := ParseDpg(name)
			if err != nil {
				return err
			}
			role, err := bootstrapRole(p, cmd, interactive)
			if err != nil {
				return err
			}
			r, err := ParseRole(role)
			if err != nil {
				return err
			}
			pair := Pair{Role: r, Dpg: d}
			dir := OutputDir(filepath.Join(env.Root, "deploy"), pair)
			values, err := bootstrapValues(env, filepath.Join(env.Root, "deploy"), pair)
			if err != nil {
				return err
			}
			_, err = Bootstrap(cmd.Context(), BootstrapOptions{
				Pair: pair, Dir: dir, Values: values,
				Client: env.HTTP, Out: cmd.OutOrStdout(),
			})
			return err
		},
	}
	bootstrap.Flags().String("role", "issuer",
		"The role whose .env file holds the DPG URL: "+strings.Join(RoleNames(), ", ")+
			". A terminal run asks for it when the flag is absent.")
	bootstrap.Flags().BoolVar(&nonInteractive, "non-interactive", false,
		"Ask nothing. The run uses the named DPG and the default role.")
	dpg.AddCommand(bootstrap)
	dpg.AddCommand(newDpgRealmCommand(env))
	return dpg
}

// newDpgRealmCommand builds vca dpg realm (ADR-035 decision 6).
func newDpgRealmCommand(env *Environment) *cobra.Command {
	var roleName, dpgName, registration string
	cmd := &cobra.Command{
		Use:   "realm --role <role> --dpg <dpg> --registration on|off",
		Short: "Turn self registration of the realm of one role on or off.",
		Long: "realm changes the self registration setting of the realm of one " +
			"role at the Keycloak of one stack, through the Keycloak admin API. " +
			"It writes the same value into the generated realm file, so a later " +
			"vca dpg bootstrap keeps it.\n\n" +
			"The first run checklist of the admin portal marks \"Turn off self " +
			"registration\" done when the run can reach the admin service: set " +
			"VCA_ADMIN_URL and log in with vca admin login first. The run then " +
			"sets the register action of every provider record of that realm.\n\n" +
			"<role> is one of " + strings.Join(RoleNames(), ", ") +
			". <dpg> is one of " + strings.Join(DpgNames(), ", ") + ".",
		Example: "  vca dpg realm --role admin --dpg <dpg> --registration off",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if registration == "" {
				return errors.New("set --registration to on or off")
			}
			allowed, err := ParseOnOff(registration)
			if err != nil {
				return err
			}
			if dpgName == "" {
				return errors.New("set --dpg to one of " + strings.Join(DpgNames(), ", "))
			}
			d, err := ParseDpg(dpgName)
			if err != nil {
				return err
			}
			r, err := ParseRole(roleName)
			if err != nil {
				return err
			}
			pair := Pair{Role: r, Dpg: d}
			deploy := filepath.Join(env.Root, "deploy")
			values, err := bootstrapValues(env, deploy, pair)
			if err != nil {
				return err
			}
			opts := RealmOptions{
				BootstrapOptions: BootstrapOptions{
					Pair: pair, Dir: OutputDir(deploy, pair), Values: values,
					Client: env.HTTP, Out: cmd.OutOrStdout(),
				},
				Allowed: allowed,
			}
			if base := env.Getenv("VCA_ADMIN_URL"); base != "" {
				token, err := LoadToken(env.StateDir)
				if err != nil {
					return err
				}
				if token != "" {
					opts.Admin = &AdminClient{BaseURL: base, Token: token, HTTP: env.HTTP}
				}
			}
			if _, err := RealmRegistration(cmd.Context(), opts); err != nil {
				return err
			}
			if opts.Admin == nil {
				anyval.DiscardWrite(fmt.Fprintln(cmd.OutOrStdout(),
					"To mark the first run checklist step done, set VCA_ADMIN_URL, run vca admin login, and run this command again."))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&roleName, "role", "admin",
		"The role whose realm changes: "+strings.Join(RoleNames(), ", ")+".")
	cmd.Flags().StringVar(&dpgName, "dpg", "",
		"The stack whose Keycloak holds the realm: "+strings.Join(DpgNames(), ", ")+".")
	cmd.Flags().StringVar(&registration, "registration", "",
		"on lets anyone register in the realm. off closes it.")
	return cmd
}

// bootstrapValues reads the .env of a pair and adds the administrator of
// the Keycloak of the stack. The generated administrator is the default;
// the environment beats it (ADR-035 decision 7).
func bootstrapValues(env *Environment, deploy string, pair Pair) (map[string]string, error) {
	values, err := ReadExisting(deploy, pair)
	if err != nil {
		return nil, err
	}
	keycloak, err := ReadKeycloakEnv(deploy, pair.Dpg)
	if err != nil {
		return nil, err
	}
	for name, from := range map[string]string{EnvBootstrapUser: KeycloakAdminEnv, EnvBootstrapSecret: KeycloakAdminPasswordEnv} {
		if v := keycloak[from]; v != "" && values[name] == "" {
			values[name] = v
		}
	}
	for _, name := range []string{EnvBootstrapURL, EnvBootstrapUser, EnvBootstrapSecret, EnvBootstrapOrg, EnvBootstrapAdapterURL} {
		if v := env.Getenv(name); v != "" {
			values[name] = v
		}
	}
	return values, nil
}

// bootstrapName reads the DPG name of vca dpg bootstrap. A terminal run
// with no argument gets the menu (ADR-007 decision 2).
func bootstrapName(p Prompter, args []string, interactive bool) (string, error) {
	if len(args) == 1 {
		return args[0], nil
	}
	if !interactive {
		return "", errors.New("name the DPG: " + strings.Join(DpgNames(), ", "))
	}
	return p.Choose(DpgQuestion, DpgNames())
}

// bootstrapRole reads the role of vca dpg bootstrap. A terminal run that
// passed no --role gets the menu. Every other run keeps the default, so
// a script behaves as before.
func bootstrapRole(p Prompter, cmd *cobra.Command, interactive bool) (string, error) {
	flag := cmd.Flag("role")
	if flag.Changed || !interactive {
		return flag.Value.String(), nil
	}
	return p.Choose(RoleQuestion, RoleNames())
}

// newAdminCommand builds the vca admin tree (ADR-009 decisions 1 and 2).
func newAdminCommand(env *Environment) *cobra.Command {
	var (
		serviceURL string
		token      string
	)
	admin := &cobra.Command{
		Use:   "admin",
		Short: "Administer a running deployment.",
		Long: "The admin commands are clients of the vca.admin.v1.AdminService " +
			"RPCs. The portal calls the same service, so no action exists in " +
			"one place only. Log in first with vca admin login.",
	}
	admin.PersistentFlags().StringVar(&serviceURL, "url", "",
		"The admin service URL. The default is VCA_ADMIN_URL.")
	admin.PersistentFlags().StringVar(&token, "token", "",
		"The bearer token. The default is the token that vca admin login saved.")

	baseURL := func() string {
		if serviceURL != "" {
			return serviceURL
		}
		return env.Getenv("VCA_ADMIN_URL")
	}

	resolve := func() (AdminClient, error) {
		base := baseURL()
		value := token
		if value == "" {
			saved, err := LoadToken(env.StateDir)
			if err != nil {
				return AdminClient{}, err
			}
			value = saved
		}
		return AdminClient{BaseURL: base, Token: value, HTTP: env.HTTP}, nil
	}

	admin.AddCommand(newAdminLoginCommand(env, baseURL))
	groups := map[string]*cobra.Command{}
	for _, c := range AdminCommands() {
		group, ok := groups[c.Group]
		if !ok {
			group = &cobra.Command{
				Use:   c.Group,
				Short: "Work with " + c.Group + " objects.",
			}
			groups[c.Group] = group
			admin.AddCommand(group)
		}
		group.AddCommand(newAdminRPCCommand(c, resolve))
	}
	for _, c := range AdminCommands() {
		if c.Verb != "" {
			continue
		}
		// A group with no verb is one command, so give it the RPC itself.
		groups[c.Group].RunE = groups[c.Group].Commands()[0].RunE
		groups[c.Group].Flags().AddFlagSet(groups[c.Group].Commands()[0].Flags())
		groups[c.Group].Short = c.Description
	}
	return admin
}

// newAdminRPCCommand builds one leaf command of the admin tree.
func newAdminRPCCommand(c AdminCommand, resolve func() (AdminClient, error)) *cobra.Command {
	var (
		body string
		file string
	)
	name := c.Verb
	if name == "" {
		name = c.Group
	}
	cmd := &cobra.Command{
		Use:   name,
		Short: c.Description,
		Long: c.Description + "\n\nThe command calls the " + c.Method +
			" RPC of " + AdminService + ". Pass the request as JSON with --json " +
			"or --file, and the answer comes back as JSON.",
		Example: "  vca admin " + c.Path() + ` --json '{}'`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			payload := []byte(body)
			if file != "" {
				data, err := os.ReadFile(file) // #nosec G304 -- the operator names the file
				if err != nil {
					return fmt.Errorf("read %s: %w", file, err)
				}
				payload = data
			}
			client, err := resolve()
			if err != nil {
				return err
			}
			answer, err := client.Call(cmd.Context(), c, payload)
			if err != nil {
				return err
			}
			anyval.DiscardWrite(fmt.Fprint(cmd.OutOrStdout(), PrettyJSON(answer)))
			return nil
		},
	}
	cmd.Flags().StringVar(&body, "json", "", "The request as a JSON object.")
	cmd.Flags().StringVar(&file, "file", "", "A file that holds the request as JSON.")
	return cmd
}

// newAdminLoginCommand builds vca admin login (ADR-010 decisions 1, 2,
// and 6). The admin service holds the OpenID Connect client, so the CLI
// needs no client id and no client secret.
func newAdminLoginCommand(env *Environment, baseURL func() string) *cobra.Command {
	var (
		provider  string
		bootstrap string
		device    bool
	)
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Log in as a super admin with OpenID Connect.",
		Long: "login asks the admin service for an authorization URL and waits " +
			"on a loopback port for the one time code. Add --device on a host " +
			"with no browser to run the device authorization grant instead. " +
			"Add --bootstrap-token at the first login to bind the first super " +
			"admin. The session token goes to a file with mode 0600.",
		Example: "  vca admin login --url https://admin.example\n" +
			"  vca admin login --device --bootstrap-token $TOKEN",
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts := LoginOptions{
				AdminURL:       baseURL(),
				Provider:       provider,
				BootstrapToken: bootstrap,
				HTTP:           env.HTTP,
				Out:            cmd.OutOrStdout(),
			}
			login := LoopbackLogin
			if device {
				login = DeviceLogin
			}
			token, err := login(cmd.Context(), opts)
			if err != nil {
				return err
			}
			path, err := SaveToken(env.StateDir, token)
			if err != nil {
				return err
			}
			anyval.DiscardWrite(fmt.Fprintf(cmd.OutOrStdout(), "login done; the token is in %s\n", path))
			return nil
		},
	}
	cmd.Flags().StringVar(&provider, "provider", "",
		"The provider id. The default is the only enabled provider.")
	cmd.Flags().StringVar(&bootstrap, "bootstrap-token", "",
		"The one time token that binds the first super admin.")
	cmd.Flags().BoolVar(&device, "device", false,
		"Use the device grant instead of the loopback flow.")
	return cmd
}

// newThemeCommand builds vca theme check, apply, and print-default
// (ADR-032 decision 6).
func newThemeCommand(env *Environment) *cobra.Command {
	theme := &cobra.Command{
		Use:   "theme",
		Short: "Check and apply the theme file of every page.",
		Long: "The look of every page comes from one file, deploy/vca/theme.yaml. " +
			"Edit it, run vca theme check, then vca theme apply.\n\n" +
			"check reads the file, names every value that breaks a rule with its " +
			"YAML path, and names every colour pairing below WCAG AA with its ratio. " +
			"apply runs the check and restarts the services that draw pages in " +
			"every deployed pair. print-default prints the shipped file.\n\n" +
			"The default path is " + ThemeHostFileEnv + ", else deploy/vca/theme.yaml. " +
			"A relative " + ThemeHostFileEnv + " resolves against deploy/vca, as the " +
			"compose file does. On Kubernetes run: helm upgrade vca deploy/vca/helm/vca " +
			"--set-file global.theme.file=theme.yaml",
		Example: "  vca theme check\n" +
			"  vca theme check --file deploy/theme.local.yaml\n" +
			"  vca theme apply\n" +
			"  vca theme print-default > deploy/theme.local.yaml",
	}
	var file string
	check := &cobra.Command{
		Use:   "check",
		Short: "Validate the theme file and name every problem.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return ThemeCheck(ThemePath(env.Root, file, env.Getenv), cmd.OutOrStdout())
		},
	}
	check.Flags().StringVar(&file, "file", "", "The theme file to check. The default is "+ThemeHostFileEnv+", else deploy/vca/theme.yaml.")
	var applyFile string
	apply := &cobra.Command{
		Use:   "apply",
		Short: "Check the theme file, then restart the services that draw pages.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return ThemeApply(cmd.Context(), ThemeOptions{
				Root: env.Root, Path: ThemePath(env.Root, applyFile, env.Getenv),
				Out: cmd.OutOrStdout(), Run: env.Run,
			})
		},
	}
	apply.Flags().StringVar(&applyFile, "file", "", "The theme file to check first. The default is "+ThemeHostFileEnv+", else deploy/vca/theme.yaml.")
	printDefault := &cobra.Command{
		Use:   "print-default",
		Short: "Print the shipped theme file.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := cmd.OutOrStdout().Write(themefile.Default())
			return err
		},
	}
	theme.AddCommand(check, apply, printDefault)
	return theme
}

// newManCommand builds vca man (ADR-009 decision 2).
func newManCommand(env *Environment) *cobra.Command {
	var dir string
	cmd := &cobra.Command{
		Use:   "man",
		Short: "Write one man page per command.",
		Long: "man writes the man pages of the whole command tree. The release " +
			"artefacts ship them, so man vca-admin-trust-upsert works on any " +
			"Linux host.",
		Example: "  go run ./cmd/vca man --dir docs/man",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if dir == "" {
				return errors.New("name the output directory with --dir")
			}
			if err := os.MkdirAll(dir, 0o750); err != nil {
				return fmt.Errorf("make %s: %w", dir, err)
			}
			tree := NewRootCommand(*env)
			tree.DisableAutoGenTag = true
			header := &doc.GenManHeader{Title: "VCA", Section: "1",
				Source: "Verifiable Credentials Adapters " + Version}
			if err := doc.GenManTree(tree, header, dir); err != nil {
				return fmt.Errorf("write the man pages: %w", err)
			}
			anyval.DiscardWrite(fmt.Fprintf(cmd.OutOrStdout(), "wrote the man pages to %s\n", dir))
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "The directory that receives the man pages.")
	return cmd
}
