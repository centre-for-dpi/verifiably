// SPDX-License-Identifier: Apache-2.0

package cli

import (
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
	// HTTP makes the DPG and admin calls.
	HTTP *http.Client
	// StateDir holds the saved admin token.
	StateDir string
	// OpenDB opens the legacy database of vca migrate export. Nil opens
	// it with database/sql.
	OpenDB OpenDB
}

// withDefaults fills the fields a caller left empty.
func (e Environment) withDefaults() Environment {
	if e.Root == "" {
		e.Root = "."
	}
	if e.In == nil {
		e.In = os.Stdin
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
	if e.Run == nil {
		e.Run = ExecRunner(e.Out, e.ErrOut)
	}
	if e.StateDir == "" {
		e.StateDir = filepath.Join(e.Root, "deploy", ".vca")
	}
	return e
}

// Execute runs the CLI and returns the process exit status.
func Execute(env Environment) int {
	env = env.withDefaults()
	root := NewRootCommand(env)
	root.SetArgs(env.Args)
	if err := root.Execute(); err != nil {
		fmt.Fprintf(env.ErrOut, "vca: %s\n", err)
		return 1
	}
	return 0
}

// selection holds the --role, --dpg, and --all flags of one command.
type selection struct {
	role string
	dpg  string
	all  bool
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

// addSelectionFlags adds --role, --dpg, and --all to a command.
func addSelectionFlags(cmd *cobra.Command, s *selection) {
	cmd.Flags().StringVar(&s.role, "role", "",
		"The deployment role: "+strings.Join(RoleNames(), ", ")+".")
	cmd.Flags().StringVar(&s.dpg, "dpg", "",
		"The digital public good: "+strings.Join(DpgNames(), ", ")+".")
	cmd.Flags().BoolVar(&s.all, "all", false,
		"Act on every role. Add --dpg to pick one stack.")
}

// NewRootCommand builds the whole command tree.
func NewRootCommand(env Environment) *cobra.Command {
	env = env.withDefaults()
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
	root.AddCommand(
		newSetupCommand(env),
		newDeployCommand(env),
		newStatusCommand(env),
		newDownCommand(env),
		newDpgCommand(env),
		newAdminCommand(env),
		newMigrateCommand(env),
		newManCommand(env),
	)
	return root
}

// newSetupCommand builds vca setup (ADR-007).
func newSetupCommand(env Environment) *cobra.Command {
	var (
		sel            selection
		envFile        string
		nonInteractive bool
		sets           []string
		outRoot        string
		yes            bool
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
		Example: "  vca setup --role issuer --dpg waltid\n" +
			"  vca setup --all --dpg inji --env-file base.env --non-interactive",
		RunE: func(cmd *cobra.Command, _ []string) error {
			pairs, err := sel.pairs()
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
			prompter := NewPrompter(cmd.InOrStdin(), cmd.OutOrStdout())
			for _, p := range pairs {
				existing, err := ReadExisting(root, p)
				if err != nil {
					return err
				}
				plan, err := BuildPlan(SetupRequest{
					Pair:        p,
					Flags:       flags,
					Env:         env.Getenv,
					File:        file,
					Existing:    existing,
					Interactive: !nonInteractive,
					Prompter:    prompter,
					Random:      env.Random,
				})
				if err != nil {
					return err
				}
				fmt.Fprint(cmd.OutOrStdout(), plan.Summary())
				if !nonInteractive && !yes {
					ok, err := prompter.Confirm("Write these files?", true)
					if err != nil {
						return err
					}
					if !ok {
						fmt.Fprintf(cmd.OutOrStdout(), "setup %s: nothing written\n", p.Name())
						continue
					}
				}
				written, err := WritePlan(root, plan)
				if err != nil {
					return err
				}
				for _, path := range written {
					fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", path)
				}
			}
			return nil
		},
	}
	addSelectionFlags(cmd, &sel)
	cmd.Flags().StringVar(&envFile, "env-file", "", "A dotenv file that prefills the answers.")
	cmd.Flags().BoolVar(&nonInteractive, "non-interactive", false,
		"Ask nothing. The run fails and lists every missing value.")
	cmd.Flags().StringArrayVar(&sets, "set", nil, "One value as NAME=value. Repeat the flag for more.")
	cmd.Flags().StringVar(&outRoot, "out", "", "The directory that holds one folder per pair.")
	cmd.Flags().BoolVar(&yes, "yes", false, "Write the files without the last question.")
	return cmd
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
	defer func() { _ = f.Close() }()
	values, err := ParseDotenv(f)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return values, nil
}

// newDeployCommand builds vca deploy (ADR-008 decisions 1, 2, and 6).
func newDeployCommand(env Environment) *cobra.Command {
	var (
		sel    selection
		dryRun bool
	)
	cmd := &cobra.Command{
		Use:   "deploy",
		Short: "Start one role and DPG with docker compose.",
		Long: "deploy runs docker compose with the profile of the role and the " +
			"DPG against the committed compose file. Add --all to start every " +
			"role of one DPG. Add --dry-run to print the rendered compose file " +
			"and the commands without starting anything.",
		Example: "  vca deploy --role verifier --dpg waltid\n" +
			"  vca deploy --all --dpg inji --dry-run",
		RunE: func(cmd *cobra.Command, _ []string) error {
			pairs, err := sel.pairs()
			if err != nil {
				return err
			}
			return Deploy(cmd.Context(), DeployOptions{
				Root: env.Root, Pairs: pairs, DryRun: dryRun,
				Out: cmd.OutOrStdout(), Run: env.Run,
			})
		},
	}
	addSelectionFlags(cmd, &sel)
	cmd.Flags().BoolVar(&dryRun, "dry-run", false,
		"Print the rendered compose file and the commands only.")
	return cmd
}

// newStatusCommand builds vca status (ADR-008 decision 6).
func newStatusCommand(env Environment) *cobra.Command {
	var sel selection
	cmd := &cobra.Command{
		Use:     "status",
		Short:   "Show the containers of one role and DPG.",
		Long:    "status runs docker compose ps with the profile of the role and the DPG.",
		Example: "  vca status --role issuer --dpg waltid",
		RunE: func(cmd *cobra.Command, _ []string) error {
			pairs, err := sel.pairs()
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
func newDownCommand(env Environment) *cobra.Command {
	var sel selection
	cmd := &cobra.Command{
		Use:   "down",
		Short: "Stop one role and DPG.",
		Long: "down runs docker compose down with the profile of the role and " +
			"the DPG. The volumes stay, so no data is lost.",
		Example: "  vca down --role issuer --dpg waltid",
		RunE: func(cmd *cobra.Command, _ []string) error {
			pairs, err := sel.pairs()
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

// newDpgCommand builds vca dpg bootstrap (ADR-008 decision 4).
func newDpgCommand(env Environment) *cobra.Command {
	dpg := &cobra.Command{
		Use:   "dpg",
		Short: "Configure a digital public good after it boots.",
		Long: "The dpg commands call the HTTP API of the digital public good. " +
			"Nothing writes into a DPG database and nothing restarts a container.",
	}
	bootstrap := &cobra.Command{
		Use:   "bootstrap [" + strings.Join(DpgNames(), "|") + "]",
		Short: "Apply the post boot configuration of one DPG.",
		Long: "bootstrap provisions the walt.id did:web issuer and its key, " +
			"imports the generated Keycloak realm for Inji and eSignet, or " +
			"creates the CREDEBL organisation. Each run checks first, so a " +
			"second run changes nothing.",
		Example: "  vca dpg bootstrap waltid --role issuer",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			d, err := ParseDpg(args[0])
			if err != nil {
				return err
			}
			role := cmd.Flag("role").Value.String()
			r, err := ParseRole(role)
			if err != nil {
				return err
			}
			pair := Pair{Role: r, Dpg: d}
			dir := OutputDir(filepath.Join(env.Root, "deploy"), pair)
			values, err := ReadExisting(filepath.Join(env.Root, "deploy"), pair)
			if err != nil {
				return err
			}
			for _, name := range []string{EnvBootstrapURL, EnvBootstrapUser, EnvBootstrapPassword, EnvBootstrapOrg} {
				if v := env.Getenv(name); v != "" {
					values[name] = v
				}
			}
			_, err = Bootstrap(cmd.Context(), BootstrapOptions{
				Pair: pair, Dir: dir, Values: values,
				Client: env.HTTP, Out: cmd.OutOrStdout(),
			})
			return err
		},
	}
	bootstrap.Flags().String("role", "issuer",
		"The role whose .env file holds the DPG URL: "+strings.Join(RoleNames(), ", ")+".")
	dpg.AddCommand(bootstrap)
	return dpg
}

// newAdminCommand builds the vca admin tree (ADR-009 decisions 1 and 2).
func newAdminCommand(env Environment) *cobra.Command {
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
		group.AddCommand(newAdminRpcCommand(c, resolve))
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

// newAdminRpcCommand builds one leaf command of the admin tree.
func newAdminRpcCommand(c AdminCommand, resolve func() (AdminClient, error)) *cobra.Command {
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
			fmt.Fprint(cmd.OutOrStdout(), PrettyJSON(answer))
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
func newAdminLoginCommand(env Environment, baseURL func() string) *cobra.Command {
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
			fmt.Fprintf(cmd.OutOrStdout(), "login done; the token is in %s\n", path)
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

// newManCommand builds vca man (ADR-009 decision 2).
func newManCommand(env Environment) *cobra.Command {
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
			tree := NewRootCommand(env)
			tree.DisableAutoGenTag = true
			header := &doc.GenManHeader{Title: "VCA", Section: "1",
				Source: "Verifiable Credentials Adapters " + Version}
			if err := doc.GenManTree(tree, header, dir); err != nil {
				return fmt.Errorf("write the man pages: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote the man pages to %s\n", dir)
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "The directory that receives the man pages.")
	return cmd
}
