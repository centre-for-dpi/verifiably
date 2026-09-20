// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	"github.com/centre-for-dpi/vc-adapters/internal/migrate"
)

// DefaultPgDriver is the database/sql driver the export uses when the
// operator names none. A build that reads a legacy database must link
// a driver with that name.
const DefaultPgDriver = "postgres"

// OpenDB opens the legacy database. A test replaces it with a fake.
type OpenDB func(driver, dsn string) (*sql.DB, error)

// migrateFlags holds the flags of vca migrate export.
type migrateFlags struct {
	fromPg       string
	fromStateDir string
	driver       string
	out          string
	salt         string
	saltFile     string
	keepClaims   []string
	issuerDID    string
	statusURL    string
	force        bool
}

// newMigrateCommand builds vca migrate (ADR-030 decision 8).
func newMigrateCommand(env *Environment) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Carry the data of a verifiably-go deployment into the services.",
		Long: "The migrate commands read the issuance log, the status lists, and " +
			"the trust registry of verifiably-go. They write the store files of " +
			"the issued-credentials service, the two status services, and the " +
			"trust-registry service.\n\n" +
			"Sessions and caches are not migrated. A holder signs in again after " +
			"the cutover, and a cache fills again by itself.",
	}
	cmd.AddCommand(newMigrateExportCommand(env), newMigrateImportCommand())
	return cmd
}

// newMigrateExportCommand builds vca migrate export.
func newMigrateExportCommand(env *Environment) *cobra.Command {
	var f migrateFlags
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Read a legacy deployment and write the import files.",
		Long: "export reads one legacy source: a PostgreSQL database with " +
			"--from-pg, or a state directory with --from-state-dir. It writes " +
			"four things under --out: the issued credential log, the bitstring " +
			"status lists, the token status lists, and the trust registry.\n\n" +
			"The hash chain of the log is built again. Each subject reference is " +
			"salted again with --salt, so the export holds no holder identifier. " +
			"Give the same salt to the issued-credentials service.\n\n" +
			"The export keeps no subject claim. Name each claim to keep with " +
			"--keep-claim.\n\n" +
			"A build reads a database only when it links a database/sql driver " +
			"with the name of --pg-driver. Use --from-state-dir otherwise.",
		Example: "  vca migrate export --from-state-dir ./state --out ./migration --salt $SALT\n" +
			"  vca migrate export --from-pg postgres://user:pass@host/db --out ./migration --salt $SALT",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runMigrateExport(cmd.Context(), cmd.OutOrStdout(), *env, f)
		},
	}
	cmd.Flags().StringVar(&f.fromPg, "from-pg", "", "The DSN of the legacy PostgreSQL database.")
	cmd.Flags().StringVar(&f.fromStateDir, "from-state-dir", "", "The legacy state directory.")
	cmd.Flags().StringVar(&f.driver, "pg-driver", DefaultPgDriver, "The database/sql driver name.")
	cmd.Flags().StringVar(&f.out, "out", "", "The directory that receives the import files.")
	cmd.Flags().StringVar(&f.salt, "salt", "", "The salt of the subject reference.")
	cmd.Flags().StringVar(&f.saltFile, "salt-file", "", "A file that holds the salt.")
	cmd.Flags().StringArrayVar(&f.keepClaims, "keep-claim", nil,
		"A subject claim to keep as a searchable claim. Repeat the flag for more.")
	cmd.Flags().StringVar(&f.issuerDID, "issuer-did", "",
		"The DID that signs the migrated status lists. Empty uses the default issuer.")
	cmd.Flags().StringVar(&f.statusURL, "status-base-url", "",
		"The public root URL of the status services.")
	cmd.Flags().BoolVar(&f.force, "force", false, "Replace the files that exist.")
	return cmd
}

// newMigrateImportCommand builds vca migrate import.
func newMigrateImportCommand() *cobra.Command {
	var (
		from  string
		into  string
		force bool
	)
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Write the import files into a service state directory.",
		Long: "import reads the files that export wrote and copies them into the " +
			"state directory of the services. It checks every document first, so " +
			"a broken export writes nothing.\n\n" +
			"The state directory holds issued-credentials.json for " +
			"VCA_ISSUED_STORE_FILE, trust-registry.json for VCA_TRUST_STORE_FILE, " +
			"and one directory per status service for its state directory.",
		Example: "  vca migrate import --from ./migration --into /var/lib/vca",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if strings.TrimSpace(into) == "" {
				return errors.New("name the service state directory with --into")
			}
			written, err := migrate.Import(from, into, force)
			if err != nil {
				return err
			}
			for _, path := range written {
				anyval.DiscardWrite(fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", path))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&from, "from", ".", "The directory that holds the export.")
	cmd.Flags().StringVar(&into, "into", "", "The state directory of the services.")
	cmd.Flags().BoolVar(&force, "force", false, "Replace the files that exist.")
	return cmd
}

// runMigrateExport reads the legacy source and writes the export.
func runMigrateExport(ctx context.Context, out io.Writer, env Environment, f migrateFlags) error {
	if (f.fromPg == "") == (f.fromStateDir == "") {
		return errors.New("name one source: --from-pg or --from-state-dir")
	}
	if strings.TrimSpace(f.out) == "" {
		return errors.New("name the output directory with --out")
	}
	salt, err := resolveSalt(env, f)
	if err != nil {
		return err
	}
	legacy, err := readLegacy(ctx, env, f)
	if err != nil {
		return err
	}
	bundle, err := migrate.Build(legacy, migrate.Options{
		Salt:          salt,
		KeepClaims:    f.keepClaims,
		IssuerDID:     f.issuerDID,
		StatusBaseURL: f.statusURL,
		Now:           time.Now().UTC(),
	})
	if err != nil {
		return err
	}
	written, err := bundle.Write(f.out, f.force)
	if err != nil {
		return err
	}
	for _, path := range written {
		anyval.DiscardWrite(fmt.Fprintf(out, "wrote %s\n", path))
	}
	c := bundle.Counts()
	anyval.DiscardWrite(fmt.Fprintf(out, "log entries %d, bitstring lists %d, token lists %d, trust entries %d\n",
		c.Issued, c.Bitstring, c.Token, c.Trust))
	anyval.DiscardWrite(fmt.Fprint(out, "sessions and caches are not migrated\n"))
	return nil
}

// SaltEnv names the environment variable that holds the salt.
const SaltEnv = "VCA_ISSUED_SALT"

// resolveSalt finds the salt in the flags or the environment.
func resolveSalt(env Environment, f migrateFlags) (string, error) {
	if f.salt != "" {
		return f.salt, nil
	}
	if f.saltFile != "" {
		data, err := os.ReadFile(f.saltFile) // #nosec G304 -- the operator names the file
		if err != nil {
			return "", fmt.Errorf("read %s: %w", f.saltFile, err)
		}
		if salt := strings.TrimSpace(string(data)); salt != "" {
			return salt, nil
		}
		return "", fmt.Errorf("the salt file %s is empty", f.saltFile)
	}
	if salt := strings.TrimSpace(env.Getenv(SaltEnv)); salt != "" {
		return salt, nil
	}
	return "", errors.New("name the subject salt with --salt, --salt-file, or " + SaltEnv)
}

// readLegacy reads the legacy source the flags name.
func readLegacy(ctx context.Context, env Environment, f migrateFlags) (migrate.Legacy, error) {
	if f.fromStateDir != "" {
		return migrate.ReadStateDir(f.fromStateDir)
	}
	open := env.OpenDB
	if open == nil {
		open = migrate.OpenPostgres
	}
	driver := f.driver
	if driver == "" {
		driver = DefaultPgDriver
	}
	db, err := open(driver, f.fromPg)
	if err != nil {
		return migrate.Legacy{}, err
	}
	defer func() { anyval.Discard(db.Close()) }()
	return migrate.ReadPostgres(ctx, db)
}
