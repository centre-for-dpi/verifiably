// SPDX-License-Identifier: Apache-2.0

// Package config reads the settings of the issuance service from the
// environment. It uses the shared services/internal/config loader.
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	shared "github.com/centre-for-dpi/vc-adapters/services/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/internal/uikit"
)

// Prefix starts every variable name of this service.
const Prefix = "VCA_ISSUANCE_"

// Config holds every setting of the service.
type Config struct {
	// Listen is the address the HTTP server binds.
	Listen string `env:"LISTEN" default:":8080"`
	// PublicURL is the address a citizen reaches this service on. The
	// download link of a document lives under it.
	PublicURL string `env:"PUBLIC_URL"`
	// AdapterURL is the base URL of the DPG adapter that issues
	// (ADR-016 decision 1).
	AdapterURL string `env:"ADAPTER_URL" required:"true"`
	// AdapterName names the DPG in the issued record.
	AdapterName string `env:"ADAPTER_NAME" default:"dpg"`
	// SchemaURL is the base URL of the schema registry. Empty turns the
	// claim check off.
	SchemaURL string `env:"SCHEMA_URL"`
	// StatusURL is the base URL of the status service. Empty makes every
	// credential not revocable.
	StatusURL string `env:"STATUS_URL"`
	// IssuedURL is the base URL of the issued credentials service. Empty
	// writes the record to the log only.
	IssuedURL string `env:"ISSUED_URL"`
	// DeliverySender names the sender of the offer and the document
	// channels. The values are log and file.
	DeliverySender string `env:"DELIVERY_SENDER" default:"log"`
	// EmailSender names the sender of the email channel. The values are
	// stub, log, and file. The stub reports that the deployment has no
	// mail gateway.
	EmailSender string `env:"EMAIL_SENDER" default:"stub"`
	// SMSSender names the sender of the SMS channel. The values are
	// stub, log, and file.
	SMSSender string `env:"SMS_SENDER" default:"stub"`
	// DeliveryDir is the directory of the file sender.
	DeliveryDir string `env:"DELIVERY_DIR"`
	// DocumentTitle is the heading of a rendered document.
	DocumentTitle string `env:"DOCUMENT_TITLE" default:"Credential"`
	// DocumentIssuer is the line above the heading of a document.
	DocumentIssuer string `env:"DOCUMENT_ISSUER"`
	// DocumentFooter is the line at the foot of a document.
	DocumentFooter string `env:"DOCUMENT_FOOTER"`
	// StoreFile keeps the offers and the batch jobs between restarts.
	// Empty keeps them in memory.
	StoreFile string `env:"STORE_FILE"`
	// OfferTTL is the life of an offer and of a rendered document.
	OfferTTL time.Duration `env:"OFFER_TTL" default:"24h"`
	// Timeout bounds one call to another service.
	Timeout time.Duration `env:"TIMEOUT" default:"30s"`
	// BatchWorkers is the number of rows the service issues at once.
	BatchWorkers int `env:"BATCH_WORKERS" default:"4"`
	// PageSizeMax caps a list page.
	PageSizeMax int `env:"PAGE_SIZE_MAX" default:"50"`
	// DocsURL is the base of the documents the help page links.
	DocsURL string `env:"DOCS_URL" default:"https://github.com/centre-for-dpi/verifiably/tree/main/vca/docs"`
	// AuditDir keeps the audit events of the issues, one file for each
	// event (ADR-039). Empty keeps them in memory.
	AuditDir string `env:"AUDIT_DIR"`
	// AdminJWKSURL is the key set of the admin service. An admin session
	// it signed opens the audit store. Empty accepts no session.
	AdminJWKSURL string `env:"ADMIN_JWKS_URL"`
	// AdminToken is the admin service token. It opens the audit store
	// too. Empty accepts no token.
	AdminToken string `env:"ADMIN_TOKEN" secret:"true"`

	// ThemeFile is the theme file of the deployment, from VCA_THEME_FILE.
	// Every service that serves HTML reads the same variable, so it
	// carries no service prefix. Empty selects the embedded default look.
	ThemeFile string
	// Auth guards the issuer pages with a session of issuer-auth
	// (ADR-036 decision 3). Its variables carry the same prefix.
	Auth staffsession.Settings
	// Peers are the candidate pairs of the deployment, from VCA_PEERS.
	// The stack switcher and the trust registry of the identity page
	// come from them (ADR-034 decision 1).
	Peers []topology.Peer
}

// Load reads the settings with getenv, for example os.Getenv.
func Load(getenv func(string) string) (Config, error) {
	var c Config
	if err := shared.Load(Prefix, &c, getenv); err != nil {
		return Config{}, err
	}
	if err := shared.Load(Prefix, &c.Auth, getenv); err != nil {
		return Config{}, err
	}
	if err := c.Auth.Check(Prefix); err != nil {
		return Config{}, err
	}
	c.ThemeFile = strings.TrimSpace(getenv(uikit.ThemeFileEnv))
	peers, err := topology.Parse(getenv(topology.Env))
	if err != nil {
		return Config{}, err
	}
	c.Peers = peers
	c.PublicURL = strings.TrimRight(c.PublicURL, "/")
	c.DocsURL = strings.TrimRight(c.DocsURL, "/")
	if c.Timeout <= 0 || c.OfferTTL <= 0 {
		return Config{}, fmt.Errorf("config: %sTIMEOUT and %sOFFER_TTL must be positive durations",
			Prefix, Prefix)
	}
	if c.BatchWorkers <= 0 {
		return Config{}, fmt.Errorf("config: %sBATCH_WORKERS must be a positive number", Prefix)
	}
	if c.PageSizeMax <= 0 {
		return Config{}, fmt.Errorf("config: %sPAGE_SIZE_MAX must be a positive number", Prefix)
	}
	switch c.DeliverySender {
	case "log", "file":
	default:
		return Config{}, fmt.Errorf("config: %sDELIVERY_SENDER must be log or file", Prefix)
	}
	for name, value := range map[string]string{"EMAIL_SENDER": c.EmailSender, "SMS_SENDER": c.SMSSender} {
		switch value {
		case "stub", "log", "file":
		default:
			return Config{}, fmt.Errorf("config: %s%s must be stub, log, or file", Prefix, name)
		}
	}
	usesFile := c.DeliverySender == "file" || c.EmailSender == "file" || c.SMSSender == "file"
	if usesFile && c.DeliveryDir == "" {
		return Config{}, fmt.Errorf("config: the file sender needs %sDELIVERY_DIR", Prefix)
	}
	return c, nil
}

// Describe lists the variables for the start log and the documentation.
func Describe() ([]shared.Variable, error) {
	own, err := shared.Describe(Prefix, &Config{})
	if err != nil {
		return nil, err
	}
	auth, err := shared.Describe(Prefix, &staffsession.Settings{})
	if err != nil {
		return nil, err
	}
	return append(own, auth...), nil
}
