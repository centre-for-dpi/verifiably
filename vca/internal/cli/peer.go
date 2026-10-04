// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	"github.com/centre-for-dpi/vc-adapters/internal/peerauth"
)

// The identity of each service on the compose network (ADR-075). Setup
// keeps one authority key per deployment in deploy/PeerDir and gives
// each service an identity file of its own under the directory of its
// pair: <pair>/PeerDir/<service>.env, and its private key in
// <pair>/PeerDir/PeerKeyDir/<service>.jwk.
const (
	// PeerDir is the directory of the authority under the deploy root,
	// and the directory of the identity files under each pair.
	PeerDir = "peer"
	// PeerKeyDir is the directory of the key files under PeerDir. It has
	// mode 0700, so no other user of the host opens it. Each key file in
	// it has mode 0644, so the container user, whose id differs from the
	// id of the operator, reads it through its bind mount.
	PeerKeyDir = "keys"
	// PeerKeyName is the name of the key file in the container, and its
	// key in the Helm Secret of the key.
	PeerKeyName = "key.jwk"
	// PeerKeyMount is the path of the key file in the container. The
	// identity file names it in VCA_PEER_KEY_FILE.
	PeerKeyMount = "/run/vca/peer/" + PeerKeyName
	// PeerAuthorityFile is the authority key in PKCS#8 PEM form.
	PeerAuthorityFile = "authority.pem"
	// CLIPeer is the caller name of the vca command. It signs its calls
	// with an identity it issues from the authority at each run.
	CLIPeer = "cli"
)

// The Connect services that stay on the compose network, by full name
// (ADR-047 decision 2). The Callers of the catalogue use them.
const (
	rpcAdmin         = "vca.admin.v1.AdminService"
	rpcAudit         = "vca.audit.v1.AuditService"
	rpcCapability    = "vca.backend.v1.CapabilityService"
	rpcIssuerBackend = "vca.backend.v1.IssuerBackendService"
	rpcHolderBackend = "vca.backend.v1.HolderBackendService"
	rpcVerifierBack  = "vca.backend.v1.VerifierBackendService"
	rpcCatalog       = "vca.backend.v1.CatalogBackendService"
	rpcTenant        = "vca.backend.v1.TenantBackendService"
	rpcNotification  = "vca.backend.v1.NotificationBackendService"
	rpcBulkImport    = "vca.backend.v1.BulkImportBackendService"
	rpcCombined      = "vca.combined.v1.CombinedService"
	rpcDataSource    = "vca.datasource.v1.DataSourceService"
	rpcDiscovery     = "vca.discovery.v1.DiscoveryService"
	rpcIngest        = "vca.ingest.v1.IngestService"
	rpcIssuance      = "vca.issuance.v1.IssuanceService"
	rpcIssued        = "vca.issued.v1.IssuedService"
	rpcPolicy        = "vca.policy.v1.PolicyService"
	rpcResults       = "vca.results.v1.ResultsService"
	rpcSchema        = "vca.schema.v1.SchemaService"
	rpcSchemaBuilder = "vca.schemabuilder.v1.SchemaBuilderService"
	rpcStatus        = "vca.status.v1.StatusService"
	rpcTrust         = "vca.trust.v1.TrustService"
	rpcWalletPortal  = "vca.walletportal.v1.WalletPortalService"
)

// auditCallers are the callers of the audit store of a service: the
// admin reads every audit log (ADR-039).
func auditCallers() []string { return []string{"admin"} }

// statusCallers are the callers of a status service: the issuance
// service allocates an entry, and the issued credentials service
// changes it.
func statusCallers() []string { return []string{"issuance", "issued-credentials"} }

// adapterCallers are the callers of the Connect services of a DPG
// adapter. Catalog fills the callers of the capability service with
// every service that draws pages.
func adapterCallers() map[string][]string {
	return map[string][]string{
		rpcCapability:    nil,
		rpcIssuerBackend: {CLIPeer, "issuance", "issued-credentials", "schema-registry"},
		rpcHolderBackend: {"wallet-auth", "wallet-portal"},
		rpcVerifierBack:  {"verifier-discovery", "verifier-ingest"},
		rpcCatalog:       {"schema-builder-ui"},
		rpcTenant:        {"admin"},
		rpcNotification:  {"admin"},
		rpcBulkImport:    {"issuance"},
	}
}

// withCallers adds the callers of one more Connect service to m.
func withCallers(m map[string][]string, service string, callers ...string) map[string][]string {
	m[service] = callers
	return m
}

// PeerFile is the identity file of one service, relative to the
// directory of its pair or of the landing.
func PeerFile(service string) string { return filepath.Join(PeerDir, service+EnvFileName) }

// PeerKeyFile is the path of the key file of a service, relative to the
// directory of its pair.
func PeerKeyFile(service string) string {
	return filepath.Join(PeerDir, PeerKeyDir, service+".jwk")
}

// peerKeyFile returns the key file of a service as a file of a plan,
// under dir.
func peerKeyFile(dir, service string, key []byte) File {
	return File{Name: filepath.Join(dir, PeerKeyFile(service)), Data: key, Mode: 0o644, DirMode: 0o700}
}

// ReadPeerAuthority reads the authority key of the deployment. A
// missing file gives nil, so the first setup run makes one.
func ReadPeerAuthority(root string) ([]byte, error) {
	path := filepath.Join(root, PeerDir, PeerAuthorityFile)
	raw, err := os.ReadFile(path) // #nosec G304 -- the path comes from the deploy root
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return raw, nil
}

// peerAuthority parses the authority of an earlier run, or makes a new
// one. A new one comes with the files that keep it, relative to the
// deploy root.
func peerAuthority(existing []byte, random io.Reader) (peerauth.Authority, []File, error) {
	if len(existing) > 0 {
		a, err := peerauth.ParseAuthority(existing)
		if err != nil {
			return peerauth.Authority{}, nil, fmt.Errorf("%s: %w", filepath.Join(PeerDir, PeerAuthorityFile), err)
		}
		return a, nil, nil
	}
	a, err := peerauth.NewAuthority(random)
	if err != nil {
		return peerauth.Authority{}, nil, err
	}
	pemBytes, err := a.PEM()
	if err != nil {
		return peerauth.Authority{}, nil, err
	}
	return a, []File{
		{Name: filepath.Join(PeerDir, PeerAuthorityFile), Data: pemBytes, Mode: 0o600},
		{Name: filepath.Join(PeerDir, ".gitignore"), Data: []byte("*\n"), Mode: 0o600},
	}, nil
}

// peerIdentity issues the identity of one service and renders its file.
// owner is the pair, or the service name of a deployment scoped service.
// deployment marks a deployment scoped service in the statement.
// It returns the identity file and the key file.
func peerIdentity(a peerauth.Authority, owner string, s Service, deployment bool, random io.Reader, now time.Time) ([]byte, []byte, error) {
	id, err := a.Issue(peerauth.ID{Service: s.Name, Pair: owner, Deployment: deployment}, random, now)
	if err != nil {
		return nil, nil, err
	}
	key, err := id.KeyJWK()
	if err != nil {
		return nil, nil, err
	}
	id.Callers = s.Callers
	values := id.Env()
	values[peerauth.KeyFileEnv] = PeerKeyMount
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	var b strings.Builder
	fmt.Fprintf(&b, "# The identity of %s on the compose network (ADR-075).\n", s.Name)
	b.WriteString("# The vca CLI wrote this file. Keep it secret. vca setup writes it again.\n")
	b.WriteString("# The private key is a file of its own, which compose mounts read only.\n")
	for _, name := range names {
		b.WriteString(name + "=" + quoteValue(values[name]) + "\n")
	}
	return []byte(b.String()), key, nil
}

// peerFiles returns the identity file of every service of a pair, and
// of the landing, from the authority of the deployment.
func peerFiles(p Pair, a peerauth.Authority, random io.Reader, now time.Time) (pair, shared []File, err error) {
	// Git ignores the identity files beside the keys.
	ignore := File{Name: filepath.Join(PeerDir, ".gitignore"), Data: []byte("*\n"), Mode: 0o600}
	pair = append(pair, ignore)
	for _, s := range ServicesFor(p) {
		data, key, err := peerIdentity(a, p.Name(), s, false, random, now)
		if err != nil {
			return nil, nil, err
		}
		pair = append(pair, File{Name: PeerFile(s.Name), Data: data, Mode: 0o600}, peerKeyFile("", s.Name, key))
	}
	for _, s := range DeploymentServices() {
		data, key, err := peerIdentity(a, s.Name, s, true, random, now)
		if err != nil {
			return nil, nil, err
		}
		shared = append(shared,
			File{Name: filepath.Join(s.Name, ignore.Name), Data: ignore.Data, Mode: ignore.Mode},
			File{Name: filepath.Join(s.Name, PeerFile(s.Name)), Data: data, Mode: 0o600},
			peerKeyFile(s.Name, s.Name, key))
	}
	return pair, shared, nil
}

// PeerUpgradeOptions holds what one run of UpgradePeerIdentities needs.
type PeerUpgradeOptions struct {
	// Deploy is the deploy directory under the repository root.
	Deploy string
	// Random is the source of the keys.
	Random io.Reader
	// Now reads the clock. Nil reads the real clock.
	Now func() time.Time
	// Out receives the report. It never shows a key.
	Out io.Writer
}

// UpgradePeerIdentities gives a deployment from before ADR-075 its
// authority and an identity file for each service of every pair
// directory with a .env, and for the landing. It keeps every identity
// file that the authority signed, so a second run changes nothing. It
// returns the number of identity files it wrote.
func UpgradePeerIdentities(opts PeerUpgradeOptions) (int, error) {
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	existing, err := ReadPeerAuthority(opts.Deploy)
	if err != nil {
		return 0, err
	}
	authority, authFiles, err := peerAuthority(existing, opts.Random)
	if err != nil {
		return 0, err
	}
	for _, f := range authFiles {
		if err := writePeerFile(opts.Deploy, f); err != nil {
			return 0, err
		}
	}
	if len(authFiles) > 0 {
		anyval.DiscardWrite(fmt.Fprintf(opts.Out, "Made the peer authority %s.\n", filepath.Join(opts.Deploy, PeerDir, PeerAuthorityFile)))
	}
	trusted := authority.PublicSet()
	type target struct {
		owner      string
		dir        string
		s          Service
		deployment bool
	}
	var targets []target
	for _, p := range AllPairs() {
		dir := OutputDir(opts.Deploy, p)
		if _, err := os.Stat(filepath.Join(dir, EnvFileName)); err != nil {
			continue
		}
		for _, s := range ServicesFor(p) {
			targets = append(targets, target{owner: p.Name(), dir: dir, s: s})
		}
	}
	for _, s := range DeploymentServices() {
		dir := filepath.Join(opts.Deploy, s.Name)
		if _, err := os.Stat(filepath.Join(dir, EnvFileName)); err == nil {
			targets = append(targets, target{owner: s.Name, dir: dir, s: s, deployment: true})
		}
	}
	written := 0
	for _, tg := range targets {
		if current(tg.dir, trusted, tg.s, tg.deployment) {
			continue
		}
		data, key, err := peerIdentity(authority, tg.owner, tg.s, tg.deployment, opts.Random, now())
		if err != nil {
			return written, err
		}
		for _, f := range []File{
			{Name: filepath.Join(PeerDir, ".gitignore"), Data: []byte("*\n"), Mode: 0o600},
			{Name: PeerFile(tg.s.Name), Data: data, Mode: 0o600},
			peerKeyFile("", tg.s.Name, key),
		} {
			if err := writePeerFile(tg.dir, f); err != nil {
				return written, err
			}
		}
		anyval.DiscardWrite(fmt.Fprintf(opts.Out, "Wrote the identity of %s/%s.\n", tg.owner, tg.s.Name))
		written++
	}
	if written == 0 {
		anyval.DiscardWrite(fmt.Fprintln(opts.Out, "Every service already holds an identity of the peer authority. Nothing changed."))
	}
	return written, nil
}

// current reports whether the identity file of the service under dir
// holds an identity of the authority with the callers of the catalogue
// and the scope of the service, and names a key file that holds the key
// of its statement. An identity file of an earlier release, with the
// key in the environment, is not current.
func current(dir, trusted string, s Service, deployment bool) bool {
	raw, err := os.ReadFile(filepath.Join(dir, PeerFile(s.Name))) // #nosec G304 -- the path comes from the deploy root
	if err != nil {
		return false
	}
	values, err := ParseDotenv(bytes.NewReader(raw))
	if err != nil || values[peerauth.AuthorityEnv] != trusted || values[peerauth.KeyEnv] != "" || values[peerauth.KeyFileEnv] != PeerKeyMount {
		return false
	}
	values[peerauth.KeyFileEnv] = filepath.Join(dir, PeerKeyFile(s.Name))
	id, err := peerauth.Load(func(k string) string { return values[k] })
	return err == nil && id.ID.Service == s.Name && id.ID.Deployment == deployment &&
		id.Callers.String() == peerauth.Callers(s.Callers).String()
}

// writePeerFile writes one file under dir with its mode, in a
// directory of mode 0750, or of its DirMode.
func writePeerFile(dir string, f File) error {
	path := filepath.Join(dir, f.Name)
	mode := f.DirMode
	if mode == 0 {
		mode = 0o750
	}
	if err := makeDir(filepath.Dir(path), mode); err != nil {
		return err
	}
	if err := os.WriteFile(path, f.Data, f.Mode); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Chmod(path, f.Mode); err != nil {
		return fmt.Errorf("set the mode of %s: %w", path, err)
	}
	return nil
}

// PeerHelmOptions holds what one run of HelmPeerSecrets needs.
type PeerHelmOptions struct {
	// Deploy is the deploy directory. It keeps the authority.
	Deploy string
	// Release is the name of the Helm release.
	Release string
	// Namespace is the namespace of the release. Empty leaves it out.
	Namespace string
	// Random is the source of the keys.
	Random io.Reader
	// Now reads the clock. Nil reads the real clock.
	Now func() time.Time
	// Out receives the manifests.
	Out io.Writer
}

// HelmPeerSecrets writes two Kubernetes Secrets per service chart to
// opts.Out: <release>-<service>-peer with the variables, and
// <release>-<service>-peer-key with the private key, which the chart of
// the service mounts as a file (ADR-075 decision 6). Under Helm one copy of each
// service runs, so the release stands in for the pair. The authority
// stays in deploy/peer, so a later run vouches for the same release.
func HelmPeerSecrets(opts PeerHelmOptions) error {
	if strings.TrimSpace(opts.Release) == "" {
		return errors.New("the peer secrets need the name of the Helm release")
	}
	if !releaseName.MatchString(opts.Release) {
		return fmt.Errorf("the release name %q is not a Helm release name: use lower case letters, digits, and dashes", opts.Release)
	}
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	existing, err := ReadPeerAuthority(opts.Deploy)
	if err != nil {
		return err
	}
	authority, authFiles, err := peerAuthority(existing, opts.Random)
	if err != nil {
		return err
	}
	for _, f := range authFiles {
		if werr := writePeerFile(opts.Deploy, f); werr != nil {
			return werr
		}
	}
	scoped := map[string]bool{}
	for _, s := range DeploymentServices() {
		scoped[s.Name] = true
	}
	// The identities of the release stay under deploy/peer, which git
	// ignores, so a later run reuses them (ADR-075 decision 5).
	dir := HelmPeerDir(opts.Deploy, opts.Release)
	trusted := authority.PublicSet()
	var b strings.Builder
	for _, s := range Catalog() {
		if !current(dir, trusted, s, scoped[s.Name]) {
			data, key, ierr := peerIdentity(authority, opts.Release, s, scoped[s.Name], opts.Random, now())
			if ierr != nil {
				return ierr
			}
			for _, f := range []File{
				{Name: PeerFile(s.Name), Data: data, Mode: 0o600, DirMode: 0o700},
				{Name: PeerKeyFile(s.Name), Data: key, Mode: 0o600, DirMode: 0o700},
			} {
				if werr := writePeerFile(dir, f); werr != nil {
					return werr
				}
			}
		}
		values, key, rerr := readHelmIdentity(dir, s.Name)
		if rerr != nil {
			return rerr
		}
		names := make([]string, 0, len(values))
		for name := range values {
			names = append(names, name)
		}
		sort.Strings(names)
		writeSecret(&b, opts, s.Name+"-peer", "The identity of "+s.Name+" on the cluster network (ADR-075).", names, values)
		// The key goes to a Secret of its own, which the pod mounts as a
		// file, so it stays out of the environment of the container.
		writeSecret(&b, opts, s.Name+"-peer-key", "The private key of "+s.Name+". The pod mounts it read only.",
			[]string{PeerKeyName}, map[string]string{PeerKeyName: string(key)})
	}
	_, err = io.WriteString(opts.Out, b.String())
	return err
}

// releaseName matches a Helm release name: a DNS label of at most 53
// characters.
var releaseName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,51}[a-z0-9])?$`)

// HelmPeerDir is the directory that keeps the identities of a Helm
// release under the deploy directory. Git ignores it with the rest of
// deploy/peer.
func HelmPeerDir(deploy, release string) string {
	return filepath.Join(deploy, PeerDir, "helm", release)
}

// readHelmIdentity reads the variables and the key of one service of a
// release from the files of an earlier run.
func readHelmIdentity(dir, service string) (map[string]string, []byte, error) {
	raw, err := os.ReadFile(filepath.Join(dir, PeerFile(service))) // #nosec G304 -- the path comes from the deploy root
	if err != nil {
		return nil, nil, fmt.Errorf("read the identity of %s: %w", service, err)
	}
	values, err := ParseDotenv(bytes.NewReader(raw))
	if err != nil {
		return nil, nil, fmt.Errorf("read the identity of %s: %w", service, err)
	}
	key, err := os.ReadFile(filepath.Join(dir, PeerKeyFile(service))) // #nosec G304 -- the path comes from the deploy root
	if err != nil {
		return nil, nil, fmt.Errorf("read the key of %s: %w", service, err)
	}
	return values, key, nil
}

// writeSecret writes one Secret of the release with the values named.
func writeSecret(b *strings.Builder, opts PeerHelmOptions, suffix, comment string, names []string, values map[string]string) {
	b.WriteString("---\n")
	b.WriteString("# " + comment + "\n")
	b.WriteString("apiVersion: v1\nkind: Secret\nmetadata:\n")
	fmt.Fprintf(b, "  name: %s-%s\n", opts.Release, suffix)
	if opts.Namespace != "" {
		fmt.Fprintf(b, "  namespace: %s\n", opts.Namespace)
	}
	b.WriteString("type: Opaque\nstringData:\n")
	for _, name := range names {
		fmt.Fprintf(b, "  %s: %q\n", name, values[name])
	}
}

// CLIPeerClient returns a copy of c that signs its Connect calls as the
// vca command. It issues an identity from the authority of the
// deployment for this run. A deployment with no authority yet gets c
// back unchanged.
func CLIPeerClient(deploy string, c *http.Client, random io.Reader) (*http.Client, error) {
	existing, err := ReadPeerAuthority(deploy)
	if err != nil || existing == nil {
		return c, err
	}
	authority, err := peerauth.ParseAuthority(existing)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Join(deploy, PeerDir, PeerAuthorityFile), err)
	}
	// The vca command calls through a port that the host publishes, so
	// its identity is deployment scoped (ADR-075 consequence 3).
	id, err := authority.Issue(peerauth.ID{Service: CLIPeer, Deployment: true}, random, time.Now())
	if err != nil {
		return nil, err
	}
	return id.Client(c), nil
}
