// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// ADR-050 decision 4: a guard test scans the tree for named mock and
// sample artefacts, and deployment files for the words that name one.
// Test doubles live in _test.go files, testdata folders and the fake
// packages, which no deployment reaches (decision 3).

// mockTokens name an artefact that must not ship: a mock image, a
// sample identity, an upstream demo host, a placeholder secret, or a
// compose default for a secret. Each is matched as plain text.
var mockTokens = []string{
	"mock-identity", "mockidentitysystem", "mock_identity", "esignet-mock",
	"MockKeyBindingWrapperService", "MockCSVDataProviderPlugin",
	"MockVCIssuancePlugin", "MockIdaDataProviderPlugin",
	"PreAuthDataProviderPlugin", "csvdp-farmer", "farmer_identity_data",
	"FarmerCredential", "Farmer Issuer", "Gorge Cooper", "James Rodrigious",
	"Jane Thompson", "MOSIPVerifiableCredential", "collab.mosip.net",
	"github.io/inji-config", "ngrok-free.app", "admin@example.com",
	"yopmail.com", "Steward1", "YourSecretPrivateKeyHere", "demo.walt.id",
	"did:web:walt.id", "OpenBadgeCredential", "BankId", "www.example.com",
	"EXAMPLE-CENTER", "Example Unit", "abc123", "1234secret",
	"Kslk30SNF2AChs2", "1234walletbindingkey", "wallet-demo", "111111",
	"Demo user", "demo-token",
}

// secretDefaultRe matches a compose default for a secret, such as
// ${INJI_DB_PASSWORD:-certify}. ADR-055 decision 1: a stack secret has
// no default.
var secretDefaultRe = regexp.MustCompile(`\$\{(?:[A-Z0-9]+_)*(?:PASSWORD|SECRET|KEY)(?:_[A-Z0-9]+)*:-[^}]+\}`)

// composeDefaultRule is the token name of secretDefaultRe in the
// allowlist and the pending list.
const composeDefaultRule = "${VAR:-default}"

// mockWordRe matches a word that names a test double or a sample in a
// deployment file or an operator document.
var mockWordRe = regexp.MustCompile(`(?i)\b(mock|dummy|fake|sample|seed|demo)\b`)

// The token scan skips _test.go and _test.sh files, .proto files (an
// RPC name is an API name), testdata and gen folders, docs/adr (the
// records describe what was removed), and the internal/fake and
// oidcflow/oidctest packages (test doubles that no binary imports, see
// TestNoBinaryImportsAFakePackage).

// nomockException names one line pattern in one file that the word
// rule or the token rule accepts, with the reason.
type nomockException struct {
	path   string // relative to the repository root
	token  string // the word or token the line holds
	reason string
}

// nomockAllowlist holds the lines that stay. Every entry names a test
// path or a use of a word that is not a mock: TestAllowlistEntriesExist
// fails when an entry no longer matches.
var nomockAllowlist = []nomockException{
	{"vca/internal/cli/migrate.go", "fake", "A comment says that a test replaces the database opener with a fake."},
	{"vca/docs/dpg-adapter-credebl.md", "fake", "The document describes the test double of the adapter tests."},
	{"vca/docs/dpg-adapter-credebl.md", "seed", "The DID call of the CREDEBL platform names its private key field seed. The document tells the operator to send the key of the operator straight to the platform."},
	{"vca/docs/dpg-adapter-inji.md", "fake", "The document describes the test double of the adapter tests."},
	{"vca/docs/dpg-adapter-waltid.md", "fake", "The document describes the test double of the adapter tests."},
	{"vca/internal/cli/credebl.go", "seed", "The CREDEBL release names its database initialisation script prisma db seed. The data comes from setup."},
	{"deploy/vca/dpg/credebl.yaml", "seed", "The CREDEBL release names the image of its database initialisation seed. It makes the roles, the agent types and the ledgers of the platform, and the platform admin of setup. It holds no sample data set."},
	{"deploy/vca/dpg/credebl.yaml", "demo", "The api gateway of the CREDEBL release serves stored invitations only under the fixed path /uploadedFiles/demo-shortening-url, so the bucket takes that name. It holds the invitations of real offers."},
	{"vca/docs/deploy.md", "demo", "The operator publishes the fixed path /uploadedFiles/demo-shortening-url of the CREDEBL api gateway, which holds the invitations of real offers."},
	{"vca/hack/contract-tests.sh", "mock-identity", "The contract script refuses a deployment that runs the mock identity system of an old release."},
	{"vca/hack/contract-tests.sh", "esignet-mock", "The contract script refuses a deployment that runs the mock plugin of an old release."},
	{"vca/hack/contract-tests.sh", "farmer_identity_data", "The contract script refuses a deployment that holds the sample identities of an old release."},
	{"vca/hack/contract-tests.sh", "FarmerCredential", "The contract script refuses a deployment that holds the sample credential of an old release."},
	// The login provider that setup names for a service. The code calls
	// it the seed of the provider registry. It holds no data.
	{"vca/services/internal/oidcflow/provider.go", "seed", "Seed is the login provider that setup names, not a data set."},
	{"vca/services/internal/oidcflow/registry.go", "seed", "Registry.Seed stores the login provider that setup names."},
	{"vca/services/admin/internal/app/app.go", "seed", "The admin service stores the login provider that setup names."},
	{"vca/services/admin/internal/config/config.go", "seed", "The login provider that setup names."},
	{"vca/services/issuer-auth/internal/config/config.go", "seed", "The login provider that setup names."},
	{"vca/services/issuer-auth/internal/server/server.go", "seed", "The service stores the login provider that setup names."},
	{"vca/services/verifier-auth/internal/config/config.go", "seed", "The login provider that setup names."},
	{"vca/services/verifier-auth/internal/server/server.go", "seed", "The service stores the login provider that setup names."},
	{"vca/services/wallet-auth/internal/config/config.go", "seed", "The login provider that setup names."},
	{"vca/services/wallet-auth/internal/server/server.go", "seed", "The service stores the login provider that setup names."},
	{"vca/services/dpg-adapter-inji/internal/app/app.go", "seed", "The holder authorization server stores the holder provider that setup names."},
	{"vca/services/dpg-adapter-inji/internal/config/config.go", "seed", "The holder provider that setup names."},
	// Values derived at request time, and the word of an image format.
	{"vca/core/preview/preview.go", "sample", "SampleData derives preview values from the schema of the issuer. Nothing issues them."},
	{"vca/services/schema-builder-ui/internal/service/service.go", "sample", "The RPC SampleData and its field sample are API names. The values come from the schema."},
	{"vca/services/data-source/internal/table/table.go", "sample", "Infer reads a sample of the rows of the operator to find the fields."},
	{"vca/core/ingest/pdf.go", "sample", "A sample is one colour value of an image in a PDF."},
}

// trackedFiles lists the committed files under deploy/ and vca/,
// relative to the repository root, without the folders the scan skips.
func trackedFiles(t *testing.T) []string {
	t.Helper()
	root, err := filepath.Abs(repoRoot())
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(context.Background(), "git", "-C", root, "ls-files", "-z", "--", "deploy", "vca") // #nosec G204 -- fixed arguments
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git ls-files: %v", err)
	}
	var files []string
	for _, name := range bytes.Split(out, []byte{0}) {
		if len(name) == 0 {
			continue
		}
		rel := filepath.ToSlash(string(name))
		if nomockSkipsFile(rel) {
			continue
		}
		if _, err := os.Stat(filepath.Join(root, rel)); err != nil {
			continue // deleted in the working tree
		}
		files = append(files, rel)
	}
	if len(files) < 100 {
		t.Fatalf("git ls-files listed %d files, want the tree", len(files))
	}
	return files
}

// nomockSkipsFile says whether the token scan leaves a file out.
func nomockSkipsFile(rel string) bool {
	if strings.HasSuffix(rel, "_test.go") || strings.HasSuffix(rel, "_test.sh") || strings.HasSuffix(rel, ".proto") {
		return true
	}
	parts := strings.Split(rel, "/")
	for i, p := range parts[:len(parts)-1] {
		if p == "testdata" || p == "gen" {
			return true
		}
		if i > 0 && (p == "adr" && parts[i-1] == "docs" || p == "fake" && parts[i-1] == "internal" ||
			p == "oidctest" && parts[i-1] == "oidcflow") {
			return true
		}
	}
	return false
}

// wordRuleApplies says whether the word rule covers a file: every
// deployment file, every Go source that a binary of VCA compiles, every
// Dockerfile, and the documents that tell an operator what to run.
func wordRuleApplies(rel string) bool {
	base := rel[strings.LastIndex(rel, "/")+1:]
	switch {
	case strings.HasPrefix(rel, "deploy/"):
		return true
	case strings.HasPrefix(rel, "vca/") && strings.HasSuffix(rel, ".go"):
		return true
	case base == "Dockerfile" || strings.HasPrefix(base, "Dockerfile."):
		return true
	case rel == "vca/docs/deploy.md", rel == "vca/docs/cli.md", rel == "vca/docs/getting-started.md", rel == "vca/docs/admin.md":
		return true
	case strings.HasPrefix(rel, "vca/docs/dpg-adapter-") && strings.HasSuffix(rel, ".md"):
		return true
	}
	return false
}

// nomockFinding is one banned token or word on one line.
type nomockFinding struct {
	path  string
	line  int
	token string
	text  string
}

// isBinary says whether a file holds a NUL byte in its first block.
func isBinary(data []byte) bool {
	if len(data) > 8000 {
		data = data[:8000]
	}
	return bytes.IndexByte(data, 0) >= 0
}

// scanFile returns every finding of one file.
func scanFile(rel string, data []byte) []nomockFinding {
	if isBinary(data) {
		return nil
	}
	var out []nomockFinding
	words := wordRuleApplies(rel)
	for i, line := range strings.Split(string(data), "\n") {
		for _, tok := range mockTokens {
			if strings.Contains(line, tok) {
				out = append(out, nomockFinding{rel, i + 1, tok, line})
			}
		}
		if secretDefaultRe.MatchString(line) {
			out = append(out, nomockFinding{rel, i + 1, composeDefaultRule, line})
		}
		if words {
			for _, m := range mockWordRe.FindAllString(line, -1) {
				out = append(out, nomockFinding{rel, i + 1, strings.ToLower(m), line})
			}
		}
	}
	return out
}

// findingMatches says whether an exception covers a finding.
func findingMatches(e nomockException, f nomockFinding) bool {
	return e.path == f.path && strings.EqualFold(e.token, f.token)
}

func excepted(list []nomockException, f nomockFinding) bool {
	for _, e := range list {
		if findingMatches(e, f) {
			return true
		}
	}
	return false
}

// scanTree returns every finding of the tracked files, sorted.
func scanTree(t *testing.T) []nomockFinding {
	t.Helper()
	var out []nomockFinding
	for _, rel := range trackedFiles(t) {
		data, err := os.ReadFile(filepath.Join(repoRoot(), rel)) // #nosec G304 -- a tracked file
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		out = append(out, scanFile(rel, data)...)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].path != out[j].path {
			return out[i].path < out[j].path
		}
		return out[i].line < out[j].line
	})
	return out
}

func TestNoMockArtefactInShippedFiles(t *testing.T) {
	for _, f := range scanTree(t) {
		if excepted(nomockAllowlist, f) {
			continue
		}
		t.Errorf("%s:%d names %q: %s", f.path, f.line, f.token, strings.TrimSpace(f.text))
	}
}

// TestNoPendingRemovals closes the guard (ADR-050 decision 4). The only
// list of exceptions is the allowlist, where each entry has a reason.
// No other list of findings may come back, so a new mock or sample
// artefact fails at once.
func TestNoPendingRemovals(t *testing.T) {
	names, err := filepath.Glob("*_test.go")
	if err != nil || len(names) == 0 {
		t.Fatalf("list the test files: %v", err)
	}
	fset := token.NewFileSet()
	for _, name := range names {
		file, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.VAR {
				continue
			}
			for _, spec := range gen.Specs {
				value, isValue := spec.(*ast.ValueSpec)
				if !isValue {
					continue
				}
				for _, id := range value.Names {
					if exceptionList(value) && id.Name != "nomockAllowlist" {
						t.Errorf("%s declares the exception list %s; put a lasting exception in nomockAllowlist with a reason", name, id.Name)
					}
					if strings.HasPrefix(strings.ToLower(id.Name), "pending") {
						t.Errorf("%s declares %s; the guard keeps no pending findings", name, id.Name)
					}
				}
			}
		}
	}
}

// exceptionList says whether a variable holds nomockException values.
func exceptionList(spec *ast.ValueSpec) bool {
	text := ""
	if spec.Type != nil {
		text = types.ExprString(spec.Type)
	}
	for _, v := range spec.Values {
		text += " " + types.ExprString(v)
	}
	return strings.Contains(text, "nomockException")
}

func TestAllowlistEntriesExist(t *testing.T) {
	findings := scanTree(t)
	for _, e := range nomockAllowlist {
		if e.reason == "" {
			t.Errorf("allowlist entry %s %q has no reason", e.path, e.token)
		}
		if !anyFinding(findings, e) {
			t.Errorf("allowlist entry %s %q matches nothing; delete it", e.path, e.token)
		}
	}
}

func anyFinding(findings []nomockFinding, e nomockException) bool {
	for _, f := range findings {
		if findingMatches(e, f) {
			return true
		}
	}
	return false
}

// TestNoDeploymentReachesTestdata: no deployment file, Dockerfile,
// compose file or CLI source names a test path (ADR-050 decision 3).
func TestNoDeploymentReachesTestdata(t *testing.T) {
	checked := 0
	for _, rel := range trackedFiles(t) {
		base := filepath.Base(rel)
		deployment := strings.HasPrefix(rel, "deploy/") ||
			base == "Dockerfile" || strings.HasPrefix(base, "Dockerfile.") ||
			strings.Contains(base, "compose") && (strings.HasSuffix(base, ".yaml") || strings.HasSuffix(base, ".yml")) ||
			strings.HasPrefix(rel, "vca/internal/cli/") && strings.HasSuffix(rel, ".go")
		if !deployment {
			continue
		}
		checked++
		data, err := os.ReadFile(filepath.Join(repoRoot(), rel)) // #nosec G304 -- a tracked file
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			for _, f := range testPathMarks(line) {
				t.Errorf("%s:%d names the test path %q", rel, i+1, f)
			}
		}
	}
	if checked < 50 {
		t.Fatalf("checked %d deployment files, want the tree", checked)
	}
}

// TestNoBinaryImportsAFakePackage: the internal/fake packages are test
// doubles (ADR-050 decision 3), so no source file outside a test
// imports one. The token scan skips them on that ground.
func TestNoBinaryImportsAFakePackage(t *testing.T) {
	fakes := 0
	for _, rel := range trackedFiles(t) {
		if !strings.HasSuffix(rel, ".go") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(repoRoot(), rel)) // #nosec G304 -- a tracked file
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			if strings.Contains(line, "/internal/fake\"") || strings.Contains(line, "/oidcflow/oidctest\"") {
				t.Errorf("%s:%d imports a fake package", rel, i+1)
			}
		}
	}
	entries, err := filepath.Glob(filepath.Join(repoRoot(), "vca", "services", "*", "internal", "fake"))
	if err != nil {
		t.Fatal(err)
	}
	fakes = len(entries)
	if fakes == 0 {
		t.Fatal("no internal/fake package found; the skip rule of the scan is stale")
	}
}

// testPathMarks returns the test path words a line holds.
func testPathMarks(line string) []string {
	var out []string
	for _, mark := range []string{"testdata", "_test.go"} {
		if strings.Contains(line, mark) {
			out = append(out, mark)
		}
	}
	return out
}

// TestScanFileFindsEachRule proves every rule of the scan on text that
// never reaches the tree.
func TestScanFileFindsEachRule(t *testing.T) {
	text := []byte("image: mosipid/mock-identity-system:0.10.1\n" +
		"POSTGRES_PASSWORD: ${INJI_DB_PASSWORD:-certify}\n" +
		"url: ${VCA_KEYCLOAK_URL:-http://127.0.0.1}\n" +
		"# a sample row\n")
	got := map[string]int{}
	for _, f := range scanFile("deploy/vca/dpg/x.yaml", text) {
		got[f.token] = f.line
	}
	want := map[string]int{"mock-identity": 1, "mock": 1, composeDefaultRule: 2, "sample": 4}
	for tok, line := range want {
		if got[tok] != line {
			t.Errorf("token %q found on line %d, want %d", tok, got[tok], line)
		}
	}
	if len(got) != len(want) {
		t.Errorf("findings %v, want %v (a KEYCLOAK URL default is not a secret)", got, want)
	}
	// Every source a binary compiles, every Dockerfile, and the
	// documents of the operator carry the word rule. A design note does
	// not.
	for _, rel := range []string{"vca/services/x/app.go", "vca/core/x/x.go", "vca/services/x/Dockerfile", "vca/docs/getting-started.md"} {
		if n := len(scanFile(rel, []byte("// a sample\n"))); n != 1 {
			t.Errorf("the word rule fired %d times on %s, want once", n, rel)
		}
	}
	if n := len(scanFile("vca/docs/ui.md", []byte("a sample\n"))); n != 0 {
		t.Errorf("the word rule fired %d times on a design note", n)
	}
	if n := len(scanFile("deploy/x.bin", append([]byte{0}, text...))); n != 0 {
		t.Errorf("the scan read %d findings from a binary file", n)
	}
}

func TestExceptionCoversOnlyAMatchingFinding(t *testing.T) {
	findings := []nomockFinding{{path: "deploy/a.yaml", line: 1, token: "mock"}}
	if !anyFinding(findings, nomockException{path: "deploy/a.yaml", token: "Mock"}) {
		t.Error("an entry with the same file and word, in another case, does not match")
	}
	for _, e := range []nomockException{
		{path: "deploy/b.yaml", token: "mock"},
		{path: "deploy/a.yaml", token: "sample"},
	} {
		if anyFinding(findings, e) {
			t.Errorf("entry %v matches a finding of another file or word", e)
		}
	}
}

func TestTestPathMarks(t *testing.T) {
	if got := testPathMarks("      - ./testdata/certs:/certs:ro"); len(got) != 1 || got[0] != "testdata" {
		t.Errorf("marks = %v, want [testdata]", got)
	}
	if got := testPathMarks("      - ./config:/config:ro"); len(got) != 0 {
		t.Errorf("marks = %v, want none", got)
	}
}

func TestNomockSkipsTestPathsOnly(t *testing.T) {
	for _, rel := range []string{
		"vca/internal/cli/x_test.go", "vca/hack/x_test.sh", "vca/proto/x.proto", "vca/services/a/testdata/x.json",
		"vca/gen/x.pb.go", "vca/docs/adr/ADR-050-no-mock-data.md", "vca/services/a/internal/fake/fake.go",
		"vca/services/internal/oidcflow/oidctest/provider.go",
	} {
		if !nomockSkipsFile(rel) {
			t.Errorf("%s is scanned, want skipped", rel)
		}
	}
	for _, rel := range []string{
		"deploy/vca/dpg/inji.yaml", "vca/internal/cli/bootstrap.go", "vca/docs/deploy.md",
		"vca/services/a/internal/service/fake.go", "vca/ui/example/example.go",
	} {
		if nomockSkipsFile(rel) {
			t.Errorf("%s is skipped, want scanned", rel)
		}
	}
}
