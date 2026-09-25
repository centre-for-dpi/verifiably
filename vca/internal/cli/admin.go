// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	adminv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
)

// AdminService is the full proto service name. The Connect URL of one
// RPC is /<service>/<method>.
const AdminService = "vca.admin.v1.AdminService"

// AdminCommand is one leaf of the vca admin command tree. It maps one
// RPC of the admin service to a command group and a verb
// (ADR-009 decisions 1 and 2).
type AdminCommand struct {
	// Group is the first word after admin, for example tenant.
	Group string
	// Verb is the second word, for example create.
	Verb string
	// Method is the RPC name, for example CreateTenant.
	Method string
	// Description is the description option of the RPC in Simplified
	// Technical English (ADR-009 decision 4).
	Description string
}

// Path is the command path, for example "tenant create".
func (c AdminCommand) Path() string {
	if c.Verb == "" {
		return c.Group
	}
	return c.Group + " " + c.Verb
}

// URL returns the Connect URL of the RPC under a base URL.
func (c AdminCommand) URL(base string) string {
	return strings.TrimRight(base, "/") + "/" + AdminService + "/" + c.Method
}

// adminPaths is the command tree of the admin service. The same table
// lives in services/admin/internal/service/commands.go, which the
// portal help page renders. A test checks that the two agree, so the
// CLI and the portal never show a different command (ADR-009 decision 3).
//
// The order is the order of the help page.
var adminPaths = []struct{ path, method string }{
	{"tenant create", "CreateTenant"},
	{"tenant get", "GetTenant"},
	{"tenant list", "ListTenants"},
	{"tenant update", "UpdateTenant"},
	{"tenant delete", "DeleteTenant"},
	{"tenant bind", "BindTenant"},
	{"tenant unbind", "UnbindTenant"},
	{"trust add", "UpsertTrustEntry"},
	{"trust get", "GetTrustEntry"},
	{"trust list", "ListTrustEntries"},
	{"trust remove", "DeleteTrustEntry"},
	{"trust approve", "ApproveTrustEntry"},
	{"trust reject", "RejectTrustEntry"},
	{"registry add", "AddTrustRegistry"},
	{"registry list", "ListTrustRegistries"},
	{"registry remove", "RemoveTrustRegistry"},
	{"registry sync", "SyncTrustRegistry"},
	{"onboard", "CreateAuthProvider"},
	{"onboard-provider", "OnboardProvider"},
	{"provider get", "GetAuthProvider"},
	{"provider list", "ListAuthProviders"},
	{"provider update", "UpdateAuthProvider"},
	{"provider remove", "DeleteAuthProvider"},
	{"apikey create", "CreateApiKey"},
	{"apikey list", "ListApiKeys"},
	{"apikey revoke", "RevokeApiKey"},
	{"stack-credential list", "ListStackCredentials"},
	{"stack-credential create", "CreateStackCredential"},
	{"stack-credential delete", "DeleteStackCredential"},
	{"health", "GetServiceHealth"},
	{"audit", "QueryAuditLog"},
	{"bind", "OnboardAdmin"},
	{"help", "ListCommands"},
}

// AdminCommands lists the command tree in the order of the help page.
// The description of each command is the description option of its RPC,
// so one sentence written once reaches the CLI, the man pages, the
// portal help page, and the OpenAPI file (ADR-009 decisions 3 and 4).
func AdminCommands() []AdminCommand {
	descriptions := adminDescriptions()
	out := make([]AdminCommand, 0, len(adminPaths))
	for _, item := range adminPaths {
		group, verb, _ := strings.Cut(item.path, " ")
		out = append(out, AdminCommand{
			Group:       group,
			Verb:        verb,
			Method:      item.method,
			Description: descriptions[item.method],
		})
	}
	return out
}

// adminDescriptions reads the description option of every RPC of the
// admin service from the generated descriptor.
func adminDescriptions() map[string]string {
	out := map[string]string{}
	sd := (&adminv1.CreateTenantRequest{}).ProtoReflect().Descriptor().
		ParentFile().Services().ByName("AdminService")
	if sd == nil {
		return out
	}
	methods := sd.Methods()
	for i := 0; i < methods.Len(); i++ {
		md := methods.Get(i)
		out[string(md.Name())] = methodDescription(md)
	}
	return out
}

// methodDescription reads the description option of one RPC.
func methodDescription(md protoreflect.MethodDescriptor) string {
	if text, ok := proto.GetExtension(md.Options(), commonv1.E_Description).(string); ok {
		return text
	}
	return ""
}

// AdminGroupNames lists the command groups in order, with no repeats.
func AdminGroupNames() []string {
	var out []string
	seen := map[string]bool{}
	for _, c := range AdminCommands() {
		if seen[c.Group] {
			continue
		}
		seen[c.Group] = true
		out = append(out, c.Group)
	}
	return out
}

// AdminClient calls the admin service over Connect. The Connect unary
// protocol over JSON is one POST per RPC, so the CLI needs no generated
// client and no extra dependency.
type AdminClient struct {
	// BaseURL is the admin service URL, for example https://admin.example.
	BaseURL string
	// Token is the bearer token of the logged in super admin.
	Token string
	// HTTP makes the calls. A nil value means http.DefaultClient.
	HTTP *http.Client
}

// ConnectError is a Connect error answer.
type ConnectError struct {
	// Status is the HTTP status the server sent.
	Status int
	// Code is the Connect error code, for example not_found.
	Code string `json:"code"`
	// Message is the error text.
	Message string `json:"message"`
}

func (e *ConnectError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("the admin service answered %d", e.Status)
	}
	return fmt.Sprintf("the admin service answered %s: %s", e.Code, e.Message)
}

// Call sends one RPC and returns the answer body.
// The request body is the JSON form of the request message.
func (c AdminClient) Call(ctx context.Context, cmd AdminCommand, body []byte) ([]byte, error) {
	if strings.TrimSpace(c.BaseURL) == "" {
		return nil, fmt.Errorf("admin: set the service URL with --url or VCA_ADMIN_URL")
	}
	if len(bytes.TrimSpace(body)) == 0 {
		body = []byte("{}")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cmd.URL(c.BaseURL), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build the request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connect-Protocol-Version", "1")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	client := c.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("call %s: %w", cmd.Method, err)
	}
	defer func() { anyval.Discard(resp.Body.Close()) }()
	answer, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("read the answer: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		fault := &ConnectError{Status: resp.StatusCode}
		anyval.Discard(json.Unmarshal(answer, fault))
		return nil, fault
	}
	return answer, nil
}

// PrettyJSON re-indents a JSON answer for the terminal. It returns the
// input unchanged when the input is not JSON.
func PrettyJSON(in []byte) string {
	var out bytes.Buffer
	if err := json.Indent(&out, in, "", "  "); err != nil {
		return string(in)
	}
	return strings.TrimRight(out.String(), "\n") + "\n"
}
