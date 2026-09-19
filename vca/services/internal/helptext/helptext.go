// SPDX-License-Identifier: Apache-2.0

// Package helptext reads the description option of every RPC from the
// generated protobuf descriptors (ADR-009 decision 4). One sentence in
// the proto file becomes the CLI help, the man page, the portal help
// page, and the OpenAPI description.
//
// The package reads the global protobuf registry. A service appears
// only when its generated package is linked into the binary. The admin
// service links vca/admin/v1, so the admin help page shows every admin
// RPC.
//
// The package holds no state. Every function is safe for concurrent use.
package helptext

import (
	"sort"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
)

// Entry is one RPC and its help text.
type Entry struct {
	// Service is the full service name, for example
	// vca.admin.v1.AdminService.
	Service string
	// Method is the RPC name, for example CreateTenant.
	Method string
	// Procedure is the Connect path, for example
	// /vca.admin.v1.AdminService/CreateTenant.
	Procedure string
	// Description is the help text in Simplified Technical English.
	// It is empty when the proto file sets no description option.
	Description string
}

// ShortService returns the service name without the package, for
// example AdminService.
func (e Entry) ShortService() string {
	if i := strings.LastIndex(e.Service, "."); i >= 0 {
		return e.Service[i+1:]
	}
	return e.Service
}

// All returns every RPC of every linked service, sorted by procedure.
func All() []Entry {
	var out []Entry
	protoregistry.GlobalFiles.RangeFiles(func(file protoreflect.FileDescriptor) bool {
		services := file.Services()
		for i := 0; i < services.Len(); i++ {
			out = append(out, entriesOf(services.Get(i))...)
		}
		return true
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Procedure < out[j].Procedure })
	return out
}

// Service returns the RPCs of one service, in proto file order. The
// name is the full name or the short name. An unknown name returns nil.
func Service(name string) []Entry {
	var out []Entry
	protoregistry.GlobalFiles.RangeFiles(func(file protoreflect.FileDescriptor) bool {
		services := file.Services()
		for i := 0; i < services.Len(); i++ {
			sd := services.Get(i)
			if !matches(string(sd.FullName()), name) {
				continue
			}
			out = entriesOf(sd)
			return false
		}
		return true
	})
	return out
}

// Describe returns the help text of one RPC. The service is the full
// name or the short name. An unknown service or RPC returns "".
func Describe(service, rpc string) string {
	for _, e := range Service(service) {
		if e.Method == rpc {
			return e.Description
		}
	}
	return ""
}

// entriesOf reads every method of one service descriptor.
func entriesOf(sd protoreflect.ServiceDescriptor) []Entry {
	methods := sd.Methods()
	out := make([]Entry, 0, methods.Len())
	for i := 0; i < methods.Len(); i++ {
		md := methods.Get(i)
		out = append(out, Entry{
			Service:     string(sd.FullName()),
			Method:      string(md.Name()),
			Procedure:   "/" + string(sd.FullName()) + "/" + string(md.Name()),
			Description: descriptionOf(md),
		})
	}
	return out
}

// descriptionOf reads the vca.common.v1.description option of one RPC.
func descriptionOf(md protoreflect.MethodDescriptor) string {
	opts, ok := md.Options().(*descriptorpb.MethodOptions)
	if !ok || opts == nil {
		return ""
	}
	value := proto.GetExtension(opts, commonv1.E_Description)
	text, ok := value.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(text)
}

// matches reports whether full is the wanted service name. The wanted
// name is the full name or the name without the package.
func matches(full, want string) bool {
	if want == "" {
		return false
	}
	if full == want {
		return true
	}
	i := strings.LastIndex(full, ".")
	return i >= 0 && full[i+1:] == want
}
