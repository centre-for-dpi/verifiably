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
	"strconv"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	combinedv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/combined/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/combined/v1/combinedv1connect"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
)

// combinedService is the service of a verifier pair that keeps the
// combined templates (ADR-026).
const combinedService = "verifier-combined"

// combinedPageSize is the page size the vca command lists templates with.
const combinedPageSize = 50

// CombinedOptions holds one run of a vca combined command (ADR-078).
type CombinedOptions struct {
	// Root is the repository root that holds the deploy directory.
	Root string
	// Pair is the verifier pair whose combined service the run calls.
	Pair Pair
	// Values are the settings of the pair, from its .env.
	Values map[string]string
	// Client calls the service. Nil means http.DefaultClient.
	Client *http.Client
	// Out receives one line per result.
	Out io.Writer
}

// client returns the combined service of the pair on its host port,
// with a client that signs as the vca command (ADR-075).
func (o CombinedOptions) client() (combinedv1connect.CombinedServiceClient, error) {
	base := ""
	for _, a := range HostPorts(o.Pair, o.Values) {
		if a.Service.Name == combinedService {
			base = "http://" + LoopbackAddress + ":" + strconv.Itoa(a.Host)
		}
	}
	if base == "" {
		return nil, fmt.Errorf("combined: the pair %s runs no %s; name a verifier pair", o.Pair.Name(), combinedService)
	}
	c := o.Client
	if c == nil {
		c = http.DefaultClient
	}
	signed, err := CLIPeerClient(filepath.Join(o.Root, "deploy"), c, rand.Reader)
	if err != nil {
		return nil, err
	}
	return combinedv1connect.NewCombinedServiceClient(signed, base), nil
}

// CombinedCreate stores the combined template of a JSON file in the
// combined service of the pair. The file holds one CombinedTemplate in
// the JSON form of the proto API.
func CombinedCreate(ctx context.Context, o CombinedOptions, file string) error {
	raw, err := os.ReadFile(file) // #nosec G304 -- the operator names the file
	if err != nil {
		return fmt.Errorf("combined create: %w", err)
	}
	var t combinedv1.CombinedTemplate
	if uerr := protojson.Unmarshal(raw, &t); uerr != nil {
		return fmt.Errorf("combined create: %s is not a combined template: %w", file, uerr)
	}
	c, err := o.client()
	if err != nil {
		return err
	}
	res, err := c.Create(ctx, connect.NewRequest(&combinedv1.CreateRequest{Template: &t}))
	if err != nil {
		return fmt.Errorf("combined create: the service of %s refused the template: %w", o.Pair.Name(), err)
	}
	anyval.DiscardWrite(fmt.Fprintf(o.Out, "Stored the combined template %s.\n", res.Msg.GetTemplate().GetId()))
	return nil
}

// CombinedList prints the combined templates of the pair, one per line:
// the id, the name, and the number of members and rules.
func CombinedList(ctx context.Context, o CombinedOptions) error {
	c, err := o.client()
	if err != nil {
		return err
	}
	count, token := 0, ""
	for {
		res, err := c.List(ctx, connect.NewRequest(&combinedv1.ListRequest{
			Page: &commonv1.Pagination{PageSize: combinedPageSize, PageToken: token},
		}))
		if err != nil {
			return fmt.Errorf("combined list: %w", err)
		}
		for _, t := range res.Msg.GetTemplates() {
			count++
			anyval.DiscardWrite(fmt.Fprintf(o.Out, "%s  %s  %d members  %d rules\n",
				t.GetId(), t.GetDisplayName(), len(t.GetMembers()), len(t.GetRules())))
		}
		token = res.Msg.GetPage().GetNextPageToken()
		if token == "" {
			break
		}
	}
	if count == 0 {
		anyval.DiscardWrite(fmt.Fprintf(o.Out, "The pair %s holds no combined template.\n", o.Pair.Name()))
	}
	return nil
}

// CombinedDelete removes one combined template of the pair.
func CombinedDelete(ctx context.Context, o CombinedOptions, id string) error {
	if id == "" {
		return errors.New("combined delete: name the id of the template")
	}
	c, err := o.client()
	if err != nil {
		return err
	}
	if _, err := c.Delete(ctx, connect.NewRequest(&combinedv1.DeleteRequest{Id: id})); err != nil {
		return fmt.Errorf("combined delete: %w", err)
	}
	anyval.DiscardWrite(fmt.Fprintf(o.Out, "Removed the combined template %s.\n", id))
	return nil
}
