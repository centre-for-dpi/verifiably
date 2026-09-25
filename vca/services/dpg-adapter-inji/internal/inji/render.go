// SPDX-License-Identifier: Apache-2.0

package inji

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/centre-for-dpi/vc-adapters/services/internal/dpgclient"
)

// renderingTemplatePath serves one SVG template of Inji Certify 0.14.0
// as image/svg+xml.
const renderingTemplatePath = "/v1/certify/rendering-template/"

// MaxRenderBytes caps an SVG template the adapter passes on.
const MaxRenderBytes = 256 << 10

// ErrRenderTooLarge reports an SVG template above MaxRenderBytes.
var ErrRenderTooLarge = errors.New("inji: the rendering template is too large")

// RenderingTemplateURL returns the address of one template under the
// public issuer URL of Certify.
func RenderingTemplateURL(issuer, id string) string {
	return strings.TrimRight(issuer, "/") + renderingTemplatePath + url.PathEscape(id)
}

// renderRef finds the template id in the render method of a template.
var renderRef = regexp.MustCompile(`/v1/certify/rendering-template/([A-Za-z0-9._~-]+)`)

// RenderRefs returns the ids of the rendering templates that a
// credential template names, once each, in order.
func RenderRefs(template string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range renderRef.FindAllStringSubmatch(template, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	return out
}

// RenderingTemplate reads one SVG template.
func (c *Certify) RenderingTemplate(ctx context.Context, id string) (string, error) {
	if c == nil {
		return "", ErrNoCertify
	}
	resp, err := c.client.Do(ctx, dpgclient.Request{
		Method: http.MethodGet, Path: renderingTemplatePath + url.PathEscape(id), Accept: "image/svg+xml",
	})
	if err != nil {
		return "", err
	}
	if len(resp.Body) > MaxRenderBytes {
		return "", fmt.Errorf("%w: %d bytes", ErrRenderTooLarge, len(resp.Body))
	}
	if !strings.Contains(string(resp.Body), "<svg") {
		return "", errors.New("inji: the rendering template is not an SVG document")
	}
	return string(resp.Body), nil
}
