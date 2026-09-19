// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
)

// XMLEncoding names how the credential sits in the XML text
// (ADR-023 decision 4).
type XMLEncoding string

const (
	// XMLText means the element text is the credential.
	XMLText XMLEncoding = "text"
	// XMLBase64 means the element text is the credential in base64.
	XMLBase64 XMLEncoding = "base64"
)

// XMLConfig says where a credential sits in an XML document.
type XMLConfig struct {
	// Path is the element path, written as dotted local names, for
	// example Envelope.Body.Credential. An attribute is the last step
	// with an at sign, for example Body.Credential.@value. The path
	// matches local names, so a namespace prefix in the document does
	// not change it.
	Path string
	// Encoding names the encoding of the text. Empty means XMLText.
	Encoding XMLEncoding
	// Namespaces maps a prefix of the path to a namespace URL. A step
	// written as prefix:name then matches only that namespace.
	Namespaces map[string]string
}

// ErrXMLPathNotFound reports that the document has nothing at the path.
var ErrXMLPathNotFound = errors.New("ingest: the XML document has nothing at the path")

// MaxXMLDepth bounds the element depth the reader follows.
const MaxXMLDepth = 64

// IsXML reports whether the bytes look like an XML document.
func IsXML(data []byte) bool {
	trimmed := strings.TrimLeft(string(data), " \r\n\t\ufeff")
	return strings.HasPrefix(trimmed, "<")
}

// DecodeXML returns the credential text at the configured path. It uses
// encoding/xml, so it needs no XPath library. It attempts no XML
// signature check, as ADR-023 decision 4 says.
func DecodeXML(data []byte, cfg XMLConfig) (string, error) {
	steps, attribute, err := parseXMLPath(cfg.Path)
	if err != nil {
		return "", err
	}
	text, err := findXMLValue(data, cfg, steps, attribute)
	if err != nil {
		return "", err
	}
	return decodeXMLText(text, cfg.Encoding)
}

// decodeXMLText applies the configured encoding to the found text.
func decodeXMLText(text string, encoding XMLEncoding) (string, error) {
	text = strings.TrimSpace(text)
	switch encoding {
	case "", XMLText:
		return text, nil
	case XMLBase64:
		raw, err := decodeBase64(text)
		if err != nil {
			return "", fmt.Errorf("ingest: the XML text is not base64: %w", err)
		}
		return string(raw), nil
	}
	return "", fmt.Errorf("ingest: the XML encoding %q is not known", encoding)
}

// decodeBase64 accepts the padded and the unpadded alphabet.
func decodeBase64(text string) ([]byte, error) {
	clean := strings.Join(strings.Fields(text), "")
	if raw, err := base64.StdEncoding.DecodeString(clean); err == nil {
		return raw, nil
	}
	return base64.RawStdEncoding.DecodeString(clean)
}

// parseXMLPath splits the path into element steps and an attribute.
func parseXMLPath(path string) ([]string, string, error) {
	path = strings.TrimSpace(strings.Trim(strings.TrimSpace(path), "/."))
	if path == "" {
		return nil, "", errors.New("ingest: the XML path is empty")
	}
	var steps []string
	attribute := ""
	for _, step := range strings.Split(path, ".") {
		step = strings.TrimSpace(step)
		if step == "" {
			return nil, "", fmt.Errorf("ingest: the XML path %q has an empty step", path)
		}
		if strings.HasPrefix(step, "@") {
			attribute = step[1:]
			if attribute == "" {
				return nil, "", fmt.Errorf("ingest: the XML path %q has an empty attribute name", path)
			}
			continue
		}
		if attribute != "" {
			return nil, "", fmt.Errorf("ingest: the XML path %q has a step after the attribute", path)
		}
		steps = append(steps, step)
	}
	if len(steps) == 0 {
		return nil, "", fmt.Errorf("ingest: the XML path %q names no element", path)
	}
	if len(steps) > MaxXMLDepth {
		return nil, "", fmt.Errorf("ingest: the XML path %q is deeper than %d steps", path, MaxXMLDepth)
	}
	return steps, attribute, nil
}

// findXMLValue walks the document and returns the text or the attribute
// at the path.
func findXMLValue(data []byte, cfg XMLConfig, steps []string, attribute string) (string, error) {
	dec := xml.NewDecoder(strings.NewReader(string(data)))
	dec.Strict = false
	var stack []xml.Name
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return "", ErrXMLPathNotFound
		}
		if err != nil {
			return "", fmt.Errorf("ingest: read the XML document: %w", err)
		}
		start, ok := tok.(xml.StartElement)
		if !ok {
			if _, isEnd := tok.(xml.EndElement); isEnd && len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			continue
		}
		stack = append(stack, start.Name)
		if len(stack) > MaxXMLDepth {
			return "", fmt.Errorf("ingest: the XML document is deeper than %d elements", MaxXMLDepth)
		}
		if !matchPath(stack, steps, cfg.Namespaces) {
			continue
		}
		if attribute != "" {
			for _, a := range start.Attr {
				if a.Name.Local == attribute {
					return a.Value, nil
				}
			}
			return "", ErrXMLPathNotFound
		}
		return elementText(dec)
	}
}

// elementText reads the character data of the element the reader is in.
// It stops at the end tag of that element.
func elementText(dec *xml.Decoder) (string, error) {
	var b strings.Builder
	depth := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			return "", fmt.Errorf("ingest: read the XML element: %w", err)
		}
		switch t := tok.(type) {
		case xml.CharData:
			if depth == 0 {
				b.Write(t)
			}
		case xml.StartElement:
			depth++
		case xml.EndElement:
			if depth == 0 {
				return b.String(), nil
			}
			depth--
		}
	}
}

// matchPath reports whether the element stack ends with the path steps.
func matchPath(stack []xml.Name, steps []string, namespaces map[string]string) bool {
	if len(stack) != len(steps) {
		return false
	}
	for i, step := range steps {
		if !matchStep(stack[i], step, namespaces) {
			return false
		}
	}
	return true
}

// matchStep reports whether one element matches one path step.
func matchStep(name xml.Name, step string, namespaces map[string]string) bool {
	prefix := ""
	local := step
	if cut := strings.Index(step, ":"); cut >= 0 {
		prefix, local = step[:cut], step[cut+1:]
	}
	if local != "*" && name.Local != local {
		return false
	}
	if prefix == "" {
		return true
	}
	return namespaces[prefix] == name.Space
}
