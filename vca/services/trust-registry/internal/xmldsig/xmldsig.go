// SPDX-License-Identifier: Apache-2.0

// Package xmldsig checks the enveloped XML signature of an ETSI TS 119 612
// trusted list (ADR-011 decision 2) against X.509 trust anchors.
//
// The package supports the profile that trusted lists use: exclusive XML
// canonicalization 1.0 without comments, the enveloped signature
// transform, SHA-256, SHA-384 or SHA-512 digests, and RSA PKCS #1 v1.5 or
// ECDSA signatures. The certificate in ds:KeyInfo must be an anchor, or
// an anchor must have issued it. Every reference must match, and one
// reference must cover the document element, so a signature over some
// other element cannot vouch for the list. Any other shape is an error:
// the package never accepts what it cannot check.
//
// References:
//   - XML Signature Syntax and Processing 1.1, https://www.w3.org/TR/xmldsig-core1/
//   - Exclusive XML Canonicalization 1.0, https://www.w3.org/TR/xml-exc-c14n/
//   - Canonical XML 1.0, https://www.w3.org/TR/xml-c14n/
//   - ETSI TS 119 612 V2.3.1 clause 5.7
package xmldsig

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/big"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Namespaces and algorithm identifiers.
const (
	NamespaceDS  = "http://www.w3.org/2000/09/xmldsig#"
	namespaceXML = "http://www.w3.org/XML/1998/namespace"

	AlgExcC14N    = "http://www.w3.org/2001/10/xml-exc-c14n#"
	AlgEnveloped  = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
	algSHA256     = "http://www.w3.org/2001/04/xmlenc#sha256"
	algSHA384     = "http://www.w3.org/2001/04/xmldsig-more#sha384"
	algSHA512     = "http://www.w3.org/2001/04/xmlenc#sha512"
	algRSASHA256  = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	algRSASHA384  = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
	algRSASHA512  = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
	algECDSA256   = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
	algECDSA384   = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
	algECDSA512   = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"
	maxReferences = 8
)

// Errors of Verify. A caller tells a changed list (ErrDigest), a wrong
// signature (ErrSignature) and an unknown signer (ErrAnchor) apart.
var (
	ErrDigest      = errors.New("xmldsig: a reference digest does not match")
	ErrSignature   = errors.New("xmldsig: the signature value does not match")
	ErrAnchor      = errors.New("xmldsig: no trust anchor vouches for the signing certificate")
	ErrUnsupported = errors.New("xmldsig: the signature uses a shape this package does not check")
	ErrMalformed   = errors.New("xmldsig: the document is not a signed XML document")
)

var digests = map[string]crypto.Hash{algSHA256: crypto.SHA256, algSHA384: crypto.SHA384, algSHA512: crypto.SHA512}

var signatures = map[string]struct {
	hash crypto.Hash
	ec   bool
}{
	algRSASHA256: {crypto.SHA256, false}, algRSASHA384: {crypto.SHA384, false}, algRSASHA512: {crypto.SHA512, false},
	algECDSA256: {crypto.SHA256, true}, algECDSA384: {crypto.SHA384, true}, algECDSA512: {crypto.SHA512, true},
}

// Verify checks the enveloped signature of doc and returns the signing
// certificate. anchors are the certificates the caller trusts; now is the
// time of the check for the certificate validity.
func Verify(doc []byte, anchors []*x509.Certificate, now time.Time) (*x509.Certificate, error) {
	root, err := parse(doc)
	if err != nil {
		return nil, err
	}
	sig, err := signatureOf(root)
	if err != nil {
		return nil, err
	}
	signedInfo := sig.child(NamespaceDS, "SignedInfo")
	if signedInfo == nil {
		return nil, fmt.Errorf("%w: ds:SignedInfo is missing", ErrMalformed)
	}
	if alg := signedInfo.child(NamespaceDS, "CanonicalizationMethod").attr("Algorithm"); alg != AlgExcC14N {
		return nil, fmt.Errorf("%w: canonicalization %q", ErrUnsupported, alg)
	}
	method, ok := signatures[signedInfo.child(NamespaceDS, "SignatureMethod").attr("Algorithm")]
	if !ok {
		return nil, fmt.Errorf("%w: signature method %q", ErrUnsupported, signedInfo.child(NamespaceDS, "SignatureMethod").attr("Algorithm"))
	}
	if err = checkReferences(root, sig, signedInfo); err != nil {
		return nil, err
	}
	cert, err := signingCertificate(sig)
	if err != nil {
		return nil, err
	}
	value, err := decode64(sig.child(NamespaceDS, "SignatureValue").textContent())
	if err != nil {
		return nil, fmt.Errorf("%w: signature value: %w", ErrMalformed, err)
	}
	var buf bytes.Buffer
	if err := canonical(&buf, signedInfo, nil, nil); err != nil {
		return nil, err
	}
	if err := checkSignature(cert.PublicKey, method.hash, method.ec, buf.Bytes(), value); err != nil {
		return nil, err
	}
	if err := vouch(cert, anchors, now); err != nil {
		return nil, err
	}
	return cert, nil
}

// Canonical returns the exclusive canonical form of a whole document.
func Canonical(doc []byte) ([]byte, error) {
	root, err := parse(doc)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := canonical(&buf, root, nil, nil); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// signatureOf returns the one ds:Signature child of the document element.
func signatureOf(root *node) (*node, error) {
	var found *node
	for _, c := range root.children {
		if c.isElement() && c.is(NamespaceDS, "Signature") {
			if found != nil {
				return nil, fmt.Errorf("%w: the list carries two signatures", ErrUnsupported)
			}
			found = c
		}
	}
	if found == nil {
		return nil, fmt.Errorf("%w: the document element has no ds:Signature", ErrMalformed)
	}
	return found, nil
}

// checkReferences digests every reference. One must cover the root.
func checkReferences(root, sig, signedInfo *node) error {
	ids, err := indexIDs(root)
	if err != nil {
		return err
	}
	refs := signedInfo.childrenNamed(NamespaceDS, "Reference")
	if len(refs) == 0 || len(refs) > maxReferences {
		return fmt.Errorf("%w: %d references", ErrUnsupported, len(refs))
	}
	coversRoot := false
	for _, ref := range refs {
		target, err := resolve(root, ids, ref.attr("URI"))
		if err != nil {
			return err
		}
		enveloped, err := transforms(ref)
		if err != nil {
			return err
		}
		hash, ok := digests[ref.child(NamespaceDS, "DigestMethod").attr("Algorithm")]
		if !ok {
			return fmt.Errorf("%w: digest %q", ErrUnsupported, ref.child(NamespaceDS, "DigestMethod").attr("Algorithm"))
		}
		want, err := decode64(ref.child(NamespaceDS, "DigestValue").textContent())
		if err != nil {
			return fmt.Errorf("%w: digest value: %w", ErrMalformed, err)
		}
		var skip *node
		if enveloped {
			skip = sig
		}
		h := hash.New()
		if err := canonical(h, target, nil, skip); err != nil {
			return err
		}
		if !bytes.Equal(h.Sum(nil), want) {
			return ErrDigest
		}
		coversRoot = coversRoot || target == root
	}
	if !coversRoot {
		return fmt.Errorf("%w: no reference covers the document element", ErrUnsupported)
	}
	return nil
}

// resolve finds the element of a same document reference.
func resolve(root *node, ids map[string]*node, uri string) (*node, error) {
	if uri == "" {
		return root, nil
	}
	id, ok := strings.CutPrefix(uri, "#")
	if !ok || id == "" {
		return nil, fmt.Errorf("%w: reference URI %q", ErrUnsupported, uri)
	}
	target, ok := ids[id]
	if !ok {
		return nil, fmt.Errorf("%w: no element has the Id %q", ErrMalformed, id)
	}
	return target, nil
}

// transforms checks the transform list. It must end with exclusive
// canonicalization and may hold the enveloped transform before it.
func transforms(ref *node) (enveloped bool, err error) {
	list := ref.child(NamespaceDS, "Transforms").childrenNamed(NamespaceDS, "Transform")
	if len(list) == 0 || list[len(list)-1].attr("Algorithm") != AlgExcC14N {
		return false, fmt.Errorf("%w: a reference must end with exclusive canonicalization", ErrUnsupported)
	}
	for _, tr := range list {
		switch tr.attr("Algorithm") {
		case AlgEnveloped:
			enveloped = true
		case AlgExcC14N:
			for _, c := range tr.children {
				if c.isElement() {
					return false, fmt.Errorf("%w: inclusive namespace prefix lists", ErrUnsupported)
				}
			}
		default:
			return false, fmt.Errorf("%w: transform %q", ErrUnsupported, tr.attr("Algorithm"))
		}
	}
	return enveloped, nil
}

// indexIDs maps the Id, ID and id attributes to their elements.
func indexIDs(root *node) (map[string]*node, error) {
	ids := map[string]*node{}
	var walk func(n *node) error
	walk = func(n *node) error {
		for _, a := range n.attrs {
			if a.Name.Space == "" && (a.Name.Local == "Id" || a.Name.Local == "ID" || a.Name.Local == "id") {
				if _, dup := ids[a.Value]; dup {
					return fmt.Errorf("%w: two elements have the Id %q", ErrMalformed, a.Value)
				}
				ids[a.Value] = n
			}
		}
		for _, c := range n.children {
			if c.isElement() {
				if err := walk(c); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return ids, walk(root)
}

// signingCertificate reads the first certificate of ds:KeyInfo.
func signingCertificate(sig *node) (*x509.Certificate, error) {
	data := sig.child(NamespaceDS, "KeyInfo").child(NamespaceDS, "X509Data").child(NamespaceDS, "X509Certificate")
	if data == nil {
		return nil, fmt.Errorf("%w: ds:KeyInfo holds no X509Certificate", ErrUnsupported)
	}
	der, err := decode64(data.textContent())
	if err != nil {
		return nil, fmt.Errorf("%w: certificate: %w", ErrMalformed, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("%w: certificate: %w", ErrMalformed, err)
	}
	return cert, nil
}

// checkSignature verifies the value over the canonical SignedInfo.
func checkSignature(pub any, hash crypto.Hash, ec bool, signed, value []byte) error {
	h := hash.New()
	h.Write(signed)
	sum := h.Sum(nil)
	switch key := pub.(type) {
	case *rsa.PublicKey:
		if !ec && rsa.VerifyPKCS1v15(key, hash, sum, value) == nil {
			return nil
		}
	case *ecdsa.PublicKey:
		size := (key.Curve.Params().BitSize + 7) / 8
		if ec && len(value) == 2*size {
			r := new(big.Int).SetBytes(value[:size])
			s := new(big.Int).SetBytes(value[size:])
			if ecdsa.Verify(key, sum, r, s) {
				return nil
			}
		}
	}
	return ErrSignature
}

// vouch checks that an anchor is the certificate or issued it, and that
// both are valid at now.
func vouch(cert *x509.Certificate, anchors []*x509.Certificate, now time.Time) error {
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return fmt.Errorf("%w: the signing certificate is not valid at %s", ErrAnchor, now.Format(time.RFC3339))
	}
	for _, a := range anchors {
		if now.Before(a.NotBefore) || now.After(a.NotAfter) {
			continue
		}
		if a.Equal(cert) {
			return nil
		}
		if a.IsCA && cert.CheckSignatureFrom(a) == nil {
			return nil
		}
	}
	return ErrAnchor
}

// decode64 reads base64 with the line breaks that XML signatures carry.
func decode64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), ""))
}

// node is one element, text, or processing instruction of the tree.
type node struct {
	parent   *node
	prefix   string
	local    string
	attrs    []xml.Attr // Name.Space holds the prefix, as RawToken gives it
	decls    map[string]string
	children []*node
	text     string
	kind     int
}

const (
	kindElement = iota
	kindText
	kindInstruction
)

func (n *node) isElement() bool { return n != nil && n.kind == kindElement }

// namespace returns the URI of a prefix in scope at n.
func (n *node) namespace(prefix string) (string, bool) {
	if prefix == "xml" {
		return namespaceXML, true
	}
	for e := n; e != nil; e = e.parent {
		if uri, ok := e.decls[prefix]; ok {
			return uri, true
		}
	}
	return "", prefix == ""
}

// is reports whether n is the element local in namespace space.
func (n *node) is(space, local string) bool {
	uri, _ := n.namespace(n.prefix)
	return n.local == local && uri == space
}

// child returns the first child element with the name, or nil. A nil
// receiver gives nil, so lookups chain.
func (n *node) child(space, local string) *node {
	if n == nil {
		return nil
	}
	for _, c := range n.children {
		if c.isElement() && c.is(space, local) {
			return c
		}
	}
	return nil
}

func (n *node) childrenNamed(space, local string) []*node {
	if n == nil {
		return nil
	}
	var out []*node
	for _, c := range n.children {
		if c.isElement() && c.is(space, local) {
			out = append(out, c)
		}
	}
	return out
}

// attr returns an attribute without a prefix, or "".
func (n *node) attr(local string) string {
	if n == nil {
		return ""
	}
	for _, a := range n.attrs {
		if a.Name.Space == "" && a.Name.Local == local {
			return a.Value
		}
	}
	return ""
}

func (n *node) textContent() string {
	if n == nil {
		return ""
	}
	var b strings.Builder
	for _, c := range n.children {
		if c.kind == kindText {
			b.WriteString(c.text)
		}
	}
	return b.String()
}

// Private use code points stand for whitespace character references
// while the parser reads the document, so that the parser keeps them
// apart from literal whitespace, which it normalizes.
var (
	charRef     = regexp.MustCompile(`&#(?:0*9|0*10|0*13|[xX]0*[9aAdD]);`)
	placeholder = map[string]rune{"9": '', "10": '', "13": '', "9x": '', "ax": '', "dx": ''}
	restore     = strings.NewReplacer("", "\t", "", "\n", "", "\r")
)

func protectReferences(doc []byte) []byte {
	return charRef.ReplaceAllFunc(doc, func(m []byte) []byte {
		s := strings.ToLower(strings.TrimSuffix(string(m[2:]), ";"))
		key := strings.TrimLeft(s, "0")
		if strings.HasPrefix(s, "x") {
			key = strings.TrimLeft(s[1:], "0") + "x"
		}
		return []byte(string(placeholder[key]))
	})
}

// parse reads the document into a tree. It refuses a DOCTYPE, text
// outside the document element, and more than one document element.
func parse(doc []byte) (*node, error) {
	if bytes.ContainsAny(doc, "") {
		return nil, fmt.Errorf("%w: the document holds reserved code points", ErrMalformed)
	}
	dec := xml.NewDecoder(bytes.NewReader(protectReferences(doc)))
	var root, cur *node
	for {
		tok, err := dec.RawToken()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if cur == nil && root != nil {
				return nil, fmt.Errorf("%w: two document elements", ErrMalformed)
			}
			n := &node{parent: cur, prefix: t.Name.Space, local: t.Name.Local, decls: map[string]string{}}
			for _, a := range t.Attr {
				a.Value = restore.Replace(normalizeSpace(a.Value))
				switch {
				case a.Name.Space == "" && a.Name.Local == "xmlns":
					n.decls[""] = a.Value
				case a.Name.Space == "xmlns":
					n.decls[a.Name.Local] = a.Value
				default:
					n.attrs = append(n.attrs, a)
				}
			}
			if cur == nil {
				root = n
			} else {
				cur.children = append(cur.children, n)
			}
			cur = n
		case xml.EndElement:
			if cur == nil {
				return nil, fmt.Errorf("%w: an end tag without a start tag", ErrMalformed)
			}
			cur = cur.parent
		case xml.CharData:
			if cur == nil {
				if len(bytes.TrimSpace(t)) > 0 {
					return nil, fmt.Errorf("%w: text outside the document element", ErrMalformed)
				}
				continue
			}
			cur.children = append(cur.children, &node{parent: cur, kind: kindText, text: restore.Replace(string(t))})
		case xml.ProcInst:
			if cur != nil {
				cur.children = append(cur.children, &node{parent: cur, kind: kindInstruction, local: t.Target, text: string(t.Inst)})
			}
		case xml.Directive:
			return nil, fmt.Errorf("%w: a DOCTYPE or other directive", ErrUnsupported)
		}
	}
	if root == nil || cur != nil {
		return nil, fmt.Errorf("%w: no complete document element", ErrMalformed)
	}
	return root, nil
}

// normalizeSpace applies attribute value normalization of XML 1.0
// clause 3.3.3 to literal whitespace.
func normalizeSpace(v string) string {
	return strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return ' '
		}
		return r
	}, v)
}

// canonical writes the exclusive canonical form of n. rendered holds the
// namespace declarations that the output ancestors carry. skip, when set,
// is left out with its subtree: the enveloped signature transform.
func canonical(w io.Writer, n *node, rendered map[string]string, skip *node) error {
	if n == skip {
		return nil
	}
	switch n.kind {
	case kindText:
		return write(w, escapeText(n.text))
	case kindInstruction:
		if n.text == "" {
			return write(w, "<?"+n.local+"?>")
		}
		return write(w, "<?"+n.local+" "+n.text+"?>")
	}
	used := []string{n.prefix}
	for _, a := range n.attrs {
		if a.Name.Space != "" && a.Name.Space != "xml" {
			used = append(used, a.Name.Space)
		}
	}
	next := map[string]string{}
	for k, v := range rendered {
		next[k] = v
	}
	var decls []string
	for _, p := range used {
		uri, ok := n.namespace(p)
		if !ok {
			return fmt.Errorf("%w: the prefix %q has no namespace", ErrMalformed, p)
		}
		if p == "xml" {
			continue
		}
		if have, seen := next[p]; seen && have == uri || !seen && p == "" && uri == "" {
			continue
		}
		next[p] = uri
		decls = append(decls, p)
	}
	sort.Strings(decls)
	var b strings.Builder
	b.WriteString("<" + qname(n.prefix, n.local))
	for _, p := range decls {
		if p == "" {
			b.WriteString(` xmlns="` + escapeAttr(next[p]) + `"`)
		} else {
			b.WriteString(" xmlns:" + p + `="` + escapeAttr(next[p]) + `"`)
		}
	}
	attrs := append([]xml.Attr(nil), n.attrs...)
	uri := func(a xml.Attr) string {
		if a.Name.Space == "" {
			return ""
		}
		u, _ := n.namespace(a.Name.Space)
		return u
	}
	sort.SliceStable(attrs, func(i, j int) bool {
		ui, uj := uri(attrs[i]), uri(attrs[j])
		if ui != uj {
			return ui < uj
		}
		return attrs[i].Name.Local < attrs[j].Name.Local
	})
	for _, a := range attrs {
		b.WriteString(" " + qname(a.Name.Space, a.Name.Local) + `="` + escapeAttr(a.Value) + `"`)
	}
	b.WriteString(">")
	if err := write(w, b.String()); err != nil {
		return err
	}
	for _, c := range n.children {
		if err := canonical(w, c, next, skip); err != nil {
			return err
		}
	}
	return write(w, "</"+qname(n.prefix, n.local)+">")
}

func qname(prefix, local string) string {
	if prefix == "" {
		return local
	}
	return prefix + ":" + local
}

var (
	textEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\r", "&#xD;")
	attrEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", `"`, "&quot;", "\t", "&#x9;", "\n", "&#xA;", "\r", "&#xD;")
)

func escapeText(s string) string { return textEscaper.Replace(s) }
func escapeAttr(s string) string { return attrEscaper.Replace(s) }

func write(w io.Writer, s string) error {
	_, err := io.WriteString(w, s)
	return err
}
