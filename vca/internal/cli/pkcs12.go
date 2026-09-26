// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"hash"
	"io"
	"math/big"
	"time"
	"unicode/utf16"
)

// The PKCS #12 key store of RFC 7292 that a Java key store of type
// PKCS12 opens. The Go standard library reads no such file and writes
// none, and ADR-027 decision 3 adds no module, so the CLI writes the one
// layout it needs: one RSA key and its self signed certificate under an
// alias. The key sits in a PBES2 shrouded bag (PBKDF2 with HMAC SHA-256,
// AES-256-CBC), and an HMAC SHA-256 MAC covers the safe. Java 17 and
// OpenSSL 3 write this layout by default.
var (
	oidData           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSHA256         = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidShroudedKeyBag = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 2}
	oidCertBag        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3}
	oidX509Cert       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}
	oidFriendlyName   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 20}
	oidLocalKeyID     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 21}
	oidPBES2          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidHMACSHA256     = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidAES256CBC      = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

// pkcs12Iterations is the iteration count of the key encryption and of
// the MAC, the default of OpenSSL 3 and of Java 17.
const pkcs12Iterations = 10000

// pkcs12CertValidity is how long the self signed certificate of the key
// store stays valid. Only the key matters to the reader.
const pkcs12CertValidity = 10 * 365 * 24 * time.Hour

// contentInfo and safeBag carry their [0] wrapper in the raw value,
// because encoding/asn1 applies no tag to a raw value.
type contentInfo struct {
	Type    asn1.ObjectIdentifier
	Content asn1.RawValue
}

type safeBag struct {
	ID    asn1.ObjectIdentifier
	Value asn1.RawValue
	Attrs []bagAttribute `asn1:"set"`
}

type bagAttribute struct {
	ID     asn1.ObjectIdentifier
	Values asn1.RawValue
}

type algorithmIdentifier struct {
	Algorithm asn1.ObjectIdentifier
	Params    asn1.RawValue `asn1:"optional"`
}

type pbkdf2Params struct {
	Salt       []byte
	Iterations int
	PRF        algorithmIdentifier
}

type pbes2Params struct {
	KDF struct {
		Algorithm asn1.ObjectIdentifier
		Params    pbkdf2Params
	}
	Cipher struct {
		Algorithm asn1.ObjectIdentifier
		IV        []byte
	}
}

type encryptedPrivateKeyInfo struct {
	Algorithm struct {
		Algorithm asn1.ObjectIdentifier
		Params    pbes2Params
	}
	Data []byte
}

type certBag struct {
	ID    asn1.ObjectIdentifier
	Value []byte `asn1:"explicit,tag:0"`
}

type macData struct {
	Digest struct {
		Algorithm algorithmIdentifier
		Value     []byte
	}
	Salt       []byte
	Iterations int
}

type pfx struct {
	Version  int
	AuthSafe contentInfo
	Mac      macData
}

// EncodePKCS12 writes a key store with the key and a self signed
// certificate of it under the alias. The password protects the key and
// the MAC.
func EncodePKCS12(key *rsa.PrivateKey, alias, password string, random io.Reader) ([]byte, error) {
	serial := make([]byte, 16)
	if _, err := io.ReadFull(random, serial); err != nil {
		return nil, fmt.Errorf("key store: %w", err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: new(big.Int).SetBytes(serial),
		Subject:      pkix.Name{CommonName: alias},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(pkcs12CertValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(random, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("key store certificate: %w", err)
	}
	keyID := sha256.Sum256(certDER)
	attrs, err := bagAttributes(alias, keyID[:20])
	if err != nil {
		return nil, err
	}
	shrouded, err := shroudKey(key, password, random)
	if err != nil {
		return nil, err
	}
	certValue, err := asn1.Marshal(certBag{ID: oidX509Cert, Value: certDER})
	if err != nil {
		return nil, fmt.Errorf("key store certificate bag: %w", err)
	}
	certSafe, err := dataContent([]safeBag{{ID: oidCertBag, Value: explicit(certValue), Attrs: attrs}})
	if err != nil {
		return nil, err
	}
	keySafe, err := dataContent([]safeBag{{ID: oidShroudedKeyBag, Value: explicit(shrouded), Attrs: attrs}})
	if err != nil {
		return nil, err
	}
	authSafe, err := asn1.Marshal([]contentInfo{certSafe, keySafe})
	if err != nil {
		return nil, fmt.Errorf("key store safe: %w", err)
	}
	salt := make([]byte, 16)
	if _, err = io.ReadFull(random, salt); err != nil {
		return nil, fmt.Errorf("key store: %w", err)
	}
	mac := hmac.New(sha256.New, pkcs12KDF(sha256.New, 3, bmpPassword(password), salt, pkcs12Iterations, sha256.Size))
	mac.Write(authSafe)
	var m macData
	m.Digest.Algorithm = algorithmIdentifier{Algorithm: oidSHA256, Params: asn1.NullRawValue}
	m.Digest.Value = mac.Sum(nil)
	m.Salt, m.Iterations = salt, pkcs12Iterations
	out, err := asn1.Marshal(pfx{Version: 3, AuthSafe: contentInfo{Type: oidData, Content: octets(authSafe)}, Mac: m})
	if err != nil {
		return nil, fmt.Errorf("key store: %w", err)
	}
	return out, nil
}

// shroudKey encrypts the PKCS #8 form of the key with PBES2.
func shroudKey(key *rsa.PrivateKey, password string, random io.Reader) ([]byte, error) {
	plain, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("key store key: %w", err)
	}
	salt, iv := make([]byte, 16), make([]byte, aes.BlockSize)
	if _, err = io.ReadFull(random, salt); err != nil {
		return nil, fmt.Errorf("key store: %w", err)
	}
	if _, err = io.ReadFull(random, iv); err != nil {
		return nil, fmt.Errorf("key store: %w", err)
	}
	dk, err := pbkdf2.Key(sha256.New, password, salt, pkcs12Iterations, 32)
	if err != nil {
		return nil, fmt.Errorf("key store key: %w", err)
	}
	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, fmt.Errorf("key store key: %w", err)
	}
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	for range pad {
		plain = append(plain, byte(pad))
	}
	sealed := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(sealed, plain)
	var info encryptedPrivateKeyInfo
	info.Algorithm.Algorithm = oidPBES2
	info.Algorithm.Params.KDF.Algorithm = oidPBKDF2
	info.Algorithm.Params.KDF.Params = pbkdf2Params{
		Salt: salt, Iterations: pkcs12Iterations,
		PRF: algorithmIdentifier{Algorithm: oidHMACSHA256, Params: asn1.NullRawValue},
	}
	info.Algorithm.Params.Cipher.Algorithm = oidAES256CBC
	info.Algorithm.Params.Cipher.IV = iv
	info.Data = sealed
	out, err := asn1.Marshal(info)
	if err != nil {
		return nil, fmt.Errorf("key store key: %w", err)
	}
	return out, nil
}

// bagAttributes returns the friendly name, which a Java key store reads
// as the alias, and the local key id that pairs the key with its
// certificate.
func bagAttributes(alias string, keyID []byte) ([]bagAttribute, error) {
	units := utf16.Encode([]rune(alias))
	name := make([]byte, 0, 2*len(units))
	for _, u := range units {
		name = append(name, byte(u>>8), byte(u))
	}
	nameValue, err := asn1.Marshal(asn1.RawValue{Tag: asn1.TagBMPString, Bytes: name})
	if err != nil {
		return nil, fmt.Errorf("key store alias: %w", err)
	}
	idValue, err := asn1.Marshal(keyID)
	if err != nil {
		return nil, fmt.Errorf("key store key id: %w", err)
	}
	return []bagAttribute{
		{ID: oidFriendlyName, Values: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: nameValue}},
		{ID: oidLocalKeyID, Values: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: idValue}},
	}, nil
}

// dataContent wraps safe bags in a content info of type data.
func dataContent(bags []safeBag) (contentInfo, error) {
	raw, err := asn1.Marshal(bags)
	if err != nil {
		return contentInfo{}, fmt.Errorf("key store bags: %w", err)
	}
	return contentInfo{Type: oidData, Content: octets(raw)}, nil
}

// octets wraps DER bytes in an OCTET STRING inside the explicit [0]
// tag of a content info.
func octets(der []byte) asn1.RawValue {
	inner, err := asn1.Marshal(der)
	if err != nil {
		return asn1.RawValue{}
	}
	return explicit(inner)
}

// explicit wraps DER bytes in the explicit context tag [0].
func explicit(der []byte) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: der}
}

// bmpPassword is the password as a BMPString with two zero bytes at the
// end, the form of RFC 7292 appendix B.1.
func bmpPassword(password string) []byte {
	units := utf16.Encode([]rune(password))
	out := make([]byte, 0, 2*len(units)+2)
	for _, u := range units {
		out = append(out, byte(u>>8), byte(u))
	}
	return append(out, 0, 0)
}

// pkcs12KDF is the key derivation of RFC 7292 appendix B.2. id is 1 for
// a key, 2 for an IV, and 3 for a MAC key.
func pkcs12KDF(newHash func() hash.Hash, id byte, password, salt []byte, iterations, size int) []byte {
	h := newHash()
	u, v := h.Size(), h.BlockSize()
	d := make([]byte, v)
	for i := range d {
		d[i] = id
	}
	fill := func(src []byte) []byte {
		if len(src) == 0 {
			return nil
		}
		out := make([]byte, v*((len(src)+v-1)/v))
		for i := range out {
			out[i] = src[i%len(src)]
		}
		return out
	}
	s, p := fill(salt), fill(password)
	block := make([]byte, 0, len(s)+len(p))
	block = append(append(block, s...), p...)
	out := make([]byte, 0, size+u)
	one := big.NewInt(1)
	for len(out) < size {
		h.Reset()
		h.Write(d)
		h.Write(block)
		a := h.Sum(nil)
		for i := 1; i < iterations; i++ {
			h.Reset()
			h.Write(a)
			a = h.Sum(a[:0])
		}
		out = append(out, a...)
		b := new(big.Int).SetBytes(fill(a)[:v])
		b.Add(b, one)
		for j := 0; j < len(block); j += v {
			chunk := new(big.Int).SetBytes(block[j : j+v])
			chunk.Add(chunk, b)
			sum := chunk.Bytes()
			if len(sum) > v {
				sum = sum[len(sum)-v:]
			}
			part := block[j : j+v]
			clear(part)
			copy(part[v-len(sum):], sum)
		}
	}
	return out[:size]
}
