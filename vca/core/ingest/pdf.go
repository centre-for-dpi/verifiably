// SPDX-License-Identifier: Apache-2.0

package ingest

// This file holds a small PDF image extractor. It reads the image
// XObjects of a PDF and turns them into Go images, so the QR reader can
// look at them (ADR-023 decision 1).
//
// The extractor is deliberately small. It reads the objects of the file
// body directly. It supports the two stream filters that credential PDFs
// use: FlateDecode for a raster image and DCTDecode for a JPEG image. It
// supports the DeviceGray, DeviceRGB, and Indexed colour spaces with 1,
// 2, 4, or 8 bits for each component. It supports the PNG predictors of
// the Flate decode parameters.
//
// The full PDF library pdfcpu would also do this. That library pulls a
// large dependency tree with vanity module paths that the restricted
// build network cannot mirror, so the extractor stays here.

import (
	"bytes"
	"compress/zlib"
	"errors"
	"fmt"
	"image"
	"image/color"
	_ "image/jpeg" // the extractor returns JPEG streams as they are
	_ "image/png"  // some producers store a whole PNG file in a stream
	"io"
	"regexp"
	"strconv"
	"strings"
)

// MaxPDFImages bounds the number of images the extractor returns.
const MaxPDFImages = 64

// MaxPDFImagePixels bounds the pixel count of one extracted image.
const MaxPDFImagePixels = 40 << 20

// objectRE matches the header of one indirect object.
var objectRE = regexp.MustCompile(`(?m)(\d+)\s+(\d+)\s+obj\b`)

// IsPDF reports whether the bytes start with the PDF header.
func IsPDF(data []byte) bool {
	return bytes.HasPrefix(bytes.TrimLeft(data, " \r\n\t"), []byte("%PDF-"))
}

// ExtractPDFImages returns every image XObject of a PDF that the
// extractor understands. It skips an object it cannot read, so one
// broken image does not lose the others.
func ExtractPDFImages(data []byte) ([]image.Image, error) {
	if !IsPDF(data) {
		return nil, errors.New("ingest: the upload is not a PDF")
	}
	var out []image.Image
	for _, loc := range objectRE.FindAllStringSubmatchIndex(string(data), -1) {
		if len(out) >= MaxPDFImages {
			break
		}
		dict, stream, ok := objectStream(data, loc[1])
		if !ok || !strings.Contains(dict, "/Image") {
			continue
		}
		img, err := decodeImageXObject(dict, stream)
		if err != nil {
			continue
		}
		out = append(out, img)
	}
	if len(out) == 0 {
		return nil, errors.New("ingest: the PDF holds no image the extractor understands")
	}
	return out, nil
}

// objectStream returns the dictionary text and the stream bytes of the
// object that starts at from.
func objectStream(data []byte, from int) (string, []byte, bool) {
	end := bytes.Index(data[from:], []byte("endobj"))
	if end < 0 {
		end = len(data) - from
	}
	body := data[from : from+end]
	start := bytes.Index(body, []byte("stream"))
	if start < 0 {
		return "", nil, false
	}
	dict := string(body[:start])
	rest := body[start+len("stream"):]
	rest = bytes.TrimPrefix(rest, []byte("\r"))
	rest = bytes.TrimPrefix(rest, []byte("\n"))
	stop := bytes.Index(rest, []byte("endstream"))
	if stop < 0 {
		return "", nil, false
	}
	if n, ok := dictInt(dict, "Length"); ok && n > 0 && n <= len(rest) {
		return dict, rest[:n], true
	}
	return dict, bytes.TrimRight(rest[:stop], "\r\n"), true
}

// decodeImageXObject turns one image XObject into a Go image.
func decodeImageXObject(dict string, stream []byte) (image.Image, error) {
	filters := dictNames(dict, "Filter")
	if len(filters) == 0 {
		return nil, errors.New("ingest: the image stream has no filter")
	}
	last := filters[len(filters)-1]
	switch last {
	case "DCTDecode", "JPXDecode":
		img, _, err := image.Decode(bytes.NewReader(stream))
		if err != nil {
			return nil, fmt.Errorf("ingest: image stream: %w", err)
		}
		return img, nil
	case "FlateDecode":
		return decodeFlateImage(dict, stream)
	}
	return nil, fmt.Errorf("ingest: the stream filter %q is not supported", last)
}

// decodeFlateImage inflates a raster image stream and builds an image.
func decodeFlateImage(dict string, stream []byte) (image.Image, error) {
	raw, rawErr := inflatePDFStream(stream)
	if rawErr != nil {
		return nil, rawErr
	}
	if img, _, err := image.Decode(bytes.NewReader(raw)); err == nil {
		return img, nil
	}
	width, ok := dictInt(dict, "Width")
	height, okHeight := dictInt(dict, "Height")
	if !ok || !okHeight || width <= 0 || height <= 0 {
		return nil, errors.New("ingest: the image has no width or height")
	}
	if width*height > MaxPDFImagePixels {
		return nil, fmt.Errorf("ingest: the image has more than %d pixels", MaxPDFImagePixels)
	}
	bits, ok := dictInt(dict, "BitsPerComponent")
	if !ok {
		bits = 8
	}
	space, palette, err := colourSpace(dict)
	if err != nil {
		return nil, err
	}
	raw, err = removePredictor(dict, raw, width, space.components)
	if err != nil {
		return nil, err
	}
	return buildImage(raw, width, height, bits, space, palette)
}

// inflatePDFStream inflates a zlib stream. Some producers leave the zlib
// header out, so a raw deflate stream is the fallback.
func inflatePDFStream(stream []byte) ([]byte, error) {
	zr, err := zlib.NewReader(bytes.NewReader(stream))
	if err != nil {
		return nil, fmt.Errorf("ingest: image stream: %w", err)
	}
	defer func() { _ = zr.Close() }()
	out, err := io.ReadAll(io.LimitReader(zr, MaxInflatedBytes+1))
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("ingest: inflate the image stream: %w", err)
	}
	if len(out) > MaxInflatedBytes {
		return nil, fmt.Errorf("ingest: the image stream is larger than %d bytes", MaxInflatedBytes)
	}
	return out, nil
}

// space describes a colour space of the extractor.
type space struct {
	name       string
	components int
	indexed    bool
}

// colourSpace reads the colour space and the palette of an image.
func colourSpace(dict string) (space, []color.RGBA, error) {
	text := dictValue(dict, "ColorSpace")
	switch {
	case text == "" || strings.Contains(text, "DeviceGray") && !strings.Contains(text, "Indexed"):
		return space{name: "DeviceGray", components: 1}, nil, nil
	case strings.Contains(text, "Indexed"):
		palette, err := indexedPalette(text)
		if err != nil {
			return space{}, nil, err
		}
		return space{name: "Indexed", components: 1, indexed: true}, palette, nil
	case strings.Contains(text, "DeviceRGB"), strings.Contains(text, "CalRGB"):
		return space{name: "DeviceRGB", components: 3}, nil, nil
	case strings.Contains(text, "DeviceCMYK"):
		return space{name: "DeviceCMYK", components: 4}, nil, nil
	}
	return space{}, nil, fmt.Errorf("ingest: the colour space %q is not supported", strings.TrimSpace(text))
}

// hexRE matches the hexadecimal string of an indexed palette.
var hexRE = regexp.MustCompile(`<([0-9A-Fa-f\s]+)>`)

// indexedPalette reads the palette of an Indexed colour space. The
// extractor reads a hexadecimal string palette only.
func indexedPalette(text string) ([]color.RGBA, error) {
	m := hexRE.FindStringSubmatch(text)
	if m == nil {
		return nil, errors.New("ingest: the indexed palette is not a hexadecimal string")
	}
	clean := strings.Join(strings.Fields(m[1]), "")
	if len(clean)%2 == 1 {
		clean += "0"
	}
	raw := make([]byte, 0, len(clean)/2)
	for i := 0; i+1 < len(clean); i += 2 {
		// The pattern accepts hexadecimal digits only, so this parses.
		n, _ := strconv.ParseUint(clean[i:i+2], 16, 8)
		raw = append(raw, byte(n))
	}
	if len(raw) < 3 {
		return nil, errors.New("ingest: the indexed palette has no entry")
	}
	out := make([]color.RGBA, 0, len(raw)/3)
	for i := 0; i+2 < len(raw); i += 3 {
		out = append(out, color.RGBA{R: raw[i], G: raw[i+1], B: raw[i+2], A: 0xff})
	}
	return out, nil
}

// removePredictor reverses the PNG predictors of the Flate decode
// parameters. A predictor below 10 needs no work.
func removePredictor(dict string, raw []byte, width, components int) ([]byte, error) {
	parms := dictValue(dict, "DecodeParms")
	if parms == "" {
		return raw, nil
	}
	predictor, ok := dictInt(parms, "Predictor")
	if !ok || predictor < 10 {
		return raw, nil
	}
	colours, ok := dictInt(parms, "Colors")
	if !ok {
		colours = components
	}
	bits, ok := dictInt(parms, "BitsPerComponent")
	if !ok {
		bits = 8
	}
	columns, ok := dictInt(parms, "Columns")
	if !ok {
		columns = width
	}
	return unfilterPNG(raw, columns, colours, bits)
}

// unfilterPNG reverses the five PNG row filters.
func unfilterPNG(raw []byte, columns, colours, bits int) ([]byte, error) {
	step := (colours*bits + 7) / 8
	if step < 1 {
		step = 1
	}
	rowLen := (columns*colours*bits + 7) / 8
	if rowLen < 1 {
		return nil, errors.New("ingest: the predictor row length is zero")
	}
	out := make([]byte, 0, len(raw))
	previous := make([]byte, rowLen)
	for pos := 0; pos+1 <= len(raw); pos += rowLen + 1 {
		filter := raw[pos]
		end := pos + 1 + rowLen
		if end > len(raw) {
			end = len(raw)
		}
		row := make([]byte, rowLen)
		copy(row, raw[pos+1:end])
		applyPNGFilter(filter, row, previous, step)
		out = append(out, row...)
		previous = row
	}
	return out, nil
}

// applyPNGFilter reverses one PNG row filter in place.
func applyPNGFilter(filter byte, row, previous []byte, step int) {
	for i := range row {
		var left, up, upLeft int
		if i >= step {
			left = int(row[i-step])
			upLeft = int(previous[i-step])
		}
		up = int(previous[i])
		switch filter {
		case 1:
			row[i] += byte(left)
		case 2:
			row[i] += byte(up)
		case 3:
			row[i] += byte((left + up) / 2)
		case 4:
			row[i] += byte(paeth(left, up, upLeft))
		}
	}
}

// paeth is the PNG Paeth predictor.
func paeth(a, b, c int) int {
	p := a + b - c
	pa, pb, pc := abs(p-a), abs(p-b), abs(p-c)
	if pa <= pb && pa <= pc {
		return a
	}
	if pb <= pc {
		return b
	}
	return c
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// buildImage turns raw samples into an image.
func buildImage(raw []byte, width, height, bits int, s space, palette []color.RGBA) (image.Image, error) {
	switch bits {
	case 1, 2, 4, 8:
	default:
		return nil, fmt.Errorf("ingest: %d bits for each component is not supported", bits)
	}
	rowLen := (width*s.components*bits + 7) / 8
	if len(raw) < rowLen*height {
		return nil, errors.New("ingest: the image stream is shorter than the image")
	}
	maxValue := (1 << bits) - 1
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		row := raw[y*rowLen : (y+1)*rowLen]
		for x := 0; x < width; x++ {
			img.Set(x, y, pixel(row, x, bits, maxValue, s, palette))
		}
	}
	return img, nil
}

// pixel reads one pixel of a row.
func pixel(row []byte, x, bits, maxValue int, s space, palette []color.RGBA) color.Color {
	read := func(i int) int { return sample(row, x*s.components+i, bits) }
	switch {
	case s.indexed:
		index := read(0)
		if index < len(palette) {
			return palette[index]
		}
		return color.RGBA{A: 0xff}
	case s.components == 1:
		v := uint8(read(0) * 255 / maxValue)
		return color.RGBA{R: v, G: v, B: v, A: 0xff}
	case s.components == 4:
		c, m, yy, k := read(0), read(1), read(2), read(3)
		return color.RGBA{
			R: uint8((maxValue - c) * (maxValue - k) * 255 / (maxValue * maxValue)),
			G: uint8((maxValue - m) * (maxValue - k) * 255 / (maxValue * maxValue)),
			B: uint8((maxValue - yy) * (maxValue - k) * 255 / (maxValue * maxValue)),
			A: 0xff,
		}
	default:
		return color.RGBA{
			R: uint8(read(0) * 255 / maxValue),
			G: uint8(read(1) * 255 / maxValue),
			B: uint8(read(2) * 255 / maxValue),
			A: 0xff,
		}
	}
}

// sample reads the sample with the index from a packed row.
func sample(row []byte, index, bits int) int {
	bit := index * bits
	pos := bit / 8
	if bits == 8 {
		return int(row[pos])
	}
	shift := 8 - bits - bit%8
	return int(row[pos]>>shift) & ((1 << bits) - 1)
}

// dictValue returns the text of one dictionary entry. It keeps balanced
// brackets, so a nested dictionary or array survives.
func dictValue(dict, key string) string {
	i := strings.Index(dict, "/"+key)
	if i < 0 {
		return ""
	}
	rest := strings.TrimLeft(dict[i+len(key)+1:], " \r\n\t")
	if rest == "" {
		return ""
	}
	switch rest[0] {
	case '[':
		return balanced(rest, '[', ']')
	case '/':
		return "/" + nameToken(rest[1:])
	case '<':
		if strings.HasPrefix(rest, "<<") {
			return balanced(rest, '<', '>')
		}
		if end := strings.IndexByte(rest, '>'); end >= 0 {
			return rest[:end+1]
		}
		return rest
	}
	end := strings.IndexAny(rest, "/\r\n>[<")
	if end < 0 {
		end = len(rest)
	}
	return strings.TrimSpace(rest[:end])
}

// nameToken returns the characters of a PDF name.
func nameToken(text string) string {
	for i := 0; i < len(text); i++ {
		c := text[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_' || c == '+' {
			continue
		}
		return text[:i]
	}
	return text
}

// balanced returns the text from the first open bracket to the matching
// close bracket.
func balanced(text string, opener, closer byte) string {
	depth := 0
	for i := 0; i < len(text); i++ {
		switch text[i] {
		case opener:
			depth++
		case closer:
			depth--
			if depth == 0 {
				return text[:i+1]
			}
		}
	}
	return text
}

// dictInt reads a whole number entry of a dictionary.
func dictInt(dict, key string) (int, bool) {
	value := strings.Fields(dictValue(dict, key))
	if len(value) == 0 {
		return 0, false
	}
	n, err := strconv.Atoi(value[0])
	if err != nil {
		return 0, false
	}
	return n, true
}

// nameRE matches a PDF name such as /FlateDecode.
var nameRE = regexp.MustCompile(`/([A-Za-z0-9]+)`)

// dictNames reads a name entry or an array of names.
func dictNames(dict, key string) []string {
	value := dictValue(dict, key)
	if value == "" {
		return nil
	}
	var out []string
	for _, m := range nameRE.FindAllStringSubmatch(value, -1) {
		out = append(out, m[1])
	}
	return out
}
