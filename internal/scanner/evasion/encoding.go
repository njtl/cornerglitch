// Package evasion provides payload encoding and header manipulation techniques
// for bypassing WAF detection and bot fingerprinting during vulnerability scanning.
package evasion

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// Encoder transforms payloads into encoded variants that may bypass WAF rules,
// signature-based detection, or input validation filters. The Mode determines
// how many variants are generated:
//
//   - "none": returns the original payload unchanged
//   - "basic": returns URL-encoded variant only
//   - "advanced": returns all encoding variants
//   - "nightmare": returns all encoding variants plus combined/layered encodings
type Encoder struct {
	Mode string // none, basic, advanced, nightmare
}

// NewEncoder creates an Encoder with the given mode. Valid modes are "none",
// "basic", "advanced", and "nightmare". An unrecognized mode defaults to "none".
func NewEncoder(mode string) *Encoder {
	switch mode {
	case "none", "basic", "advanced", "nightmare":
		// valid
	default:
		mode = "none"
	}
	return &Encoder{Mode: mode}
}

// Encode returns multiple encoded variants of the payload based on the
// encoder's mode. The original payload is always included as the first variant.
func (e *Encoder) Encode(payload string) []string {
	switch e.Mode {
	case "none":
		return []string{payload}

	case "basic":
		return uniqueStrings([]string{
			payload,
			URLEncode(payload),
		})

	case "advanced":
		return uniqueStrings([]string{
			payload,
			URLEncode(payload),
			DoubleURLEncode(payload),
			UnicodeEncode(payload),
			HTMLEntityEncode(payload),
			Base64Encode(payload),
			HexEncode(payload),
		})

	case "nightmare":
		variants := []string{
			payload,
			URLEncode(payload),
			DoubleURLEncode(payload),
			UnicodeEncode(payload),
			HTMLEntityEncode(payload),
			Base64Encode(payload),
			HexEncode(payload),
			// Combined/layered encodings for maximum evasion.
			URLEncode(UnicodeEncode(payload)),
			DoubleURLEncode(HTMLEntityEncode(payload)),
			Base64Encode(URLEncode(payload)),
			HexEncode(URLEncode(payload)),
			mixedCaseEncode(payload),
			nullByteInject(payload),
			commentInject(payload),
		}
		return uniqueStrings(variants)

	default:
		return []string{payload}
	}
}

// URLEncode performs standard percent-encoding on every non-alphanumeric
// character in the string. Unlike net/url.QueryEscape, this encodes all
// special characters including - _ . ~ for maximum obfuscation.
func URLEncode(s string) string {
	var b strings.Builder
	b.Grow(len(s) * 3)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isAlphanumeric(c) {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// DoubleURLEncode applies URL encoding twice. This bypasses WAFs that decode
// URL encoding only once before matching against signatures.
func DoubleURLEncode(s string) string {
	return URLEncode(URLEncode(s))
}

// UnicodeEncode converts each character to its Unicode escape sequence
// (\uXXXX format). This can bypass filters that don't normalize Unicode.
func UnicodeEncode(s string) string {
	var b strings.Builder
	b.Grow(len(s) * 6)
	for _, r := range s {
		if isAlphanumericRune(r) {
			b.WriteRune(r)
		} else {
			fmt.Fprintf(&b, "\\u%04x", r)
		}
	}
	return b.String()
}

// HTMLEntityEncode converts each non-alphanumeric character to its numeric
// HTML entity (&#xXX; format). This bypasses filters that don't decode HTML
// entities before matching.
func HTMLEntityEncode(s string) string {
	var b strings.Builder
	b.Grow(len(s) * 6)
	for _, r := range s {
		if isAlphanumericRune(r) {
			b.WriteRune(r)
		} else {
			fmt.Fprintf(&b, "&#x%x;", r)
		}
	}
	return b.String()
}

// Base64Encode returns the standard base64 encoding of the string.
func Base64Encode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// HexEncode returns the hex-encoded representation of the string, with each
// byte prefixed by 0x for use in contexts that interpret hex literals.
func HexEncode(s string) string {
	encoded := hex.EncodeToString([]byte(s))
	var b strings.Builder
	b.Grow(len(encoded) * 2)
	for i := 0; i < len(encoded); i += 2 {
		if i > 0 {
			b.WriteString("0x")
		} else {
			b.WriteString("0x")
		}
		b.WriteString(encoded[i : i+2])
	}
	return b.String()
}

// mixedCaseEncode randomly alternates the case of alphabetic characters.
// This bypasses case-sensitive signature matching.
func mixedCaseEncode(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i, r := range s {
		if r >= 'a' && r <= 'z' && i%2 == 0 {
			b.WriteRune(r - 32) // to uppercase
		} else if r >= 'A' && r <= 'Z' && i%2 == 1 {
			b.WriteRune(r + 32) // to lowercase
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// nullByteInject inserts null byte sequences at word boundaries. Some parsers
// stop at null bytes, causing the WAF to see a truncated (harmless) string
// while the backend processes the full payload.
func nullByteInject(s string) string {
	var b strings.Builder
	b.Grow(len(s) * 2)
	for i, r := range s {
		b.WriteRune(r)
		if r == ' ' || r == '/' || r == '=' || (i > 0 && i%5 == 0) {
			b.WriteString("%00")
		}
	}
	return b.String()
}

// commentInject inserts SQL/HTML comment sequences into the payload. This
// breaks up keywords that WAFs look for while remaining valid syntax.
func commentInject(s string) string {
	// Insert inline comments between characters of common keywords.
	result := s
	result = strings.ReplaceAll(result, "SELECT", "SEL/**/ECT")
	result = strings.ReplaceAll(result, "select", "sel/**/ect")
	result = strings.ReplaceAll(result, "UNION", "UNI/**/ON")
	result = strings.ReplaceAll(result, "union", "uni/**/on")
	result = strings.ReplaceAll(result, "script", "scr<!---->ipt")
	result = strings.ReplaceAll(result, "SCRIPT", "SCR<!---->IPT")
	return result
}

// isAlphanumeric reports whether b is an ASCII letter or digit.
func isAlphanumeric(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// isAlphanumericRune reports whether r is an ASCII letter or digit.
func isAlphanumericRune(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}

// uniqueStrings returns a deduplicated copy of the input slice, preserving order.
func uniqueStrings(ss []string) []string {
	seen := make(map[string]struct{}, len(ss))
	result := make([]string, 0, len(ss))
	for _, s := range ss {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			result = append(result, s)
		}
	}
	return result
}
