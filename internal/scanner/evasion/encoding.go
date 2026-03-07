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
			// WAF-specific encoding variants.
			UTF7Encode(payload),
			IBM037Encode(payload),
			HTMLEntityEncodeWithLeadingZeros(payload),
			OverlongUTF8Encode(payload),
			IISUnicodeEncode(payload),
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

// UTF7Encode converts a string to UTF-7 format where non-alphanumeric
// characters are encoded as modified base64 blocks (+XXXX-). This bypasses
// WAFs that don't handle charset=utf-7 Content-Type headers.
func UTF7Encode(s string) string {
	var b strings.Builder
	b.Grow(len(s) * 4)
	for _, r := range s {
		if isAlphanumericRune(r) || r == ' ' {
			b.WriteRune(r)
		} else {
			// UTF-7 modified base64 encoding for single chars
			// Format: +<base64>-
			hi := byte(r >> 8)
			lo := byte(r & 0xFF)
			encoded := base64.StdEncoding.EncodeToString([]byte{hi, lo})
			// Remove padding
			encoded = strings.TrimRight(encoded, "=")
			fmt.Fprintf(&b, "+%s-", encoded)
		}
	}
	return b.String()
}

// IBM037Encode converts ASCII characters to their IBM037 (EBCDIC) byte
// equivalents. This targets WAFs that don't handle charset=ibm037. Only
// common printable ASCII characters are mapped; unmapped chars pass through.
func IBM037Encode(s string) string {
	// Partial ASCII-to-EBCDIC mapping for common chars
	asciiToEBCDIC := map[byte]byte{
		'a': 0x81, 'b': 0x82, 'c': 0x83, 'd': 0x84, 'e': 0x85,
		'f': 0x86, 'g': 0x87, 'h': 0x88, 'i': 0x89, 'j': 0x91,
		'k': 0x92, 'l': 0x93, 'm': 0x94, 'n': 0x95, 'o': 0x96,
		'p': 0x97, 'q': 0x98, 'r': 0x99, 's': 0xA2, 't': 0xA3,
		'u': 0xA4, 'v': 0xA5, 'w': 0xA6, 'x': 0xA7, 'y': 0xA8,
		'z': 0xA9,
		'A': 0xC1, 'B': 0xC2, 'C': 0xC3, 'D': 0xC4, 'E': 0xC5,
		'F': 0xC6, 'G': 0xC7, 'H': 0xC8, 'I': 0xC9, 'J': 0xD1,
		'K': 0xD2, 'L': 0xD3, 'M': 0xD4, 'N': 0xD5, 'O': 0xD6,
		'P': 0xD7, 'Q': 0xD8, 'R': 0xD9, 'S': 0xE2, 'T': 0xE3,
		'U': 0xE4, 'V': 0xE5, 'W': 0xE6, 'X': 0xE7, 'Y': 0xE8,
		'Z': 0xE9,
		'0': 0xF0, '1': 0xF1, '2': 0xF2, '3': 0xF3, '4': 0xF4,
		'5': 0xF5, '6': 0xF6, '7': 0xF7, '8': 0xF8, '9': 0xF9,
		' ': 0x40, '.': 0x4B, '<': 0x4C, '(': 0x4D, '+': 0x4E,
		'&': 0x50, '!': 0x5A, '$': 0x5B, '*': 0x5C, ')': 0x5D,
		';': 0x5E, '-': 0x60, '/': 0x61, ',': 0x6B, '%': 0x6C,
		'_': 0x6D, '>': 0x6E, '?': 0x6F, '\'': 0x7D, '=': 0x7E,
		'"': 0x7F,
	}
	result := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if mapped, ok := asciiToEBCDIC[s[i]]; ok {
			result = append(result, mapped)
		} else {
			result = append(result, s[i])
		}
	}
	return string(result)
}

// HTMLEntityEncodeWithLeadingZeros converts each non-alphanumeric character to
// its decimal HTML entity with leading zeros (e.g., < becomes &#0000060;).
// This targets CVE-2025-27110 where WAFs don't normalize leading zeros.
func HTMLEntityEncodeWithLeadingZeros(s string) string {
	var b strings.Builder
	b.Grow(len(s) * 12)
	for _, r := range s {
		if isAlphanumericRune(r) {
			b.WriteRune(r)
		} else {
			fmt.Fprintf(&b, "&#%07d;", r)
		}
	}
	return b.String()
}

// OverlongUTF8Encode replaces / and . with their overlong UTF-8 two-byte
// sequences (%C0%AF for / and %C0%AE for .). This bypasses WAFs that
// validate paths before UTF-8 normalization.
func OverlongUTF8Encode(s string) string {
	var b strings.Builder
	b.Grow(len(s) * 6)
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '/':
			b.WriteString("%C0%AF")
		case '.':
			b.WriteString("%C0%AE")
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// IISUnicodeEncode converts each non-alphanumeric character to the IIS-style
// %uXXXX format. This bypasses WAFs that only handle standard percent-encoding.
func IISUnicodeEncode(s string) string {
	var b strings.Builder
	b.Grow(len(s) * 6)
	for _, r := range s {
		if isAlphanumericRune(r) {
			b.WriteRune(r)
		} else {
			fmt.Fprintf(&b, "%%u%04X", r)
		}
	}
	return b.String()
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
