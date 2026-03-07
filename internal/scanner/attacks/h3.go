// Package attacks — H3Module sends HTTP/3 and QUIC confusion probes to test
// how targets handle Alt-Svc headers and related HTTP/3 upgrade vectors.
package attacks

import (
	"github.com/cornerglitch/internal/scanner"
)

// H3Module probes targets for HTTP/3 / QUIC weaknesses via HTTP requests.
type H3Module struct{}

func (m *H3Module) Name() string     { return "h3" }
func (m *H3Module) Category() string { return "protocol" }

// GenerateRequests creates HTTP requests that test H3/QUIC behavior.
func (m *H3Module) GenerateRequests(target string) []scanner.AttackRequest {
	return []scanner.AttackRequest{
		{
			Method:      "GET",
			Path:        "/",
			Headers:     map[string]string{"Alt-Svc": "clear"},
			Category:    "H3-QUIC",
			SubCategory: "alt-svc-clear",
			Description: "Send Alt-Svc: clear to test response handling",
		},
		{
			Method:      "GET",
			Path:        "/",
			Headers:     map[string]string{"Upgrade": "h3"},
			Category:    "H3-QUIC",
			SubCategory: "upgrade-h3",
			Description: "Request HTTP/3 upgrade over TCP (nonsensical but tests parser)",
		},
		{
			Method:      "GET",
			Path:        "/",
			Headers:     map[string]string{"Alt-Svc": `h3=":443"; ma=86400, h3=":0"; ma=1, h3=":-1"; ma=86400`},
			Category:    "H3-QUIC",
			SubCategory: "alt-svc-confusion",
			Description: "Send conflicting Alt-Svc values to test parser handling",
		},
		{
			Method:      "GET",
			Path:        "/",
			Headers:     map[string]string{"Alt-Svc": "h3=\":\xF0\x9F\x92\xA9\"; ma=86400"},
			Category:    "H3-QUIC",
			SubCategory: "alt-svc-emoji",
			Description: "Send Alt-Svc with emoji as port (parser crash test)",
		},
		{
			Method:      "GET",
			Path:        "/",
			Headers:     map[string]string{"Alt-Svc": "h3=\":443\x00\"; ma=86400"},
			Category:    "H3-QUIC",
			SubCategory: "alt-svc-null",
			Description: "Send Alt-Svc with null byte (parser crash test)",
		},
		{
			Method:      "GET",
			Path:        "/",
			Headers:     map[string]string{"Alt-Svc": `h3=":99999"; ma=86400`},
			Category:    "H3-QUIC",
			SubCategory: "alt-svc-huge-port",
			Description: "Alt-Svc with port > 65535 (integer overflow test)",
		},
		{
			Method:      "GET",
			Path:        "/",
			Headers:     map[string]string{"Alt-Svc": `h3=":443"; ma=-1`},
			Category:    "H3-QUIC",
			SubCategory: "alt-svc-negative-maxage",
			Description: "Alt-Svc with negative max-age",
		},
		{
			Method:      "GET",
			Path:        "/",
			Headers:     map[string]string{"Alt-Svc": `h99=":443"; ma=86400`},
			Category:    "H3-QUIC",
			SubCategory: "alt-svc-fake-proto",
			Description: "Alt-Svc with nonexistent protocol h99",
		},
		{
			Method:      "GET",
			Path:        "/",
			Headers:     map[string]string{"Alt-Svc": "h3=\":443\"; ma=86400\r\nX-Injected: yes"},
			Category:    "H3-QUIC",
			SubCategory: "alt-svc-crlf-inject",
			Description: "Alt-Svc with CRLF injection attempt",
		},
		{
			Method:      "GET",
			Path:        "/",
			Headers:     map[string]string{"Alt-Svc": `h3=":443"; ma=86400, h3-29=":443"; ma=86400`},
			Category:    "H3-QUIC",
			SubCategory: "alt-svc-old-draft",
			Description: "Alt-Svc advertising obsolete h3-29 draft version",
		},
	}
}
