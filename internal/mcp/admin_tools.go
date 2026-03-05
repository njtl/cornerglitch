package mcp

import (
	"encoding/json"
	"fmt"
)

// AdminToolHandler provides callbacks for admin operations that require
// access to dashboard singletons (to avoid import cycles).
type AdminToolHandler struct {
	ToggleFeature  func(name string, enabled bool) error
	GetMetrics     func() map[string]interface{}
	SetErrorWeights func(weights map[string]float64) error
	NightmareToggle func(subsystem string, enabled bool) error
}

// AdminServer wraps the MCP server with authenticated admin tools.
type AdminServer struct {
	*Server
	handler *AdminToolHandler
}

// NewAdminServer creates an MCP server with admin tools added.
func NewAdminServer(handler *AdminToolHandler) *AdminServer {
	as := &AdminServer{
		Server:  NewServer(),
		handler: handler,
	}
	as.registerAdminTools()
	return as
}

func (as *AdminServer) registerAdminTools() {
	// Override tools registry with admin-only tools (no honeypot tools)
	as.tools = &ToolRegistry{tools: make(map[string]*Tool)}

	as.tools.Register(&Tool{
		Name:        "toggle_feature",
		Description: "Enable or disable a server feature flag",
		Category:    "admin",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"feature": map[string]interface{}{
					"type":        "string",
					"description": "Feature flag name to toggle",
				},
				"enabled": map[string]interface{}{
					"type":        "boolean",
					"description": "Whether to enable or disable the feature",
				},
			},
			"required": []string{"feature", "enabled"},
		},
		Handler: func(args json.RawMessage) map[string]interface{} {
			var params struct {
				Feature string `json:"feature"`
				Enabled bool   `json:"enabled"`
			}
			if err := json.Unmarshal(args, &params); err != nil {
				return errorContent("invalid arguments")
			}
			if as.handler.ToggleFeature == nil {
				return errorContent("toggle_feature not configured")
			}
			if err := as.handler.ToggleFeature(params.Feature, params.Enabled); err != nil {
				return errorContent(err.Error())
			}
			return map[string]interface{}{
				"content": []map[string]interface{}{
					{"type": "text", "text": fmt.Sprintf("Feature '%s' set to %v", params.Feature, params.Enabled)},
				},
			}
		},
	})

	as.tools.Register(&Tool{
		Name:        "get_metrics",
		Description: "Get current server metrics",
		Category:    "admin",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
		Handler: func(args json.RawMessage) map[string]interface{} {
			if as.handler.GetMetrics == nil {
				return errorContent("get_metrics not configured")
			}
			metrics := as.handler.GetMetrics()
			data, _ := json.MarshalIndent(metrics, "", "  ")
			return map[string]interface{}{
				"content": []map[string]interface{}{
					{"type": "text", "text": string(data)},
				},
			}
		},
	})

	as.tools.Register(&Tool{
		Name:        "set_error_profile",
		Description: "Set error type weights for the error generator",
		Category:    "admin",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"weights": map[string]interface{}{
					"type":        "object",
					"description": "Map of error type to weight (0.0-1.0)",
				},
			},
			"required": []string{"weights"},
		},
		Handler: func(args json.RawMessage) map[string]interface{} {
			var params struct {
				Weights map[string]float64 `json:"weights"`
			}
			if err := json.Unmarshal(args, &params); err != nil {
				return errorContent("invalid arguments")
			}
			if as.handler.SetErrorWeights == nil {
				return errorContent("set_error_profile not configured")
			}
			if err := as.handler.SetErrorWeights(params.Weights); err != nil {
				return errorContent(err.Error())
			}
			return map[string]interface{}{
				"content": []map[string]interface{}{
					{"type": "text", "text": "Error profile updated"},
				},
			}
		},
	})

	as.tools.Register(&Tool{
		Name:        "nightmare_toggle",
		Description: "Enable or disable nightmare mode for a subsystem",
		Category:    "admin",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"subsystem": map[string]interface{}{
					"type":        "string",
					"description": "Subsystem to toggle: server, scanner, or proxy",
					"enum":        []string{"server", "scanner", "proxy"},
				},
				"enabled": map[string]interface{}{
					"type":        "boolean",
					"description": "Whether to enable or disable nightmare mode",
				},
			},
			"required": []string{"subsystem", "enabled"},
		},
		Handler: func(args json.RawMessage) map[string]interface{} {
			var params struct {
				Subsystem string `json:"subsystem"`
				Enabled   bool   `json:"enabled"`
			}
			if err := json.Unmarshal(args, &params); err != nil {
				return errorContent("invalid arguments")
			}
			if as.handler.NightmareToggle == nil {
				return errorContent("nightmare_toggle not configured")
			}
			if err := as.handler.NightmareToggle(params.Subsystem, params.Enabled); err != nil {
				return errorContent(err.Error())
			}
			action := "activated"
			if !params.Enabled {
				action = "deactivated"
			}
			return map[string]interface{}{
				"content": []map[string]interface{}{
					{"type": "text", "text": fmt.Sprintf("Nightmare mode %s for %s", action, params.Subsystem)},
				},
			}
		},
	})

	as.tools.Register(&Tool{
		Name:        "get_mcp_stats",
		Description: "Get MCP honeypot statistics",
		Category:    "admin",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
		Handler: func(args json.RawMessage) map[string]interface{} {
			stats := as.Stats()
			data, _ := json.MarshalIndent(stats, "", "  ")
			return map[string]interface{}{
				"content": []map[string]interface{}{
					{"type": "text", "text": string(data)},
				},
			}
		},
	})

	as.tools.Register(&Tool{
		Name:        "list_sessions",
		Description: "List active MCP sessions with client fingerprints",
		Category:    "admin",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
		Handler: func(args json.RawMessage) map[string]interface{} {
			sessions := as.Sessions()
			data, _ := json.MarshalIndent(sessions, "", "  ")
			return map[string]interface{}{
				"content": []map[string]interface{}{
					{"type": "text", "text": string(data)},
				},
			}
		},
	})
}

func errorContent(msg string) map[string]interface{} {
	return map[string]interface{}{
		"isError": true,
		"content": []map[string]interface{}{
			{"type": "text", "text": msg},
		},
	}
}
