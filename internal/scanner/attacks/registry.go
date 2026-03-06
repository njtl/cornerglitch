// Package attacks provides the built-in attack module registry for the
// Glitch Scanner. It exposes AllModules() to return every available module
// and ListModules() for human-readable discovery.
package attacks

import (
	"fmt"
	"sort"

	"github.com/glitchWebServer/internal/scanner"
)

// ModuleInfo describes a registered attack module for listing purposes.
type ModuleInfo struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	Requests int    `json:"requests"`
}

// AllModules returns instances of all built-in attack modules. The caller
// can filter by name before registering them with the scanner engine.
func AllModules() []scanner.AttackModule {
	return []scanner.AttackModule{
		&OWASPModule{},
		&InjectionModule{},
		&FuzzingModule{},
		&ProtocolModule{},
		&AuthModule{},
		&ChaosModule{},
		&TLSModule{},
		&SlowHTTPModule{},
		&BreakageModule{},
		&H3Module{},
	}
}

// GetModule returns a single module by name, or an error if not found.
func GetModule(name string) (scanner.AttackModule, error) {
	for _, m := range AllModules() {
		if m.Name() == name {
			return m, nil
		}
	}
	return nil, fmt.Errorf("unknown module %q; available: %v", name, ListModuleNames())
}

// ListModuleNames returns the names of all available modules in sorted order.
func ListModuleNames() []string {
	mods := AllModules()
	names := make([]string, len(mods))
	for i, m := range mods {
		names[i] = m.Name()
	}
	sort.Strings(names)
	return names
}

// ListModules returns detailed info about each registered module.
func ListModules() []ModuleInfo {
	mods := AllModules()
	infos := make([]ModuleInfo, len(mods))
	dummyTarget := "http://localhost:8765"
	for i, m := range mods {
		reqs := m.GenerateRequests(dummyTarget)
		infos[i] = ModuleInfo{
			Name:     m.Name(),
			Category: m.Category(),
			Requests: len(reqs),
		}
	}
	sort.Slice(infos, func(i, j int) bool {
		return infos[i].Name < infos[j].Name
	})
	return infos
}

// FilterModules returns only modules whose names appear in the given list.
// If the list is empty, all modules are returned.
func FilterModules(names []string) []scanner.AttackModule {
	if len(names) == 0 {
		return AllModules()
	}

	nameSet := make(map[string]bool, len(names))
	for _, n := range names {
		nameSet[n] = true
	}

	var filtered []scanner.AttackModule
	for _, m := range AllModules() {
		if nameSet[m.Name()] {
			filtered = append(filtered, m)
		}
	}
	return filtered
}

// ModulesByName returns only modules whose names appear in the given list.
// This is an alias for FilterModules for convenience.
func ModulesByName(names []string) []scanner.AttackModule {
	return FilterModules(names)
}

// ModuleNames returns the names of all available modules in sorted order.
// This is an alias for ListModuleNames for convenience.
func ModuleNames() []string {
	return ListModuleNames()
}
