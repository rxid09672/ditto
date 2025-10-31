package modules

// CompleterAdapter wraps ModuleRegistry to provide completion interface
type CompleterAdapter struct {
	registry *ModuleRegistry
}

// NewCompleterAdapter creates a new adapter for the completer
func NewCompleterAdapter(registry *ModuleRegistry) *CompleterAdapter {
	return &CompleterAdapter{registry: registry}
}

// ModuleWrapper wraps EmpireModule to provide GetID method
type ModuleWrapper struct {
	*EmpireModule
}

// GetID returns the module ID
func (m *ModuleWrapper) GetID() string {
	return m.ID
}

// ListAllModules returns all modules wrapped for completion
func (a *CompleterAdapter) ListAllModules() []interface{ GetID() string } {
	modules := a.registry.ListAllModules()
	result := make([]interface{ GetID() string }, len(modules))
	for i, mod := range modules {
		result[i] = &ModuleWrapper{EmpireModule: mod}
	}
	return result
}

