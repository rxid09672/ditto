package extensions

import (
	"fmt"
)

// WASMRuntime manages WASM extensions
type WASMRuntime struct {
	extensions map[string]*Extension
	logger     interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

// Extension represents a loaded extension
type Extension struct {
	Name    string
	WASM    []byte
	Exports map[string]interface{}
}

// NewWASMRuntime creates a new WASM runtime
func NewWASMRuntime(logger interface {
	Info(string, ...interface{})
	Debug(string, ...interface{})
	Error(string, ...interface{})
}) *WASMRuntime {
	return &WASMRuntime{
		extensions: make(map[string]*Extension),
		logger:     logger,
	}
}

// LoadExtension loads a WASM extension
func (wr *WASMRuntime) LoadExtension(name string, wasmData []byte) error {
	wr.logger.Info("Loading WASM extension: %s", name)
	ext := &Extension{
		Name:    name,
		WASM:    wasmData,
		Exports: make(map[string]interface{}),
	}
	wr.extensions[name] = ext
	return nil
}

// ListExtensions lists all loaded extensions
func (wr *WASMRuntime) ListExtensions() []string {
	names := make([]string, 0, len(wr.extensions))
	for name := range wr.extensions {
		names = append(names, name)
	}
	return names
}

