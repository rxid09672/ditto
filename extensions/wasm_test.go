package extensions

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockLogger struct {
	logs []string
}

func (m *mockLogger) Info(format string, v ...interface{}) {
	m.logs = append(m.logs, "INFO: "+format)
}

func (m *mockLogger) Debug(format string, v ...interface{}) {
	m.logs = append(m.logs, "DEBUG: "+format)
}

func (m *mockLogger) Error(format string, v ...interface{}) {
	m.logs = append(m.logs, "ERROR: "+format)
}

func TestNewWASMRuntime(t *testing.T) {
	logger := &mockLogger{}
	wr := NewWASMRuntime(logger)
	
	require.NotNil(t, wr)
	assert.NotNil(t, wr.extensions)
	assert.Equal(t, logger, wr.logger)
}

func TestWASMRuntime_LoadExtension(t *testing.T) {
	logger := &mockLogger{}
	wr := NewWASMRuntime(logger)
	
	wasmData := []byte{0x00, 0x61, 0x73, 0x6D} // WASM magic number
	
	err := wr.LoadExtension("test-ext", wasmData)
	
	require.NoError(t, err)
	assert.Len(t, wr.ListExtensions(), 1)
	assert.Contains(t, wr.ListExtensions(), "test-ext")
}

func TestWASMRuntime_LoadExtension_Multiple(t *testing.T) {
	logger := &mockLogger{}
	wr := NewWASMRuntime(logger)
	
	wr.LoadExtension("ext1", []byte("wasm1"))
	wr.LoadExtension("ext2", []byte("wasm2"))
	
	extensions := wr.ListExtensions()
	assert.Len(t, extensions, 2)
}

func TestWASMRuntime_ListExtensions_Empty(t *testing.T) {
	logger := &mockLogger{}
	wr := NewWASMRuntime(logger)
	
	extensions := wr.ListExtensions()
	
	assert.Len(t, extensions, 0)
}

func TestExtension_Structure(t *testing.T) {
	logger := &mockLogger{}
	wr := NewWASMRuntime(logger)
	
	wasmData := []byte("test wasm")
	wr.LoadExtension("test", wasmData)
	
	// Extension should be stored
	extensions := wr.ListExtensions()
	assert.Contains(t, extensions, "test")
}

func BenchmarkWASMRuntime_LoadExtension(b *testing.B) {
	logger := &mockLogger{}
	wr := NewWASMRuntime(logger)
	wasmData := []byte("test wasm")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = wr.LoadExtension(string(rune(i)), wasmData)
	}
}

