package payload

import (
	"testing"

	"github.com/ditto/ditto/core"
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

func TestNewGenerator(t *testing.T) {
	logger := &mockLogger{}
	gen := NewGenerator(logger)
	
	require.NotNil(t, gen)
	assert.NotNil(t, gen.logger)
}

func TestGenerator_Generate_Stager(t *testing.T) {
	logger := &mockLogger{}
	gen := NewGenerator(logger)
	cfg := core.DefaultConfig()
	
	opts := Options{
		Type:      "stager",
		Arch:      "amd64",
		OS:        "windows",
		Encrypt:   false,
		Obfuscate: false,
		Config:    cfg,
	}
	
	payload, err := gen.Generate(opts)
	
	require.NoError(t, err)
	assert.NotNil(t, payload)
	assert.Greater(t, len(payload), 0)
}

func TestGenerator_Generate_Shellcode(t *testing.T) {
	logger := &mockLogger{}
	gen := NewGenerator(logger)
	cfg := core.DefaultConfig()
	
	opts := Options{
		Type:      "shellcode",
		Arch:      "amd64",
		OS:        "windows",
		Encrypt:   false,
		Obfuscate: false,
		Config:    cfg,
	}
	
	payload, err := gen.Generate(opts)
	
	require.NoError(t, err)
	assert.NotNil(t, payload)
}

func TestGenerator_Generate_Full(t *testing.T) {
	logger := &mockLogger{}
	gen := NewGenerator(logger)
	cfg := core.DefaultConfig()
	
	opts := Options{
		Type:      "full",
		Arch:      "amd64",
		OS:        "windows",
		Encrypt:   false,
		Obfuscate: false,
		Config:    cfg,
	}
	
	payload, err := gen.Generate(opts)
	
	require.NoError(t, err)
	assert.NotNil(t, payload)
}

func TestGenerator_Generate_UnknownType(t *testing.T) {
	logger := &mockLogger{}
	gen := NewGenerator(logger)
	cfg := core.DefaultConfig()
	
	opts := Options{
		Type:      "unknown",
		Arch:      "amd64",
		OS:        "windows",
		Encrypt:   false,
		Obfuscate: false,
		Config:    cfg,
	}
	
	_, err := gen.Generate(opts)
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown payload type")
}

func TestGenerator_Generate_WithObfuscation(t *testing.T) {
	logger := &mockLogger{}
	gen := NewGenerator(logger)
	cfg := core.DefaultConfig()
	
	opts := Options{
		Type:      "stager",
		Arch:      "amd64",
		OS:        "windows",
		Encrypt:   false,
		Obfuscate: true,
		Config:    cfg,
	}
	
	payload, err := gen.Generate(opts)
	
	require.NoError(t, err)
	assert.NotNil(t, payload)
}

func TestGenerator_Generate_WithEncryption(t *testing.T) {
	logger := &mockLogger{}
	gen := NewGenerator(logger)
	cfg := core.DefaultConfig()
	
	opts := Options{
		Type:      "stager",
		Arch:      "amd64",
		OS:        "windows",
		Encrypt:   true,
		Obfuscate: false,
		Config:    cfg,
	}
	
	payload, err := gen.Generate(opts)
	
	require.NoError(t, err)
	assert.NotNil(t, payload)
}

func TestGenerator_Generate_WithCompression(t *testing.T) {
	logger := &mockLogger{}
	gen := NewGenerator(logger)
	cfg := core.DefaultConfig()
	cfg.Encryption.Compression = true
	
	opts := Options{
		Type:      "stager",
		Arch:      "amd64",
		OS:        "windows",
		Encrypt:   false,
		Obfuscate: false,
		Config:    cfg,
	}
	
	payload, err := gen.Generate(opts)
	
	require.NoError(t, err)
	assert.NotNil(t, payload)
}

func TestGenerator_Generate_Linux(t *testing.T) {
	logger := &mockLogger{}
	gen := NewGenerator(logger)
	cfg := core.DefaultConfig()
	
	opts := Options{
		Type:      "stager",
		Arch:      "amd64",
		OS:        "linux",
		Encrypt:   false,
		Obfuscate: false,
		Config:    cfg,
	}
	
	payload, err := gen.Generate(opts)
	
	require.NoError(t, err)
	assert.NotNil(t, payload)
}

func TestGenerator_Generate_Darwin(t *testing.T) {
	logger := &mockLogger{}
	gen := NewGenerator(logger)
	cfg := core.DefaultConfig()
	
	opts := Options{
		Type:      "stager",
		Arch:      "amd64",
		OS:        "darwin",
		Encrypt:   false,
		Obfuscate: false,
		Config:    cfg,
	}
	
	payload, err := gen.Generate(opts)
	
	require.NoError(t, err)
	assert.NotNil(t, payload)
}

func TestGenerator_GenerateShellcode_Windows(t *testing.T) {
	logger := &mockLogger{}
	gen := NewGenerator(logger)
	cfg := core.DefaultConfig()
	
	opts := Options{
		Type:      "shellcode",
		Arch:      "amd64",
		OS:        "windows",
		Config:    cfg,
	}
	
	payload, err := gen.generateShellcode(opts)
	
	require.NoError(t, err)
	assert.NotNil(t, payload)
}

func TestGenerator_GenerateShellcode_UnsupportedOS(t *testing.T) {
	logger := &mockLogger{}
	gen := NewGenerator(logger)
	cfg := core.DefaultConfig()
	
	opts := Options{
		Type:      "shellcode",
		Arch:      "amd64",
		OS:        "freebsd",
		Config:    cfg,
	}
	
	_, err := gen.generateShellcode(opts)
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported OS")
}

func BenchmarkGenerator_Generate(b *testing.B) {
	logger := &mockLogger{}
	gen := NewGenerator(logger)
	cfg := core.DefaultConfig()
	
	opts := Options{
		Type:      "stager",
		Arch:      "amd64",
		OS:        "windows",
		Encrypt:   false,
		Obfuscate: false,
		Config:    cfg,
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = gen.Generate(opts)
	}
}

