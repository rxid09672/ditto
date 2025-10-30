package registry

import (
	"runtime"
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

func TestNewRegistryOps(t *testing.T) {
	logger := &mockLogger{}
	ro := NewRegistryOps(logger)
	
	require.NotNil(t, ro)
	assert.Equal(t, logger, ro.logger)
}

func TestRegistryOps_ReadKey_UnsupportedOS(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows-specific test")
	}
	
	logger := &mockLogger{}
	ro := NewRegistryOps(logger)
	
	_, err := ro.ReadKey("SOFTWARE\\Test", "Value")
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "only supported on Windows")
}

func TestRegistryOps_WriteKey_UnsupportedOS(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows-specific test")
	}
	
	logger := &mockLogger{}
	ro := NewRegistryOps(logger)
	
	err := ro.WriteKey("SOFTWARE\\Test", "Value", "data", "string")
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "only supported on Windows")
}

func TestRegistryOps_EnumKeys_UnsupportedOS(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows-specific test")
	}
	
	logger := &mockLogger{}
	ro := NewRegistryOps(logger)
	
	_, err := ro.EnumKeys("SOFTWARE\\Test")
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "only supported on Windows")
}

// Note: Windows-specific registry tests would require actual Windows API calls
// These are basic unit tests for the structure and error handling

func TestRegistryOps_ReadKey_Windows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific test")
	}
	
	logger := &mockLogger{}
	ro := NewRegistryOps(logger)
	
	_, err := ro.ReadKey("SOFTWARE\\Test", "Value")
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not yet implemented")
	assert.Greater(t, len(logger.logs), 0)
}

func TestRegistryOps_WriteKey_Windows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific test")
	}
	
	logger := &mockLogger{}
	ro := NewRegistryOps(logger)
	
	err := ro.WriteKey("SOFTWARE\\Test", "Value", "data", "string")
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not yet implemented")
	assert.Greater(t, len(logger.logs), 0)
}

func TestRegistryOps_EnumKeys_Windows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific test")
	}
	
	logger := &mockLogger{}
	ro := NewRegistryOps(logger)
	
	_, err := ro.EnumKeys("SOFTWARE\\Test")
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not yet implemented")
	assert.Greater(t, len(logger.logs), 0)
}

func TestRegistryOps_WriteKey_DifferentTypes(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific test")
	}
	
	logger := &mockLogger{}
	ro := NewRegistryOps(logger)
	
	tests := []struct {
		name  string
		value interface{}
		vtype string
	}{
		{"string", "test", "string"},
		{"dword", uint32(123), "dword"},
		{"qword", uint64(456), "qword"},
		{"binary", []byte{1, 2, 3}, "binary"},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ro.WriteKey("SOFTWARE\\Test", "Value", tt.value, tt.vtype)
			assert.Error(t, err) // Not implemented yet
		})
	}
}
