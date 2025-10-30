package screenshot

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

func TestNewScreenshot(t *testing.T) {
	logger := &mockLogger{}
	s := NewScreenshot(logger)
	
	require.NotNil(t, s)
	assert.Equal(t, logger, s.logger)
}

func TestScreenshot_Capture_Windows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific test")
	}
	
	logger := &mockLogger{}
	s := NewScreenshot(logger)
	
	_, err := s.Capture()
	
	// Will fail due to not implemented, but structure is tested
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not yet implemented")
}

func TestScreenshot_Capture_UnsupportedOS(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows-specific test")
	}
	
	logger := &mockLogger{}
	s := NewScreenshot(logger)
	
	_, err := s.Capture()
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not supported")
}

func TestScreenshot_Capture_Logs(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific test")
	}
	
	logger := &mockLogger{}
	s := NewScreenshot(logger)
	
	s.Capture()
	
	// Should log attempt
	assert.Greater(t, len(logger.logs), 0)
}

