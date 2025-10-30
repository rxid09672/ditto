package processes

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

func TestNewProcessManager(t *testing.T) {
	logger := &mockLogger{}
	pm := NewProcessManager(logger)
	
	require.NotNil(t, pm)
	assert.Equal(t, logger, pm.logger)
}

func TestProcessManager_ListProcesses_Windows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific test")
	}
	
	logger := &mockLogger{}
	pm := NewProcessManager(logger)
	
	_, err := pm.ListProcesses()
	
	// Will fail due to not implemented, but structure is tested
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not yet implemented")
}

func TestProcessManager_ListProcesses_Linux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-specific test")
	}
	
	logger := &mockLogger{}
	pm := NewProcessManager(logger)
	
	_, err := pm.ListProcesses()
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not yet implemented")
}

func TestProcessManager_ListProcesses_Unsupported(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "linux" {
		t.Skip("Windows/Linux-specific test")
	}
	
	logger := &mockLogger{}
	pm := NewProcessManager(logger)
	
	_, err := pm.ListProcesses()
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported OS")
}

func TestProcessManager_KillProcess(t *testing.T) {
	logger := &mockLogger{}
	pm := NewProcessManager(logger)
	
	err := pm.KillProcess(12345)
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not yet implemented")
}

func TestProcessManager_KillProcess_Logs(t *testing.T) {
	logger := &mockLogger{}
	pm := NewProcessManager(logger)
	
	pm.KillProcess(12345)
	
	assert.Greater(t, len(logger.logs), 0)
}

