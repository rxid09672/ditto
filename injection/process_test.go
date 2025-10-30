// +build windows

package injection

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

type mockDirectSyscall struct {
	calls map[string][]uintptr
}

func (m *mockDirectSyscall) Call(syscallName string, args ...uintptr) (uintptr, uintptr, error) {
	if m.calls == nil {
		m.calls = make(map[string][]uintptr)
	}
	m.calls[syscallName] = args
	return 0, 0, nil
}

func (m *mockDirectSyscall) GetSyscallNumber(syscallName string) (uint16, bool) {
	return 0, true
}

func TestNewProcessInjection(t *testing.T) {
	logger := &mockLogger{}
	
	pi := NewProcessInjection(logger)
	
	require.NotNil(t, pi)
	assert.Equal(t, logger, pi.logger)
	assert.Nil(t, pi.directSyscall)
}

func TestProcessInjection_SetDirectSyscall(t *testing.T) {
	logger := &mockLogger{}
	pi := NewProcessInjection(logger)
	
	mockSyscall := &mockDirectSyscall{}
	pi.SetDirectSyscall(mockSyscall)
	
	assert.Equal(t, mockSyscall, pi.directSyscall)
}

func TestProcessInjection_SetDirectSyscall_Nil(t *testing.T) {
	logger := &mockLogger{}
	pi := NewProcessInjection(logger)
	
	pi.SetDirectSyscall(nil)
	
	assert.Nil(t, pi.directSyscall)
}

// Note: Windows-specific injection tests would require actual Windows API calls
// These are basic unit tests for the structure

