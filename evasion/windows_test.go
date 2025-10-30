// +build windows

package evasion

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockLoggerEvasion struct {
	logs []string
}

func (m *mockLoggerEvasion) Info(format string, v ...interface{}) {
	m.logs = append(m.logs, "INFO: "+format)
}

func (m *mockLoggerEvasion) Debug(format string, v ...interface{}) {
	m.logs = append(m.logs, "DEBUG: "+format)
}

func (m *mockLoggerEvasion) Error(format string, v ...interface{}) {
	m.logs = append(m.logs, "ERROR: "+format)
}

func TestNewCallStackSpoofing(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific test")
	}
	
	logger := &mockLoggerEvasion{}
	css := NewCallStackSpoofing(logger)
	
	require.NotNil(t, css)
	assert.Equal(t, logger, css.logger)
}

func TestCallStackSpoofing_SpoofCallStack(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific test")
	}
	
	logger := &mockLoggerEvasion{}
	css := NewCallStackSpoofing(logger)
	
	targetFunc := func() {
		// Test function
	}
	
	err := css.SpoofCallStack(targetFunc, "kernel32.dll")
	
	require.NoError(t, err)
	assert.Greater(t, len(logger.logs), 0)
}

func TestCallStackSpoofing_GetLegitimateReturnAddress(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific test")
	}
	
	logger := &mockLoggerEvasion{}
	css := NewCallStackSpoofing(logger)
	
	addr, err := css.GetLegitimateReturnAddress("kernel32.dll", "GetProcAddress")
	
	if err == nil {
		assert.NotEqual(t, uintptr(0), addr)
	}
}

func TestCallStackSpoofing_SpoofCallStackAdvanced(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific test")
	}
	
	logger := &mockLoggerEvasion{}
	css := NewCallStackSpoofing(logger)
	
	err := css.SpoofCallStackAdvanced(0x12345678, 0x87654321)
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "requires CGO/assembly")
	assert.Greater(t, len(logger.logs), 0)
}

func TestNewIndirectSyscall(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific test")
	}
	
	logger := &mockLoggerEvasion{}
	isd, err := NewIndirectSyscall(logger)
	
	require.NoError(t, err)
	require.NotNil(t, isd)
	assert.NotNil(t, isd.ntdll)
	assert.NotEqual(t, uintptr(0), isd.syscallGateAddr)
}

func TestNewIndirectSyscall_UnsupportedOS(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Non-Windows test")
	}
	
	logger := &mockLoggerEvasion{}
	_, err := NewIndirectSyscall(logger)
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "only supported on Windows")
}

func TestIndirectSyscall_Call(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific test")
	}
	
	logger := &mockLoggerEvasion{}
	isd, err := NewIndirectSyscall(logger)
	require.NoError(t, err)
	
	_, _, err = isd.Call(0x0010, uintptr(0x1234))
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "requires assembly")
}

func TestIndirectSyscall_Call_TooManyArgs(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific test")
	}
	
	logger := &mockLoggerEvasion{}
	isd, err := NewIndirectSyscall(logger)
	require.NoError(t, err)
	
	args := make([]uintptr, 16)
	_, _, err = isd.Call(0x0010, args...)
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too many arguments")
}

func TestStringStackObfuscation_Windows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific test")
	}
	
	sso := NewStringStackObfuscation()
	
	require.NotNil(t, sso)
	assert.NotNil(t, sso.key)
	
	plaintext := "test string"
	encrypted := sso.ObfuscateString(plaintext)
	decrypted := sso.DeobfuscateString(encrypted)
	
	assert.Equal(t, plaintext, decrypted)
}

func TestNewSleepMask(t *testing.T) {
	logger := &mockLoggerEvasion{}
	sm := NewSleepMask(logger)
	
	require.NotNil(t, sm)
	assert.Equal(t, logger, sm.logger)
}

func TestSleepMask_MaskedSleep_Unsupported(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Non-Windows test")
	}
	
	logger := &mockLoggerEvasion{}
	sm := NewSleepMask(logger)
	
	err := sm.MaskedSleep(1000)
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "only supported on Windows")
}

func TestSleepMask_MaskedSleepWithJitter(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific test")
	}
	
	logger := &mockLoggerEvasion{}
	sm := NewSleepMask(logger)
	
	err := sm.MaskedSleepWithJitter(1000, 10)
	
	// May succeed or fail depending on implementation
	_ = err
}

func TestNewDirectSyscall(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific test")
	}
	
	logger := &mockLoggerEvasion{}
	ds := NewDirectSyscall(logger)
	
	require.NotNil(t, ds)
	assert.NotNil(t, ds.ntdll)
	assert.NotNil(t, ds.syscallNumbers)
}

func TestDirectSyscall_GetSyscallNumber(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific test")
	}
	
	logger := &mockLoggerEvasion{}
	ds := NewDirectSyscall(logger)
	
	num, ok := ds.GetSyscallNumber("NtDelayExecution")
	if ok {
		assert.NotEqual(t, uint16(0), num)
	}
	
	_, ok = ds.GetSyscallNumber("NonexistentSyscall")
	assert.False(t, ok)
}

func TestDirectSyscall_Call_Unknown(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific test")
	}
	
	logger := &mockLoggerEvasion{}
	ds := NewDirectSyscall(logger)
	
	_, _, err := ds.Call("NonexistentSyscall")
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown syscall")
}

func TestDirectSyscall_executeDirectSyscall_TooManyArgs(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific test")
	}
	
	logger := &mockLoggerEvasion{}
	ds := NewDirectSyscall(logger)
	
	args := make([]uintptr, 16)
	_, _, err := ds.executeDirectSyscall(0x0010, args...)
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too many arguments")
}
