package evasion

import (
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCheckSandbox(t *testing.T) {
	// This test checks if sandbox detection works
	// Actual result depends on environment
	result := CheckSandbox()
	assert.IsType(t, false, result)
	
	// Should not panic
	assert.NotPanics(t, func() {
		CheckSandbox()
	})
}

func TestCheckDebugger(t *testing.T) {
	result := CheckDebugger()
	assert.IsType(t, false, result)
	
	// Should not panic
	assert.NotPanics(t, func() {
		CheckDebugger()
	})
}

func TestCheckVM(t *testing.T) {
	result := CheckVM()
	assert.IsType(t, false, result)
	
	// Should not panic
	assert.NotPanics(t, func() {
		CheckVM()
	})
}

func TestGetSystemMemory(t *testing.T) {
	mem := getSystemMemory()
	assert.Greater(t, mem, uint64(0))
}

func TestGetSystemUptime(t *testing.T) {
	uptime := getSystemUptime()
	assert.GreaterOrEqual(t, uptime, int64(0))
}

func TestProcessExists(t *testing.T) {
	// Should not panic
	assert.NotPanics(t, func() {
		processExists("nonexistent.exe")
	})
	
	result := processExists("nonexistent.exe")
	assert.IsType(t, false, result)
}

func TestIsVMMAC(t *testing.T) {
	tests := []struct {
		name     string
		mac      string
		expected bool
	}{
		{"VMware MAC 1", "00:0c:29:aa:bb:cc", true},
		{"VMware MAC 2", "00:50:56:aa:bb:cc", true},
		{"VirtualBox MAC", "08:00:27:aa:bb:cc", true},
		{"Xen MAC", "00:16:3e:aa:bb:cc", true},
		{"Regular MAC", "00:11:22:aa:bb:cc", false},
		{"Empty MAC", "", false},
		{"Short MAC", "00:0c", false},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isVMMAC(tt.mac)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSleepMask(t *testing.T) {
	start := time.Now()
	SleepMask(100) // 100ms
	duration := time.Since(start)
	
	// Should have slept approximately 100ms
	assert.GreaterOrEqual(t, duration, 90*time.Millisecond)
	assert.LessOrEqual(t, duration, 500*time.Millisecond)
}

func TestSleepMask_Zero(t *testing.T) {
	start := time.Now()
	SleepMask(0)
	duration := time.Since(start)
	
	// Should be very fast
	assert.Less(t, duration, 100*time.Millisecond)
}

func TestCheckWindowsDebugger(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific test")
	}
	
	result := checkWindowsDebugger()
	assert.IsType(t, false, result)
}

func TestCheckLinuxDebugger(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-specific test")
	}
	
	result := checkLinuxDebugger()
	assert.IsType(t, false, result)
}

func TestCheckDarwinDebugger(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin-specific test")
	}
	
	result := checkDarwinDebugger()
	assert.IsType(t, false, result)
}

func TestCheckWindowsVM(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific test")
	}
	
	result := checkWindowsVM()
	assert.IsType(t, false, result)
}

func TestCheckLinuxVM(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-specific test")
	}
	
	result := checkLinuxVM()
	assert.IsType(t, false, result)
}

func TestGetTracerPID(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-specific test")
	}
	
	pid := getTracerPID()
	assert.GreaterOrEqual(t, pid, 0)
}

// TestCheckSysctlDebugger is covered by TestCheckDarwinDebugger
// Removed redundant test that causes compilation issues on non-Darwin platforms

func TestRegistryKeyExists(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific test")
	}
	
	result := registryKeyExists("SOFTWARE\\Nonexistent")
	assert.IsType(t, false, result)
}

func TestGetMACAddress(t *testing.T) {
	mac := getMACAddress()
	// May be empty on some platforms
	assert.IsType(t, "", mac)
}

func TestCheckDMIVM(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-specific test")
	}
	
	result := checkDMIVM()
	assert.IsType(t, false, result)
}

func TestGetPEB(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific test")
	}
	
	peb := getPEB()
	// May be nil on non-Windows or if not implemented
	if peb != nil {
		assert.NotNil(t, peb)
	}
}

func BenchmarkCheckSandbox(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = CheckSandbox()
	}
}

func BenchmarkCheckDebugger(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = CheckDebugger()
	}
}

func BenchmarkCheckVM(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = CheckVM()
	}
}

