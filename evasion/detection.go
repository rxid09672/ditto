package evasion

import (
	"runtime"
	"time"
)

// CheckSandbox detects sandbox environments
func CheckSandbox() bool {
	// Check CPU count
	if runtime.NumCPU() < 2 {
		return true
	}
	
	// Check RAM
	mem := getSystemMemory()
	if mem < 2*1024*1024*1024 { // Less than 2GB
		return true
	}
	
	// Check uptime
	uptime := getSystemUptime()
	if uptime < 300 { // Less than 5 minutes
		return true
	}
	
	return false
}

// CheckDebugger detects debugger attachment
func CheckDebugger() bool {
	// Platform-specific debugger detection
	switch runtime.GOOS {
	case "windows":
		return checkWindowsDebugger()
	case "linux":
		return checkLinuxDebugger()
	case "darwin":
		return checkDarwinDebugger()
	default:
		return false
	}
}

// CheckVM detects virtual machine environment
func CheckVM() bool {
	// Check for VM artifacts
	switch runtime.GOOS {
	case "windows":
		return checkWindowsVM()
	case "linux":
		return checkLinuxVM()
	default:
		return false
	}
}

func checkWindowsDebugger() bool {
	// Check for common debugger processes
	debuggers := []string{
		"ollydbg.exe",
		"x64dbg.exe",
		"windbg.exe",
		"ida.exe",
		"ida64.exe",
		"wireshark.exe",
		"fiddler.exe",
	}
	
	for _, dbg := range debuggers {
		if processExists(dbg) {
			return true
		}
	}
	
	// Check PEB BeingDebugged flag
	peb := getPEB()
	if peb != nil && peb.BeingDebugged != 0 {
		return true
	}
	
	return false
}

func checkLinuxDebugger() bool {
	// Check /proc/self/status for TracerPid
	tracerPid := getTracerPID()
	return tracerPid > 0
}

func checkDarwinDebugger() bool {
	// This function is implemented in detection_darwin.go via build tags
	// Stub for non-Darwin builds - will be replaced by detection_darwin.go on Darwin
	return false
}

func checkWindowsVM() bool {
	// Check registry keys
	vmKeys := []string{
		`SOFTWARE\VMware\VMware Tools`,
		`SOFTWARE\Oracle\VirtualBox Guest Additions`,
		`SYSTEM\ControlSet001\Services\VBoxGuest`,
		`SYSTEM\ControlSet001\Services\VBoxMouse`,
		`SYSTEM\ControlSet001\Services\VBoxService`,
		`SYSTEM\ControlSet001\Services\VBoxSF`,
	}
	
	for _, key := range vmKeys {
		if registryKeyExists(key) {
			return true
		}
	}
	
	// Check MAC addresses
	mac := getMACAddress()
	if isVMMAC(mac) {
		return true
	}
	
	return false
}

func checkLinuxVM() bool {
	// Check for VM indicators in /sys/class/dmi/id
	return checkDMIVM()
}

func getSystemMemory() uint64 {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	return mem.Sys
}

func isVMMAC(mac string) bool {
	vmPrefixes := []string{
		"00:0c:29", // VMware
		"00:50:56", // VMware
		"08:00:27", // VirtualBox
		"00:16:3e", // Xen
	}
	
	for _, prefix := range vmPrefixes {
		if len(mac) >= len(prefix) && mac[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

// Platform-specific helpers are implemented in detection_windows.go, detection_linux.go, detection_unix.go
// These declarations are replaced by build tags on specific platforms

// SleepMask masks sleep operations
func SleepMask(duration int) {
	// Implement sleep masking to evade timing analysis
	// Would use techniques like: timers, event-based waits, etc.
	time.Sleep(time.Duration(duration) * time.Millisecond)
}

