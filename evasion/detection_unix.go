//go:build !windows && !linux && !darwin
// +build !windows,!linux,!darwin

package evasion

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func getSystemUptime() int64 {
	// Read /proc/uptime on Linux
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		parts := strings.Fields(string(data))
		if len(parts) > 0 {
			if uptime, err := strconv.ParseFloat(parts[0], 64); err == nil {
				return int64(uptime)
			}
		}
	}
	
	// Fallback for other systems
	return 3600
}

func processExists(name string) bool {
	// Use ps command
	cmd := exec.Command("ps", "-C", name)
	err := cmd.Run()
	return err == nil
}

func getPEB() *PEB {
	return nil // Not available on non-Windows
}

func checkSysctlDebugger() bool {
	return false // Implemented in detection_darwin.go
}

func registryKeyExists(key string) bool {
	return false // Windows only
}

func getMACAddress() string {
	// Use ip or ifconfig command
	cmd := exec.Command("sh", "-c", "ip link show | grep -oP 'link/ether \\K[^ ]+' | head -1")
	if output, err := cmd.CombinedOutput(); err == nil {
		return strings.TrimSpace(string(output))
	}
	
	// Fallback to ifconfig
	cmd = exec.Command("sh", "-c", "ifconfig | grep -oP 'ether \\K[^ ]+' | head -1")
	if output, err := cmd.CombinedOutput(); err == nil {
		return strings.TrimSpace(string(output))
	}
	
	return ""
}

type PEB struct {
	BeingDebugged byte
}

