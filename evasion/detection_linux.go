// +build linux

package evasion

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func getSystemUptime() int64 {
	// Read /proc/uptime
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		parts := strings.Fields(string(data))
		if len(parts) > 0 {
			if uptime, err := strconv.ParseFloat(parts[0], 64); err == nil {
				return int64(uptime)
			}
		}
	}
	return 3600
}

func processExists(name string) bool {
	cmd := exec.Command("pgrep", "-x", name)
	err := cmd.Run()
	return err == nil
}

func getPEB() *PEB {
	return nil // Windows only
}

func registryKeyExists(key string) bool {
	return false // Windows only
}

func getMACAddress() string {
	// Read from /sys/class/net
	if data, err := os.ReadFile("/sys/class/net/eth0/address"); err == nil {
		return strings.TrimSpace(string(data))
	}
	// Fallback to ip command
	cmd := exec.Command("ip", "link", "show", "eth0")
	if output, err := cmd.CombinedOutput(); err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "link/ether") {
				parts := strings.Fields(line)
				for i, part := range parts {
					if part == "link/ether" && i+1 < len(parts) {
						return parts[i+1]
					}
				}
			}
		}
	}
	return ""
}

func getTracerPID() int {
	// Read /proc/self/status
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "TracerPid:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				pid, err := strconv.Atoi(parts[1])
				if err == nil {
					return pid
				}
			}
		}
	}
	
	return 0
}

func checkDMIVM() bool {
	// Check /sys/class/dmi/id/product_name
	productName, err := os.ReadFile("/sys/class/dmi/id/product_name")
	if err != nil {
		return false
	}
	
	name := strings.ToLower(strings.TrimSpace(string(productName)))
	vmIndicators := []string{"vmware", "virtualbox", "qemu", "xen", "kvm", "bochs"}
	for _, indicator := range vmIndicators {
		if strings.Contains(name, indicator) {
			return true
		}
	}
	
	// Check board_vendor
	boardVendor, err := os.ReadFile("/sys/class/dmi/id/board_vendor")
	if err == nil {
		vendor := strings.ToLower(strings.TrimSpace(string(boardVendor)))
		for _, indicator := range vmIndicators {
			if strings.Contains(vendor, indicator) {
				return true
			}
		}
	}
	
	return false
}

type PEB struct {
	BeingDebugged byte
}

