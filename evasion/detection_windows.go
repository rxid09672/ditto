//go:build windows
// +build windows

package evasion

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func getSystemUptime() int64 {
	if runtime.GOOS != "windows" {
		return 3600 // Default fallback
	}

	// Use Windows API to get system uptime
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	getTickCount64 := kernel32.NewProc("GetTickCount64")
	if getTickCount64 != nil {
		ret, _, _ := getTickCount64.Call()
		return int64(ret) / 1000 // Convert milliseconds to seconds
	}
	return 3600
}

func processExists(name string) bool {
	if runtime.GOOS != "windows" {
		return false
	}

	// Use tasklist command
	cmd := exec.Command("tasklist", "/FI", fmt.Sprintf("IMAGENAME eq %s", name))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}

	return strings.Contains(strings.ToLower(string(output)), strings.ToLower(name))
}

func getPEB() *PEB {
	if runtime.GOOS != "windows" {
		return nil
	}

	// Read PEB via NtQueryInformationProcess
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	ntQueryInformationProcess := ntdll.NewProc("NtQueryInformationProcess")

	if ntQueryInformationProcess == nil {
		return nil
	}

	const ProcessBasicInformation = 0
	var pbi struct {
		Reserved1       uintptr
		PebBaseAddress  uintptr
		Reserved2       [2]uintptr
		UniqueProcessId uintptr
		Reserved3       uintptr
	}

	ret, _, _ := ntQueryInformationProcess.Call(
		windows.CurrentProcess(),
		ProcessBasicInformation,
		uintptr(unsafe.Pointer(&pbi)),
		unsafe.Sizeof(pbi),
		0,
	)

	if ret != 0 || pbi.PebBaseAddress == 0 {
		return nil
	}

	// Read BeingDebugged flag from PEB
	var beingDebugged byte
	addr := pbi.PebBaseAddress + 0x02 // BeingDebugged offset
	mem := (*[1]byte)(unsafe.Pointer(addr))
	beingDebugged = (*mem)[0]

	return &PEB{
		BeingDebugged: beingDebugged,
	}
}

func registryKeyExists(key string) bool {
	if runtime.GOOS != "windows" {
		return false
	}

	// Parse hive and path
	parts := strings.SplitN(key, "\\", 2)
	if len(parts) == 0 {
		return false
	}

	var hive registry.Key
	switch strings.ToUpper(parts[0]) {
	case "HKLM", "HKEY_LOCAL_MACHINE":
		hive = registry.LOCAL_MACHINE
	case "HKCU", "HKEY_CURRENT_USER":
		hive = registry.CURRENT_USER
	case "HKCR", "HKEY_CLASSES_ROOT":
		hive = registry.CLASSES_ROOT
	case "HKU", "HKEY_USERS":
		hive = registry.USERS
	case "HKCC", "HKEY_CURRENT_CONFIG":
		hive = registry.CURRENT_CONFIG
	default:
		return false
	}

	path := ""
	if len(parts) > 1 {
		path = parts[1]
	}

	k, err := registry.OpenKey(hive, path, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	k.Close()
	return true
}

func getMACAddress() string {
	if runtime.GOOS != "windows" {
		return ""
	}

	// Use getmac command
	cmd := exec.Command("getmac", "/fo", "csv", "/nh")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return ""
	}

	// Parse CSV output
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, ",") {
			parts := strings.Split(line, ",")
			if len(parts) > 0 {
				mac := strings.TrimSpace(parts[0])
				// Remove dashes
				mac = strings.ReplaceAll(mac, "-", ":")
				return mac
			}
		}
	}

	return ""
}
