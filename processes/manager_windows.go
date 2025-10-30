// +build windows

package processes

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func (pm *ProcessManager) killProcess(pid int) error {
	pm.logger.Info("Killing process: %d", pid)
	
	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("failed to find process: %w", err)
	}
	
	return proc.Kill()
}

func (pm *ProcessManager) listProcessesWindows() ([]ProcessInfo, error) {
	// Use CreateToolhelp32Snapshot
	handle, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to create snapshot: %w", err)
	}
	defer syscall.CloseHandle(handle)
	
	var entry syscall.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	
	err = syscall.Process32First(handle, &entry)
	if err != nil {
		return nil, fmt.Errorf("failed to get first process: %w", err)
	}
	
	processes := make([]ProcessInfo, 0, 50)
	for {
		procInfo := ProcessInfo{
			PID:  int(entry.ProcessID),
			PPID: int(entry.ParentProcessID),
			Name: strings.TrimRight(string(entry.ExeFile[:]), "\x00"),
		}
		
		// Get process owner
		if owner, err := getProcessOwnerWindows(uint32(entry.ProcessID)); err == nil {
			procInfo.Owner = owner
		}
		
		// Get process path
		if path, err := getProcessPathWindows(uint32(entry.ProcessID)); err == nil {
			procInfo.Path = path
		}
		
		processes = append(processes, procInfo)
		
		err = syscall.Process32Next(handle, &entry)
		if err != nil {
			break
		}
	}
	
	return processes, nil
}

func getProcessOwnerWindows(pid uint32) (string, error) {
	handle, err := syscall.OpenProcess(syscall.PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer syscall.CloseHandle(handle)
	
	var token syscall.Token
	if err = syscall.OpenProcessToken(handle, syscall.TOKEN_QUERY, &token); err != nil {
		return "", err
	}
	defer token.Close()
	
	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return "", err
	}
	
	account, domain, _, err := tokenUser.User.Sid.LookupAccount("")
	if err != nil {
		return "", err
	}
	
	return fmt.Sprintf("%s\\%s", domain, account), nil
}

func getProcessPathWindows(pid uint32) (string, error) {
	handle, err := syscall.OpenProcess(syscall.PROCESS_QUERY_INFORMATION|syscall.PROCESS_VM_READ, false, pid)
	if err != nil {
		return "", err
	}
	defer syscall.CloseHandle(handle)
	
	var size uint32 = 260
	buf := make([]uint16, size)
	
	mod := windows.NewLazySystemDLL("kernel32.dll")
	getModuleFileNameEx := mod.NewProc("GetModuleFileNameExW")
	
	ret, _, _ := getModuleFileNameEx.Call(
		uintptr(handle),
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(size),
	)
	
	if ret == 0 {
		return "", fmt.Errorf("failed to get module filename")
	}
	
	return windows.UTF16ToString(buf), nil
}

