// +build !windows

package injection

import (
	"fmt"
	"runtime"
)

// ProcessInjection handles process injection operations
type ProcessInjection struct {
	logger       interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
	directSyscall interface{}
	shellcodeAddr uintptr
	shellcodeSize uintptr
}

// NewProcessInjection creates a new process injection handler
func NewProcessInjection(logger interface {
	Info(string, ...interface{})
	Debug(string, ...interface{})
	Error(string, ...interface{})
}) *ProcessInjection {
	return &ProcessInjection{
		logger: logger,
	}
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

// Platform-specific implementations
func (pi *ProcessInjection) injectWindows(pid int, shellcode []byte, method string) error {
	return fmt.Errorf("Windows injection only supported on Windows")
}

