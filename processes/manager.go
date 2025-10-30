package processes

import (
	"fmt"
	"runtime"
)

// ProcessInfo represents process information
type ProcessInfo struct {
	PID       int
	PPID      int
	Name      string
	Path      string
	Owner     string
	Arch      string
	SessionID int
}

// ProcessManager manages process operations
type ProcessManager struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

// NewProcessManager creates a new process manager
func NewProcessManager(logger interface {
	Info(string, ...interface{})
	Debug(string, ...interface{})
	Error(string, ...interface{})
}) *ProcessManager {
	return &ProcessManager{logger: logger}
}

// ListProcesses lists all running processes
func (pm *ProcessManager) ListProcesses() ([]ProcessInfo, error) {
	switch runtime.GOOS {
	case "windows":
		return pm.listProcessesWindows()
	case "linux":
		return pm.listProcessesLinux()
	default:
		return nil, fmt.Errorf("unsupported OS")
	}
}

// KillProcess kills a process
func (pm *ProcessManager) KillProcess(pid int) error {
	pm.logger.Info("Killing process: %d", pid)
	return fmt.Errorf("not yet implemented")
}

func (pm *ProcessManager) listProcessesWindows() ([]ProcessInfo, error) {
	return nil, fmt.Errorf("not yet implemented")
}

func (pm *ProcessManager) listProcessesLinux() ([]ProcessInfo, error) {
	return nil, fmt.Errorf("not yet implemented")
}

