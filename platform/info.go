package platform

import (
	"os"
	"os/user"
	"runtime"
)

// GetHostname returns the system hostname
func GetHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

// GetUsername returns the current username
func GetUsername() string {
	u, err := user.Current()
	if err != nil {
		return "unknown"
	}
	return u.Username
}

// GetOS returns the operating system name
func GetOS() string {
	return runtime.GOOS
}

// GetArch returns the architecture
func GetArch() string {
	return runtime.GOARCH
}

// GetProcessID returns the current process ID
func GetProcessID() int {
	return os.Getpid()
}

// GetParentProcessID returns the parent process ID
func GetParentProcessID() int {
	return os.Getppid()
}

// IsAdmin checks if running with administrative privileges
func IsAdmin() bool {
	switch runtime.GOOS {
	case "windows":
		return isWindowsAdmin()
	case "linux", "darwin":
		return os.Geteuid() == 0
	default:
		return false
	}
}

func isWindowsAdmin() bool {
	// Windows admin check would use Windows API
	// Simplified for cross-platform compatibility
	return false
}

// GetSystemInfo returns comprehensive system information
func GetSystemInfo() map[string]interface{} {
	return map[string]interface{}{
		"hostname":      GetHostname(),
		"username":      GetUsername(),
		"os":            GetOS(),
		"arch":          GetArch(),
		"process_id":    GetProcessID(),
		"parent_pid":    GetParentProcessID(),
		"is_admin":      IsAdmin(),
		"num_cpu":       runtime.NumCPU(),
		"go_version":    runtime.Version(),
		"num_goroutine": runtime.NumGoroutine(),
	}
}

// GetHomeDir returns the home directory
func GetHomeDir() string {
	u, err := user.Current()
	if err != nil {
		return os.Getenv("HOME")
	}
	return u.HomeDir
}

// GetTempDir returns the temp directory
func GetTempDir() string {
	return os.TempDir()
}

// GetWorkingDir returns the current working directory
func GetWorkingDir() string {
	wd, err := os.Getwd()
	if err != nil {
		return "unknown"
	}
	return wd
}

