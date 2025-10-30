package commands

import (
	"context"
	"os/exec"
	"runtime"
	"time"
)

// Executor handles command execution
type Executor struct {
	timeout time.Duration
}

// NewExecutor creates a new command executor
func NewExecutor(timeout time.Duration) *Executor {
	return &Executor{timeout: timeout}
}

// Execute runs a system command
func (e *Executor) Execute(command string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), e.timeout)
	defer cancel()
	
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.CommandContext(ctx, "cmd.exe", "/c", command)
	case "linux", "darwin":
		cmd = exec.CommandContext(ctx, "/bin/sh", "-c", command)
	default:
		cmd = exec.CommandContext(ctx, command)
	}
	
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// ExecuteShell starts an interactive shell
func (e *Executor) ExecuteShell() error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd.exe")
	case "linux", "darwin":
		cmd = exec.Command("/bin/sh")
	default:
		return nil
	}
	
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	
	return cmd.Run()
}

// DownloadFile downloads a file from URL
func (e *Executor) DownloadFile(url, destination string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("powershell", "-Command", 
			"Invoke-WebRequest -Uri", url, "-OutFile", destination)
	case "linux", "darwin":
		cmd = exec.Command("curl", "-o", destination, url)
	default:
		return nil
	}
	
	return cmd.Run()
}

// UploadFile uploads a file to URL
func (e *Executor) UploadFile(source, url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("powershell", "-Command",
			"Invoke-WebRequest -Uri", url, "-Method POST -InFile", source)
	case "linux", "darwin":
		cmd = exec.Command("curl", "-X", "POST", "-F", "file=@"+source, url)
	default:
		return nil
	}
	
	return cmd.Run()
}

