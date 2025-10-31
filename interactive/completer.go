package interactive

import (
	"strings"
)

// ANSI color codes (similar to Sliver's implementation)
const (
	Reset      = "\x1b[0m"
	Bold       = "\x1b[1m"
	GreenFG    = "\x1b[32m"
	YellowFG   = "\x1b[33m"
	RedFG      = "\x1b[31m"
	BlueFG     = "\x1b[34m"
	CyanFG     = "\x1b[36m"
	ResetFG    = "\x1b[39m"
	BoldReset  = "\x1b[22m"
)

// CommandInfo stores information about a command
type CommandInfo struct {
	Name        string
	Aliases     []string
	Description string
	Valid       bool
}

// Completer handles command completion and validation
type Completer struct {
	commands      map[string]*CommandInfo
	moduleRegistry interface {
		ListAllModules() []interface{ GetID() string }
	} // ModuleRegistry interface for module completion
}

// NewCompleter creates a new command completer
func NewCompleter() *Completer {
	commands := map[string]*CommandInfo{
		"help":           {Name: "help", Aliases: []string{"h", "?"}, Description: "Show help information", Valid: true},
		"server":         {Name: "server", Aliases: []string{"srv", "s"}, Description: "Start/stop C2 server", Valid: true},
		"stop-server":    {Name: "stop-server", Aliases: []string{"stop"}, Description: "Stop the running server", Valid: true},
		"jobs":           {Name: "jobs", Aliases: []string{"j"}, Description: "List all active jobs/listeners", Valid: true},
		"kill":           {Name: "kill", Aliases: []string{"k"}, Description: "Stop a job by ID", Valid: true},
		"generate":       {Name: "generate", Aliases: []string{"gen", "g"}, Description: "Generate implant", Valid: true},
		"sessions":       {Name: "sessions", Aliases: []string{"sess"}, Description: "List all active sessions", Valid: true},
		"use":            {Name: "use", Aliases: []string{"u"}, Description: "Use/interact with a session", Valid: true},
		"listen":         {Name: "listen", Aliases: []string{"l"}, Description: "Start a listener", Valid: true},
		"port-forward":   {Name: "port-forward", Aliases: []string{"pf"}, Description: "Create port forward", Valid: true},
		"socks5":         {Name: "socks5", Aliases: nil, Description: "Start SOCKS5 proxy", Valid: true},
		"loot":           {Name: "loot", Aliases: nil, Description: "Manage loot items", Valid: true},
		"persist":        {Name: "persist", Aliases: nil, Description: "Install persistence", Valid: true},
		"implants":       {Name: "implants", Aliases: nil, Description: "List saved implants", Valid: true},
		"implant":        {Name: "implant", Aliases: []string{"get-implant"}, Description: "Get implant details", Valid: true},
		"version":        {Name: "version", Aliases: []string{"v"}, Description: "Show version", Valid: true},
		"clear":          {Name: "clear", Aliases: []string{"cls"}, Description: "Clear screen", Valid: true},
		"exit":           {Name: "exit", Aliases: []string{"quit", "q"}, Description: "Exit Ditto", Valid: true},
		"modules":        {Name: "modules", Aliases: nil, Description: "List available modules", Valid: true},
		"sync-sessions":  {Name: "sync-sessions", Aliases: nil, Description: "Sync sessions from server", Valid: true},
	}
	
	return &Completer{
		commands: commands,
	}
}

// IsValidCommand checks if a command is valid
func (c *Completer) IsValidCommand(cmd string) bool {
	cmd = strings.ToLower(strings.TrimSpace(cmd))
	
	// Check direct match
	if _, ok := c.commands[cmd]; ok {
		return true
	}
	
	// Check aliases
	for _, info := range c.commands {
		for _, alias := range info.Aliases {
			if alias == cmd {
				return true
			}
		}
	}
	
	return false
}

// GetCommandInfo returns information about a command
func (c *Completer) GetCommandInfo(cmd string) *CommandInfo {
	cmd = strings.ToLower(strings.TrimSpace(cmd))
	
	// Check direct match
	if info, ok := c.commands[cmd]; ok {
		return info
	}
	
	// Check aliases
	for _, info := range c.commands {
		for _, alias := range info.Aliases {
			if alias == cmd {
				return info
			}
		}
	}
	
	return nil
}

// Complete performs tab completion
func (c *Completer) Complete(line string) []string {
	line = strings.TrimSpace(line)
	parts := strings.Fields(line)
	
	if len(parts) == 0 {
		// No input - return all commands
		completions := make([]string, 0, len(c.commands))
		for name := range c.commands {
			completions = append(completions, name+" ")
		}
		return completions
	}
	
	// If we're completing the first word (command)
	if len(parts) == 1 {
		prefix := strings.ToLower(parts[0])
		completions := make([]string, 0)
		seen := make(map[string]bool)
		
		// Check commands and aliases
		for name, info := range c.commands {
			if strings.HasPrefix(name, prefix) {
				if !seen[name] {
					completions = append(completions, name+" ")
					seen[name] = true
				}
			}
			for _, alias := range info.Aliases {
				if strings.HasPrefix(alias, prefix) && !seen[name] {
					completions = append(completions, name+" ")
					seen[name] = true
				}
			}
		}
		
		return completions
	}
	
	// Handle module command completion
	if len(parts) >= 1 && (parts[0] == "module" || parts[0] == "run") {
		if len(parts) == 2 {
			// Completing module ID
			prefix := parts[1]
			completions := make([]string, 0)
			
			if c.moduleRegistry != nil {
				allModules := c.moduleRegistry.ListAllModules()
				for _, mod := range allModules {
					moduleID := mod.GetID()
					if strings.HasPrefix(moduleID, prefix) {
						completions = append(completions, moduleID+" ")
					}
				}
			}
			
			return completions
		}
	}
	
	// Handle generate command completion
	if len(parts) >= 1 && (parts[0] == "generate" || parts[0] == "gen" || parts[0] == "g") {
		// Position-based completion
		if len(parts) == 2 {
			// Completing payload type
			prefix := strings.ToLower(parts[1])
			types := []string{"stager", "shellcode", "full"}
			completions := make([]string, 0)
			for _, t := range types {
				if strings.HasPrefix(t, prefix) {
					completions = append(completions, t+" ")
				}
			}
			return completions
		} else if len(parts) == 3 {
			// Completing OS
			prefix := strings.ToLower(parts[2])
			oses := []string{"linux", "windows", "darwin"}
			completions := make([]string, 0)
			for _, os := range oses {
				if strings.HasPrefix(os, prefix) {
					completions = append(completions, os+" ")
				}
			}
			return completions
		} else if len(parts) == 4 {
			// Completing architecture
			prefix := strings.ToLower(parts[3])
			arches := []string{"amd64", "386", "arm64"}
			completions := make([]string, 0)
			for _, arch := range arches {
				if strings.HasPrefix(arch, prefix) {
					completions = append(completions, arch+" ")
				}
			}
			return completions
		} else if len(parts) >= 5 {
			// Completing flags
			lastPart := parts[len(parts)-1]
			flags := []string{
				"--output", "-o",
				"--callback", "-c",
				"--delay", "-d",
				"--jitter", "-j",
				"--user-agent", "-u",
				"--protocol", "-p",
				"--no-encrypt",
				"--no-obfuscate",
				"--debug",
				"--modules", "-m",
				"--evasion",
			}
			
			// Check if last part is a flag value (starts with -)
			if strings.HasPrefix(lastPart, "-") {
				// Complete flag name
				completions := make([]string, 0)
				for _, flag := range flags {
					if strings.HasPrefix(flag, lastPart) {
						completions = append(completions, flag+" ")
					}
				}
				return completions
			} else {
				// Check if previous part was a flag that needs a value
				if len(parts) >= 2 {
					prevPart := parts[len(parts)-2]
					if prevPart == "--output" || prevPart == "-o" {
						// File path completion (just suggest common paths)
						return []string{"./", "/tmp/", "~/"}
					} else if prevPart == "--callback" || prevPart == "-c" {
						// URL suggestions
						return []string{"http://", "https://"}
					} else if prevPart == "--protocol" || prevPart == "-p" {
						// Protocol options
						return []string{"http", "https", "mtls"}
					} else if prevPart == "--evasion" {
						// Evasion options
						return []string{"sandbox", "debugger", "vm", "etw", "amsi", "sleepmask", "syscalls"}
					}
				}
				// Otherwise suggest flags
				completions := make([]string, 0)
				for _, flag := range flags {
					completions = append(completions, flag+" ")
				}
				return completions
			}
		}
	}
	
	// For subsequent arguments, return empty (could be enhanced later)
	return []string{}
}

// SetModuleRegistry sets the module registry for autocomplete
func (c *Completer) SetModuleRegistry(registry interface {
	ListAllModules() []interface{ GetID() string }
}) {
	c.moduleRegistry = registry
}

// HighlightCommand highlights a command based on validity (similar to Sliver)
func HighlightCommand(cmd string, isValid bool) string {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return cmd
	}
	
	if isValid {
		// Green for valid commands (like Sliver)
		return Bold + GreenFG + cmd + ResetFG + BoldReset
	} else {
		// Yellow for invalid commands (warning)
		return Bold + YellowFG + cmd + ResetFG + BoldReset
	}
}

// HighlightLine highlights an entire command line
func (c *Completer) HighlightLine(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return line
	}
	
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return line
	}
	
	cmd := parts[0]
	isValid := c.IsValidCommand(cmd)
	
	// Highlight the command
	highlighted := HighlightCommand(cmd, isValid)
	
	// Add the rest of the arguments
	if len(parts) > 1 {
		highlighted += " " + strings.Join(parts[1:], " ")
	}
	
	return highlighted
}

// GetCommandColor returns the color code for a command based on validity
func GetCommandColor(isValid bool) string {
	if isValid {
		return Bold + GreenFG
	}
	return Bold + YellowFG
}

// ResetColors returns the reset code
func ResetColors() string {
	return ResetFG + BoldReset
}

