package interactive

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/chzyer/readline"
)

// ReadlineInput wraps readline for enhanced input with completion and highlighting
type ReadlineInput struct {
	rl       *readline.Instance
	completer *Completer
	prompt   string
}

// getHistoryPath returns a path for the history file
func getHistoryPath() string {
	// Try to use user's home directory
	if u, err := user.Current(); err == nil {
		historyDir := filepath.Join(u.HomeDir, ".ditto")
		os.MkdirAll(historyDir, 0755) // Create directory if it doesn't exist
		return filepath.Join(historyDir, "history")
	}
	
	// Fallback to /tmp if we can't get home directory
	return "/tmp/ditto_history"
}

// getSessionHistoryPath returns a path for session-specific history file
func getSessionHistoryPath() string {
	// Try to use user's home directory
	if u, err := user.Current(); err == nil {
		historyDir := filepath.Join(u.HomeDir, ".ditto")
		os.MkdirAll(historyDir, 0755) // Create directory if it doesn't exist
		return filepath.Join(historyDir, "history_sessions")
	}
	
	// Fallback to /tmp if we can't get home directory
	return "/tmp/ditto_history_sessions"
}

// NewReadlineInput creates a new readline input handler
func NewReadlineInput(prompt string) (*ReadlineInput, error) {
	return NewReadlineInputWithCompleter(prompt, NewCompleter())
}

// NewReadlineInputWithCompleter creates a new readline input handler with a specific completer
func NewReadlineInputWithCompleter(prompt string, completer *Completer) (*ReadlineInput, error) {
	return NewReadlineInputWithCompleterAndHistory(prompt, completer, "")
}

// NewReadlineInputWithCompleterAndHistory creates a new readline input handler with a specific completer and history file
// If historyPath is empty, uses the default history path
func NewReadlineInputWithCompleterAndHistory(prompt string, completer *Completer, historyPath string) (*ReadlineInput, error) {
	if completer == nil {
		completer = NewCompleter()
	}
	
	// Build completer items
	items := make([]readline.PrefixCompleterInterface, 0)
	
	// Add all commands to completer
	for name := range completer.commands {
		items = append(items, readline.PcItem(name))
	}
	
	// Also add aliases as separate completions
	for _, info := range completer.commands {
		for _, alias := range info.Aliases {
			items = append(items, readline.PcItem(alias))
		}
	}
	
	// Create prefix completer with all items (variadic args)
	completerFunc := readline.NewPrefixCompleter(items...)
	
	// Use provided history path or default
	if historyPath == "" {
		historyPath = getHistoryPath()
	}
	
	config := &readline.Config{
		Prompt:          prompt,
		HistoryFile:     historyPath,
		AutoComplete:   completerFunc,
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
		HistorySearchFold: true,
	}
	
	rl, err := readline.NewEx(config)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize readline: %w", err)
	}
	
	return &ReadlineInput{
		rl:       rl,
		completer: completer,
		prompt:   prompt,
	}, nil
}

// SetPrompt updates the prompt
func (r *ReadlineInput) SetPrompt(prompt string) {
	r.prompt = prompt
	r.rl.SetPrompt(prompt)
}

// ReadLine reads a line with completion and highlighting
func (r *ReadlineInput) ReadLine() (string, error) {
	line, err := r.rl.Readline()
	if err != nil {
		if err == readline.ErrInterrupt {
			return "", io.EOF
		}
		return "", err
	}
	
	return strings.TrimSpace(line), nil
}

// Close closes the readline instance
func (r *ReadlineInput) Close() error {
	if r.rl != nil {
		return r.rl.Close()
	}
	return nil
}

// FallbackInput is a simple fallback when readline is not available
type FallbackInput struct {
	scanner *bufio.Scanner
	prompt  string
}

// NewFallbackInput creates a simple input handler without readline
func NewFallbackInput(prompt string) *FallbackInput {
	return &FallbackInput{
		scanner: bufio.NewScanner(os.Stdin),
		prompt:  prompt,
	}
}

// ReadLine reads a line using standard input
func (f *FallbackInput) ReadLine() (string, error) {
	fmt.Print(f.prompt)
	if !f.scanner.Scan() {
		return "", io.EOF
	}
	return strings.TrimSpace(f.scanner.Text()), nil
}

// SetPrompt updates the prompt
func (f *FallbackInput) SetPrompt(prompt string) {
	f.prompt = prompt
}

// Close does nothing for fallback input
func (f *FallbackInput) Close() error {
	return nil
}

