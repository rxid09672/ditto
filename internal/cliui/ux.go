// Package cliui provides a user-friendly CLI experience with colors, formatting,
// and interactive features. All features respect NO_COLOR, TERM=dumb, and
// environment variables for graceful fallbacks.
//
// Default path: stdlib only. Optional TUI features go behind build tag `tui`.
package cliui

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

var (
	// Colors is the global color helper instance
	C = &Colors{}
	
	// TTY detection cache (per file descriptor)
	ttyCache = make(map[*os.File]bool)
	ttyMu    sync.RWMutex
	
	// terminalWidth caches terminal width detection
	termWidthCache *int
	termWidthMu    sync.Once
	
	// enabled controls whether colors/output enhancements are enabled
	enabled bool
	enabledMu sync.Mutex
	enabledInit bool
)

// Colors provides ANSI color codes with graceful fallbacks
type Colors struct{}

func (c *Colors) Bold(s string) string   { return colorize(s, "\033[1m", "\033[0m") }
func (c *Colors) Dim(s string) string    { return colorize(s, "\033[2m", "\033[0m") }
func (c *Colors) Green(s string) string  { return colorize(s, "\033[32m", "\033[0m") }
func (c *Colors) Yellow(s string) string { return colorize(s, "\033[33m", "\033[0m") }
func (c *Colors) Red(s string) string    { return colorize(s, "\033[31m", "\033[0m") }
func (c *Colors) Blue(s string) string   { return colorize(s, "\033[34m", "\033[0m") }
func (c *Colors) Cyan(s string) string   { return colorize(s, "\033[36m", "\033[0m") }
func (c *Colors) Reset() string          { return "\033[0m" }

// colorize applies ANSI color codes if colors are enabled
func colorize(s, code, reset string) string {
	if !isEnabled() {
		return s
	}
	return code + s + reset
}

// isEnabled checks if colors/enhancements should be enabled
func isEnabled() bool {
	enabledMu.Lock()
	defer enabledMu.Unlock()
	
	if !enabledInit {
		// Check NO_COLOR first (takes precedence)
		if os.Getenv("NO_COLOR") != "" {
			enabled = false
			enabledInit = true
			return enabled
		}
		
		// Check DITTO_PRETTY
		if os.Getenv("DITTO_PRETTY") == "1" {
			enabled = true
			enabledInit = true
			return enabled
		}
		
		// Check TERM=dumb
		if os.Getenv("TERM") == "dumb" {
			enabled = false
			enabledInit = true
			return enabled
		}
		
		// Check if we're on Windows and if ANSI is supported
		if runtime.GOOS == "windows" {
			// On Windows, only enable if TTY and likely supports ANSI
			enabled = DetectTTY(os.Stdout) && windowsSupportsANSI()
		} else {
			// On Unix, enable if TTY
			enabled = DetectTTY(os.Stdout)
		}
		enabledInit = true
	}
	return enabled
}

// windowsSupportsANSI checks if Windows console supports ANSI codes
func windowsSupportsANSI() bool {
	// Check for Windows 10+ ANSI support via environment
	// This is a conservative check; in practice, Windows 10+ supports ANSI
	if term := os.Getenv("TERM"); term != "" && term != "dumb" {
		return true
	}
	// Assume Windows 10+ supports ANSI (we can't reliably detect older versions)
	return true
}

// DetectTTY checks if the given file descriptor is a terminal
func DetectTTY(f *os.File) bool {
	if f == nil {
		return false
	}
	
	// Check cache
	ttyMu.RLock()
	if cached, ok := ttyCache[f]; ok {
		ttyMu.RUnlock()
		return cached
	}
	ttyMu.RUnlock()
	
	// Detect
	fileInfo, err := f.Stat()
	isTTY := err == nil && (fileInfo.Mode()&os.ModeCharDevice) != 0
	
	// Cache result
	ttyMu.Lock()
	ttyCache[f] = isTTY
	ttyMu.Unlock()
	
	return isTTY
}

// TermWidth returns the terminal width, defaulting to 80 if unavailable
func TermWidth() int {
	termWidthMu.Do(func() {
		// First check COLUMNS env var
		if cols := os.Getenv("COLUMNS"); cols != "" {
			if w, err := strconv.Atoi(cols); err == nil && w > 0 {
				termWidthCache = intPtr(w)
				return
			}
		}
		
		// Try to detect from terminal
		if DetectTTY(os.Stdout) {
			// On Unix, try to get terminal size
			if width := getTerminalWidth(); width > 0 {
				termWidthCache = intPtr(width)
				return
			}
		}
		
		// Default to 80
		termWidthCache = intPtr(80)
	})
	return *termWidthCache
}

func intPtr(i int) *int {
	return &i
}

// getTerminalWidth attempts to get terminal width (Unix-specific)
func getTerminalWidth() int {
	// Try using ioctl if available (requires syscall, but we'll use a simple approach)
	// For now, we'll use a conservative default and let COLUMNS override
	// In a real implementation, you'd use syscall.TIOCGWINSZ on Unix
	return 0 // Return 0 to fall back to default
}

// Wrap wraps text to the given width, preserving words
func Wrap(s string, width int) string {
	if width <= 0 {
		width = TermWidth()
	}
	
	words := strings.Fields(s)
	if len(words) == 0 {
		return s
	}
	
	var lines []string
	var currentLine strings.Builder
	
	for _, word := range words {
		wordLen := utf8.RuneCountInString(word)
		currentLen := utf8.RuneCountInString(currentLine.String())
		
		if currentLen > 0 && currentLen+1+wordLen > width {
			lines = append(lines, currentLine.String())
			currentLine.Reset()
		}
		
		if currentLine.Len() > 0 {
			currentLine.WriteString(" ")
		}
		currentLine.WriteString(word)
	}
	
	if currentLine.Len() > 0 {
		lines = append(lines, currentLine.String())
	}
	
	return strings.Join(lines, "\n")
}

// Ellipsize truncates a string to maxLen with ellipsis
func Ellipsize(s string, maxLen int) string {
	if maxLen <= 0 {
		return s
	}
	
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	
	if maxLen <= 3 {
		return strings.Repeat(".", maxLen)
	}
	
	return string(runes[:maxLen-3]) + "..."
}

// Banner prints an ASCII banner with app name and version
func Banner(app, version string) {
	if !shouldShowBanner() {
		return
	}
	
	appDisplay := app
	if len([]rune(app)) > 35 {
		appDisplay = Ellipsize(app, 35)
	}
	versionDisplay := fmt.Sprintf("v%s", version)
	if len([]rune(versionDisplay)) > 35 {
		versionDisplay = Ellipsize(versionDisplay, 35)
	}
	
	banner := fmt.Sprintf(`
    ╔════════════════════════════════════════╗
    ║                                        ║
    ║     ██████╗ ██╗████████╗████████╗    ║
    ║     ██╔══██╗██║╚══██╔══╝╚══██╔══╝    ║
    ║     ██║  ██║██║   ██║      ██║       ║
    ║     ██║  ██║██║   ██║      ██║       ║
    ║     ██████╔╝██║   ██║      ██║       ║
    ║     ╚═════╝ ╚═╝   ╚═╝      ╚═╝       ║
    ║                                        ║
    ║     %-35s ║
    ║     %-35s ║
    ║                                        ║
    ║   AUTHORIZED USE ONLY                 ║
    ╚════════════════════════════════════════╝
`, 
		appDisplay,
		versionDisplay)
	
	fmt.Print(banner)
}

// shouldShowBanner checks if banner should be displayed
func shouldShowBanner() bool {
	if os.Getenv("DITTO_NO_BANNER") != "" {
		return false
	}
	// Only show in interactive mode (TTY)
	return DetectTTY(os.Stdout)
}

// H1 prints a level 1 heading
func H1(s string) {
	fmt.Println()
	fmt.Println(C.Bold(C.Cyan(s)))
	fmt.Println(strings.Repeat("─", utf8.RuneCountInString(s)))
}

// H2 prints a level 2 heading
func H2(s string) {
	fmt.Println()
	fmt.Println(C.Bold(s))
}

// Bullets prints a bulleted list
func Bullets(items []string) {
	for _, item := range items {
		fmt.Printf("  • %s\n", item)
	}
}

// KV prints a key-value grid
func KV(pairs map[string]string) {
	maxKeyLen := 0
	for k := range pairs {
		if len := utf8.RuneCountInString(k); len > maxKeyLen {
			maxKeyLen = len
		}
	}
	
	for k, v := range pairs {
		fmt.Printf("  %-*s  %s\n", maxKeyLen, C.Dim(k+":"), v)
	}
}

// Spinner provides a simple spinner for progress indication
type Spinner struct {
	label    string
	frames   []string
	current  int
	mu       sync.Mutex
	ctx      context.Context
	cancel   context.CancelFunc
	done     chan struct{}
	active   bool
}

// NewSpinner creates a new spinner
func NewSpinner(label string) *Spinner {
	frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	ctx, cancel := context.WithCancel(context.Background())
	return &Spinner{
		label:  label,
		frames: frames,
		ctx:    ctx,
		cancel: cancel,
		done:   make(chan struct{}),
	}
}

// Start starts the spinner (only if TTY)
func (s *Spinner) Start(ctx context.Context) *Spinner {
	if !DetectTTY(os.Stdout) {
		// Non-TTY: just print the label
		fmt.Printf("%s...\n", s.label)
		return s
	}
	
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if s.active {
		return s
	}
	
	s.active = true
	s.ctx = ctx
	
	// Merge contexts
	mergedCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	
	go func() {
		defer close(s.done)
		ticker := time.NewTicker(100 * time.Millisecond) // ~10Hz
		defer ticker.Stop()
		
		for {
			select {
			case <-mergedCtx.Done():
				return
			case <-ticker.C:
				s.mu.Lock()
				active := s.active
				current := s.current
				s.mu.Unlock()
				
				if !active {
					return
				}
				
				fmt.Printf("\r%s %s", s.frames[current], s.label)
				os.Stdout.Sync()
				
				s.mu.Lock()
				s.current = (s.current + 1) % len(s.frames)
				s.mu.Unlock()
			}
		}
	}()
	
	return s
}

// Stop stops the spinner and prints final status
func (s *Spinner) Stop(ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if !s.active {
		return
	}
	
	s.active = false
	if s.cancel != nil {
		s.cancel()
	}
	
	// Wait for goroutine to finish
	select {
	case <-s.done:
	case <-time.After(200 * time.Millisecond):
	}
	
	if DetectTTY(os.Stdout) {
		// Clear line and print result
		if ok {
			fmt.Printf("\r%s %s %s\n", C.Green("✓"), s.label, C.Dim("done"))
		} else {
			fmt.Printf("\r%s %s %s\n", C.Red("✗"), s.label, C.Dim("failed"))
		}
	} else {
		// Non-TTY: status already printed in Start
		if ok {
			fmt.Printf("%s %s\n", C.Green("✓"), C.Dim("done"))
		} else {
			fmt.Printf("%s %s\n", C.Red("✗"), C.Dim("failed"))
		}
	}
}

// Choose presents a numbered menu and returns the selected option
func Choose(ctx context.Context, prompt string, options []string, defaultIdx int) (idx int, chosen string, err error) {
	if len(options) == 0 {
		return -1, "", fmt.Errorf("no options provided")
	}
	
	if defaultIdx < 0 || defaultIdx >= len(options) {
		defaultIdx = 0
	}
	
	// If not a TTY, return default immediately
	if !DetectTTY(os.Stdin) {
		fmt.Printf("%s (non-interactive, using default: %d)\n", prompt, defaultIdx+1)
		return defaultIdx, options[defaultIdx], nil
	}
	
	// Print menu
	fmt.Println(prompt)
	for i, opt := range options {
		marker := " "
		if i == defaultIdx {
			marker = C.Cyan("→")
		}
		fmt.Printf("  %s [%d] %s\n", marker, i+1, opt)
	}
	fmt.Printf("\nEnter choice [%d-%d] (default: %d): ", 1, len(options), defaultIdx+1)
	
	// Read input with timeout
	resultCh := make(chan chooseResult, 1)
	
	go func() {
		defer func() {
			// Recover from any panic in stdin reading
			if r := recover(); r != nil {
				resultCh <- chooseResult{idx: defaultIdx, err: fmt.Errorf("panic: %v", r)}
			}
		}()
		
		reader := bufio.NewReader(os.Stdin)
		line, err := reader.ReadString('\n')
		if err != nil {
			resultCh <- chooseResult{idx: defaultIdx, err: err}
			return
		}
		
		line = strings.TrimSpace(line)
		if line == "" {
			resultCh <- chooseResult{idx: defaultIdx, chosen: options[defaultIdx]}
			return
		}
		
		choice, err := strconv.Atoi(line)
		if err != nil || choice < 1 || choice > len(options) {
			resultCh <- chooseResult{idx: defaultIdx, chosen: options[defaultIdx]}
			return
		}
		
		resultCh <- chooseResult{idx: choice - 1, chosen: options[choice-1]}
	}()
	
	select {
	case <-ctx.Done():
		// Context cancelled - return default
		return defaultIdx, options[defaultIdx], ctx.Err()
	case result := <-resultCh:
		if result.err != nil {
			return defaultIdx, options[defaultIdx], result.err
		}
		return result.idx, result.chosen, nil
	}
}

type chooseResult struct {
	idx    int
	chosen string
	err    error
}

// UserError represents a user-facing error with a helpful hint
type UserError struct {
	Cause    string
	NextHint string
}

func (e *UserError) Error() string {
	if e.NextHint != "" {
		return fmt.Sprintf("%s\n  → %s", e.Cause, e.NextHint)
	}
	return e.Cause
}

// NewUserError creates a new user error
func NewUserError(cause, nextHint string) error {
	return &UserError{Cause: cause, NextHint: nextHint}
}

// PrintError prints an error in a user-friendly format
func PrintError(err error) {
	if err == nil {
		return
	}
	
	fmt.Fprintf(os.Stderr, "%s %s\n", C.Red("✗"), err.Error())
}

// PrintJSONSyntax prints JSON/YAML with light syntax highlighting
func PrintJSONSyntax(data string) {
	// Simple key highlighting using regex
	keyPattern := regexp.MustCompile(`"([^"]+)":\s*`)
	lines := strings.Split(data, "\n")
	
	for _, line := range lines {
		// Highlight keys
		highlighted := keyPattern.ReplaceAllStringFunc(line, func(match string) string {
			key := strings.TrimSuffix(strings.TrimPrefix(match, `"`), `":`)
			return C.Dim(`"` + key + `":`) + " "
		})
		fmt.Println(highlighted)
	}
}

// EnableColors forces colors to be enabled (for --pretty flag)
func EnableColors() {
	enabledMu.Lock()
	defer enabledMu.Unlock()
	enabled = true
	enabledInit = true
}

// DisableColors forces colors to be disabled
func DisableColors() {
	enabledMu.Lock()
	defer enabledMu.Unlock()
	enabled = false
	enabledInit = true
}

