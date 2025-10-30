package core

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Logger provides structured logging
type Logger struct {
	debug   bool
	logger  *log.Logger
	file    *os.File
	mu      sync.Mutex
	maxSize int64
}

// NewLogger creates a new logger instance
func NewLogger(debug bool) *Logger {
	l := &Logger{
		debug:   debug,
		logger:  log.New(os.Stdout, "", log.LstdFlags),
		maxSize: 10 * 1024 * 1024, // 10MB default
	}
	return l
}

// SetFile sets the log file output
func (l *Logger) SetFile(path string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	
	if l.file != nil {
		l.file.Close()
	}
	
	// Create directory if it doesn't exist
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}
	
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}
	
	l.file = file
	// Use multi-writer to write to both file and stdout
	l.logger.SetOutput(file)
	return nil
}

// Debug logs debug messages
func (l *Logger) Debug(format string, v ...interface{}) {
	if l.debug {
		l.log("DEBUG", format, v...)
	}
}

// Info logs info messages
func (l *Logger) Info(format string, v ...interface{}) {
	l.log("INFO", format, v...)
}

// Warn logs warning messages
func (l *Logger) Warn(format string, v ...interface{}) {
	l.log("WARN", format, v...)
}

// Error logs error messages
func (l *Logger) Error(format string, v ...interface{}) {
	l.log("ERROR", format, v...)
}

func (l *Logger) log(level, format string, v ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	message := fmt.Sprintf(format, v...)
	output := fmt.Sprintf("[%s] [%s] %s", timestamp, level, message)
	
	// Write to file if available
	if l.file != nil {
		l.logger.Print(output)
	}
	// Always write to stdout as well (for interactive debugging)
	fmt.Println(output)
}

// Close closes the logger
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

