package main

import (
	"os"
	"path/filepath"

	"github.com/ditto/ditto/core"
)

// runInteractive starts an interactive server CLI (like Empire/Sliver)
func runInteractive(logger *core.Logger, cfg *core.Config) {
	// Set up server-side logging to ~/.ditto/ditto_logs.log (like Empire/Sliver)
	homeDir, err := os.UserHomeDir()
	if err != nil {
		// Fallback to current directory if home directory can't be determined
		homeDir = "."
		logger.Warn("Failed to get user home directory, using current directory for logs: %v", err)
	}
	
	logPath := filepath.Join(homeDir, ".ditto", "ditto_logs.log")
	if err := logger.SetFile(logPath); err != nil {
		logger.Warn("Failed to set log file %s: %v (continuing with stdout only)", logPath, err)
	} else {
		logger.Info("Server logging initialized: %s", logPath)
		logger.Info("Starting Ditto Interactive Server")
	}
	
	server := NewInteractiveServer(logger, cfg)
	server.Run()
}

