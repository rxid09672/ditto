package main

import (
	"github.com/ditto/ditto/core"
)

// runInteractive starts an interactive server CLI (like Empire/Sliver)
func runInteractive(logger *core.Logger, cfg *core.Config) {
	server := NewInteractiveServer(logger, cfg)
	server.Run()
}

