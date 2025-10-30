package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/ditto/ditto/banner"
	"github.com/ditto/ditto/core"
)

// runInteractive starts an interactive CLI client
func runInteractive(logger *core.Logger, cfg *core.Config) {
	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Print("\n[ditto] > ")
		if !scanner.Scan() {
			break
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		command := parts[0]
		args := parts[1:]

		switch command {
		case "help", "h", "?":
			printHelp()
		case "generate", "gen", "g":
			handleGenerate(logger, cfg, args)
		case "server", "srv", "s":
			handleServer(logger, cfg, args)
		case "client", "cli", "c":
			handleClient(logger, cfg, args)
		case "exit", "quit", "q":
			fmt.Println("Exiting Ditto...")
			return
		case "version", "v":
			fmt.Printf("Ditto v%s\nBuild: %s\nCommit: %s\n", version, buildTime, gitCommit)
		case "clear", "cls":
			fmt.Print("\033[H\033[2J")
			banner.PrintDittoBanner()
		default:
			fmt.Printf("Unknown command: %s\nType 'help' for available commands.\n", command)
		}
	}
}

func printHelp() {
	help := `
Available Commands:
  help, h, ?              Show this help message
  generate, gen, g        Generate payload
  server, srv, s          Start C2 server
  client, cli, c         Connect as client
  version, v              Show version information
  clear, cls              Clear screen
  exit, quit, q           Exit Ditto

Examples:
  generate stager windows amd64 output.exe
  server 0.0.0.0:8443
  client https://server.com:8443
`
	fmt.Println(help)
}

func handleGenerate(logger *core.Logger, cfg *core.Config, args []string) {
	if len(args) < 3 {
		fmt.Println("Usage: generate <payload_type> <os> <arch> [output]")
		fmt.Println("  payload_type: stager, shellcode, or full")
		fmt.Println("  os: linux, windows, darwin")
		fmt.Println("  arch: amd64, 386, arm64")
		return
	}

	payloadType := args[0]
	osTarget := args[1]
	arch := args[2]
	output := ""
	if len(args) > 3 {
		output = args[3]
	} else {
		output = fmt.Sprintf("payload_%s_%s_%s.bin", payloadType, osTarget, arch)
	}

	generatePayload(logger, cfg, payloadType, output, arch, osTarget, true, true)
}

func handleServer(logger *core.Logger, cfg *core.Config, args []string) {
	listenAddr := "0.0.0.0:8443"
	if len(args) > 0 {
		listenAddr = args[0]
	}

	fmt.Printf("Starting server on %s...\n", listenAddr)
	fmt.Println("Press Ctrl+C to stop")
	runServer(logger, cfg, listenAddr)
}

func handleClient(logger *core.Logger, cfg *core.Config, args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: client <callback_url>")
		fmt.Println("Example: client https://server.com:8443")
		return
	}

	callbackURL := args[0]
	fmt.Printf("Connecting to %s...\n", callbackURL)
	runClient(logger, cfg, callbackURL)
}

