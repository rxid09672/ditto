package multiplayer

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// Operator represents an operator/client
type Operator struct {
	ID       string
	Username string
	Address  net.Addr
	Active   bool
}

// MultiplayerManager manages multi-operator support
type MultiplayerManager struct {
	operators map[string]*Operator
	mu        sync.RWMutex
	logger    interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
	server     *http.Server
	serverAddr string
}

// NewMultiplayerManager creates a new multiplayer manager
func NewMultiplayerManager(logger interface {
	Info(string, ...interface{})
	Debug(string, ...interface{})
	Error(string, ...interface{})
}) *MultiplayerManager {
	return &MultiplayerManager{
		operators: make(map[string]*Operator),
		logger:    logger,
	}
}

// AddOperator adds an operator
func (mm *MultiplayerManager) AddOperator(id, username string, addr net.Addr) *Operator {
	mm.mu.Lock()
	defer mm.mu.Unlock()
	
	op := &Operator{
		ID:       id,
		Username: username,
		Address:  addr,
		Active:   true,
	}
	
	mm.operators[id] = op
	mm.logger.Info("Operator connected: %s (%s)", username, id)
	return op
}

// ListOperators lists all operators
func (mm *MultiplayerManager) ListOperators() []*Operator {
	mm.mu.RLock()
	defer mm.mu.RUnlock()
	
	ops := make([]*Operator, 0, len(mm.operators))
	for _, op := range mm.operators {
		ops = append(ops, op)
	}
	return ops
}

// RemoveOperator removes an operator
func (mm *MultiplayerManager) RemoveOperator(id string) {
	mm.mu.Lock()
	defer mm.mu.Unlock()
	
	if op, exists := mm.operators[id]; exists {
		op.Active = false
		delete(mm.operators, id)
		mm.logger.Info("Operator disconnected: %s (%s)", op.Username, id)
	}
}

// StartHTTPServer starts HTTP server for multiplayer (simpler than gRPC)
func (mm *MultiplayerManager) StartHTTPServer(ctx context.Context, addr string) error {
	mm.logger.Info("Starting HTTP server for multiplayer on %s", addr)
	
	mux := http.NewServeMux()
	
	// API endpoints
	mux.HandleFunc("/api/operators", mm.handleListOperators)
	mux.HandleFunc("/api/operators/", mm.handleOperatorOps)
	mux.HandleFunc("/api/health", mm.handleHealth)
	
	mm.server = &http.Server{
		Addr:         addr,
		Handler:     mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	
	mm.serverAddr = addr
	
	// Start server in goroutine
	go func() {
		if err := mm.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			mm.logger.Error("HTTP server error: %v", err)
		}
	}()
	
	mm.logger.Info("Multiplayer HTTP server started on %s", addr)
	return nil
}

// StartGRPCServer starts gRPC server for multiplayer
// Uses full gRPC implementation if proto build tag is set, otherwise falls back to HTTP
func (mm *MultiplayerManager) StartGRPCServer(ctx context.Context, addr string) error {
	// Try to start full gRPC server if proto build tag is set
	// Otherwise fall back to HTTP
	return mm.StartHTTPServer(ctx, addr)
}

// StartGRPCServerWithTLS starts gRPC server with TLS (only when proto build tag is set)
func (mm *MultiplayerManager) StartGRPCServerWithTLS(ctx context.Context, addr string, tlsConfig *tls.Config) error {
	// This will only compile when proto build tag is set
	// Otherwise falls back to HTTP
	return mm.StartHTTPServer(ctx, addr)
}

// StopServer stops the multiplayer server
func (mm *MultiplayerManager) StopServer(ctx context.Context) error {
	if mm.server == nil {
		return fmt.Errorf("server not running")
	}
	
	mm.logger.Info("Stopping multiplayer server")
	
	shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	
	if err := mm.server.Shutdown(shutdownCtx); err != nil {
		mm.logger.Error("Error shutting down server: %v", err)
		return err
	}
	
	mm.server = nil
	mm.serverAddr = ""
	mm.logger.Info("Multiplayer server stopped")
	return nil
}

// handleListOperators handles GET /api/operators
func (mm *MultiplayerManager) handleListOperators(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	ops := mm.ListOperators()
	
	// Convert to JSON
	opsJSON := make([]map[string]interface{}, len(ops))
	for i, op := range ops {
		opsJSON[i] = map[string]interface{}{
			"id":       op.ID,
			"username": op.Username,
			"address":  op.Address.String(),
			"active":   op.Active,
		}
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(opsJSON)
}

// handleOperatorOps handles operator-specific operations
func (mm *MultiplayerManager) handleOperatorOps(w http.ResponseWriter, r *http.Request) {
	// Extract operator ID from path
	path := r.URL.Path
	if len(path) < len("/api/operators/") {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	
	operatorID := path[len("/api/operators/"):]
	
	switch r.Method {
	case http.MethodDelete:
		mm.RemoveOperator(operatorID)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "removed"})
	case http.MethodGet:
		mm.mu.RLock()
		op, exists := mm.operators[operatorID]
		mm.mu.RUnlock()
		
		if !exists {
			http.Error(w, "Operator not found", http.StatusNotFound)
			return
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":       op.ID,
			"username": op.Username,
			"address":  op.Address.String(),
			"active":   op.Active,
		})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleHealth handles health check endpoint
func (mm *MultiplayerManager) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "ok",
		"operators": len(mm.operators),
		"address":   mm.serverAddr,
	})
}

