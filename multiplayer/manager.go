package multiplayer

import (
	"context"
	"fmt"
	"net"
	"sync"
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

// StartGRPCServer starts gRPC server for multiplayer
// Note: Full gRPC implementation requires protobuf definitions and generated code
// This is a placeholder that can be extended when gRPC is needed
func (mm *MultiplayerManager) StartGRPCServer(ctx context.Context, addr string) error {
	mm.logger.Info("Starting gRPC server for multiplayer on %s", addr)
	
	// TODO: Implement gRPC server when protobuf definitions are created
	// Example implementation would be:
	// 1. Create/listen on address
	// 2. Register gRPC services
	// 3. Handle incoming connections
	// 4. Manage operator sessions
	
	return fmt.Errorf("gRPC server requires protobuf definitions - install google.golang.org/grpc and define .proto files")
}

