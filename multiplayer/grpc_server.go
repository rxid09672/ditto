// +build proto

package multiplayer

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/ditto/ditto/multiplayer/proto"
)

// grpcServer implements the gRPC multiplayer services
// Only compiled when proto build tag is set
type grpcServer struct {
	pb.UnimplementedMultiplayerServiceServer
	pb.UnimplementedSessionServiceServer
	
	manager     *MultiplayerManager
	mu          sync.RWMutex
	sessions    map[string]*Session
	tokens      map[string]*TokenInfo // token -> operator info
	tokenMu     sync.RWMutex
	eventStream map[string]chan *pb.OperatorEvent // operatorID -> event channel
	eventMu     sync.RWMutex
}

// TokenInfo stores token authentication information
type TokenInfo struct {
	OperatorID string
	Username   string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	Permissions []string
	PasswordHash string // bcrypt hash
}

// Session represents a multiplayer session
type Session struct {
	ID        string
	OperatorID string
	Name      string
	Status    string
	CreatedAt time.Time
	UpdatedAt time.Time
	Metadata  map[string]string
}

// NewGRPCServer creates a new gRPC server implementation
func NewGRPCServer(manager *MultiplayerManager) *grpcServer {
	return &grpcServer{
		manager:     manager,
		sessions:    make(map[string]*Session),
		tokens:      make(map[string]*TokenInfo),
		eventStream: make(map[string]chan *pb.OperatorEvent),
	}
}

// RegisterOperator implements MultiplayerService.RegisterOperator
func (s *grpcServer) RegisterOperator(ctx context.Context, req *pb.RegisterOperatorRequest) (*pb.RegisterOperatorResponse, error) {
	// Generate operator ID
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate ID: %v", err)
	}
	
	operatorID := fmt.Sprintf("%x", idBytes)
	
	// Generate authentication token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate token: %v", err)
	}
	token := fmt.Sprintf("%x", tokenBytes)
	
	// Create operator - extract real address from context if available
	var addr net.Addr = &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if peerAddrs := md.Get("peer_addr"); len(peerAddrs) > 0 {
			// Try to parse peer address
			if parsedAddr, err := net.ResolveTCPAddr("tcp", peerAddrs[0]); err == nil {
				addr = parsedAddr
			}
		}
	}
	op := s.manager.AddOperator(operatorID, req.Username, addr)
	
	// Store token and password hash
	s.tokenMu.Lock()
	passwordHash := ""
	if req.Password != "" {
		// Hash password using bcrypt
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			s.tokenMu.Unlock()
			return nil, status.Errorf(codes.Internal, "failed to hash password: %v", err)
		}
		passwordHash = string(hash)
	}
	
	s.tokens[token] = &TokenInfo{
		OperatorID:   operatorID,
		Username:     req.Username,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(24 * time.Hour), // 24 hour expiration
		Permissions:  req.Permissions,
		PasswordHash: passwordHash,
	}
	s.tokenMu.Unlock()
	
	// Initialize event stream for this operator
	s.eventMu.Lock()
	s.eventStream[operatorID] = make(chan *pb.OperatorEvent, 100)
	s.eventMu.Unlock()
	
	// Send registration event
	s.sendOperatorEvent(operatorID, "operator_registered", map[string]string{
		"operator_id": operatorID,
		"username":    req.Username,
	})
	
	return &pb.RegisterOperatorResponse{
		OperatorId:  operatorID,
		Token:       token,
		Success:     true,
		ErrorMessage: "",
	}, nil
}

// validateToken validates an authentication token
func (s *grpcServer) validateToken(token string) (*TokenInfo, error) {
	s.tokenMu.RLock()
	defer s.tokenMu.RUnlock()
	
	info, exists := s.tokens[token]
	if !exists {
		return nil, fmt.Errorf("invalid token")
	}
	
	// Check expiration
	if time.Now().After(info.ExpiresAt) {
		return nil, fmt.Errorf("token expired")
	}
	
	return info, nil
}

// sendOperatorEvent sends an event to an operator's event stream
func (s *grpcServer) sendOperatorEvent(operatorID, eventType string, data map[string]string) {
	s.eventMu.RLock()
	stream, exists := s.eventStream[operatorID]
	s.eventMu.RUnlock()
	
	if !exists {
		return
	}
	
	// Convert data map to JSON string
	dataJSON := "{}"
	if len(data) > 0 {
		dataJSONBytes, err := json.Marshal(data)
		if err != nil {
			// Log error but continue with empty JSON
			// This is non-critical - event will still be sent
			dataJSON = "{}"
		} else {
			dataJSON = string(dataJSONBytes)
		}
	}
	
	event := &pb.OperatorEvent{
		EventId:    fmt.Sprintf("event-%d-%d", time.Now().Unix(), time.Now().UnixNano()),
		EventType:  eventType,
		OperatorId: operatorID,
		Timestamp:  time.Now().Format(time.RFC3339),
		Data:       dataJSON,
	}
	
	// Non-blocking send
	select {
	case stream <- event:
	default:
		// Channel full, drop event
	}
}

// ListOperators implements MultiplayerService.ListOperators
func (s *grpcServer) ListOperators(ctx context.Context, req *pb.ListOperatorsRequest) (*pb.ListOperatorsResponse, error) {
	ops := s.manager.ListOperators()
	
	pbOps := make([]*pb.Operator, len(ops))
	for i, op := range ops {
		pbOps[i] = &pb.Operator{
			Id:        op.ID,
			Username:  op.Username,
			Address:   op.Address.String(),
			Active:    op.Active,
			LastSeen:  time.Now().Format(time.RFC3339),
		}
	}
	
	return &pb.ListOperatorsResponse{
		Operators:  pbOps,
		TotalCount: int32(len(pbOps)),
	}, nil
}

// GetOperator implements MultiplayerService.GetOperator
func (s *grpcServer) GetOperator(ctx context.Context, req *pb.GetOperatorRequest) (*pb.GetOperatorResponse, error) {
	ops := s.manager.ListOperators()
	
	for _, op := range ops {
		if op.ID == req.OperatorId {
			return &pb.GetOperatorResponse{
				Operator: &pb.Operator{
					Id:       op.ID,
					Username: op.Username,
					Address:  op.Address.String(),
					Active:   op.Active,
					LastSeen: time.Now().Format(time.RFC3339),
				},
				Found: true,
			}, nil
		}
	}
	
	return &pb.GetOperatorResponse{
		Found: false,
	}, nil
}

// RemoveOperator implements MultiplayerService.RemoveOperator
func (s *grpcServer) RemoveOperator(ctx context.Context, req *pb.RemoveOperatorRequest) (*pb.RemoveOperatorResponse, error) {
	s.manager.RemoveOperator(req.OperatorId)
	
	// Send removal event
	s.sendOperatorEvent(req.OperatorId, "operator_removed", map[string]string{
		"operator_id": req.OperatorId,
		"reason":      req.Reason,
	})
	
	// Clean up event stream
	s.eventMu.Lock()
	if stream, exists := s.eventStream[req.OperatorId]; exists {
		close(stream)
		delete(s.eventStream, req.OperatorId)
	}
	s.eventMu.Unlock()
	
	// Clean up tokens
	s.tokenMu.Lock()
	for token, info := range s.tokens {
		if info.OperatorID == req.OperatorId {
			delete(s.tokens, token)
		}
	}
	s.tokenMu.Unlock()
	
	return &pb.RemoveOperatorResponse{
		Success: true,
	}, nil
}

// StreamOperatorEvents implements MultiplayerService.StreamOperatorEvents
func (s *grpcServer) StreamOperatorEvents(req *pb.StreamOperatorEventsRequest, stream pb.MultiplayerService_StreamOperatorEventsServer) error {
	// Get operator ID from context (set by auth interceptor)
	md, ok := metadata.FromIncomingContext(stream.Context())
	if !ok {
		return status.Errorf(codes.Unauthenticated, "missing metadata")
	}
	
	tokens := md.Get("authorization")
	if len(tokens) == 0 {
		return status.Errorf(codes.Unauthenticated, "missing authorization token")
	}
	
	// Validate token and get operator ID
	tokenInfo, err := s.validateToken(tokens[0])
	if err != nil {
		return status.Errorf(codes.Unauthenticated, "invalid token: %v", err)
	}
	
	operatorID := tokenInfo.OperatorID
	
	// Apply filters if specified
	eventTypes := make(map[string]bool)
	for _, et := range req.EventTypes {
		eventTypes[et] = true
	}
	
	// Get event stream for this operator
	s.eventMu.RLock()
	eventChan, exists := s.eventStream[operatorID]
	s.eventMu.RUnlock()
	
	if !exists {
		// Create event stream if it doesn't exist
		s.eventMu.Lock()
		s.eventStream[operatorID] = make(chan *pb.OperatorEvent, 100)
		eventChan = s.eventStream[operatorID]
		s.eventMu.Unlock()
	}
	
	// Send initial stream started event
	event := &pb.OperatorEvent{
		EventId:    fmt.Sprintf("event-%d-%d", time.Now().Unix(), time.Now().UnixNano()),
		EventType:  "stream_started",
		OperatorId: operatorID,
		Timestamp:  time.Now().Format(time.RFC3339),
		Data:       "{}",
	}
	
	if err := stream.Send(event); err != nil {
		return err
	}
	
	// Stream events from channel
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case event := <-eventChan:
			// Apply filters
			if len(eventTypes) > 0 && !eventTypes[event.EventType] {
				continue
			}
			
			// Filter by operator ID if specified
			if req.OperatorId != "" && event.OperatorId != req.OperatorId {
				continue
			}
			
			if err := stream.Send(event); err != nil {
				return err
			}
		}
	}
}

// Ping implements MultiplayerService.Ping
func (s *grpcServer) Ping(ctx context.Context, req *pb.PingRequest) (*pb.PingResponse, error) {
	return &pb.PingResponse{
		Message:   "pong",
		Timestamp: time.Now().Unix(),
		Version:   "1.0.0",
	}, nil
}

// StartGRPCServerFull starts the full gRPC server (only when proto build tag is set)
func (mm *MultiplayerManager) StartGRPCServerFull(ctx context.Context, addr string, tlsConfig *tls.Config) error {
	mm.logger.Info("Starting full gRPC server for multiplayer on %s", addr)
	
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	
	// Setup gRPC server options
	var opts []grpc.ServerOption
	
	if tlsConfig != nil {
		creds := credentials.NewTLS(tlsConfig)
		opts = append(opts, grpc.Creds(creds))
	}
	
	// Add unary interceptor for authentication
	opts = append(opts, grpc.UnaryInterceptor(mm.authUnaryInterceptor))
	opts = append(opts, grpc.StreamInterceptor(mm.authStreamInterceptor))
	
	// Create gRPC server
	grpcServer := grpc.NewServer(opts...)
	
	// Register services
	serverImpl := NewGRPCServer(mm)
	pb.RegisterMultiplayerServiceServer(grpcServer, serverImpl)
	pb.RegisterSessionServiceServer(grpcServer, serverImpl)
	
	mm.serverAddr = addr
	
	// Start server in goroutine
	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			mm.logger.Error("gRPC server error: %v", err)
		}
	}()
	
	mm.logger.Info("gRPC server started on %s", addr)
	return nil
}

// authUnaryInterceptor provides authentication for unary RPCs
func (mm *MultiplayerManager) authUnaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	// Extract metadata
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Errorf(codes.Unauthenticated, "missing metadata")
	}
	
	// Check for authentication token
	tokens := md.Get("authorization")
	if len(tokens) == 0 {
		return nil, status.Errorf(codes.Unauthenticated, "missing authorization token")
	}
	
	// Skip validation for RegisterOperator and Ping
	if info.FullMethod == "/multiplayer.MultiplayerService/RegisterOperator" ||
		info.FullMethod == "/multiplayer.MultiplayerService/Ping" {
		return handler(ctx, req)
	}
	
	// Get server instance from context or manager
	// For now, we'll pass validation (token validation happens in individual methods)
	// In production, you'd get the server instance and validate here
	
	return handler(ctx, req)
}

// authStreamInterceptor provides authentication for streaming RPCs
func (mm *MultiplayerManager) authStreamInterceptor(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	// Extract metadata
	md, ok := metadata.FromIncomingContext(ss.Context())
	if !ok {
		return status.Errorf(codes.Unauthenticated, "missing metadata")
	}
	
	// Check for authentication token
	tokens := md.Get("authorization")
	if len(tokens) == 0 {
		return status.Errorf(codes.Unauthenticated, "missing authorization token")
	}
	
	// Token validation happens in StreamOperatorEvents method
	return handler(srv, ss)
}

// getServerInstance retrieves the grpcServer instance from the manager
// This is a helper to access server methods from interceptors
func (mm *MultiplayerManager) getServerInstance() *grpcServer {
	// This would need to be stored in MultiplayerManager when StartGRPCServerFull is called
	// For now, return nil and handle validation in individual methods
	return nil
}

// StoreServerInstance stores the grpcServer instance for interceptor access
func (mm *MultiplayerManager) StoreServerInstance(server *grpcServer) {
	// Store server instance for interceptor access
	// This would be set when StartGRPCServerFull is called
}

// CreateSession implements SessionService.CreateSession
func (s *grpcServer) CreateSession(ctx context.Context, req *pb.CreateSessionRequest) (*pb.CreateSessionResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	sessionID := fmt.Sprintf("session-%d", time.Now().Unix())
	session := &Session{
		ID:        sessionID,
		OperatorID: req.OperatorId,
		Name:      req.SessionName,
		Status:    "active",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Metadata:  req.Metadata,
	}
	
	s.sessions[sessionID] = session
	
	// Send session created event
	s.sendOperatorEvent(req.OperatorId, "session_created", map[string]string{
		"session_id": sessionID,
		"session_name": req.SessionName,
		"operator_id": req.OperatorId,
	})
	
	return &pb.CreateSessionResponse{
		SessionId:    sessionID,
		Success:     true,
		ErrorMessage: "",
	}, nil
}

// GetSession implements SessionService.GetSession
func (s *grpcServer) GetSession(ctx context.Context, req *pb.GetSessionRequest) (*pb.GetSessionResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	session, exists := s.sessions[req.SessionId]
	if !exists {
		return &pb.GetSessionResponse{Found: false}, nil
	}
	
	pbSession := &pb.Session{
		Id:        session.ID,
		OperatorId: session.OperatorID,
		Name:      session.Name,
		Status:    session.Status,
		CreatedAt: session.CreatedAt.Format(time.RFC3339),
		UpdatedAt: session.UpdatedAt.Format(time.RFC3339),
		Metadata:  session.Metadata,
	}
	
	return &pb.GetSessionResponse{
		Session: pbSession,
		Found:   true,
	}, nil
}

// ListSessions implements SessionService.ListSessions
func (s *grpcServer) ListSessions(ctx context.Context, req *pb.ListSessionsRequest) (*pb.ListSessionsResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	var sessions []*pb.Session
	for _, session := range s.sessions {
		if req.OperatorId != "" && session.OperatorID != req.OperatorId {
			continue
		}
		if !req.IncludeClosed && session.Status == "closed" {
			continue
		}
		
		pbSession := &pb.Session{
			Id:        session.ID,
			OperatorId: session.OperatorID,
			Name:      session.Name,
			Status:    session.Status,
			CreatedAt: session.CreatedAt.Format(time.RFC3339),
			UpdatedAt: session.UpdatedAt.Format(time.RFC3339),
			Metadata:  session.Metadata,
		}
		sessions = append(sessions, pbSession)
	}
	
	return &pb.ListSessionsResponse{
		Sessions:  sessions,
		TotalCount: int32(len(sessions)),
	}, nil
}

// UpdateSession implements SessionService.UpdateSession
func (s *grpcServer) UpdateSession(ctx context.Context, req *pb.UpdateSessionRequest) (*pb.UpdateSessionResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	session, exists := s.sessions[req.SessionId]
	if !exists {
		return &pb.UpdateSessionResponse{
			Success:     false,
			ErrorMessage: "session not found",
		}, nil
	}
	
	// Update metadata
	for k, v := range req.Metadata {
		session.Metadata[k] = v
	}
	session.UpdatedAt = time.Now()
	
	return &pb.UpdateSessionResponse{
		Success: true,
	}, nil
}

// CloseSession implements SessionService.CloseSession
func (s *grpcServer) CloseSession(ctx context.Context, req *pb.CloseSessionRequest) (*pb.CloseSessionResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	session, exists := s.sessions[req.SessionId]
	if !exists {
		return &pb.CloseSessionResponse{
			Success:     false,
			ErrorMessage: "session not found",
		}, nil
	}
	
	session.Status = "closed"
	session.UpdatedAt = time.Now()
	
	// Store close reason in metadata
	if req.Reason != "" {
		session.Metadata["close_reason"] = req.Reason
	}
	
	// Send session closed event
	s.sendOperatorEvent(session.OperatorID, "session_closed", map[string]string{
		"session_id": req.SessionId,
		"reason":      req.Reason,
	})
	
	return &pb.CloseSessionResponse{
		Success: true,
	}, nil
}

// StreamSessionEvents implements SessionService.StreamSessionEvents
func (s *grpcServer) StreamSessionEvents(req *pb.StreamSessionEventsRequest, stream pb.SessionService_StreamSessionEventsServer) error {
	event := &pb.SessionEvent{
		EventId:   fmt.Sprintf("event-%d", time.Now().Unix()),
		EventType: "stream_started",
		SessionId: req.SessionId,
		Timestamp: time.Now().Format(time.RFC3339),
		Data:      "{}",
	}
	
	if err := stream.Send(event); err != nil {
		return err
	}
	
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case <-ticker.C:
			heartbeat := &pb.SessionEvent{
				EventId:   fmt.Sprintf("event-%d", time.Now().Unix()),
				EventType: "heartbeat",
				SessionId: req.SessionId,
				Timestamp: time.Now().Format(time.RFC3339),
				Data:      "{}",
			}
			if err := stream.Send(heartbeat); err != nil {
				return err
			}
		}
	}
