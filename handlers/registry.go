package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	
	"github.com/ditto/ditto/core"
)

// MessageType represents the type of message
type MessageType string

const (
	MessageTypeBeacon      MessageType = "beacon"
	MessageTypeTask        MessageType = "task"
	MessageTypeResult      MessageType = "result"
	MessageTypeUpgrade     MessageType = "upgrade"
	MessageTypeHeartbeat   MessageType = "heartbeat"
	MessageTypeDownload    MessageType = "download"
	MessageTypeUpload      MessageType = "upload"
	MessageTypeExecute     MessageType = "execute"
	MessageTypeShell       MessageType = "shell"
	MessageTypeScreenshot  MessageType = "screenshot"
	MessageTypeProcessList MessageType = "process_list"
	MessageTypePrivEsc     MessageType = "priv_esc"
)

// Message represents a C2 message
type Message struct {
	Type      MessageType              `json:"type"`
	ID        string                   `json:"id"`
	SessionID string                   `json:"session_id"`
	Data      map[string]interface{}   `json:"data"`
	Timestamp int64                    `json:"timestamp"`
}

// Handler processes incoming messages
type Handler interface {
	// Handle processes a message and returns a response
	Handle(ctx context.Context, msg *Message, session *core.Session) (*Message, error)
	
	// Type returns the message type this handler processes
	Type() MessageType
}

// HandlerRegistry manages message handlers
type HandlerRegistry struct {
	handlers map[MessageType]Handler
	mu       sync.RWMutex
}

// NewHandlerRegistry creates a new handler registry
func NewHandlerRegistry() *HandlerRegistry {
	return &HandlerRegistry{
		handlers: make(map[MessageType]Handler),
	}
}

// Register registers a handler
func (hr *HandlerRegistry) Register(handler Handler) {
	hr.mu.Lock()
	defer hr.mu.Unlock()
	hr.handlers[handler.Type()] = handler
}

// GetHandler retrieves a handler by message type
func (hr *HandlerRegistry) GetHandler(msgType MessageType) (Handler, bool) {
	hr.mu.RLock()
	defer hr.mu.RUnlock()
	handler, ok := hr.handlers[msgType]
	return handler, ok
}

// ProcessMessage processes a message using the appropriate handler
func (hr *HandlerRegistry) ProcessMessage(ctx context.Context, msg *Message, session *core.Session) (*Message, error) {
	handler, ok := hr.GetHandler(msg.Type)
	if !ok {
		return nil, fmt.Errorf("no handler for message type: %s", msg.Type)
	}
	return handler.Handle(ctx, msg, session)
}

// BaseHandler provides common handler functionality
type BaseHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

// NewBaseHandler creates a new base handler
func NewBaseHandler(logger interface {
	Info(string, ...interface{})
	Debug(string, ...interface{})
	Error(string, ...interface{})
}) *BaseHandler {
	return &BaseHandler{logger: logger}
}

// CreateResponse creates a response message
func CreateResponse(msgType MessageType, sessionID string, data map[string]interface{}) *Message {
	return &Message{
		Type:      msgType,
		SessionID: sessionID,
		Data:      data,
		Timestamp: 0, // Will be set by caller
	}
}

// CreateErrorResponse creates an error response message
func CreateErrorResponse(sessionID string, err error) *Message {
	return &Message{
		Type:      MessageTypeResult,
		SessionID: sessionID,
		Data: map[string]interface{}{
			"error": err.Error(),
			"status": "error",
		},
		Timestamp: 0,
	}
}

// DecodeMessage decodes a message from bytes
func DecodeMessage(data []byte) (*Message, error) {
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("failed to decode message: %w", err)
	}
	return &msg, nil
}

// EncodeMessage encodes a message to bytes
func EncodeMessage(msg *Message) ([]byte, error) {
	return json.Marshal(msg)
}

