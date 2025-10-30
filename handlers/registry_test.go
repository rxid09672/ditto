package handlers

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ditto/ditto/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHandlerRegistry(t *testing.T) {
	registry := NewHandlerRegistry()
	
	require.NotNil(t, registry)
	assert.NotNil(t, registry.handlers)
	assert.Len(t, registry.handlers, 0)
}

func TestHandlerRegistry_Register(t *testing.T) {
	registry := NewHandlerRegistry()
	logger := &mockLogger{}
	handler := NewBeaconHandler(logger, core.NewSessionManager())
	
	registry.Register(handler)
	
	assert.Len(t, registry.handlers, 1)
}

func TestHandlerRegistry_GetHandler_Exists(t *testing.T) {
	registry := NewHandlerRegistry()
	logger := &mockLogger{}
	handler := NewBeaconHandler(logger, core.NewSessionManager())
	
	registry.Register(handler)
	
	retrieved, ok := registry.GetHandler(MessageTypeBeacon)
	
	assert.True(t, ok)
	assert.Equal(t, handler, retrieved)
}

func TestHandlerRegistry_GetHandler_NotExists(t *testing.T) {
	registry := NewHandlerRegistry()
	
	_, ok := registry.GetHandler(MessageTypeExecute)
	
	assert.False(t, ok)
}

func TestHandlerRegistry_ProcessMessage(t *testing.T) {
	registry := NewHandlerRegistry()
	logger := &mockLogger{}
	sessionManager := core.NewSessionManager()
	session := core.NewSession("test-session", core.SessionTypeBeacon, "http")
	sessionManager.AddSession(session)
	
	handler := NewBeaconHandler(logger, sessionManager)
	registry.Register(handler)
	
	msg := &Message{
		ID:   "msg-1",
		Type: MessageTypeBeacon,
		Data: map[string]interface{}{},
	}
	
	ctx := context.Background()
	response, err := registry.ProcessMessage(ctx, msg, session)
	
	require.NoError(t, err)
	assert.NotNil(t, response)
}

func TestHandlerRegistry_ProcessMessage_NoHandler(t *testing.T) {
	registry := NewHandlerRegistry()
	
	msg := &Message{
		ID:   "msg-1",
		Type: MessageTypeExecute,
		Data: map[string]interface{}{},
	}
	
	session := core.NewSession("test", core.SessionTypeBeacon, "http")
	ctx := context.Background()
	
	_, err := registry.ProcessMessage(ctx, msg, session)
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no handler")
}

func TestDecodeMessage(t *testing.T) {
	original := &Message{
		ID:        "msg-1",
		Type:      MessageTypeBeacon,
		SessionID: "session-1",
		Data:      map[string]interface{}{"test": "value"},
		Timestamp: 1234567890,
	}
	
	data, err := EncodeMessage(original)
	require.NoError(t, err)
	
	decoded, err := DecodeMessage(data)
	
	require.NoError(t, err)
	assert.Equal(t, original.ID, decoded.ID)
	assert.Equal(t, original.Type, decoded.Type)
	assert.Equal(t, original.SessionID, decoded.SessionID)
}

func TestDecodeMessage_InvalidJSON(t *testing.T) {
	invalidData := []byte(`{"invalid": json}`)
	
	_, err := DecodeMessage(invalidData)
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode")
}

func TestEncodeMessage(t *testing.T) {
	msg := &Message{
		ID:        "msg-1",
		Type:      MessageTypeBeacon,
		SessionID: "session-1",
		Data:      map[string]interface{}{"test": "value"},
	}
	
	data, err := EncodeMessage(msg)
	
	require.NoError(t, err)
	assert.NotEmpty(t, data)
	
	var decoded Message
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, msg.ID, decoded.ID)
}

func TestHandlerRegistry_Concurrent(t *testing.T) {
	registry := NewHandlerRegistry()
	logger := &mockLogger{}
	sessionManager := core.NewSessionManager()
	
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			handler := NewBeaconHandler(logger, sessionManager)
			registry.Register(handler)
			registry.GetHandler(MessageTypeBeacon)
			done <- true
		}(i)
	}
	
	for i := 0; i < 10; i++ {
		<-done
	}
	
	// Should not panic
	assert.NotNil(t, registry.handlers)
}

