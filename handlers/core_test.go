package handlers

import (
	"context"
	"testing"
	"time"

	"github.com/ditto/ditto/core"
	"github.com/ditto/ditto/tasks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockLogger struct {
	logs []string
}

func (m *mockLogger) Info(format string, v ...interface{}) {
	m.logs = append(m.logs, "INFO: "+format)
}

func (m *mockLogger) Debug(format string, v ...interface{}) {
	m.logs = append(m.logs, "DEBUG: "+format)
}

func (m *mockLogger) Error(format string, v ...interface{}) {
	m.logs = append(m.logs, "ERROR: "+format)
}

type mockExecutor struct {
	output string
	err    error
}

func (m *mockExecutor) Execute(command string) (string, error) {
	return m.output, m.err
}

func TestNewBeaconHandler(t *testing.T) {
	logger := &mockLogger{}
	sessionManager := core.NewSessionManager()
	
	handler := NewBeaconHandler(logger, sessionManager, tasks.NewQueue(100))
	
	require.NotNil(t, handler)
	assert.NotNil(t, handler.BaseHandler)
	assert.Equal(t, sessionManager, handler.sessionManager)
}

func TestBeaconHandler_Type(t *testing.T) {
	logger := &mockLogger{}
	handler := NewBeaconHandler(logger, core.NewSessionManager(), tasks.NewQueue(100))
	
	assert.Equal(t, MessageTypeBeacon, handler.Type())
}

func TestBeaconHandler_Handle(t *testing.T) {
	logger := &mockLogger{}
	sessionManager := core.NewSessionManager()
	session := core.NewSession("test-session", core.SessionTypeBeacon, "http")
	sessionManager.AddSession(session)
	
	handler := NewBeaconHandler(logger, sessionManager, tasks.NewQueue(100))
	
	msg := &Message{
		ID:   "msg-1",
		Type: MessageTypeBeacon,
		Data: map[string]interface{}{
			"metadata": map[string]interface{}{
				"os": "windows",
			},
		},
	}
	
	ctx := context.Background()
	response, err := handler.Handle(ctx, msg, session)
	
	require.NoError(t, err)
	assert.NotNil(t, response)
	assert.Equal(t, session.ID, response.Data["session_id"])
}

func TestNewExecuteHandler(t *testing.T) {
	logger := &mockLogger{}
	executor := &mockExecutor{output: "test output"}
	
	handler := NewExecuteHandler(logger, executor)
	
	require.NotNil(t, handler)
	assert.NotNil(t, handler.BaseHandler)
	assert.Equal(t, executor, handler.executor)
}

func TestExecuteHandler_Type(t *testing.T) {
	logger := &mockLogger{}
	handler := NewExecuteHandler(logger, &mockExecutor{})
	
	assert.Equal(t, MessageTypeExecute, handler.Type())
}

func TestExecuteHandler_Handle_Success(t *testing.T) {
	logger := &mockLogger{}
	executor := &mockExecutor{output: "command output"}
	handler := NewExecuteHandler(logger, executor)
	
	session := core.NewSession("test-session", core.SessionTypeInteractive, "http")
	msg := &Message{
		ID:   "msg-1",
		Type: MessageTypeExecute,
		Data: map[string]interface{}{
			"command": "whoami",
		},
	}
	
	ctx := context.Background()
	response, err := handler.Handle(ctx, msg, session)
	
	require.NoError(t, err)
	assert.NotNil(t, response)
	assert.Equal(t, "success", response.Data["status"])
}

func TestExecuteHandler_Handle_MissingCommand(t *testing.T) {
	logger := &mockLogger{}
	handler := NewExecuteHandler(logger, &mockExecutor{})
	
	session := core.NewSession("test-session", core.SessionTypeInteractive, "http")
	msg := &Message{
		ID:   "msg-1",
		Type: MessageTypeExecute,
		Data: map[string]interface{}{},
	}
	
	ctx := context.Background()
	response, err := handler.Handle(ctx, msg, session)
	
	require.NoError(t, err)
	assert.NotNil(t, response)
	assert.Contains(t, response.Data, "error")
}

func TestExecuteHandler_Handle_ExecutionError(t *testing.T) {
	logger := &mockLogger{}
	executor := &mockExecutor{err: assert.AnError}
	handler := NewExecuteHandler(logger, executor)
	
	session := core.NewSession("test-session", core.SessionTypeInteractive, "http")
	msg := &Message{
		ID:   "msg-1",
		Type: MessageTypeExecute,
		Data: map[string]interface{}{
			"command": "invalid",
		},
	}
	
	ctx := context.Background()
	response, err := handler.Handle(ctx, msg, session)
	
	require.NoError(t, err)
	assert.NotNil(t, response)
	assert.Contains(t, response.Data, "error")
}

func TestNewBaseHandler(t *testing.T) {
	logger := &mockLogger{}
	
	handler := NewBaseHandler(logger)
	
	require.NotNil(t, handler)
	assert.Equal(t, logger, handler.logger)
}

func TestCreateResponse(t *testing.T) {
	response := CreateResponse(MessageTypeBeacon, "session-1", map[string]interface{}{
		"test": "value",
	})
	
	assert.NotNil(t, response)
	assert.Equal(t, MessageTypeBeacon, response.Type)
	assert.Equal(t, "session-1", response.SessionID)
	assert.Equal(t, "value", response.Data["test"])
}

func TestCreateErrorResponse(t *testing.T) {
	err := assert.AnError
	response := CreateErrorResponse("session-1", err)
	
	assert.NotNil(t, response)
	assert.Contains(t, response.Data, "error")
}

func TestMessageType_String(t *testing.T) {
	assert.Equal(t, "beacon", string(MessageTypeBeacon))
	assert.Equal(t, "execute", string(MessageTypeExecute))
	assert.Equal(t, "result", string(MessageTypeResult))
}

func TestBeaconHandler_Handle_UpdatesLastSeen(t *testing.T) {
	logger := &mockLogger{}
	sessionManager := core.NewSessionManager()
	session := core.NewSession("test-session", core.SessionTypeBeacon, "http")
	sessionManager.AddSession(session)
	
	handler := NewBeaconHandler(logger, sessionManager, tasks.NewQueue(100))
	
	before := session.LastSeen
	time.Sleep(10 * time.Millisecond)
	
	msg := &Message{
		ID:   "msg-1",
		Type: MessageTypeBeacon,
		Data: map[string]interface{}{},
	}
	
	ctx := context.Background()
	handler.Handle(ctx, msg, session)
	
	assert.True(t, session.LastSeen.After(before))
}

func TestBeaconHandler_Handle_ExtractsMetadata(t *testing.T) {
	logger := &mockLogger{}
	sessionManager := core.NewSessionManager()
	session := core.NewSession("test-session", core.SessionTypeBeacon, "http")
	sessionManager.AddSession(session)
	
	handler := NewBeaconHandler(logger, sessionManager, tasks.NewQueue(100))
	
	msg := &Message{
		ID:   "msg-1",
		Type: MessageTypeBeacon,
		Data: map[string]interface{}{
			"metadata": map[string]interface{}{
				"os":   "windows",
				"arch": "amd64",
			},
		},
	}
	
	ctx := context.Background()
	handler.Handle(ctx, msg, session)
	
	os, ok := session.GetMetadata("os")
	assert.True(t, ok)
	assert.Equal(t, "windows", os)
	
	arch, ok := session.GetMetadata("arch")
	assert.True(t, ok)
	assert.Equal(t, "amd64", arch)
}

