package transport

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ditto/ditto/core"
	"github.com/ditto/ditto/tasks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMTLSTransport(t *testing.T) {
	logger := &mockLogger{}
	cfg := core.DefaultConfig()
	
	transport := NewmTLSTransport(cfg, logger)
	
	require.NotNil(t, transport)
	assert.Equal(t, logger, transport.logger)
}

func TestMTLSTransport_Name(t *testing.T) {
	logger := &mockLogger{}
	cfg := core.DefaultConfig()
	
	transport := NewmTLSTransport(cfg, logger)
	
	assert.Equal(t, "mtls", transport.Name())
}

func TestMTLSTransport_Stop_NotStarted(t *testing.T) {
	logger := &mockLogger{}
	cfg := core.DefaultConfig()
	
	transport := NewmTLSTransport(cfg, logger)
	
	err := transport.Stop()
	assert.NoError(t, err)
}

func TestMTLSTransport_Accept_NotStarted(t *testing.T) {
	logger := &mockLogger{}
	cfg := core.DefaultConfig()
	
	transport := NewmTLSTransport(cfg, logger)
	
	_, err := transport.Accept()
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "transport not started")
}

func TestNewServer(t *testing.T) {
	logger := &mockLogger{}
	cfg := core.DefaultConfig()
	
	server := NewServer(cfg, logger)
	
	require.NotNil(t, server)
	assert.Equal(t, cfg, server.config)
	assert.Equal(t, logger, server.logger)
	assert.NotNil(t, server.sessions)
	assert.NotNil(t, server.handler)
	assert.NotNil(t, server.taskQueue)
}

func TestServer_HandleBeacon_NewSession(t *testing.T) {
	logger := &mockLogger{}
	cfg := core.DefaultConfig()
	server := NewServer(cfg, logger)
	
	req := httptest.NewRequest("POST", "/beacon", nil)
	w := httptest.NewRecorder()
	
	server.handleBeacon(w, req)
	
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "session_id")
}

func TestServer_HandleBeacon_ExistingSession(t *testing.T) {
	logger := &mockLogger{}
	cfg := core.DefaultConfig()
	server := NewServer(cfg, logger)
	
	req := httptest.NewRequest("POST", "/beacon", nil)
	req.Header.Set("X-Session-ID", "test-session-123")
	w := httptest.NewRecorder()
	
	server.handleBeacon(w, req)
	
	assert.Equal(t, http.StatusOK, w.Code)
	
	// Call again with same session ID
	req2 := httptest.NewRequest("POST", "/beacon", nil)
	req2.Header.Set("X-Session-ID", "test-session-123")
	w2 := httptest.NewRecorder()
	
	server.handleBeacon(w2, req2)
	
	assert.Equal(t, http.StatusOK, w2.Code)
}

func TestServer_HandleTask(t *testing.T) {
	logger := &mockLogger{}
	cfg := core.DefaultConfig()
	server := NewServer(cfg, logger)
	
	req := httptest.NewRequest("GET", "/task", nil)
	req.Header.Set("X-Session-ID", "test-session")
	w := httptest.NewRecorder()
	
	server.handleTask(w, req)
	
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestServer_HandleTask_NoSessionID(t *testing.T) {
	logger := &mockLogger{}
	cfg := core.DefaultConfig()
	server := NewServer(cfg, logger)
	
	req := httptest.NewRequest("GET", "/task", nil)
	w := httptest.NewRecorder()
	
	server.handleTask(w, req)
	
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Missing session ID")
}

func TestServer_HandleResult(t *testing.T) {
	logger := &mockLogger{}
	cfg := core.DefaultConfig()
	server := NewServer(cfg, logger)
	
	req := httptest.NewRequest("POST", "/result", nil)
	req.Header.Set("X-Session-ID", "test-session")
	w := httptest.NewRecorder()
	
	server.handleResult(w, req)
	
	// Should return 400 for invalid JSON
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestServer_HandleResult_NoSessionID(t *testing.T) {
	logger := &mockLogger{}
	cfg := core.DefaultConfig()
	server := NewServer(cfg, logger)
	
	req := httptest.NewRequest("POST", "/result", nil)
	w := httptest.NewRecorder()
	
	server.handleResult(w, req)
	
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Missing session ID")
}

func TestServer_HandleHealth(t *testing.T) {
	logger := &mockLogger{}
	cfg := core.DefaultConfig()
	server := NewServer(cfg, logger)
	
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	
	server.handleHealth(w, req)
	
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "OK", w.Body.String())
}

func TestServer_GetPendingTasks(t *testing.T) {
	logger := &mockLogger{}
	cfg := core.DefaultConfig()
	server := NewServer(cfg, logger)
	
	// Add a task
	task := &tasks.Task{
		ID:      "test-task",
		Type:    "execute",
		Command: "whoami",
	}
	server.taskQueue.Add(task)
	
	tasks := server.getPendingTasks("test-session")
	
	assert.Len(t, tasks, 1)
	assert.Equal(t, "test-task", tasks[0]["id"])
}

func TestServer_GetPendingTasks_Empty(t *testing.T) {
	logger := &mockLogger{}
	cfg := core.DefaultConfig()
	server := NewServer(cfg, logger)
	
	tasks := server.getPendingTasks("test-session")
	
	assert.Len(t, tasks, 0)
}

func TestGenerateSessionID(t *testing.T) {
	id1 := generateSessionID()
	time.Sleep(1 * time.Millisecond)
	id2 := generateSessionID()
	
	assert.NotEmpty(t, id1)
	assert.NotEmpty(t, id2)
	assert.NotEqual(t, id1, id2)
	assert.Contains(t, id1, "sess-")
}

func TestServer_Sessions_Concurrent(t *testing.T) {
	logger := &mockLogger{}
	cfg := core.DefaultConfig()
	server := NewServer(cfg, logger)
	
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			req := httptest.NewRequest("POST", "/beacon", nil)
			w := httptest.NewRecorder()
			server.handleBeacon(w, req)
			done <- true
		}(i)
	}
	
	for i := 0; i < 10; i++ {
		<-done
	}
	
	// Should not panic
	assert.NotNil(t, server.sessions)
}

