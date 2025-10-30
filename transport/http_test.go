package transport

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ditto/ditto/core"
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

func TestNewHTTPTransport(t *testing.T) {
	logger := &mockLogger{}
	cfg := core.DefaultConfig()
	cfg.Server.TLSEnabled = false
	
	transport := NewHTTPTransport(cfg, logger)
	
	require.NotNil(t, transport)
	assert.Equal(t, cfg, transport.config)
	assert.Equal(t, logger, transport.logger)
}

func TestHTTPTransport_Name_HTTP(t *testing.T) {
	logger := &mockLogger{}
	cfg := core.DefaultConfig()
	cfg.Server.TLSEnabled = false
	
	transport := NewHTTPTransport(cfg, logger)
	
	assert.Equal(t, "http", transport.Name())
}

func TestHTTPTransport_Name_HTTPS(t *testing.T) {
	logger := &mockLogger{}
	cfg := core.DefaultConfig()
	cfg.Server.TLSEnabled = true
	
	transport := NewHTTPTransport(cfg, logger)
	
	assert.Equal(t, "https", transport.Name())
}

func TestHTTPTransport_Start_HTTP(t *testing.T) {
	logger := &mockLogger{}
	cfg := core.DefaultConfig()
	cfg.Server.TLSEnabled = false
	
	transport := NewHTTPTransport(cfg, logger)
	
	ctx := context.Background()
	tConfig := &TransportConfig{
		BindAddr: "127.0.0.1:0", // Use port 0 for automatic port allocation
	}
	
	err := transport.Start(ctx, tConfig)
	
	require.NoError(t, err)
	assert.NotNil(t, transport.server)
	assert.NotNil(t, transport.listener)
	
	// Cleanup
	transport.Stop()
}

func TestHTTPTransport_Stop(t *testing.T) {
	logger := &mockLogger{}
	cfg := core.DefaultConfig()
	cfg.Server.TLSEnabled = false
	
	transport := NewHTTPTransport(cfg, logger)
	
	ctx := context.Background()
	tConfig := &TransportConfig{
		BindAddr: "127.0.0.1:0",
	}
	
	err := transport.Start(ctx, tConfig)
	require.NoError(t, err)
	
	err = transport.Stop()
	assert.NoError(t, err)
}

func TestHTTPTransport_Stop_NotStarted(t *testing.T) {
	logger := &mockLogger{}
	cfg := core.DefaultConfig()
	
	transport := NewHTTPTransport(cfg, logger)
	
	err := transport.Stop()
	assert.NoError(t, err)
}

func TestHTTPTransport_Accept(t *testing.T) {
	logger := &mockLogger{}
	cfg := core.DefaultConfig()
	
	transport := NewHTTPTransport(cfg, logger)
	
	_, err := transport.Accept()
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not support Accept()")
}

func TestHTTPTransport_Connect(t *testing.T) {
	logger := &mockLogger{}
	cfg := core.DefaultConfig()
	
	transport := NewHTTPTransport(cfg, logger)
	
	_, err := transport.Connect(context.Background(), "127.0.0.1:8080")
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not implemented")
}

func TestHTTPTransport_HandleBeacon(t *testing.T) {
	logger := &mockLogger{}
	cfg := core.DefaultConfig()
	
	transport := NewHTTPTransport(cfg, logger)
	
	req := httptest.NewRequest("POST", "/beacon", nil)
	w := httptest.NewRecorder()
	
	transport.handleBeacon(w, req)
	
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "OK", w.Body.String())
}

func TestHTTPTransport_HandleTask(t *testing.T) {
	logger := &mockLogger{}
	cfg := core.DefaultConfig()
	
	transport := NewHTTPTransport(cfg, logger)
	
	req := httptest.NewRequest("POST", "/task", nil)
	w := httptest.NewRecorder()
	
	transport.handleTask(w, req)
	
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "OK", w.Body.String())
}

func TestHTTPTransport_HandleResult(t *testing.T) {
	logger := &mockLogger{}
	cfg := core.DefaultConfig()
	
	transport := NewHTTPTransport(cfg, logger)
	
	req := httptest.NewRequest("POST", "/result", nil)
	w := httptest.NewRecorder()
	
	transport.handleResult(w, req)
	
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "OK", w.Body.String())
}

func TestHTTPTransport_HandleUpgrade(t *testing.T) {
	logger := &mockLogger{}
	cfg := core.DefaultConfig()
	
	transport := NewHTTPTransport(cfg, logger)
	
	req := httptest.NewRequest("POST", "/upgrade", nil)
	w := httptest.NewRecorder()
	
	transport.handleUpgrade(w, req)
	
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "OK", w.Body.String())
}

func TestNewHTTPConnection(t *testing.T) {
	req := httptest.NewRequest("POST", "/test", nil)
	w := httptest.NewRecorder()
	
	conn := NewHTTPConnection(req, w)
	
	require.NotNil(t, conn)
	assert.Equal(t, req, conn.req)
	assert.Equal(t, w, conn.resp)
	assert.NotNil(t, conn.done)
}

func TestHTTPConnection_Read(t *testing.T) {
	req := httptest.NewRequest("POST", "/test", nil)
	w := httptest.NewRecorder()
	
	conn := NewHTTPConnection(req, w)
	
	// Reading from empty body should return EOF
	buf := make([]byte, 10)
	n, err := conn.Read(buf)
	
	assert.Equal(t, 0, n)
	assert.Error(t, err)
}

func TestHTTPConnection_Write(t *testing.T) {
	req := httptest.NewRequest("POST", "/test", nil)
	w := httptest.NewRecorder()
	
	conn := NewHTTPConnection(req, w)
	
	data := []byte("test data")
	n, err := conn.Write(data)
	
	assert.NoError(t, err)
	assert.Equal(t, len(data), n)
	assert.Equal(t, data, w.Body.Bytes())
}

func TestHTTPConnection_Close(t *testing.T) {
	req := httptest.NewRequest("POST", "/test", nil)
	w := httptest.NewRecorder()
	
	conn := NewHTTPConnection(req, w)
	
	err := conn.Close()
	
	assert.NoError(t, err)
	
	// Verify done channel is closed
	select {
	case <-conn.done:
		// Expected
	default:
		t.Error("done channel should be closed")
	}
}

func TestHTTPConnection_RemoteAddr(t *testing.T) {
	req := httptest.NewRequest("POST", "/test", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	w := httptest.NewRecorder()
	
	conn := NewHTTPConnection(req, w)
	
	addr := conn.RemoteAddr()
	
	assert.NotNil(t, addr)
	assert.Equal(t, "127.0.0.1", addr.(*net.TCPAddr).IP.String())
	assert.Equal(t, 54321, addr.(*net.TCPAddr).Port)
}

func TestHTTPConnection_RemoteAddr_Invalid(t *testing.T) {
	req := httptest.NewRequest("POST", "/test", nil)
	req.RemoteAddr = "invalid"
	w := httptest.NewRecorder()
	
	conn := NewHTTPConnection(req, w)
	
	addr := conn.RemoteAddr()
	
	// Should return default address on error
	assert.NotNil(t, addr)
}

func TestHTTPConnection_LocalAddr(t *testing.T) {
	req := httptest.NewRequest("POST", "/test", nil)
	w := httptest.NewRecorder()
	
	conn := NewHTTPConnection(req, w)
	
	addr := conn.LocalAddr()
	
	assert.Nil(t, addr)
}

func TestHTTPConnection_SetDeadline(t *testing.T) {
	req := httptest.NewRequest("POST", "/test", nil)
	w := httptest.NewRecorder()
	
	conn := NewHTTPConnection(req, w)
	
	err := conn.SetDeadline(time.Now().Add(time.Second))
	
	assert.NoError(t, err)
}

func TestHTTPConnection_SetReadDeadline(t *testing.T) {
	req := httptest.NewRequest("POST", "/test", nil)
	w := httptest.NewRecorder()
	
	conn := NewHTTPConnection(req, w)
	
	err := conn.SetReadDeadline(time.Now().Add(time.Second))
	
	assert.NoError(t, err)
}

func TestHTTPConnection_SetWriteDeadline(t *testing.T) {
	req := httptest.NewRequest("POST", "/test", nil)
	w := httptest.NewRecorder()
	
	conn := NewHTTPConnection(req, w)
	
	err := conn.SetWriteDeadline(time.Now().Add(time.Second))
	
	assert.NoError(t, err)
}

