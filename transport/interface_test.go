package transport

import (
	"net"
	"testing"
	"time"

	"github.com/ditto/ditto/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTransportRegistry(t *testing.T) {
	registry := NewTransportRegistry()
	
	require.NotNil(t, registry)
	assert.NotNil(t, registry.transports)
	assert.Len(t, registry.transports, 0)
}

func TestTransportRegistry_Register(t *testing.T) {
	registry := NewTransportRegistry()
	logger := &mockLogger{}
	cfg := core.DefaultConfig()
	transport := NewHTTPTransport(cfg, logger)
	
	registry.Register("http", transport)
	
	assert.Len(t, registry.transports, 1)
	retrieved, ok := registry.GetTransport("http")
	assert.True(t, ok)
	assert.Equal(t, transport, retrieved)
}

func TestTransportRegistry_GetTransport_Exists(t *testing.T) {
	registry := NewTransportRegistry()
	logger := &mockLogger{}
	cfg := core.DefaultConfig()
	transport := NewHTTPTransport(cfg, logger)
	
	registry.Register("http", transport)
	
	retrieved, ok := registry.GetTransport("http")
	assert.True(t, ok)
	assert.Equal(t, transport, retrieved)
}

func TestTransportRegistry_GetTransport_NotExists(t *testing.T) {
	registry := NewTransportRegistry()
	
	_, ok := registry.GetTransport("nonexistent")
	assert.False(t, ok)
}

func TestTransportRegistry_ListTransports(t *testing.T) {
	registry := NewTransportRegistry()
	logger := &mockLogger{}
	cfg := core.DefaultConfig()
	
	registry.Register("http", NewHTTPTransport(cfg, logger))
	registry.Register("mtls", NewmTLSTransport(cfg, logger))
	
	transports := registry.ListTransports()
	
	assert.Len(t, transports, 2)
	assert.Contains(t, transports, "http")
	assert.Contains(t, transports, "mtls")
}

func TestNewMultiConn(t *testing.T) {
	// Create mock connections
	conn1 := &mockConnection{id: "1"}
	conn2 := &mockConnection{id: "2"}
	
	mc := NewMultiConn(conn1, conn2)
	
	require.NotNil(t, mc)
	assert.Len(t, mc.conns, 2)
	assert.Equal(t, 0, mc.current)
}

func TestNewMultiConn_Empty(t *testing.T) {
	assert.Panics(t, func() {
		NewMultiConn()
	})
}

func TestMultiConn_Read(t *testing.T) {
	conn1 := &mockConnection{id: "1", readData: []byte("data1")}
	conn2 := &mockConnection{id: "2", readData: []byte("data2")}
	
	mc := NewMultiConn(conn1, conn2)
	
	buf := make([]byte, 10)
	n, err := mc.Read(buf)
	
	assert.NoError(t, err)
	assert.Equal(t, len("data1"), n)
	assert.Equal(t, "data1", string(buf[:n]))
}

func TestMultiConn_Read_Failover(t *testing.T) {
	conn1 := &mockConnection{id: "1", readError: assert.AnError}
	conn2 := &mockConnection{id: "2", readData: []byte("data2")}
	
	mc := NewMultiConn(conn1, conn2)
	
	buf := make([]byte, 10)
	n, err := mc.Read(buf)
	
	assert.NoError(t, err)
	assert.Equal(t, len("data2"), n)
	assert.Equal(t, "data2", string(buf[:n]))
	assert.Equal(t, 1, mc.current) // Should have switched to conn2
}

func TestMultiConn_Write(t *testing.T) {
	conn1 := &mockConnection{id: "1"}
	conn2 := &mockConnection{id: "2"}
	
	mc := NewMultiConn(conn1, conn2)
	
	data := []byte("test")
	n, err := mc.Write(data)
	
	assert.NoError(t, err)
	assert.Equal(t, len(data), n)
}

func TestMultiConn_Close(t *testing.T) {
	conn1 := &mockConnection{id: "1"}
	conn2 := &mockConnection{id: "2"}
	
	mc := NewMultiConn(conn1, conn2)
	
	err := mc.Close()
	
	assert.NoError(t, err)
	assert.True(t, conn1.closed)
	assert.True(t, conn2.closed)
}

func TestMultiConn_RemoteAddr(t *testing.T) {
	conn1 := &mockConnection{id: "1"}
	conn2 := &mockConnection{id: "2"}
	
	mc := NewMultiConn(conn1, conn2)
	
	addr := mc.RemoteAddr()
	
	assert.NotNil(t, addr)
}

func TestMultiConn_LocalAddr(t *testing.T) {
	conn1 := &mockConnection{id: "1"}
	conn2 := &mockConnection{id: "2"}
	
	mc := NewMultiConn(conn1, conn2)
	
	addr := mc.LocalAddr()
	
	assert.NotNil(t, addr)
}

func TestNewBufferedConn(t *testing.T) {
	conn := &mockConnection{id: "1"}
	
	bc := NewBufferedConn(conn)
	
	require.NotNil(t, bc)
	assert.Equal(t, conn, bc.conn)
}

func TestBufferedConn_Read(t *testing.T) {
	conn := &mockConnection{id: "1", readData: []byte("test")}
	bc := NewBufferedConn(conn)
	
	buf := make([]byte, 10)
	n, err := bc.Read(buf)
	
	assert.NoError(t, err)
	assert.Equal(t, len("test"), n)
}

func TestBufferedConn_Write(t *testing.T) {
	conn := &mockConnection{id: "1"}
	bc := NewBufferedConn(conn)
	
	data := []byte("test")
	n, err := bc.Write(data)
	
	assert.NoError(t, err)
	assert.Equal(t, len(data), n)
}

func TestBufferedConn_Close(t *testing.T) {
	conn := &mockConnection{id: "1"}
	bc := NewBufferedConn(conn)
	
	err := bc.Close()
	
	assert.NoError(t, err)
	assert.True(t, conn.closed)
}

func TestBufferedConn_RemoteAddr(t *testing.T) {
	conn := &mockConnection{id: "1"}
	bc := NewBufferedConn(conn)
	
	addr := bc.RemoteAddr()
	
	assert.NotNil(t, addr)
}

func TestBufferedConn_LocalAddr(t *testing.T) {
	conn := &mockConnection{id: "1"}
	bc := NewBufferedConn(conn)
	
	addr := bc.LocalAddr()
	
	assert.NotNil(t, addr)
}

func TestBufferedConn_SetDeadline(t *testing.T) {
	conn := &mockConnection{id: "1"}
	bc := NewBufferedConn(conn)
	
	err := bc.SetDeadline(time.Now().Add(time.Second))
	
	assert.NoError(t, err)
}

// Mock connection for testing
type mockConnection struct {
	id        string
	readData  []byte
	readError error
	writeErr  error
	closed    bool
}

func (m *mockConnection) Read(b []byte) (int, error) {
	if m.readError != nil {
		return 0, m.readError
	}
	copy(b, m.readData)
	return len(m.readData), nil
}

func (m *mockConnection) Write(b []byte) (int, error) {
	if m.writeErr != nil {
		return 0, m.writeErr
	}
	return len(b), nil
}

func (m *mockConnection) Close() error {
	m.closed = true
	return nil
}

func (m *mockConnection) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
}

func (m *mockConnection) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

func (m *mockConnection) SetDeadline(t time.Time) error {
	return nil
}

func (m *mockConnection) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockConnection) SetWriteDeadline(t time.Time) error {
	return nil
}

