package transport

import (
	"bufio"
	"context"
	"net"
	"time"
)

// Transport defines the interface for C2 transports
type Transport interface {
	// Name returns the transport name
	Name() string
	
	// Start starts the transport listener
	Start(ctx context.Context, config *TransportConfig) error
	
	// Stop stops the transport
	Stop() error
	
	// Accept accepts incoming connections
	Accept() (Connection, error)
	
	// Connect connects to a remote server
	Connect(ctx context.Context, addr string) (Connection, error)
}

// Connection represents a transport connection
type Connection interface {
	// Read reads data from the connection
	Read(b []byte) (n int, err error)
	
	// Write writes data to the connection
	Write(b []byte) (n int, err error)
	
	// Close closes the connection
	Close() error
	
	// RemoteAddr returns the remote address
	RemoteAddr() net.Addr
	
	// LocalAddr returns the local address
	LocalAddr() net.Addr
	
	// SetDeadline sets read/write deadlines
	SetDeadline(t time.Time) error
	
	// SetReadDeadline sets read deadline
	SetReadDeadline(t time.Time) error
	
	// SetWriteDeadline sets write deadline
	SetWriteDeadline(t time.Time) error
}

// TransportConfig holds transport configuration
type TransportConfig struct {
	// Common settings
	BindAddr string
	ReadTimeout time.Duration
	WriteTimeout time.Duration
	
	// TLS settings
	TLSEnabled bool
	TLSCertPath string
	TLSKeyPath string
	
	// Protocol-specific settings
	ProtocolSpecific map[string]interface{}
}

// TransportRegistry manages available transports
type TransportRegistry struct {
	transports map[string]Transport
}

// NewTransportRegistry creates a new transport registry
func NewTransportRegistry() *TransportRegistry {
	return &TransportRegistry{
		transports: make(map[string]Transport),
	}
}

// Register registers a transport
func (tr *TransportRegistry) Register(name string, transport Transport) {
	tr.transports[name] = transport
}

// GetTransport retrieves a transport by name
func (tr *TransportRegistry) GetTransport(name string) (Transport, bool) {
	transport, ok := tr.transports[name]
	return transport, ok
}

// ListTransports returns all registered transport names
func (tr *TransportRegistry) ListTransports() []string {
	names := make([]string, 0, len(tr.transports))
	for name := range tr.transports {
		names = append(names, name)
	}
	return names
}

// MultiConn wraps multiple connections for failover
type MultiConn struct {
	conns []Connection
	current int
}

// NewMultiConn creates a multi-connection wrapper
func NewMultiConn(conns ...Connection) *MultiConn {
	if len(conns) == 0 {
		panic("must provide at least one connection")
	}
	return &MultiConn{
		conns: conns,
		current: 0,
	}
}

func (mc *MultiConn) Read(b []byte) (n int, err error) {
	startIdx := mc.current
	for {
		conn := mc.conns[mc.current]
		n, err = conn.Read(b)
		if err == nil {
			return n, nil
		}
		// Try next connection
		mc.current = (mc.current + 1) % len(mc.conns)
		// If we've tried all connections, return error
		if mc.current == startIdx {
			return 0, err
		}
	}
}

func (mc *MultiConn) Write(b []byte) (n int, err error) {
	startIdx := mc.current
	for {
		conn := mc.conns[mc.current]
		n, err = conn.Write(b)
		if err == nil {
			return n, nil
		}
		// Try next connection
		mc.current = (mc.current + 1) % len(mc.conns)
		// If we've tried all connections, return error
		if mc.current == startIdx {
			return 0, err
		}
	}
}

func (mc *MultiConn) Close() error {
	var firstErr error
	for _, conn := range mc.conns {
		if err := conn.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (mc *MultiConn) RemoteAddr() net.Addr {
	return mc.conns[mc.current].RemoteAddr()
}

func (mc *MultiConn) LocalAddr() net.Addr {
	return mc.conns[mc.current].LocalAddr()
}

func (mc *MultiConn) SetDeadline(t time.Time) error {
	var firstErr error
	for _, conn := range mc.conns {
		if err := conn.SetDeadline(t); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (mc *MultiConn) SetReadDeadline(t time.Time) error {
	var firstErr error
	for _, conn := range mc.conns {
		if err := conn.SetReadDeadline(t); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (mc *MultiConn) SetWriteDeadline(t time.Time) error {
	var firstErr error
	for _, conn := range mc.conns {
		if err := conn.SetWriteDeadline(t); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// BufferedConn wraps a connection with actual buffering for improved performance
type BufferedConn struct {
	conn Connection
	r    *bufio.Reader
	w    *bufio.Writer
}

// NewBufferedConn creates a buffered connection with actual buffering
func NewBufferedConn(conn Connection) *BufferedConn {
	return &BufferedConn{
		conn: conn,
		r:    bufio.NewReader(conn),
		w:    bufio.NewWriter(conn),
	}
}

func (bc *BufferedConn) Read(b []byte) (n int, err error) {
	return bc.r.Read(b)
}

func (bc *BufferedConn) Write(b []byte) (n int, err error) {
	return bc.w.Write(b)
}

func (bc *BufferedConn) Close() error {
	// Flush buffered writes before closing
	if err := bc.w.Flush(); err != nil {
		return err
	}
	return bc.conn.Close()
}

func (bc *BufferedConn) RemoteAddr() net.Addr {
	return bc.conn.RemoteAddr()
}

func (bc *BufferedConn) LocalAddr() net.Addr {
	return bc.conn.LocalAddr()
}

func (bc *BufferedConn) SetDeadline(t time.Time) error {
	return bc.conn.SetDeadline(t)
}

func (bc *BufferedConn) SetReadDeadline(t time.Time) error {
	return bc.conn.SetReadDeadline(t)
}

func (bc *BufferedConn) SetWriteDeadline(t time.Time) error {
	return bc.conn.SetWriteDeadline(t)
}

