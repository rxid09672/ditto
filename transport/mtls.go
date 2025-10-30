package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/ditto/ditto/core"
)

// mTLSTransport implements mutual TLS transport
type mTLSTransport struct {
	listener net.Listener
	config   *tls.Config
	logger   interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

// NewmTLSTransport creates a new mTLS transport
func NewmTLSTransport(config *core.Config, logger interface {
	Info(string, ...interface{})
	Debug(string, ...interface{})
	Error(string, ...interface{})
}) *mTLSTransport {
	return &mTLSTransport{
		logger: logger,
	}
}

func (mt *mTLSTransport) Name() string {
	return "mtls"
}

func (mt *mTLSTransport) Start(ctx context.Context, tConfig *TransportConfig) error {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}
	
	if tConfig.TLSEnabled {
		cert, err := tls.LoadX509KeyPair(tConfig.TLSCertPath, tConfig.TLSKeyPath)
		if err != nil {
			return fmt.Errorf("failed to load certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	
	var err error
	mt.listener, err = tls.Listen("tcp", tConfig.BindAddr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to start mTLS listener: %w", err)
	}
	
	mt.config = tlsConfig
	mt.logger.Info("mTLS transport started on %s", tConfig.BindAddr)
	
	return nil
}

func (mt *mTLSTransport) Stop() error {
	if mt.listener != nil {
		return mt.listener.Close()
	}
	return nil
}

func (mt *mTLSTransport) Accept() (Connection, error) {
	if mt.listener == nil {
		return nil, fmt.Errorf("transport not started")
	}
	
	conn, err := mt.listener.Accept()
	if err != nil {
		return nil, err
	}
	
	tlsConn := conn.(*tls.Conn)
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}
	
	return &tlsConnection{conn: tlsConn}, nil
}

func (mt *mTLSTransport) Connect(ctx context.Context, addr string) (Connection, error) {
	dialer := &net.Dialer{
		Timeout: 30 * time.Second,
	}
	
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}
	
	tlsConn := tls.Client(conn, mt.config)
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}
	
	return &tlsConnection{conn: tlsConn}, nil
}

// tlsConnection wraps a TLS connection
type tlsConnection struct {
	conn *tls.Conn
}

func (tc *tlsConnection) Read(b []byte) (n int, err error) {
	return tc.conn.Read(b)
}

func (tc *tlsConnection) Write(b []byte) (n int, err error) {
	return tc.conn.Write(b)
}

func (tc *tlsConnection) Close() error {
	return tc.conn.Close()
}

func (tc *tlsConnection) RemoteAddr() net.Addr {
	return tc.conn.RemoteAddr()
}

func (tc *tlsConnection) LocalAddr() net.Addr {
	return tc.conn.LocalAddr()
}

func (tc *tlsConnection) SetDeadline(t time.Time) error {
	return tc.conn.SetDeadline(t)
}

func (tc *tlsConnection) SetReadDeadline(t time.Time) error {
	return tc.conn.SetReadDeadline(t)
}

func (tc *tlsConnection) SetWriteDeadline(t time.Time) error {
	return tc.conn.SetWriteDeadline(t)
}

