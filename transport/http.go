package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/ditto/ditto/core"
)

// HTTPTransport implements HTTP/HTTPS transport
type HTTPTransport struct {
	server   *http.Server
	listener net.Listener
	config   *core.Config
	logger   interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

// NewHTTPTransport creates a new HTTP transport
func NewHTTPTransport(config *core.Config, logger interface {
	Info(string, ...interface{})
	Debug(string, ...interface{})
	Error(string, ...interface{})
}) *HTTPTransport {
	return &HTTPTransport{
		config: config,
		logger: logger,
	}
}

func (ht *HTTPTransport) Name() string {
	if ht.config.Server.TLSEnabled {
		return "https"
	}
	return "http"
}

func (ht *HTTPTransport) Start(ctx context.Context, tConfig *TransportConfig) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/beacon", ht.handleBeacon)
	mux.HandleFunc("/task", ht.handleTask)
	mux.HandleFunc("/result", ht.handleResult)
	mux.HandleFunc("/upgrade", ht.handleUpgrade)
	
	ht.server = &http.Server{
		Handler:      mux,
		ReadTimeout:  ht.config.Server.ReadTimeout,
		WriteTimeout: ht.config.Server.WriteTimeout,
		IdleTimeout:  ht.config.Server.KeepAlive,
	}
	
	if ht.config.Server.TLSEnabled {
		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
		ht.server.TLSConfig = tlsConfig
		
		var err error
		ht.listener, err = tls.Listen("tcp", tConfig.BindAddr, tlsConfig)
		if err != nil {
			return fmt.Errorf("failed to start TLS listener: %w", err)
		}
	} else {
		var err error
		ht.listener, err = net.Listen("tcp", tConfig.BindAddr)
		if err != nil {
			return fmt.Errorf("failed to start listener: %w", err)
		}
	}
	
	ht.logger.Info("HTTP transport started on %s", tConfig.BindAddr)
	
	go func() {
		if ht.config.Server.TLSEnabled {
			ht.server.ServeTLS(ht.listener, ht.config.Server.TLSCertPath, ht.config.Server.TLSKeyPath)
		} else {
			ht.server.Serve(ht.listener)
		}
	}()
	
	return nil
}

func (ht *HTTPTransport) Stop() error {
	if ht.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return ht.server.Shutdown(ctx)
	}
	return nil
}

func (ht *HTTPTransport) Accept() (Connection, error) {
	// HTTP connections are handled per-request
	return nil, fmt.Errorf("HTTP transport does not support Accept()")
}

func (ht *HTTPTransport) Connect(ctx context.Context, addr string) (Connection, error) {
	// Client-side connection via HTTP client
	return nil, fmt.Errorf("not implemented")
}

func (ht *HTTPTransport) handleBeacon(w http.ResponseWriter, r *http.Request) {
	// Handle beacon request
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func (ht *HTTPTransport) handleTask(w http.ResponseWriter, r *http.Request) {
	// Handle task request
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func (ht *HTTPTransport) handleResult(w http.ResponseWriter, r *http.Request) {
	// Handle result request
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func (ht *HTTPTransport) handleUpgrade(w http.ResponseWriter, r *http.Request) {
	// Handle upgrade request
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// HTTPConnection wraps HTTP request/response as a connection
type HTTPConnection struct {
	req  *http.Request
	resp http.ResponseWriter
	done chan struct{}
}

func NewHTTPConnection(req *http.Request, resp http.ResponseWriter) *HTTPConnection {
	return &HTTPConnection{
		req:  req,
		resp: resp,
		done: make(chan struct{}),
	}
}

func (hc *HTTPConnection) Read(b []byte) (n int, err error) {
	return hc.req.Body.Read(b)
}

func (hc *HTTPConnection) Write(b []byte) (n int, err error) {
	return hc.resp.Write(b)
}

func (hc *HTTPConnection) Close() error {
	close(hc.done)
	return nil
}

func (hc *HTTPConnection) RemoteAddr() net.Addr {
	host, port, err := net.SplitHostPort(hc.req.RemoteAddr)
	if err != nil {
		return &net.TCPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 0}
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return &net.TCPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 0}
	}
	portNum := 0
	if port != "" {
		fmt.Sscanf(port, "%d", &portNum)
	}
	return &net.TCPAddr{IP: ip, Port: portNum}
}

func (hc *HTTPConnection) LocalAddr() net.Addr {
	return nil
}

func (hc *HTTPConnection) SetDeadline(t time.Time) error {
	return nil
}

func (hc *HTTPConnection) SetReadDeadline(t time.Time) error {
	return nil
}

func (hc *HTTPConnection) SetWriteDeadline(t time.Time) error {
	return nil
}

