package pivoting

import (
	"context"
	"fmt"
	"net"
	"sync"
)

// PortForward manages port forwarding through implant
type PortForward struct {
	ID         uint64
	SessionID  string
	RemoteAddr string
	LocalAddr  string
	listener   net.Listener
	mu         sync.RWMutex
}

// PortForwardManager manages port forwards
type PortForwardManager struct {
	forwards map[uint64]*PortForward
	nextID   uint64
	mu       sync.RWMutex
}

// NewPortForwardManager creates a new port forward manager
func NewPortForwardManager() *PortForwardManager {
	return &PortForwardManager{
		forwards: make(map[uint64]*PortForward),
		nextID:   1,
	}
}

// AddPortForward adds a new port forward
func (pfm *PortForwardManager) AddPortForward(sessionID, remoteAddr, localAddr string) (*PortForward, error) {
	pfm.mu.Lock()
	defer pfm.mu.Unlock()
	
	id := pfm.nextID
	pfm.nextID++
	
	pf := &PortForward{
		ID:         id,
		SessionID:  sessionID,
		RemoteAddr: remoteAddr,
		LocalAddr:  localAddr,
	}
	
	pfm.forwards[id] = pf
	return pf, nil
}

// RemovePortForward removes a port forward
func (pfm *PortForwardManager) RemovePortForward(id uint64) error {
	pfm.mu.Lock()
	defer pfm.mu.Unlock()
	
	pf, ok := pfm.forwards[id]
	if !ok {
		return fmt.Errorf("port forward not found")
	}
	
	if pf.listener != nil {
		pf.listener.Close()
	}
	
	delete(pfm.forwards, id)
	return nil
}

// Start starts a port forward
func (pf *PortForward) Start(ctx context.Context, handler func(net.Conn)) error {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	
	listener, err := net.Listen("tcp", pf.LocalAddr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	
	pf.listener = listener
	
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				conn, err := listener.Accept()
				if err != nil {
					continue
				}
				go handler(conn)
			}
		}
	}()
	
	return nil
}

// Stop stops a port forward
func (pf *PortForward) Stop() error {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	
	if pf.listener != nil {
		return pf.listener.Close()
	}
	return nil
}

// SOCKS5Proxy implements SOCKS5 proxy server
type SOCKS5Proxy struct {
	ID        uint64
	SessionID string
	BindAddr  string
	Username  string
	Password  string
	listener  net.Listener
	mu        sync.RWMutex
}

// SOCKS5Manager manages SOCKS5 proxies
type SOCKS5Manager struct {
	proxies map[uint64]*SOCKS5Proxy
	nextID  uint64
	mu      sync.RWMutex
}

// NewSOCKS5Manager creates a new SOCKS5 manager
func NewSOCKS5Manager() *SOCKS5Manager {
	return &SOCKS5Manager{
		proxies: make(map[uint64]*SOCKS5Proxy),
		nextID:  1,
	}
}

// AddSOCKS5 adds a new SOCKS5 proxy
func (sm *SOCKS5Manager) AddSOCKS5(sessionID, bindAddr, username, password string) (*SOCKS5Proxy, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	id := sm.nextID
	sm.nextID++
	
	proxy := &SOCKS5Proxy{
		ID:        id,
		SessionID: sessionID,
		BindAddr:  bindAddr,
		Username:  username,
		Password:  password,
	}
	
	sm.proxies[id] = proxy
	return proxy, nil
}

// RemoveSOCKS5 removes a SOCKS5 proxy
func (sm *SOCKS5Manager) RemoveSOCKS5(id uint64) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	proxy, ok := sm.proxies[id]
	if !ok {
		return fmt.Errorf("SOCKS5 proxy not found")
	}
	
	if proxy.listener != nil {
		proxy.listener.Close()
	}
	
	delete(sm.proxies, id)
	return nil
}

// Start starts a SOCKS5 proxy
func (sp *SOCKS5Proxy) Start(ctx context.Context, handler func(net.Conn)) error {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	
	listener, err := net.Listen("tcp", sp.BindAddr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	
	sp.listener = listener
	
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				conn, err := listener.Accept()
				if err != nil {
					continue
				}
				go handler(conn)
			}
		}
	}()
	
	return nil
}

// Stop stops a SOCKS5 proxy
func (sp *SOCKS5Proxy) Stop() error {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	
	if sp.listener != nil {
		return sp.listener.Close()
	}
	return nil
}

