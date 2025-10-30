package pivoting

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPortForwardManager(t *testing.T) {
	pfm := NewPortForwardManager()
	
	require.NotNil(t, pfm)
	assert.NotNil(t, pfm.forwards)
	assert.Equal(t, uint64(1), pfm.nextID)
}

func TestPortForwardManager_AddPortForward(t *testing.T) {
	pfm := NewPortForwardManager()
	
	pf, err := pfm.AddPortForward("session-1", "127.0.0.1:8080", "127.0.0.1:9090")
	
	require.NoError(t, err)
	assert.NotNil(t, pf)
	assert.Equal(t, uint64(1), pf.ID)
	assert.Equal(t, "session-1", pf.SessionID)
	assert.Equal(t, "127.0.0.1:8080", pf.RemoteAddr)
	assert.Equal(t, "127.0.0.1:9090", pf.LocalAddr)
}

func TestPortForwardManager_RemovePortForward(t *testing.T) {
	pfm := NewPortForwardManager()
	
	pf, _ := pfm.AddPortForward("session-1", "127.0.0.1:8080", "127.0.0.1:9090")
	
	err := pfm.RemovePortForward(pf.ID)
	
	require.NoError(t, err)
	
	// Should be removed
	err = pfm.RemovePortForward(pf.ID)
	assert.Error(t, err)
}

func TestPortForwardManager_RemovePortForward_NotFound(t *testing.T) {
	pfm := NewPortForwardManager()
	
	err := pfm.RemovePortForward(999)
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestPortForward_Start(t *testing.T) {
	pfm := NewPortForwardManager()
	pf, _ := pfm.AddPortForward("session-1", "127.0.0.1:8080", "127.0.0.1:0")
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	handler := func(conn net.Conn) {
		conn.Close()
	}
	
	err := pf.Start(ctx, handler)
	
	require.NoError(t, err)
	assert.NotNil(t, pf.listener)
	
	// Cleanup
	pf.Stop()
}

func TestPortForward_Stop(t *testing.T) {
	pfm := NewPortForwardManager()
	pf, _ := pfm.AddPortForward("session-1", "127.0.0.1:8080", "127.0.0.1:0")
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	pf.Start(ctx, func(conn net.Conn) {})
	
	err := pf.Stop()
	
	require.NoError(t, err)
}

func TestPortForward_Stop_NotStarted(t *testing.T) {
	pfm := NewPortForwardManager()
	pf, _ := pfm.AddPortForward("session-1", "127.0.0.1:8080", "127.0.0.1:9090")
	
	err := pf.Stop()
	
	require.NoError(t, err)
}

func TestNewSOCKS5Manager(t *testing.T) {
	sm := NewSOCKS5Manager()
	
	require.NotNil(t, sm)
	assert.NotNil(t, sm.proxies)
	assert.Equal(t, uint64(1), sm.nextID)
}

func TestSOCKS5Manager_AddSOCKS5(t *testing.T) {
	sm := NewSOCKS5Manager()
	
	proxy, err := sm.AddSOCKS5("session-1", "127.0.0.1:1080", "user", "pass")
	
	require.NoError(t, err)
	assert.NotNil(t, proxy)
	assert.Equal(t, uint64(1), proxy.ID)
	assert.Equal(t, "session-1", proxy.SessionID)
	assert.Equal(t, "127.0.0.1:1080", proxy.BindAddr)
}

func TestSOCKS5Manager_RemoveSOCKS5(t *testing.T) {
	sm := NewSOCKS5Manager()
	
	proxy, _ := sm.AddSOCKS5("session-1", "127.0.0.1:1080", "", "")
	
	err := sm.RemoveSOCKS5(proxy.ID)
	
	require.NoError(t, err)
	
	err = sm.RemoveSOCKS5(proxy.ID)
	assert.Error(t, err)
}

func TestSOCKS5Proxy_Start(t *testing.T) {
	sm := NewSOCKS5Manager()
	proxy, _ := sm.AddSOCKS5("session-1", "127.0.0.1:0", "", "")
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	handler := func(conn net.Conn) {
		conn.Close()
	}
	
	err := proxy.Start(ctx, handler)
	
	require.NoError(t, err)
	assert.NotNil(t, proxy.listener)
	
	proxy.Stop()
}

func TestSOCKS5Proxy_Stop(t *testing.T) {
	sm := NewSOCKS5Manager()
	proxy, _ := sm.AddSOCKS5("session-1", "127.0.0.1:0", "", "")
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	proxy.Start(ctx, func(conn net.Conn) {})
	
	err := proxy.Stop()
	
	require.NoError(t, err)
}

func TestPortForwardManager_Concurrent(t *testing.T) {
	pfm := NewPortForwardManager()
	
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			pf, _ := pfm.AddPortForward(string(rune(id)), "127.0.0.1:8080", "127.0.0.1:0")
			pfm.RemovePortForward(pf.ID)
			done <- true
		}(i)
	}
	
	for i := 0; i < 10; i++ {
		<-done
	}
	
	// Should not panic
	assert.NotNil(t, pfm.forwards)
}

func TestPortForward_Start_CancelContext(t *testing.T) {
	pfm := NewPortForwardManager()
	pf, _ := pfm.AddPortForward("session-1", "127.0.0.1:8080", "127.0.0.1:0")
	
	ctx, cancel := context.WithCancel(context.Background())
	
	pf.Start(ctx, func(conn net.Conn) {})
	
	// Cancel context
	cancel()
	
	// Give goroutine time to exit
	time.Sleep(10 * time.Millisecond)
	
	// Should handle cancellation gracefully
	_ = pf
}

